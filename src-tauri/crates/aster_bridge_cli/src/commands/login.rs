//
// Aster Communications Inc.
//
// Copyright (c) 2026 Aster Communications Inc.
//
// This file is part of this project.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.
//
use std::path::Path;
use std::sync::Arc;

use aster_bridge_core::account_state::AccountState;
use aster_bridge_core::api_client::ApiClient;
use aster_bridge_core::auth::device_identity::{self, DeviceIdentity};
use aster_bridge_core::auth::session::Session;
use aster_bridge_core::db::Database;
use aster_bridge_core::error::BridgeError;
use aster_bridge_core::ops::{self, SignInPoll};
use aster_bridge_core::runtime::{self, ClientProfile, StartError};
use serde_json::json;
use tokio::sync::RwLock;
use tokio::time::MissedTickBehavior;

use super::common;
use crate::context::{self, Context};
use crate::exit::{CliError, CliResult, EXIT_DEVICE, EXIT_ERROR, EXIT_OK, LINK_DEVICE_URL};
use crate::lock::InstanceLock;
use crate::output::{Output, Tone};
use crate::secret_backend::{self, map_store_error};
use crate::spinner::{Spinner, FRAME_INTERVAL};
use crate::signals;
use crate::state::{self, AccountInfo, PendingLogin, PlanInfo};

const PENDING_REUSE_MARGIN: i64 = 15;

pub async fn run(ctx: &Context, no_wait: bool) -> CliResult<i32> {
    let dir = ctx.data_dir.clone();
    let out = ctx.out;
    let _lock = InstanceLock::acquire(&dir)?;

    let existing = state::load(&dir);
    if let Some(account) = existing.account.as_ref().filter(|_| secret_backend::has_record(&dir)) {
        if out.json {
            out.json(json!({
                "status": "signed_in",
                "already_signed_in": true,
                "account": { "email": account.email, "username": account.username, "user_id": account.user_id },
            }));
        } else {
            out.banner(Tone::Good, "Connected to Aster Mail");
            out.blank();
            out.fields(&[("Account", account.email.clone())]);
            out.blank();
            out.line(out.dim(
                "To use a different account, run aster-bridge logout first.",
            ));
        }
        return Ok(EXIT_OK);
    }

    secret_backend::activate_or_create(&dir, ctx.global.secret_backend)?;
    let mut identity = device_identity::get_or_create_identity(&dir)
        .map_err(|e| map_store_error("Couldn't create the device identity", e))?;
    let client = context::api_client();

    let pending = match state::load_pending(&dir) {
        Some(pending) if pending.expires_at - state::now() > PENDING_REUSE_MARGIN => pending,
        _ => {
            let code = ops::request_device_code(&client, &identity, ClientProfile::Cli)
                .await
                .map_err(request_error)?;
            let pending = PendingLogin {
                expires_at: state::now() + i64::try_from(code.expires_in).unwrap_or(600),
                code: code.code,
                normalized: code.normalized,
            };
            state::save_pending(&dir, &pending).map_err(CliError::general)?;
            pending
        }
    };

    show_code(&out, &pending, no_wait);
    if no_wait {
        return Ok(EXIT_OK);
    }

    let session = wait_for_confirmation(&out, &client, &mut identity, &dir, &pending).await?;
    drop(identity);
    finish(ctx, &client, session).await
}

fn request_error(error: BridgeError) -> CliError {
    match error {
        BridgeError::Network(e) => common::network_error(&e.to_string()),
        BridgeError::PlanUpgradeRequired(_) => common::access_denied(None),
        other => CliError::general(format!("Couldn't get a sign-in code: {}", other)),
    }
}

fn format_remaining(expires_at: i64) -> String {
    let secs = (expires_at - state::now()).max(0);
    format!("{}:{:02}", secs / 60, secs % 60)
}

fn show_code(out: &Output, pending: &PendingLogin, no_wait: bool) {
    if out.json {
        out.json(json!({
            "status": "pending",
            "code": pending.code,
            "url": LINK_DEVICE_URL,
            "expires_at": pending.expires_at,
        }));
        return;
    }
    out.banner(Tone::Accent, "Link this device");
    out.blank();
    out.line(format!(
        "  {} Open {} in a browser where you're signed in to Aster Mail.",
        out.accent("1."),
        out.bold(LINK_DEVICE_URL)
    ));
    out.line(format!("  {} Enter this code:", out.accent("2.")));
    out.blank();
    out.line(format!("      {}", out.heading(&pending.code)));
    out.blank();
    if no_wait {
        out.line(format!(
            "The code expires in {}. After you enter it, run aster-bridge login again to finish signing in.",
            format_remaining(pending.expires_at)
        ));
    }
}

fn expired(dir: &Path) -> CliError {
    state::clear_pending(dir);
    CliError::new(EXIT_DEVICE, "code_expired", "The sign-in code expired.")
        .with_hint("To get a new code, run: aster-bridge login")
}

async fn wait_for_confirmation(
    out: &Output,
    client: &ApiClient,
    identity: &mut DeviceIdentity,
    dir: &Path,
    pending: &PendingLogin,
) -> CliResult<Session> {
    let animated = out.animates();
    let mut poll = tokio::time::interval(context::login_poll_interval());
    poll.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut redraw = tokio::time::interval(FRAME_INTERVAL);
    redraw.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let cancel = signals::ctrl_c();
    tokio::pin!(cancel);
    let mut warned = false;

    let waiting = if animated {
        "Waiting for you to enter the code".to_string()
    } else {
        format!(
            "Waiting for you to enter the code. It expires in {}.",
            format_remaining(pending.expires_at)
        )
    };
    let mut spinner = Spinner::start(out, waiting);
    spinner.set_detail(waiting_detail(pending.expires_at));

    let result = loop {
        if state::now() >= pending.expires_at {
            break Err(expired(dir));
        }
        tokio::select! {
            _ = &mut cancel => {
                break Err(CliError::new(EXIT_ERROR, "canceled", "Sign-in canceled.")
                    .with_hint("The code stays valid until it expires. To continue, run: aster-bridge login"));
            }
            _ = redraw.tick(), if animated => {
                spinner.set_detail(waiting_detail(pending.expires_at));
                spinner.tick();
            }
            _ = poll.tick() => {
                match ops::poll_device_sign_in(client, identity, dir, &pending.normalized).await {
                    Ok(SignInPoll::Pending(_)) => {}
                    Ok(SignInPoll::Expired) => break Err(expired(dir)),
                    Ok(SignInPoll::Confirmed(session)) => break Ok(*session),
                    Err(BridgeError::Network(e)) => {
                        if !warned {
                            spinner.clear();
                            out.warn(format!("Couldn't reach Aster Mail, so Aster Bridge keeps trying. Details: {}", e));
                            warned = true;
                        }
                    }
                    Err(BridgeError::Api(message)) if message.starts_with("404") || message.starts_with("410") => {
                        break Err(expired(dir));
                    }
                    Err(e) => break Err(CliError::general(format!("Couldn't finish signing in: {}", e))),
                }
            }
        }
    };
    if result.is_ok() {
        spinner.finish(Tone::Good, "Code accepted.");
    } else {
        spinner.clear();
    }
    result
}

fn waiting_detail(expires_at: i64) -> String {
    format!(
        "expires in {}. Press Control-C to cancel.",
        format_remaining(expires_at)
    )
}

async fn finish(ctx: &Context, client: &ApiClient, session: Session) -> CliResult<i32> {
    let dir = &ctx.data_dir;
    let out = &ctx.out;
    state::clear_pending(dir);

    let profile = client.get_user_profile(session.access_token.as_str()).await.ok();
    let user_id = profile
        .as_ref()
        .map(|p| p.user_id)
        .unwrap_or(session.user_id)
        .to_string();
    let account = AccountInfo {
        user_id: user_id.clone(),
        email: profile
            .as_ref()
            .map(|p| p.email.clone())
            .unwrap_or_else(|| session.email.clone()),
        username: profile
            .as_ref()
            .map(|p| p.username.clone())
            .unwrap_or_else(|| session.username.clone()),
        display_name: profile.and_then(|p| p.display_name),
    };

    let db = Database::open(dir).map_err(|e| map_store_error("Couldn't create the mail cache", e))?;
    let previous_owner = state::load(dir).cache_user_id;
    if previous_owner.as_deref().is_some_and(|owner| owner != user_id) {
        db.clear_all_user_data().map_err(|e| {
            CliError::general(format!("Couldn't clear the previous account's cache: {}", e))
        })?;
    }
    drop(db);

    let config = common::load_config()?;
    let tuning = context::tuning(&config);
    let session = Arc::new(RwLock::new(session));
    let access = runtime::check_bridge_access(client, &session, tuning.plan_retry_delay).await;
    drop(session);
    let plan = match &access {
        Ok(grant) => Some(PlanInfo {
            code: Some(grant.plan_code().to_string()),
            has_bridge_access: true,
            checked_at: state::now(),
        }),
        Err(StartError::BridgeAccessRequired { plan_code }) => Some(PlanInfo {
            code: plan_code.clone(),
            has_bridge_access: false,
            checked_at: state::now(),
        }),
        Err(_) => None,
    };

    state::update(dir, |s| {
        s.account = Some(account.clone());
        s.cache_user_id = Some(user_id.clone());
        s.plan = plan.clone();
        s.account_state = AccountState::Active;
        s.ports = None;
        s.last_stop = None;
        s.last_sync = None;
    })
    .map_err(|e| CliError::general(format!("Couldn't save the sign-in: {}", e)))?;

    match access {
        Ok(grant) => {
            if out.json {
                out.json(json!({
                    "status": "signed_in",
                    "account": { "email": account.email, "username": account.username, "user_id": account.user_id },
                    "plan": plan,
                }));
            } else {
                connected_panel(
                    out,
                    &account.email,
                    Some(common::plan_label(Some(grant.plan_code()))),
                );
            }
            Ok(EXIT_OK)
        }
        Err(StartError::BridgeAccessRequired { plan_code }) => {
            Err(common::access_denied(plan_code.as_deref()).with_hint(common::upgrade_then_refresh_hint()))
        }
        Err(error) => {
            if out.json {
                out.json(json!({
                    "status": "signed_in",
                    "account": { "email": account.email, "username": account.username, "user_id": account.user_id },
                    "plan": null,
                    "warning": error.to_string(),
                }));
            } else {
                out.warn(format!(
                    "Couldn't check your plan: {}. Aster Bridge checks it again when it starts.",
                    error
                ));
                connected_panel(out, &account.email, None);
            }
            Ok(EXIT_OK)
        }
    }
}

fn connected_panel(out: &Output, email: &str, plan: Option<String>) {
    out.blank();
    out.banner(Tone::Good, "Connected to Aster Mail");
    out.blank();
    let mut rows = vec![("Account", email.to_string())];
    if let Some(plan) = plan {
        rows.push(("Plan", plan));
    }
    out.fields(&rows);
    out.blank();
    out.line(out.bold("Next steps"));
    out.steps(&[
        (
            "Start the mail servers".to_string(),
            "aster-bridge serve".to_string(),
        ),
        (
            "Create a password for an email app".to_string(),
            "aster-bridge app-password create".to_string(),
        ),
        (
            "Keep it running whenever you sign in".to_string(),
            "aster-bridge service install".to_string(),
        ),
    ]);
    out.blank();
    out.line(out.dim("To check the connection later, run: aster-bridge status"));
}
