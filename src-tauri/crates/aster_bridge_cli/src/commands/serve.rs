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
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use aster_bridge_core::account_state::AccountState;
use aster_bridge_core::api_client::ApiClient;
use aster_bridge_core::auth::app_passwords::AppPasswords;
use aster_bridge_core::auth::device_identity;
use aster_bridge_core::auth::session::{self, Session};
use aster_bridge_core::config::{self, BridgeConfig};
use aster_bridge_core::db::Database;
use aster_bridge_core::runtime::{
    self, BridgeRuntime, ClientProfile, RunningBridge, RuntimeDeps, Service, StartError,
    StartOptions, StopReason, LOOPBACK_HOST,
};
use aster_bridge_core::tls;
use serde_json::{json, Value};
use tokio::sync::{Mutex, Notify, RwLock};

use super::common::{self, VERSION};
use crate::context::{self, Context};
use crate::control;
use crate::events::{self, CliEvents, SinkGuard};
use crate::exit::{CliError, CliResult, EXIT_ERROR, EXIT_NOT_READY, EXIT_OK};
use crate::lock::InstanceLock;
use crate::output::Tone;
use crate::secret_backend::{self, map_store_error};
use crate::signals;
use crate::state::{self, AccountInfo, PlanInfo, StopInfo};

pub async fn run(ctx: &Context, json_events: bool, service: bool) -> CliResult<i32> {
    #[cfg(windows)]
    if service {
        unsafe {
            windows_sys::Win32::System::Console::FreeConsole();
        }
    }
    let ndjson = json_events || ctx.out.json;
    let _log = context::init_logging(ctx, true);
    let base_delay = context::service_retry_delay();
    let mut delay = base_delay;
    loop {
        let attempt_started = std::time::Instant::now();
        match serve(ctx, ndjson).await {
            Err(error) if service && error.exit_code >= EXIT_NOT_READY => {
                tracing::error!("aster-bridge stopped: {} ({})", error.message, error.code);
                ctx.out.error(&error);
                tokio::select! {
                    _ = tokio::time::sleep(context::service_failure_delay()) => {}
                    _ = signals::shutdown() => {}
                }
                return Ok(error.exit_code);
            }
            Err(error) if service => {
                if attempt_started.elapsed() >= SERVICE_HEALTHY_RUN {
                    delay = base_delay;
                }
                tracing::error!(
                    "aster-bridge stopped: {} ({}); trying again in {} seconds",
                    error.message,
                    error.code,
                    delay.as_secs()
                );
                tokio::select! {
                    _ = tokio::time::sleep(delay) => {}
                    _ = signals::shutdown() => return Ok(EXIT_OK),
                }
                delay = (delay * 2).min(SERVICE_RETRY_MAX);
            }
            Err(error) => {
                tracing::error!("aster-bridge stopped: {} ({})", error.message, error.code);
                return Err(error);
            }
            Ok(code) => return Ok(code),
        }
    }
}

const SERVICE_RETRY_MAX: Duration = Duration::from_secs(300);
const SERVICE_HEALTHY_RUN: Duration = Duration::from_secs(300);

fn plan_check_failed(detail: &str) -> CliError {
    CliError::new(
        EXIT_ERROR,
        "plan_check_failed",
        "Couldn't confirm your plan with Aster Mail, so Aster Bridge didn't start.",
    )
    .with_hint(format!(
        "Check your internet connection and try again. Details: {}",
        detail
    ))
}

fn config_key(service: Service) -> Option<&'static str> {
    match service {
        Service::Imap => Some("imap_port"),
        Service::Imaps => Some("imap_implicit_tls_port"),
        Service::Smtp => Some("smtp_port"),
        Service::Smtps => Some("smtp_implicit_tls_port"),
        Service::Jmap => Some("jmap_port"),
        Service::Carddav => Some("carddav_port"),
        Service::Pop3 => Some("pop3_port"),
        Service::Pop3s => Some("pop3s_port"),
        _ => None,
    }
}

fn start_error(error: StartError) -> CliError {
    match error {
        StartError::PortUnavailable {
            service,
            port,
            message,
            held_by_bridge,
        } => {
            let hint = match config_key(service) {
                Some(key) => format!(
                    "To use a different port, run: aster-bridge config set {} <port>",
                    key
                ),
                None => "To use a different port, run: aster-bridge config set".to_string(),
            };
            if held_by_bridge {
                CliError::locked(format!(
                    "Port {} for {} is in use by another copy of Aster Bridge.",
                    port,
                    service.label()
                ))
                .with_hint(format!("To run both, quit the other copy or change the port. {}", hint))
            } else {
                CliError::new(
                    EXIT_ERROR,
                    "port_unavailable",
                    format!("Port {} for {} isn't available: {}", port, service.label(), message),
                )
                .with_hint(hint)
            }
        }
        StartError::BridgeAccessRequired { plan_code } => {
            common::access_denied(plan_code.as_deref())
        }
        StartError::PlanCheckFailed(detail) => plan_check_failed(&detail),
        StartError::NotSignedIn => CliError::not_signed_in(),
        StartError::DeviceRevoked => CliError::device_revoked(),
        StartError::Io(message) | StartError::Database(message) => {
            CliError::general(format!("Aster Bridge couldn't start: {}", message))
        }
    }
}

async fn serve(ctx: &Context, ndjson: bool) -> CliResult<i32> {
    let dir = ctx.data_dir.clone();
    let _lock = InstanceLock::acquire(&dir)?;
    let cached = state::load(&dir);
    if cached.account.is_none() {
        return Err(CliError::not_signed_in());
    }
    if secret_backend::activate_existing(&dir, ctx.global.secret_backend)?.is_none() {
        return Err(CliError::not_signed_in());
    }
    tls::install_default_crypto_provider();
    let mut config = common::load_config()?;
    let identity = device_identity::get_or_create_identity(&dir)
        .map_err(|e| map_store_error("Couldn't load the device identity", e))?;
    let Some(device_id) = identity.device_id else {
        return Err(CliError::not_signed_in());
    };
    let db = Arc::new(
        Database::open(&dir).map_err(|e| map_store_error("Couldn't open the mail cache", e))?,
    );
    let client = Arc::new(context::api_client());

    tracing::info!("aster-bridge {} starting", VERSION);
    let session = session::restore_or_login(&config, &identity, &client)
        .await
        .map_err(|e| common::map_login_error(&dir, e))?;
    let email = session.email.clone();
    let account = AccountInfo {
        user_id: session.user_id.to_string(),
        email: session.email.clone(),
        username: session.username.clone(),
        display_name: cached.account.as_ref().and_then(|a| a.display_name.clone()),
    };
    common::save_state(&dir, |s| {
        s.account = Some(account);
        s.account_state = AccountState::Active;
    });

    let session = Arc::new(RwLock::new(session));
    let tuning = context::tuning(&config);
    let grant = match runtime::check_bridge_access(&client, &session, tuning.plan_retry_delay).await {
        Ok(grant) => grant,
        Err(StartError::BridgeAccessRequired { plan_code }) => {
            let code = plan_code.or_else(|| cached.plan.as_ref().and_then(|p| p.code.clone()));
            common::save_state(&dir, |s| {
                s.plan = Some(PlanInfo {
                    code: code.clone(),
                    has_bridge_access: false,
                    checked_at: state::now(),
                })
            });
            tracing::warn!("plan does not include Aster Bridge");
            return Err(common::access_denied(code.as_deref()));
        }
        Err(error) => return Err(start_error(error)),
    };
    let plan_code = grant.plan_code().to_string();
    common::save_state(&dir, |s| {
        s.plan = Some(PlanInfo {
            code: Some(plan_code.clone()),
            has_bridge_access: true,
            checked_at: state::now(),
        })
    });

    let tls_config = if config.tls_enabled {
        match tls::ensure_cert(&dir).and_then(|(certs, key)| tls::server_config(certs, key)) {
            Ok(server_config) => Some(server_config),
            Err(e) => {
                ctx.out.warn(format!(
                    "TLS is off because the certificate couldn't be loaded: {}",
                    e
                ));
                tracing::warn!("TLS disabled: {}", e);
                config.tls_enabled = false;
                None
            }
        }
    } else {
        None
    };

    let passwords = Arc::new(AppPasswords::new(db.clone()));
    let _sink = SinkGuard::install(CliEvents::new(dir.clone(), ndjson));
    let running = BridgeRuntime::start(
        grant,
        RuntimeDeps {
            session: session.clone(),
            db: db.clone(),
            client: client.clone(),
            passwords: passwords.clone(),
        },
        StartOptions {
            config: config.clone(),
            tls: tls_config,
            device_id,
            signing_key: identity.ed25519_signing_key.clone(),
            profile: ClientProfile::Cli,
            tuning,
        },
    )
    .await
    .map_err(start_error)?;
    drop(identity);

    let ports = running.bound_ports();
    if let Ok(mut saved) = config::load_config() {
        if ports.apply_to_config(&mut saved) {
            if let Err(e) = config::save_config(&saved) {
                tracing::warn!("couldn't save the selected ports: {}", e);
            }
        }
    }
    common::save_state(&dir, |s| s.ports = Some(ports.into()));

    let stop = Arc::new(Notify::new());
    let shared = Arc::new(Shared {
        data_dir: dir.clone(),
        running: running.clone(),
        db: db.clone(),
        passwords,
        client,
        session,
        stop: stop.clone(),
        started_at: state::now(),
        config,
        refresh_lock: Mutex::new(()),
    });
    let control_server = match control::start(&dir, handler(shared.clone())).await {
        Ok(server) => Some(server),
        Err(e) => {
            ctx.out.warn(format!(
                "Other aster-bridge commands can't reach this process: {}",
                e
            ));
            None
        }
    };

    let services = shared.services();
    if ndjson {
        events::emit_line(
            "ready",
            json!({
                "pid": std::process::id(),
                "version": VERSION,
                "account": email,
                "plan": plan_code,
                "services": services,
            }),
        );
    } else {
        print_banner(ctx, &email, &plan_code, &services);
    }
    tracing::info!("aster-bridge is running");

    let reason = tokio::select! {
        reason = running.wait() => reason,
        _ = signals::shutdown() => shutdown(ctx, &running, &db, ndjson).await,
        _ = stop.notified() => shutdown(ctx, &running, &db, ndjson).await,
    };
    drop(control_server);

    common::save_state(&dir, |s| {
        s.last_stop = Some(StopInfo {
            reason: reason.code().to_string(),
            at: state::now(),
        })
    });
    if ndjson {
        let detail = match &reason {
            StopReason::Fatal(message) => Some(message.clone()),
            _ => None,
        };
        events::emit_line("stopped", json!({ "reason": reason.code(), "detail": detail }));
    }

    match reason {
        StopReason::UserRequested => {
            if !ndjson {
                ctx.out.line("Aster Bridge stopped.");
            }
            Ok(EXIT_OK)
        }
        StopReason::AccessRevoked => {
            common::save_state(&dir, |s| {
                let code = s.plan.as_ref().and_then(|p| p.code.clone());
                s.plan = Some(PlanInfo {
                    code,
                    has_bridge_access: false,
                    checked_at: state::now(),
                });
            });
            Err(CliError::access_required(
                "Your plan no longer includes Aster Bridge, so Aster Bridge stopped.",
            ))
        }
        StopReason::DeviceRevoked => {
            common::forget_device(&dir);
            Err(CliError::device_revoked())
        }
        StopReason::Fatal(message) => Err(CliError::general(format!(
            "Aster Bridge stopped because of an error: {}",
            message
        ))),
    }
}

fn print_banner(ctx: &Context, email: &str, plan_code: &str, services: &[Value]) {
    let out = &ctx.out;
    out.line(format!(
        "{} {}",
        out.dot(Tone::Good),
        out.bold("Aster Bridge is running")
    ));
    out.fields(&[
        ("Account", email.to_string()),
        ("Plan", common::plan_label(Some(plan_code))),
        ("Data folder", ctx.data_dir.display().to_string()),
    ]);
    out.blank();
    out.table(&["SERVICE", "ADDRESS", "SECURITY"], &service_rows(services));
    out.blank();
    out.line(format!(
        "To connect an email app, use {} as the username and an app password. To create one, run: aster-bridge app-password create",
        email
    ));
    out.line(out.dim("Press Control-C to stop."));
}

pub fn service_rows(services: &[Value]) -> Vec<Vec<String>> {
    services
        .iter()
        .map(|service| {
            vec![
                service["label"].as_str().unwrap_or_default().to_string(),
                format!(
                    "{}:{}",
                    service["host"].as_str().unwrap_or(LOOPBACK_HOST),
                    service["port"].as_u64().unwrap_or_default()
                ),
                common::security_label(service["security"].as_str().unwrap_or_default())
                    .to_string(),
            ]
        })
        .collect()
}

async fn shutdown(ctx: &Context, running: &RunningBridge, db: &Database, ndjson: bool) -> StopReason {
    let waiting = |db: &Database| -> HashMap<i64, i64> {
        db.outbox_list_pending()
            .map(|rows| {
                rows.into_iter()
                    .filter(|row| row.status != "failed")
                    .map(|row| (row.id, row.attempts))
                    .collect()
            })
            .unwrap_or_default()
    };
    let initial = waiting(db);
    if !initial.is_empty() {
        if !ndjson {
            ctx.out.line(format!(
                "Sending {} before stopping...",
                common::plural(initial.len(), "queued message", "queued messages")
            ));
        }
        tracing::info!("draining {} queued messages before stopping", initial.len());
        if let Some(trigger) = running.outbox_trigger() {
            for id in initial.keys() {
                let _ = trigger.try_send(*id);
            }
        }
        let deadline = tokio::time::Instant::now() + context::drain_timeout();
        let settle = async {
            loop {
                tokio::time::sleep(Duration::from_millis(250)).await;
                let now_waiting = waiting(db);
                let unsettled = initial
                    .iter()
                    .any(|(id, attempts)| now_waiting.get(id).is_some_and(|a| a == attempts));
                if !unsettled {
                    break;
                }
            }
        };
        tokio::select! {
            _ = settle => {}
            _ = tokio::time::sleep_until(deadline) => {
                tracing::warn!("stopping before every queued message was sent");
            }
            _ = signals::shutdown() => {}
        }
    }
    running.stop(StopReason::UserRequested);
    StopReason::UserRequested
}

struct Shared {
    data_dir: PathBuf,
    running: RunningBridge,
    db: Arc<Database>,
    passwords: Arc<AppPasswords>,
    client: Arc<ApiClient>,
    session: Arc<RwLock<Session>>,
    stop: Arc<Notify>,
    started_at: i64,
    config: BridgeConfig,
    refresh_lock: Mutex<()>,
}

fn handler(shared: Arc<Shared>) -> control::Handler {
    Arc::new(move |op, args| {
        let shared = shared.clone();
        Box::pin(async move { shared.handle(&op, args).await })
    })
}

impl Shared {
    async fn handle(&self, op: &str, args: Value) -> CliResult<Value> {
        match op {
            "ping" => Ok(json!({ "pid": std::process::id(), "version": VERSION })),
            "status" => Ok(self.status()),
            "sync_now" => {
                self.running
                    .sync_now()
                    .await
                    .map_err(|e| CliError::general(format!("Sync didn't finish: {}", e)))?;
                Ok(json!({ "synced": true }))
            }
            "outbox_list" => common::outbox_list(&self.db),
            "outbox_retry" => self.outbox_retry(args.get("id").and_then(Value::as_i64)).await,
            "refresh_plan" => self.refresh_plan().await,
            "repair_cache" => {
                self.db
                    .repair_cache()
                    .map_err(|e| CliError::general(format!("Couldn't rebuild the cache: {}", e)))?;
                self.running
                    .sync_now()
                    .await
                    .map_err(|e| CliError::general(format!("The cache was rebuilt, but sync didn't finish: {}", e)))?;
                Ok(json!({ "repaired": true, "synced": true }))
            }
            "app_password_create" => common::app_password_create(
                &self.passwords,
                &state::load(&self.data_dir),
                args.get("label").and_then(Value::as_str),
            ),
            "app_password_list" => Ok(common::app_password_list(&self.passwords)),
            "app_password_revoke" => common::app_password_revoke(
                &self.passwords,
                args.get("id").and_then(Value::as_str).unwrap_or_default(),
            ),
            "stop" => {
                self.stop.notify_one();
                Ok(json!({ "stopping": true }))
            }
            other => Err(CliError::usage(format!("Unknown operation: {}", other))),
        }
    }

    fn services(&self) -> Vec<Value> {
        let ports = self.running.bound_ports();
        let tls = self.config.tls_enabled;
        let starttls = if tls { "starttls" } else { "none" };
        let web = |https: bool| if https && tls { "https" } else { "http" };
        [
            (Service::Imap, ports.imap, starttls),
            (Service::Imaps, ports.imaps, "tls"),
            (Service::Smtp, ports.smtp, starttls),
            (Service::Smtps, ports.smtps, "tls"),
            (Service::Pop3, ports.pop3, starttls),
            (Service::Pop3s, ports.pop3s, "tls"),
            (Service::Jmap, ports.jmap, web(self.config.jmap_https_enabled)),
            (Service::Carddav, ports.carddav, web(self.config.carddav_https_enabled)),
        ]
        .into_iter()
        .filter(|(_, port, _)| *port != 0)
        .map(|(service, port, security)| {
            json!({
                "name": service,
                "label": service.label(),
                "host": LOOPBACK_HOST,
                "port": port,
                "security": security,
                "running": self.running.service_running(service),
            })
        })
        .collect()
    }

    fn status(&self) -> Value {
        let outbox = self.db.outbox_stats().unwrap_or_default();
        let (messages, app_passwords, last_sync) = self.db.db_stats().unwrap_or((0, 0, None));
        json!({
            "running": self.running.is_running(),
            "pid": std::process::id(),
            "version": VERSION,
            "started_at": self.started_at,
            "services": self.services(),
            "tls_enabled": self.config.tls_enabled,
            "outbox": {
                "pending": outbox.pending,
                "failed": outbox.failed,
                "sent_24h": outbox.sent_24h,
            },
            "cache": {
                "messages": messages,
                "app_passwords": app_passwords,
                "last_sync": last_sync,
            },
        })
    }

    async fn outbox_retry(&self, id: Option<i64>) -> CliResult<Value> {
        let trigger = self
            .running
            .outbox_trigger()
            .ok_or_else(CliError::not_running)?;
        let ids: Vec<i64> = match id {
            Some(id) => {
                let row = self
                    .db
                    .outbox_get(id)
                    .map_err(|e| CliError::general(format!("Couldn't read the outbox: {}", e)))?
                    .ok_or_else(|| {
                        CliError::new(
                            EXIT_ERROR,
                            "not_found",
                            format!("No queued message has the ID {}.", id),
                        )
                        .with_hint("To see queued messages and their IDs, run: aster-bridge outbox list")
                    })?;
                if row.status == "sent" {
                    return Err(CliError::new(
                        EXIT_ERROR,
                        "already_sent",
                        format!("Message {} was already sent.", id),
                    ));
                }
                vec![id]
            }
            None => self
                .db
                .outbox_list_pending()
                .map_err(|e| CliError::general(format!("Couldn't read the outbox: {}", e)))?
                .into_iter()
                .filter(|row| row.status != "sending")
                .map(|row| row.id)
                .collect(),
        };
        for id in &ids {
            match tokio::time::timeout(Duration::from_secs(5), trigger.send(*id)).await {
                Ok(Ok(())) => {}
                _ => {
                    return Err(CliError::general(
                        "The outbox is busy. Wait a moment and try again.",
                    ))
                }
            }
        }
        Ok(json!({ "queued": ids }))
    }

    async fn refresh_plan(&self) -> CliResult<Value> {
        let _guard = self.refresh_lock.lock().await;
        let current = state::load(&self.data_dir);
        if common::plan_is_fresh(&current) {
            return Ok(json!({ "refreshed": false, "plan": current.plan }));
        }
        let token = {
            let session = self.session.read().await;
            session.access_token.clone()
        };
        let result = self.client.get_plan_info(token.as_str()).await;
        let plan = common::plan_from_result(current.plan.as_ref(), result)?;
        common::save_state(&self.data_dir, |s| s.plan = Some(plan.clone()));
        if !plan.has_bridge_access {
            tracing::warn!("plan no longer includes Aster Bridge");
            self.running.stop(StopReason::AccessRevoked);
        }
        Ok(json!({ "refreshed": true, "plan": plan }))
    }
}
