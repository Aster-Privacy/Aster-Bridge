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
use std::io::Write;
use std::time::Duration;

use aster_bridge_core::account_state::AccountState;
use serde_json::{json, Value};

use super::common;
use super::serve::service_rows;
use crate::context::Context;
use crate::control;
use crate::exit::{CliResult, EXIT_ACCESS, EXIT_NOT_READY, EXIT_OK};
use crate::lock::InstanceLock;
use crate::output::{format_relative, format_timestamp, Tone};
use crate::secret_backend;
use crate::signals;
use crate::state::{self, CliState};

const LIVE_INTERVAL: Duration = Duration::from_secs(2);

struct Snapshot {
    state: CliState,
    signed_in: bool,
    live: Option<Value>,
    refreshed: Option<bool>,
}

impl Snapshot {
    fn running(&self) -> bool {
        self.live
            .as_ref()
            .and_then(|v| v["running"].as_bool())
            .unwrap_or(false)
    }

    fn denied(&self) -> bool {
        self.state
            .plan
            .as_ref()
            .is_some_and(|plan| !plan.has_bridge_access)
    }
}

pub async fn run(ctx: &Context, refresh: bool, live: bool) -> CliResult<i32> {
    if live {
        return run_live(ctx).await;
    }
    let snapshot = snapshot(ctx, refresh).await?;
    render(ctx, &snapshot);
    Ok(exit_code(&snapshot))
}

async fn live_status(ctx: &Context) -> Option<Value> {
    control::call_running(&ctx.data_dir, "status", Value::Null)
        .await
        .unwrap_or(None)
}

async fn snapshot(ctx: &Context, refresh: bool) -> CliResult<Snapshot> {
    let dir = &ctx.data_dir;
    let mut live = live_status(ctx).await;
    let mut refreshed = None;
    if refresh {
        common::require_account(dir)?;
        if live.is_some() {
            refreshed = control::call_running(dir, "refresh_plan", Value::Null)
                .await?
                .and_then(|v| v["refreshed"].as_bool());
        }
        if refreshed.is_none() {
            refreshed = Some(refresh_offline(ctx).await?);
        }
        live = live_status(ctx).await;
    }
    let state = state::load(dir);
    let signed_in = state.account.is_some() && secret_backend::has_record(dir);
    Ok(Snapshot {
        state,
        signed_in,
        live,
        refreshed,
    })
}

async fn refresh_offline(ctx: &Context) -> CliResult<bool> {
    let _lock = InstanceLock::acquire(&ctx.data_dir)?;
    let current = common::signed_in_state(ctx)?;
    if common::plan_is_fresh(&current) {
        return Ok(false);
    }
    let (client, session) = common::sign_in_offline(ctx).await?;
    let result = client.get_plan_info(session.access_token.as_str()).await;
    let plan = common::plan_from_result(current.plan.as_ref(), result)?;
    common::save_state(&ctx.data_dir, |s| s.plan = Some(plan));
    Ok(true)
}

fn exit_code(snapshot: &Snapshot) -> i32 {
    if !snapshot.signed_in {
        EXIT_NOT_READY
    } else if snapshot.denied() {
        EXIT_ACCESS
    } else if !snapshot.running() {
        EXIT_NOT_READY
    } else {
        EXIT_OK
    }
}

fn to_json(ctx: &Context, s: &Snapshot) -> Value {
    let live = s.live.as_ref();
    let pick = |key: &str| live.map(|v| v[key].clone()).unwrap_or(Value::Null);
    json!({
        "signed_in": s.signed_in,
        "running": s.running(),
        "account": if s.signed_in { json!(s.state.account) } else { Value::Null },
        "plan": s.state.plan,
        "account_state": s.state.account_state,
        "last_sync": s.state.last_sync,
        "last_stop": s.state.last_stop,
        "pid": pick("pid"),
        "started_at": pick("started_at"),
        "services": live.map(|v| v["services"].clone()).unwrap_or_else(|| json!([])),
        "outbox": pick("outbox"),
        "cache": pick("cache"),
        "tls_enabled": pick("tls_enabled"),
        "refreshed": s.refreshed,
        "data_dir": ctx.data_dir.display().to_string(),
    })
}

fn stop_label(reason: &str) -> &'static str {
    match reason {
        "user_requested" => "Stopped by you",
        "access_revoked" => "Plan doesn't include Aster Bridge",
        "device_revoked" => "Device removed from your account",
        "fatal" => "Stopped because of an error",
        _ => "Stopped",
    }
}

fn render(ctx: &Context, s: &Snapshot) {
    let out = &ctx.out;
    if out.json {
        out.json(to_json(ctx, s));
        return;
    }
    if !s.signed_in {
        out.banner(Tone::Muted, "Signed out");
        out.blank();
        out.line(format!(
            "To link this device to your account, run: {}",
            out.strong_accent("aster-bridge login")
        ));
        return;
    }

    let running = s.running();
    let denied = s.denied();
    let live = s.live.as_ref().filter(|_| running);
    let now = state::now();
    match live {
        Some(v) => {
            let started_at = v["started_at"].as_i64().unwrap_or_default();
            out.line(format!(
                "{} {}  {}",
                out.mark(Tone::Good),
                out.heading("Connected and running"),
                out.dim(&format!(
                    "since {}, process {}",
                    format_relative(started_at, now),
                    v["pid"].as_u64().unwrap_or_default()
                ))
            ));
        }
        None if denied => out.banner(Tone::Bad, "Stopped"),
        None => out.banner(Tone::Warn, "Stopped"),
    }
    out.blank();

    let mut rows: Vec<(&str, String)> = Vec::new();
    if let Some(account) = &s.state.account {
        rows.push(("Account", account.email.clone()));
    }
    let plan = match &s.state.plan {
        Some(plan) => {
            let mut text = common::plan_label(plan.code.as_deref());
            if !plan.has_bridge_access {
                text.push_str(&format!(" {}", out.tone("(doesn't include Aster Bridge)", Tone::Bad)));
            }
            format!(
                "{}  {}",
                text,
                out.dim(&format!("checked {}", format_timestamp(plan.checked_at)))
            )
        }
        None => "Not checked yet".to_string(),
    };
    rows.push(("Plan", plan));
    if s.state.account_state != AccountState::Active {
        rows.push((
            "Account status",
            out.tone(common::account_state_label(s.state.account_state), Tone::Bad),
        ));
    }
    rows.push((
        "Last sync",
        match s.state.last_sync {
            Some(sync) if sync.failed => format!(
                "{} {}",
                format_relative(sync.at, now),
                out.tone("(failed)", Tone::Warn)
            ),
            Some(sync) => format!(
                "{}  {}",
                format_relative(sync.at, now),
                out.dim(&format_timestamp(sync.at))
            ),
            None => "Never".to_string(),
        },
    ));
    if let Some(v) = live {
        let outbox = &v["outbox"];
        let pending = outbox["pending"].as_u64().unwrap_or_default();
        let failed = outbox["failed"].as_u64().unwrap_or_default();
        let sent = outbox["sent_24h"].as_u64().unwrap_or_default();
        let mut text = if pending == 0 && failed == 0 && sent == 0 {
            "Empty".to_string()
        } else {
            format!("{} waiting, {} sent after retrying in the last 24 hours", pending, sent)
        };
        if failed > 0 {
            text.push_str(&format!(", {}", out.tone(&format!("{} failed", failed), Tone::Bad)));
        }
        rows.push(("Outbox", text));
    }
    if !running {
        if let Some(stop) = &s.state.last_stop {
            rows.push((
                "Last stop",
                format!("{}  {}", stop_label(&stop.reason), out.dim(&format_timestamp(stop.at))),
            ));
        }
    }
    out.fields(&rows);

    if let Some(v) = live {
        let services = v["services"].as_array().cloned().unwrap_or_default();
        if !services.is_empty() {
            out.blank();
            let table: Vec<Vec<String>> = service_rows(&services)
                .into_iter()
                .zip(services.iter())
                .map(|(mut row, service)| {
                    row.push(if service["running"].as_bool().unwrap_or(false) {
                        out.tone("Running", Tone::Good)
                    } else {
                        out.tone("Stopped", Tone::Bad)
                    });
                    row
                })
                .collect();
            out.table(&["SERVICE", "ADDRESS", "SECURITY", "STATE"], &table);
        }
    }

    let mut hints: Vec<String> = Vec::new();
    if s.refreshed == Some(false) {
        hints.push("Aster Bridge checked your plan less than a minute ago, so it shows that result.".to_string());
    }
    if denied {
        hints.push(common::upgrade_then_refresh_hint());
    } else if s.state.account_state != AccountState::Active {
        if let Some(hint) = common::account_state_error(s.state.account_state).hint {
            hints.push(hint);
        }
    } else if !running {
        hints.push(format!(
            "To start Aster Bridge, run: {}",
            out.strong_accent("aster-bridge serve")
        ));
    }
    if !hints.is_empty() {
        out.blank();
        for hint in hints {
            out.line(hint);
        }
    }
}

async fn run_live(ctx: &Context) -> CliResult<i32> {
    let out = &ctx.out;
    let redraw = out.stdout_is_terminal() && out.ansi();
    let cancel = signals::ctrl_c();
    tokio::pin!(cancel);
    let mut tick = tokio::time::interval(LIVE_INTERVAL);
    if redraw {
        crate::output::out_text!("\x1b[?25l\x1b[2J\x1b[H");
        let _ = std::io::stdout().flush();
    }
    let stop = |redraw: bool| {
        if redraw {
            crate::output::out_text!("\x1b[?25h");
            let _ = std::io::stdout().flush();
        }
    };
    loop {
        tokio::select! {
            _ = &mut cancel => {
                stop(redraw);
                if redraw {
                    out.blank();
                }
                return Ok(EXIT_OK);
            }
            _ = tick.tick() => {}
        }
        let taken = tokio::select! {
            _ = &mut cancel => {
                stop(redraw);
                if redraw {
                    out.blank();
                }
                return Ok(EXIT_OK);
            }
            taken = snapshot(ctx, false) => taken,
        };
        let taken = match taken {
            Ok(taken) => taken,
            Err(e) => {
                stop(redraw);
                return Err(e);
            }
        };
        if redraw {
            crate::output::out_text!("\x1b[?2026h\x1b[H");
        }
        render(ctx, &taken);
        if redraw {
            out.blank();
            out.line(out.dim("Updates every 2 seconds. Press Control-C to stop."));
            crate::output::out_text!("\x1b[0J\x1b[?2026l");
        } else if !out.json {
            out.blank();
        }
        let _ = std::io::stdout().flush();
    }
}
