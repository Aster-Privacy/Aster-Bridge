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
use serde_json::{json, Value};

use super::common;
use crate::cli::OutboxCommand;
use crate::context::Context;
use crate::control;
use crate::exit::{CliError, CliResult, EXIT_OK};
use crate::output::{format_timestamp, Tone};

pub async fn run(ctx: &Context, command: OutboxCommand) -> CliResult<i32> {
    common::require_account(&ctx.data_dir)?;
    match command {
        OutboxCommand::List => list(ctx).await,
        OutboxCommand::Retry { id } => retry(ctx, id).await,
    }
}

fn status_label(status: &str) -> &'static str {
    match status {
        "pending" => "Waiting",
        "sending" => "Sending",
        "failed" => "Failed",
        "sent" => "Sent",
        _ => "Unknown",
    }
}

async fn list(ctx: &Context) -> CliResult<i32> {
    let result = common::call_or_offline(ctx, "outbox_list", Value::Null, |offline| {
        common::outbox_list(&offline.db)
    })
    .await?;
    let out = &ctx.out;
    if out.json {
        out.json(result);
        return Ok(EXIT_OK);
    }
    let messages = result["messages"].as_array().cloned().unwrap_or_default();
    if messages.is_empty() {
        out.line("No messages are waiting to send.");
        return Ok(EXIT_OK);
    }
    let rows: Vec<Vec<String>> = messages
        .iter()
        .map(|message| {
            let status = message["status"].as_str().unwrap_or_default();
            let tone = if status == "failed" { Tone::Bad } else { Tone::Warn };
            vec![
                message["id"].as_i64().unwrap_or_default().to_string(),
                common::truncate(message["to"].as_str().unwrap_or_default(), 28),
                common::truncate(message["subject"].as_str().unwrap_or("(no subject)"), 32),
                out.tone(status_label(status), tone),
                message["attempts"].as_i64().unwrap_or_default().to_string(),
                format_timestamp(message["queued_at"].as_i64().unwrap_or_default()),
                common::truncate(message["last_error"].as_str().unwrap_or("-"), 40),
            ]
        })
        .collect();
    out.table(
        &["ID", "TO", "SUBJECT", "STATE", "ATTEMPTS", "QUEUED", "LAST ERROR"],
        &rows,
    );
    out.blank();
    out.line("To try sending again, run: aster-bridge outbox retry [ID]");
    Ok(EXIT_OK)
}

async fn retry(ctx: &Context, id: Option<i64>) -> CliResult<i32> {
    let result = control::call_running(&ctx.data_dir, "outbox_retry", json!({ "id": id }))
        .await?
        .ok_or_else(|| {
            CliError::not_running()
                .with_hint("Aster Bridge sends queued messages while it runs. To start it, run: aster-bridge serve")
        })?;
    let out = &ctx.out;
    if out.json {
        out.json(result);
        return Ok(EXIT_OK);
    }
    let count = result["queued"].as_array().map(Vec::len).unwrap_or_default();
    if count == 0 {
        out.line("No messages are waiting to send.");
    } else {
        out.line(format!(
            "Sending {} again. To check progress, run: aster-bridge outbox list",
            common::plural(count, "message", "messages")
        ));
    }
    Ok(EXIT_OK)
}
