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
use aster_bridge_core::auth::app_passwords::AppPasswords;
use serde_json::{json, Value};

use super::common;
use crate::cli::AppPasswordCommand;
use crate::context::Context;
use crate::exit::{CliResult, EXIT_OK};
use crate::output::{format_timestamp, Tone};

pub async fn run(ctx: &Context, command: AppPasswordCommand) -> CliResult<i32> {
    let state = common::require_account(&ctx.data_dir)?;
    let email = state.account.map(|a| a.email).unwrap_or_default();
    match command {
        AppPasswordCommand::Create { label } => create(ctx, label, &email).await,
        AppPasswordCommand::List => list(ctx).await,
        AppPasswordCommand::Revoke { id } => revoke(ctx, &id).await,
    }
}

async fn create(ctx: &Context, label: Option<String>, email: &str) -> CliResult<i32> {
    common::clean_label(label.as_deref())?;
    let result = common::call_or_offline(
        ctx,
        "app_password_create",
        json!({ "label": label }),
        |offline| {
            let passwords = AppPasswords::new(offline.db.clone());
            common::app_password_create(&passwords, &offline.state, label.as_deref())
        },
    )
    .await?;
    let out = &ctx.out;
    if out.json {
        out.json(result);
        return Ok(EXIT_OK);
    }
    let text = |key: &str| result[key].as_str().unwrap_or_default().to_string();
    out.line(format!(
        "{} Created an app password named {}.",
        out.dot(Tone::Good),
        text("label")
    ));
    out.blank();
    out.line(format!("    {}", out.bold(&text("password"))));
    out.blank();
    out.line("Copy this password now. Aster Bridge doesn't show it again.");
    out.line(format!(
        "In your email app, use {} as the username and this password as the password.",
        email
    ));
    out.fields(&[("ID", text("id"))]);
    Ok(EXIT_OK)
}

fn short_date(text: &str) -> String {
    let trimmed = text.trim();
    match trimmed.parse::<i64>() {
        Ok(unix) => format_timestamp(unix),
        Err(_) => trimmed.replace('T', " ").chars().take(16).collect(),
    }
}

async fn list(ctx: &Context) -> CliResult<i32> {
    let result = common::call_or_offline(ctx, "app_password_list", Value::Null, |offline| {
        Ok(common::app_password_list(&AppPasswords::new(offline.db.clone())))
    })
    .await?;
    let out = &ctx.out;
    if out.json {
        out.json(result);
        return Ok(EXIT_OK);
    }
    let items = result["app_passwords"].as_array().cloned().unwrap_or_default();
    if items.is_empty() {
        out.line("You don't have any app passwords.");
        out.line("To create one for an email app, run: aster-bridge app-password create --label <name>");
        return Ok(EXIT_OK);
    }
    let rows: Vec<Vec<String>> = items
        .iter()
        .map(|item| {
            vec![
                item["id"].as_str().unwrap_or_default().to_string(),
                common::truncate(item["label"].as_str().unwrap_or_default(), 32),
                short_date(item["created_at"].as_str().unwrap_or_default()),
                item["last_used_at"]
                    .as_i64()
                    .map(format_timestamp)
                    .unwrap_or_else(|| "Never".to_string()),
                item["use_count"].as_i64().unwrap_or_default().to_string(),
            ]
        })
        .collect();
    out.table(&["ID", "LABEL", "CREATED", "LAST USED", "USES"], &rows);
    Ok(EXIT_OK)
}

async fn revoke(ctx: &Context, id: &str) -> CliResult<i32> {
    let result = common::call_or_offline(
        ctx,
        "app_password_revoke",
        json!({ "id": id }),
        |offline| common::app_password_revoke(&AppPasswords::new(offline.db.clone()), id),
    )
    .await?;
    let out = &ctx.out;
    if out.json {
        out.json(result);
    } else {
        out.line(format!(
            "Revoked app password {}. Email apps that use it can't sign in anymore.",
            id.trim()
        ));
    }
    Ok(EXIT_OK)
}
