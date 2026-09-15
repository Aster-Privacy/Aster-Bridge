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
use crate::exit::{CliError, CliResult, CODE_APP_PASSWORD_REVOKE, EXIT_OK};
use crate::output::{format_timestamp, Tone};
use crate::spinner;

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
    let label = Some(common::clean_label(label.as_deref())?);
    let owned_label = label.clone();
    let out = &ctx.out;
    let result = spinner::while_working(
        out,
        out.json,
        "Creating an app password",
        common::call_or_offline(
            ctx,
            "app_password_create",
            json!({ "label": label }),
            move |offline| {
                let passwords = AppPasswords::new(offline.db.clone());
                common::app_password_create(&passwords, &offline.state, owned_label.as_deref())
            },
        ),
    )
    .await?;
    if out.json {
        out.json(result);
        return Ok(EXIT_OK);
    }
    let text = |key: &str| result[key].as_str().unwrap_or_default().to_string();
    out.banner(Tone::Good, "App password created");
    out.fields(&[("Label", text("label")), ("ID", text("id"))]);
    out.blank();
    out.line(format!("    {}", out.heading(&text("password"))));
    out.blank();
    out.line("Copy this password now. Aster Bridge doesn't show it again.");
    out.line(format!(
        "In your email app, use {} as the username and this password as the password.",
        out.bold(email)
    ));
    Ok(EXIT_OK)
}

fn short_date(text: &str) -> String {
    let trimmed = text.trim();
    if let Ok(unix) = trimmed.parse::<i64>() {
        return format_timestamp(unix);
    }
    if let Ok(parsed) = chrono::DateTime::parse_from_rfc3339(trimmed) {
        return format_timestamp(parsed.timestamp());
    }
    for pattern in ["%Y-%m-%d %H:%M:%S%.f", "%Y-%m-%dT%H:%M:%S%.f"] {
        if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(trimmed, pattern) {
            return format_timestamp(naive.and_utc().timestamp());
        }
    }
    trimmed.replace('T', " ").chars().take(16).collect()
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
        out.banner(Tone::Muted, "No app passwords");
        out.line(format!(
            "To create one for an email app, run: {}",
            out.strong_accent("aster-bridge app-password create --label <name>")
        ));
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
    let owned_id = id.to_string();
    let result = common::call_or_offline(
        ctx,
        "app_password_revoke",
        json!({ "id": id }),
        move |offline| {
            common::app_password_revoke(&AppPasswords::new(offline.db.clone()), &owned_id)
        },
    )
    .await?;
    let out = &ctx.out;
    let revoked = result
        .get("revoked")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);
    let Some(revoked) = revoked else {
        return Err(CliError::coded(
            CODE_APP_PASSWORD_REVOKE,
            format!("Aster Bridge didn't confirm that it revoked app password {}.", id.trim()),
        )
        .with_hint("To check which app passwords are active, run: aster-bridge app-password list"));
    };
    if out.json {
        out.json(result);
    } else {
        out.line(format!(
            "{} Revoked app password {}. Email apps that use it can't sign in anymore.",
            out.mark(Tone::Good),
            revoked
        ));
    }
    Ok(EXIT_OK)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_created_at_matches_unix_rendering() {
        assert_eq!(short_date("2026-09-15T14:51:00Z"), format_timestamp(1789483860));
    }

    #[test]
    fn unix_created_at_still_renders() {
        assert_eq!(short_date("1789483860"), format_timestamp(1789483860));
    }

    #[test]
    fn space_separated_created_at_is_read_as_utc() {
        assert_eq!(short_date("2026-09-15 14:51:00"), format_timestamp(1789483860));
    }

    #[test]
    fn unparsable_created_at_falls_back_to_text() {
        assert_eq!(short_date("2026-09-15 14:51 something"), "2026-09-15 14:51");
    }
}
