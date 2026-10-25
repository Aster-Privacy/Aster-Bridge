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

use aster_bridge_core::api_client::ApiClient;
use aster_bridge_core::db::Database;
use aster_bridge_core::tag_ops::{self, TagOpError};
use aster_bridge_core::tags::{self, SlotOverride, BUILTIN_TAG_SLOTS};
use serde_json::{json, Value};

use super::common;
use crate::cli::TagsCommand;
use crate::context::Context;
use crate::control;
use crate::exit::{
    CliError, CliResult, CODE_LOCKED, CODE_SETTINGS_READ, CODE_SETTINGS_WRITE, EXIT_OK,
};
use crate::output::Tone;

pub enum TagChoice {
    Auto,
    Off,
    Label { name: String, create: bool },
}

impl TagChoice {
    fn to_args(&self, slot: usize) -> Value {
        match self {
            TagChoice::Auto => json!({ "slot": slot, "mode": "auto" }),
            TagChoice::Off => json!({ "slot": slot, "mode": "off" }),
            TagChoice::Label { name, create } => {
                json!({ "slot": slot, "mode": "label", "name": name, "create": create })
            }
        }
    }

    pub fn from_args(args: &Value) -> CliResult<(usize, TagChoice)> {
        let slot = args.get("slot").and_then(Value::as_u64).unwrap_or_default() as usize;
        let choice = match args.get("mode").and_then(Value::as_str) {
            Some("auto") => TagChoice::Auto,
            Some("off") => TagChoice::Off,
            Some("label") => TagChoice::Label {
                name: args.get("name").and_then(Value::as_str).unwrap_or_default().to_string(),
                create: args.get("create").and_then(Value::as_bool).unwrap_or(false),
            },
            _ => return Err(choose_one()),
        };
        Ok((slot, choice))
    }
}

fn choose_one() -> CliError {
    CliError::usage("Choose --auto, --off, or --label <name>.")
}

pub async fn run(ctx: &Context, command: TagsCommand) -> CliResult<i32> {
    common::require_account(&ctx.data_dir)?;
    match command {
        TagsCommand::List => list(ctx).await,
        TagsCommand::Set { slot, auto, off, label, create } => {
            let choice = match (auto, off, label) {
                (true, _, _) => TagChoice::Auto,
                (_, true, _) => TagChoice::Off,
                (_, _, Some(name)) => TagChoice::Label { name, create },
                _ => return Err(choose_one()),
            };
            set(ctx, slot as usize, choice).await
        }
    }
}

pub fn list_on(db: &Database) -> CliResult<Value> {
    let read = |e: String| CliError::coded(CODE_SETTINGS_READ, format!("Couldn't read the tag settings: {}", e));
    let assigned = db.builtin_tag_slots().map_err(read)?;
    let overrides = db.builtin_tag_slot_overrides().map_err(read)?;
    let names: HashMap<String, String> = db
        .list_custom_tags()
        .map_err(read)?
        .into_iter()
        .map(|tag| (tag.tag_token, tag.name))
        .collect();
    let slots: Vec<Value> = assigned
        .into_iter()
        .enumerate()
        .map(|(index, token)| {
            let slot = index + 1;
            let mode = match overrides.get(&slot) {
                Some(SlotOverride::Off) => "off",
                Some(SlotOverride::Label(chosen)) if token.as_deref() == Some(chosen.as_str()) => "label",
                _ => "auto",
            };
            let label = token.as_ref().and_then(|t| names.get(t)).cloned();
            json!({
                "slot": slot,
                "keyword": tags::builtin_keyword(slot),
                "mode": mode,
                "tag_token": token,
                "label": label,
            })
        })
        .collect();
    Ok(json!({ "slots": slots }))
}

pub async fn set_on(
    db: &Database,
    client: &ApiClient,
    access_token: &str,
    identity_key: Option<&str>,
    slot: usize,
    choice: TagChoice,
) -> CliResult<Value> {
    if !(1..=BUILTIN_TAG_SLOTS).contains(&slot) {
        return Err(CliError::usage(format!("Choose a tag from 1 to {}.", BUILTIN_TAG_SLOTS)));
    }
    let chosen = match choice {
        TagChoice::Auto => None,
        TagChoice::Off => Some(SlotOverride::Off),
        TagChoice::Label { name, create } => {
            let found = if create {
                tag_ops::create_label(db, client, access_token, identity_key, &name).await.map(Some)
            } else {
                tag_ops::find_label_by_name(db, &name)
            };
            match found {
                Ok(Some(tag)) => Some(SlotOverride::Label(tag.tag_token)),
                Ok(None) => {
                    return Err(CliError::usage(format!(
                        "No label is named \"{}\". To create it, run the command again with --create.",
                        name.trim()
                    )))
                }
                Err(TagOpError::Invalid(msg)) => return Err(CliError::usage(msg)),
                Err(TagOpError::Locked) => {
                    return Err(CliError::coded(
                        CODE_LOCKED,
                        "Aster Bridge is locked, so it can't create a label yet.",
                    ))
                }
                Err(TagOpError::LimitReached) => {
                    return Err(CliError::usage(
                        "You reached your plan's label limit. To add this label, delete a label or upgrade your plan.",
                    ))
                }
                Err(e) => {
                    return Err(CliError::coded(
                        CODE_SETTINGS_WRITE,
                        format!("Couldn't create the label: {:?}", e),
                    ))
                }
            }
        }
    };
    let changed = db
        .set_builtin_tag_slot(slot, chosen.as_ref())
        .map_err(|e| CliError::coded(CODE_SETTINGS_WRITE, format!("Couldn't save the tag setting: {}", e)))?;
    if !changed.is_empty() {
        let refs: Vec<&str> = changed.iter().map(|id| id.as_str()).collect();
        let _ = db.jmap_record_updated_batch("Email", &refs);
    }
    list_on(db)
}

async fn list(ctx: &Context) -> CliResult<i32> {
    let result =
        common::call_or_offline(ctx, "builtin_tags_list", Value::Null, |offline| list_on(&offline.db)).await?;
    print_slots(ctx, &result, None);
    Ok(EXIT_OK)
}

async fn set(ctx: &Context, slot: usize, choice: TagChoice) -> CliResult<i32> {
    let result = match control::call_running(&ctx.data_dir, "builtin_tags_set", choice.to_args(slot)).await? {
        Some(value) => value,
        None => {
            let offline = common::open_offline(ctx)?;
            if matches!(choice, TagChoice::Label { create: true, .. }) {
                let (client, session) = common::sign_in_offline(ctx).await?;
                set_on(
                    &offline.db,
                    &client,
                    &session.access_token,
                    session.identity_key.as_deref(),
                    slot,
                    choice,
                )
                .await?
            } else {
                set_on(&offline.db, &crate::context::api_client(), "", None, slot, choice).await?
            }
        }
    };
    print_slots(ctx, &result, Some(slot));
    Ok(EXIT_OK)
}

fn print_slots(ctx: &Context, result: &Value, changed: Option<usize>) {
    let out = &ctx.out;
    if out.json {
        out.json(result.clone());
        return;
    }
    match changed {
        Some(slot) => out.banner(Tone::Good, &format!("Updated tag {}", slot)),
        None => out.banner(Tone::Accent, "Built-in tags"),
    }
    let rows: Vec<Vec<String>> = result["slots"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|slot| {
            let mode = slot["mode"].as_str().unwrap_or_default();
            let shown = match (mode, slot["label"].as_str()) {
                ("off", _) => "Doesn't sync".to_string(),
                (_, Some(name)) => common::truncate(name, 40),
                (_, None) => "Doesn't sync, no label matches".to_string(),
            };
            let setting = match mode {
                "off" => "Off",
                "label" => "Chosen",
                _ => "Match by name",
            };
            vec![
                slot["slot"].as_u64().unwrap_or_default().to_string(),
                slot["keyword"].as_str().unwrap_or_default().to_string(),
                shown,
                setting.to_string(),
            ]
        })
        .collect();
    out.table(&["Tag", "Keyword", "Label", "Setting"], &rows);
    out.line(out.dim(
        "To sync a tag to a label, run: aster-bridge tags set <tag> --label <name>. To create the label, add --create.",
    ));
}
