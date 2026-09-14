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
use aster_bridge_core::config::{self, BridgeConfig};
use aster_bridge_core::ops;
use aster_bridge_core::tls;
use serde_json::{json, Map, Value};

use super::common::{self, VERSION};
use crate::cli::ConfigCommand;
use crate::context::Context;
use crate::control;
use crate::exit::{CliError, CliResult, EXIT_OK};
use crate::output::{Output, Tone};

const HIDDEN_KEYS: [&str; 2] = ["service_mode", "autostart"];
const MIN_POLL_SECS: u64 = 5;
const MAX_POLL_SECS: u64 = 86_400;

pub fn version(out: &Output) -> CliResult<i32> {
    let (os, arch) = (std::env::consts::OS, std::env::consts::ARCH);
    if out.json {
        out.json(json!({ "version": VERSION, "os": os, "arch": arch }));
    } else {
        out.line(format!("aster-bridge {} ({} {})", VERSION, os, arch));
    }
    Ok(EXIT_OK)
}

pub async fn sync_now(ctx: &Context) -> CliResult<i32> {
    common::require_account(&ctx.data_dir)?;
    let out = &ctx.out;
    if !out.json {
        out.line("Syncing...");
    }
    let result = control::call_running(&ctx.data_dir, "sync_now", Value::Null)
        .await?
        .ok_or_else(CliError::not_running)?;
    if out.json {
        out.json(result);
    } else {
        out.line(format!("{} Sync finished.", out.dot(Tone::Good)));
    }
    Ok(EXIT_OK)
}

pub fn tls_fingerprint(ctx: &Context) -> CliResult<i32> {
    let dir = &ctx.data_dir;
    let config = common::load_config()?;
    let fingerprint = match tls::cert_fingerprint_sha256(dir) {
        Some(fingerprint) => fingerprint,
        None => {
            tls::install_default_crypto_provider();
            tls::ensure_cert(dir).map_err(|e| {
                CliError::general(format!("Couldn't create the TLS certificate: {}", e))
            })?;
            tls::cert_fingerprint_sha256(dir)
                .ok_or_else(|| CliError::general("Couldn't read the TLS certificate."))?
        }
    };
    let path = tls::cert_pem_path(dir).display().to_string();
    let out = &ctx.out;
    if out.json {
        out.json(json!({
            "sha256": fingerprint,
            "certificate": path,
            "tls_enabled": config.tls_enabled,
        }));
        return Ok(EXIT_OK);
    }
    out.fields(&[
        ("SHA-256", fingerprint),
        ("Certificate", path),
        ("TLS", if config.tls_enabled { "On".to_string() } else { "Off".to_string() }),
    ]);
    out.blank();
    out.line("When your email app asks you to trust the certificate, check that the fingerprint it shows matches this one.");
    Ok(EXIT_OK)
}

fn all_settings(config: &BridgeConfig) -> CliResult<Map<String, Value>> {
    match serde_json::to_value(config) {
        Ok(Value::Object(map)) => Ok(map),
        _ => Err(CliError::general("Couldn't read the settings.")),
    }
}

fn visible_settings(config: &BridgeConfig) -> CliResult<Map<String, Value>> {
    let mut map = all_settings(config)?;
    for key in HIDDEN_KEYS {
        map.remove(key);
    }
    Ok(map)
}

fn unknown_key(key: &str) -> CliError {
    CliError::usage(format!("There's no setting named {}.", key))
        .with_hint("To see every setting, run: aster-bridge config get")
}

fn display_value(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

pub async fn config(ctx: &Context, command: ConfigCommand) -> CliResult<i32> {
    match command {
        ConfigCommand::Get { key } => config_get(ctx, key.as_deref()),
        ConfigCommand::Set { key, value } => config_set(ctx, &key, &value).await,
    }
}

fn config_get(ctx: &Context, key: Option<&str>) -> CliResult<i32> {
    let settings = visible_settings(&common::load_config()?)?;
    let out = &ctx.out;
    match key {
        None => {
            if out.json {
                out.json(json!({ "settings": settings }));
            } else {
                let rows: Vec<(&str, String)> = settings
                    .iter()
                    .map(|(name, value)| (name.as_str(), display_value(value)))
                    .collect();
                out.fields(&rows);
            }
        }
        Some(key) => {
            let value = settings.get(key.trim()).ok_or_else(|| unknown_key(key))?;
            if out.json {
                out.json(json!({ "key": key.trim(), "value": value }));
            } else {
                out.line(display_value(value));
            }
        }
    }
    Ok(EXIT_OK)
}

fn parse_value(key: &str, current: &Value, raw: &str) -> CliResult<Value> {
    let raw = raw.trim();
    match current {
        Value::Bool(_) => match raw.to_ascii_lowercase().as_str() {
            "true" | "on" | "yes" | "1" => Ok(Value::Bool(true)),
            "false" | "off" | "no" | "0" => Ok(Value::Bool(false)),
            _ => Err(CliError::usage(format!("{} must be true or false.", key))),
        },
        Value::Number(_) if key.ends_with("_port") => {
            let port: u16 = raw.parse().map_err(|_| {
                CliError::usage(format!("{} must be a port number from 1024 to 65535.", key))
            })?;
            if ops::validate_port(port).is_err() {
                return Err(if port < 1024 {
                    CliError::usage(format!(
                        "{} must be 1024 or higher, because lower ports need administrator access.",
                        key
                    ))
                } else {
                    CliError::usage(format!(
                        "Port {} is reserved for a database server. Choose a different port.",
                        port
                    ))
                });
            }
            Ok(Value::from(port))
        }
        Value::Number(_) if key == "poll_interval_secs" => raw
            .parse::<u64>()
            .ok()
            .filter(|secs| (MIN_POLL_SECS..=MAX_POLL_SECS).contains(secs))
            .map(Value::from)
            .ok_or_else(|| {
                CliError::usage(format!(
                    "{} must be a number of seconds from {} to {}.",
                    key, MIN_POLL_SECS, MAX_POLL_SECS
                ))
            }),
        Value::Number(_) => raw
            .parse::<u64>()
            .map(Value::from)
            .map_err(|_| CliError::usage(format!("{} must be a whole number.", key))),
        Value::String(_) => Ok(Value::String(raw.to_string())),
        _ => Err(CliError::usage(format!("{} can't be changed from the command line.", key))),
    }
}

async fn config_set(ctx: &Context, key: &str, raw: &str) -> CliResult<i32> {
    let key = key.trim();
    if HIDDEN_KEYS.contains(&key) {
        return Err(unknown_key(key));
    }
    let current = common::load_config()?;
    let mut settings = all_settings(&current)?;
    let existing = settings.get(key).ok_or_else(|| unknown_key(key))?;
    let value = parse_value(key, existing, raw)?;
    settings.insert(key.to_string(), value.clone());
    let mut updated: BridgeConfig = serde_json::from_value(Value::Object(settings))
        .map_err(|e| CliError::usage(format!("{} can't be set to {}: {}", key, raw.trim(), e)))?;
    updated.data_dir = current.data_dir.clone();
    if config::validate_ports(&updated).is_err() {
        return Err(CliError::usage(format!(
            "Port {} is already used by another setting. Choose a different port.",
            display_value(&value)
        ))
        .with_hint("To see the ports in use, run: aster-bridge config get"));
    }
    config::save_config(&updated)
        .map_err(|e| CliError::general(format!("Couldn't save the settings: {}", e)))?;

    let running = control::running(&ctx.data_dir).await.is_some();
    let out = &ctx.out;
    if out.json {
        out.json(json!({ "key": key, "value": value, "restart_required": running }));
    } else {
        out.line(format!("Set {} to {}.", key, display_value(&value)));
        if running {
            out.line("Aster Bridge is running. To use the new setting, stop it and start it again.");
        }
    }
    Ok(EXIT_OK)
}

pub async fn repair_cache(ctx: &Context) -> CliResult<i32> {
    common::require_account(&ctx.data_dir)?;
    let out = &ctx.out;
    if !out.json {
        out.line("Rebuilding the mail cache...");
    }
    let result = common::call_or_offline(ctx, "repair_cache", Value::Null, |offline| {
        offline
            .db
            .repair_cache()
            .map_err(|e| CliError::general(format!("Couldn't rebuild the cache: {}", e)))?;
        Ok(json!({ "repaired": true, "synced": false }))
    })
    .await?;
    if out.json {
        out.json(result);
    } else if result["synced"].as_bool() == Some(true) {
        out.line(format!(
            "{} Rebuilt the mail cache and synced your mail.",
            out.dot(Tone::Good)
        ));
    } else {
        out.line(format!(
            "{} Rebuilt the mail cache. Aster Bridge downloads your mail again the next time it starts.",
            out.dot(Tone::Good)
        ));
    }
    Ok(EXIT_OK)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_are_parsed_by_type() {
        assert_eq!(parse_value("tls_enabled", &json!(true), "off").unwrap(), json!(false));
        assert!(parse_value("tls_enabled", &json!(true), "maybe").is_err());
        assert_eq!(parse_value("imap_port", &json!(1143), " 2143 ").unwrap(), json!(2143));
        assert!(parse_value("imap_port", &json!(1143), "143").is_err());
        assert!(parse_value("imap_port", &json!(1143), "5432").is_err());
        assert!(parse_value("imap_port", &json!(1143), "70000").is_err());
        assert!(parse_value("poll_interval_secs", &json!(30), "2").is_err());
        assert_eq!(parse_value("poll_interval_secs", &json!(30), "60").unwrap(), json!(60));
    }

    #[test]
    fn hidden_settings_stay_hidden() {
        let map = visible_settings(&BridgeConfig::default()).unwrap();
        assert!(!map.contains_key("service_mode"));
        assert!(!map.contains_key("autostart"));
        assert!(!map.contains_key("data_dir"));
        assert!(map.contains_key("imap_port"));
    }
}
