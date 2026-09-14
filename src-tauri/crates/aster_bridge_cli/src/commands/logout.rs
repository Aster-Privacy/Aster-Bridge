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
use std::time::Duration;

use aster_bridge_core::auth::device_identity;
use aster_bridge_core::db;
use serde_json::{json, Value};

use super::service;
use crate::cli::SecretBackendChoice;
use crate::context::Context;
use crate::control;
use crate::exit::{CliResult, EXIT_OK};
use crate::lock::InstanceLock;
use crate::output::Tone;
use crate::secret_backend;
use crate::state::{self, CliState};

const STOP_WAIT: Duration = Duration::from_secs(30);
const LOCAL_FILES: [&str; 2] = ["device_identity.bin", "device_passphrase.bin"];

pub async fn run(ctx: &Context, keep_cache: bool) -> CliResult<i32> {
    let dir = &ctx.data_dir;
    let out = &ctx.out;
    let _lock = match control::running(dir).await {
        Some(client) => {
            if !out.json {
                out.line("Stopping Aster Bridge...");
            }
            let _ = client.call("stop", Value::Null).await;
            InstanceLock::acquire_within(dir, STOP_WAIT).await?
        }
        None => InstanceLock::acquire(dir)?,
    };

    let before = state::load(dir);
    let had_record = secret_backend::has_record(dir);
    let was_signed_in = before.account.is_some() || had_record;

    let backend_ready = match secret_backend::activate_existing(dir, SecretBackendChoice::Auto) {
        Ok(found) => found.is_some(),
        Err(error) => {
            out.warn(format!(
                "Couldn't open the key store, so some keys may stay in it: {}",
                error.message
            ));
            false
        }
    };

    if backend_ready {
        let _ = device_identity::clear_device_id(dir);
        device_identity::clear_passphrase(dir);
        device_identity::clear_identity(dir);
    }
    for name in LOCAL_FILES {
        let _ = std::fs::remove_file(dir.join(name));
    }
    state::clear_pending(dir);

    if keep_cache {
        let kept = CliState {
            cache_user_id: before.cache_user_id.clone(),
            ..CliState::default()
        };
        if let Err(e) = state::save(dir, &kept) {
            out.warn(format!("Couldn't update the saved state: {}", e));
        }
    } else {
        remove_cache(dir);
        if backend_ready {
            let _ = db::forget_db_key();
        }
        state::remove(dir);
        secret_backend::remove_record(dir);
        let _ = std::fs::remove_dir_all(secret_backend::secrets_dir(dir));
    }
    let _ = std::fs::remove_file(control::control_path(dir));

    let service_installed = service::is_installed(dir);
    if out.json {
        out.json(json!({
            "signed_in": false,
            "was_signed_in": was_signed_in,
            "cache_kept": keep_cache,
            "service_installed": service_installed,
        }));
        return Ok(EXIT_OK);
    }
    if !was_signed_in {
        out.line("You're already signed out.");
    } else if keep_cache {
        out.line(format!(
            "{} Signed out. The mail cache stays on this computer.",
            out.dot(Tone::Muted)
        ));
    } else {
        out.line(format!(
            "{} Signed out. Aster Bridge removed this device's keys and the mail cache.",
            out.dot(Tone::Muted)
        ));
    }
    if service_installed {
        out.line("The background service is still installed. To remove it, run: aster-bridge service uninstall");
    }
    Ok(EXIT_OK)
}

fn remove_cache(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        if entry.file_name().to_string_lossy().starts_with("bridge.db") {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}
