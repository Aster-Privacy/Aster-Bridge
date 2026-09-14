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

pub const EXIT_OK: i32 = 0;
pub const EXIT_ERROR: i32 = 1;
pub const EXIT_USAGE: i32 = 2;
pub const EXIT_NOT_READY: i32 = 3;
pub const EXIT_ACCESS: i32 = 4;
pub const EXIT_DEVICE: i32 = 5;
pub const EXIT_SECRET_STORE: i32 = 6;
pub const EXIT_LOCKED: i32 = 7;

pub const UPGRADE_URL: &str = "https://app.astermail.org/settings/billing";
pub const LINK_DEVICE_URL: &str = "https://app.astermail.org/link-device";

#[derive(Debug, Clone)]
pub struct CliError {
    pub exit_code: i32,
    pub code: String,
    pub message: String,
    pub hint: Option<String>,
}

pub type CliResult<T> = Result<T, CliError>;

impl CliError {
    pub fn new(exit_code: i32, code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            exit_code,
            code: code.into(),
            message: message.into(),
            hint: None,
        }
    }

    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }

    pub fn general(message: impl Into<String>) -> Self {
        Self::new(EXIT_ERROR, "error", message)
    }

    pub fn usage(message: impl Into<String>) -> Self {
        Self::new(EXIT_USAGE, "usage", message)
    }

    pub fn not_signed_in() -> Self {
        Self::new(EXIT_NOT_READY, "not_signed_in", "You're not signed in.")
            .with_hint("To link this device to your account, run: aster-bridge login")
    }

    pub fn not_running() -> Self {
        Self::new(EXIT_NOT_READY, "not_running", "Aster Bridge isn't running.")
            .with_hint("To start it, run: aster-bridge serve")
    }

    pub fn access_required(message: impl Into<String>) -> Self {
        Self::new(EXIT_ACCESS, "bridge_access_required", message).with_hint(format!(
            "To use Aster Bridge, upgrade your plan at {}",
            UPGRADE_URL
        ))
    }

    pub fn device_revoked() -> Self {
        Self::new(
            EXIT_DEVICE,
            "device_revoked",
            "This device was removed from your account, so Aster Bridge signed it out.",
        )
        .with_hint("To link it again, run: aster-bridge login")
    }

    pub fn secret_store(message: impl Into<String>) -> Self {
        Self::new(EXIT_SECRET_STORE, "secret_store_unavailable", message)
    }

    pub fn locked(message: impl Into<String>) -> Self {
        Self::new(EXIT_LOCKED, "locked", message)
    }

    pub fn to_json(&self) -> Value {
        json!({
            "code": self.code,
            "message": self.message,
            "hint": self.hint,
            "exit_code": self.exit_code,
        })
    }

    pub fn from_json(value: &Value) -> Self {
        let text = |key: &str| value.get(key).and_then(Value::as_str).map(str::to_string);
        Self {
            exit_code: value
                .get("exit_code")
                .and_then(Value::as_i64)
                .map(|c| c as i32)
                .unwrap_or(EXIT_ERROR),
            code: text("code").unwrap_or_else(|| "error".to_string()),
            message: text("message").unwrap_or_else(|| "Aster Bridge returned an error.".to_string()),
            hint: text("hint"),
        }
    }
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_round_trip_keeps_exit_code_and_hint() {
        let original = CliError::access_required("Your plan doesn't include Aster Bridge.");
        let restored = CliError::from_json(&original.to_json());
        assert_eq!(restored.exit_code, EXIT_ACCESS);
        assert_eq!(restored.code, "bridge_access_required");
        assert_eq!(restored.hint, original.hint);
    }
}
