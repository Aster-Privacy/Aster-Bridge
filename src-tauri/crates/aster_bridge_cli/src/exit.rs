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

pub const CODE_INTERNAL: &str = "internal_error";
pub const CODE_NETWORK: &str = "network";
pub const CODE_SETTINGS_READ: &str = "settings_read_failed";
pub const CODE_SETTINGS_WRITE: &str = "settings_write_failed";
pub const CODE_CACHE_REBUILD: &str = "cache_rebuild_failed";
pub const CODE_SYNC: &str = "sync_failed";
pub const CODE_OUTBOX_READ: &str = "outbox_read_failed";
pub const CODE_OUTBOX_NOT_FOUND: &str = "outbox_message_not_found";
pub const CODE_OUTBOX_RETRY: &str = "outbox_retry_failed";
pub const CODE_TLS_CERTIFICATE: &str = "tls_certificate_failed";
pub const CODE_SIGN_IN: &str = "sign_in_failed";
pub const CODE_SIGN_IN_CANCELED: &str = "sign_in_canceled";
pub const CODE_SERVER_START: &str = "server_start_failed";
pub const CODE_SERVER_STOPPED: &str = "server_stopped";
pub const CODE_APP_PASSWORD_SAVE: &str = "app_password_save_failed";
pub const CODE_APP_PASSWORD_REVOKE: &str = "app_password_revoke_failed";
pub const CODE_SERVICE_UNSUPPORTED: &str = "service_unsupported";
pub const CODE_SERVICE_COMMAND: &str = "service_command_failed";
pub const CODE_SERVICE_FILE: &str = "service_file_failed";
pub const CODE_PROGRAM_PATH: &str = "program_path_unknown";
pub const CODE_DATA_DIR: &str = "data_dir_failed";
pub const CODE_CONTROL_UNREACHABLE: &str = "control_unreachable";
pub const CODE_CONTROL_TIMEOUT: &str = "control_timeout";
pub const CODE_PLAN_CHECK: &str = "plan_check_failed";
pub const CODE_USAGE: &str = "usage";
pub const CODE_NOT_SIGNED_IN: &str = "not_signed_in";
pub const CODE_NOT_RUNNING: &str = "not_running";
pub const CODE_ACCESS_REQUIRED: &str = "bridge_access_required";
pub const CODE_DEVICE_REVOKED: &str = "device_revoked";
pub const CODE_CODE_EXPIRED: &str = "code_expired";
pub const CODE_SECRET_STORE: &str = "secret_store_unavailable";
pub const CODE_SECRET_KEY_FILE_MISSING: &str = "secret_key_file_missing";
pub const CODE_SECRET_KEY_FILE_INVALID: &str = "secret_key_file_invalid";
pub const CODE_PORT_UNAVAILABLE: &str = "port_unavailable";
pub const CODE_OUTBOX_ALREADY_SENT: &str = "outbox_already_sent";
pub const CODE_LOCKED: &str = "locked";
pub const CODE_NOT_FOUND: &str = "not_found";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ErrorDoc {
    pub reference: &'static str,
    pub code: &'static str,
    pub exit_code: i32,
    pub summary: &'static str,
    pub resolution: &'static str,
}

pub const CATALOG: &[ErrorDoc] = &[
    ErrorDoc {
        reference: "ASTER-1000",
        code: CODE_INTERNAL,
        exit_code: EXIT_ERROR,
        summary: "Aster Bridge stopped with an unexpected error.",
        resolution: "Run the command again with --log-level debug, then read the log file that aster-bridge status reports.",
    },
    ErrorDoc {
        reference: "ASTER-1001",
        code: CODE_NETWORK,
        exit_code: EXIT_ERROR,
        summary: "Aster Bridge can't reach Aster Mail.",
        resolution: "Check your internet connection and any proxy settings, then run the command again.",
    },
    ErrorDoc {
        reference: "ASTER-1002",
        code: CODE_SETTINGS_READ,
        exit_code: EXIT_ERROR,
        summary: "Aster Bridge can't read its settings file.",
        resolution: "Check that you can read the data folder, then run: aster-bridge config get",
    },
    ErrorDoc {
        reference: "ASTER-1003",
        code: CODE_SETTINGS_WRITE,
        exit_code: EXIT_ERROR,
        summary: "Aster Bridge can't save its settings.",
        resolution: "Check that you can write to the data folder, then run the command again.",
    },
    ErrorDoc {
        reference: "ASTER-1004",
        code: CODE_CACHE_REBUILD,
        exit_code: EXIT_ERROR,
        summary: "Aster Bridge can't rebuild the local mail cache.",
        resolution: "Check the free space on the disk that holds the data folder, then run: aster-bridge repair-cache",
    },
    ErrorDoc {
        reference: "ASTER-1005",
        code: CODE_SYNC,
        exit_code: EXIT_ERROR,
        summary: "Aster Bridge can't finish syncing your mail.",
        resolution: "Run: aster-bridge sync now. If it keeps failing, check your internet connection.",
    },
    ErrorDoc {
        reference: "ASTER-1006",
        code: CODE_OUTBOX_READ,
        exit_code: EXIT_ERROR,
        summary: "Aster Bridge can't read the outbox.",
        resolution: "Run: aster-bridge outbox list",
    },
    ErrorDoc {
        reference: "ASTER-1007",
        code: CODE_OUTBOX_NOT_FOUND,
        exit_code: EXIT_ERROR,
        summary: "The outbox holds no message with that ID.",
        resolution: "To see the messages that are waiting, run: aster-bridge outbox list",
    },
    ErrorDoc {
        reference: "ASTER-1008",
        code: CODE_OUTBOX_RETRY,
        exit_code: EXIT_ERROR,
        summary: "Aster Bridge can't send the message again.",
        resolution: "Start the servers with aster-bridge serve, then retry the message.",
    },
    ErrorDoc {
        reference: "ASTER-1009",
        code: CODE_TLS_CERTIFICATE,
        exit_code: EXIT_ERROR,
        summary: "Aster Bridge can't create its TLS certificate.",
        resolution: "Check that you can write to the data folder, then run: aster-bridge tls fingerprint",
    },
    ErrorDoc {
        reference: "ASTER-1010",
        code: CODE_SIGN_IN,
        exit_code: EXIT_ERROR,
        summary: "Aster Bridge can't finish signing in.",
        resolution: "Run: aster-bridge login",
    },
    ErrorDoc {
        reference: "ASTER-1011",
        code: CODE_SIGN_IN_CANCELED,
        exit_code: EXIT_ERROR,
        summary: "You canceled the sign-in.",
        resolution: "To start again, run: aster-bridge login",
    },
    ErrorDoc {
        reference: "ASTER-1012",
        code: CODE_SERVER_START,
        exit_code: EXIT_ERROR,
        summary: "Aster Bridge can't start its servers.",
        resolution: "Check that no other program uses the ports, then run: aster-bridge serve",
    },
    ErrorDoc {
        reference: "ASTER-1013",
        code: CODE_SERVER_STOPPED,
        exit_code: EXIT_ERROR,
        summary: "Aster Bridge stopped after an error.",
        resolution: "Run: aster-bridge serve. If it keeps stopping, read the log file that aster-bridge status reports.",
    },
    ErrorDoc {
        reference: "ASTER-1014",
        code: CODE_APP_PASSWORD_SAVE,
        exit_code: EXIT_ERROR,
        summary: "Aster Bridge can't save the app password.",
        resolution: "Check that you can write to the data folder, then create the password again.",
    },
    ErrorDoc {
        reference: "ASTER-1015",
        code: CODE_APP_PASSWORD_REVOKE,
        exit_code: EXIT_ERROR,
        summary: "Aster Bridge can't revoke the app password.",
        resolution: "To check the ID, run: aster-bridge app-password list",
    },
    ErrorDoc {
        reference: "ASTER-1016",
        code: CODE_SERVICE_UNSUPPORTED,
        exit_code: EXIT_ERROR,
        summary: "This system has no service manager that Aster Bridge can use.",
        resolution: "Start Aster Bridge yourself with: aster-bridge serve",
    },
    ErrorDoc {
        reference: "ASTER-1017",
        code: CODE_SERVICE_COMMAND,
        exit_code: EXIT_ERROR,
        summary: "The service manager refused the command.",
        resolution: "Read the message above, then run: aster-bridge service status",
    },
    ErrorDoc {
        reference: "ASTER-1018",
        code: CODE_SERVICE_FILE,
        exit_code: EXIT_ERROR,
        summary: "Aster Bridge can't write the service file.",
        resolution: "Check that you can write to your home folder, then run: aster-bridge service install",
    },
    ErrorDoc {
        reference: "ASTER-1019",
        code: CODE_PROGRAM_PATH,
        exit_code: EXIT_ERROR,
        summary: "Aster Bridge can't find its own program file.",
        resolution: "Run the command again from the folder that holds the aster-bridge program.",
    },
    ErrorDoc {
        reference: "ASTER-1020",
        code: CODE_DATA_DIR,
        exit_code: EXIT_ERROR,
        summary: "Aster Bridge can't use the data folder.",
        resolution: "Check that the folder exists and that you can write to it, or pass --data-dir.",
    },
    ErrorDoc {
        reference: "ASTER-1021",
        code: CODE_CONTROL_UNREACHABLE,
        exit_code: EXIT_ERROR,
        summary: "Aster Bridge is running, but it isn't answering.",
        resolution: "Stop it, then start it again with: aster-bridge serve",
    },
    ErrorDoc {
        reference: "ASTER-1022",
        code: CODE_PLAN_CHECK,
        exit_code: EXIT_ERROR,
        summary: "Aster Bridge can't check your plan.",
        resolution: "Check your internet connection, then run: aster-bridge status --refresh",
    },
    ErrorDoc {
        reference: "ASTER-1023",
        code: CODE_PORT_UNAVAILABLE,
        exit_code: EXIT_ERROR,
        summary: "Another program already uses one of the ports Aster Bridge needs.",
        resolution: "Quit the other program, or choose a different port with: aster-bridge config set",
    },
    ErrorDoc {
        reference: "ASTER-1024",
        code: CODE_OUTBOX_ALREADY_SENT,
        exit_code: EXIT_ERROR,
        summary: "That message was already sent, so Aster Bridge can't send it again.",
        resolution: "To see the messages that are waiting, run: aster-bridge outbox list",
    },
    ErrorDoc {
        reference: "ASTER-1025",
        code: CODE_NOT_FOUND,
        exit_code: EXIT_ERROR,
        summary: "Aster Bridge couldn't find the item you asked for.",
        resolution: "Check the ID, then run the command again. To list app passwords, run: aster-bridge app-password list",
    },
    ErrorDoc {
        reference: "ASTER-1026",
        code: CODE_CONTROL_TIMEOUT,
        exit_code: EXIT_ERROR,
        summary: "Aster Bridge is taking longer than expected to finish the request.",
        resolution: "The work keeps going in the background. To check on it, run: aster-bridge status",
    },
    ErrorDoc {
        reference: "ASTER-2000",
        code: CODE_USAGE,
        exit_code: EXIT_USAGE,
        summary: "The command or its options aren't valid.",
        resolution: "To see the commands and their options, run: aster-bridge --help",
    },
    ErrorDoc {
        reference: "ASTER-3001",
        code: CODE_NOT_SIGNED_IN,
        exit_code: EXIT_NOT_READY,
        summary: "This device isn't linked to an Aster Mail account.",
        resolution: "To link it, run: aster-bridge login",
    },
    ErrorDoc {
        reference: "ASTER-3002",
        code: CODE_NOT_RUNNING,
        exit_code: EXIT_NOT_READY,
        summary: "Aster Bridge isn't running.",
        resolution: "To start it, run: aster-bridge serve",
    },
    ErrorDoc {
        reference: "ASTER-4001",
        code: CODE_ACCESS_REQUIRED,
        exit_code: EXIT_ACCESS,
        summary: "Your plan doesn't include Aster Bridge, which needs a Star plan or higher.",
        resolution: "Upgrade your plan, then run: aster-bridge status --refresh",
    },
    ErrorDoc {
        reference: "ASTER-4002",
        code: "suspended",
        exit_code: EXIT_ACCESS,
        summary: "Your Aster Mail account is suspended, so Aster Bridge can't connect.",
        resolution: "Sign in at app.astermail.org to learn why.",
    },
    ErrorDoc {
        reference: "ASTER-4003",
        code: "deletion_scheduled",
        exit_code: EXIT_ACCESS,
        summary: "Your Aster Mail account is scheduled for deletion, so Aster Bridge can't connect.",
        resolution: "To keep your account, cancel the deletion at app.astermail.org.",
    },
    ErrorDoc {
        reference: "ASTER-4004",
        code: "family_policy",
        exit_code: EXIT_ACCESS,
        summary: "Your family plan requires two-factor authentication before Aster Bridge can connect.",
        resolution: "Turn on two-factor authentication at app.astermail.org/settings.",
    },
    ErrorDoc {
        reference: "ASTER-5001",
        code: CODE_DEVICE_REVOKED,
        exit_code: EXIT_DEVICE,
        summary: "This device was removed from your account, so Aster Bridge signed it out.",
        resolution: "To link it again, run: aster-bridge login",
    },
    ErrorDoc {
        reference: "ASTER-5002",
        code: CODE_CODE_EXPIRED,
        exit_code: EXIT_DEVICE,
        summary: "The sign-in code expired before you entered it.",
        resolution: "To get a new code, run: aster-bridge login",
    },
    ErrorDoc {
        reference: "ASTER-6001",
        code: CODE_SECRET_STORE,
        exit_code: EXIT_SECRET_STORE,
        summary: "Aster Bridge can't reach the system keychain.",
        resolution: "On a server, store the keys in a file instead: set ASTER_BRIDGE_SECRET_BACKEND=file and ASTER_BRIDGE_SECRET_KEY_FILE.",
    },
    ErrorDoc {
        reference: "ASTER-6002",
        code: CODE_SECRET_KEY_FILE_MISSING,
        exit_code: EXIT_SECRET_STORE,
        summary: "This data folder uses a secret key file, but the path isn't set.",
        resolution: "Set ASTER_BRIDGE_SECRET_KEY_FILE to the key file, then run the command again.",
    },
    ErrorDoc {
        reference: "ASTER-6003",
        code: CODE_SECRET_KEY_FILE_INVALID,
        exit_code: EXIT_SECRET_STORE,
        summary: "Aster Bridge can't use the secret key file.",
        resolution: "Check that the file holds 32 bytes of hex and that you can read it.",
    },
    ErrorDoc {
        reference: "ASTER-7001",
        code: CODE_LOCKED,
        exit_code: EXIT_LOCKED,
        summary: "Another Aster Bridge process is using this data folder.",
        resolution: "Stop the other process, or pass --data-dir to use a folder of your own.",
    },
];

pub fn lookup(query: &str) -> Option<&'static ErrorDoc> {
    let wanted = query.trim();
    CATALOG.iter().find(|doc| {
        doc.code.eq_ignore_ascii_case(wanted) || doc.reference.eq_ignore_ascii_case(wanted)
    })
}

pub fn reference_for(code: &str) -> Option<&'static str> {
    CATALOG
        .iter()
        .find(|doc| doc.code == code)
        .map(|doc| doc.reference)
}

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

    pub fn coded(code: &'static str, message: impl Into<String>) -> Self {
        match lookup(code) {
            Some(doc) => Self::new(doc.exit_code, doc.code, message).with_hint(doc.resolution),
            None => Self::new(EXIT_ERROR, code, message),
        }
    }

    pub fn usage(message: impl Into<String>) -> Self {
        Self::new(EXIT_USAGE, CODE_USAGE, message)
    }

    pub fn reference(&self) -> Option<&'static str> {
        reference_for(&self.code)
    }

    pub fn not_signed_in() -> Self {
        Self::new(EXIT_NOT_READY, CODE_NOT_SIGNED_IN, "You're not signed in.")
            .with_hint("To link this device to your account, run: aster-bridge login")
    }

    pub fn not_running() -> Self {
        Self::new(EXIT_NOT_READY, CODE_NOT_RUNNING, "Aster Bridge isn't running.")
            .with_hint("To start it, run: aster-bridge serve")
    }

    pub fn access_required(message: impl Into<String>) -> Self {
        Self::new(EXIT_ACCESS, CODE_ACCESS_REQUIRED, message).with_hint(format!(
            "To use Aster Bridge, upgrade your plan at {}",
            UPGRADE_URL
        ))
    }

    pub fn device_revoked() -> Self {
        Self::new(
            EXIT_DEVICE,
            CODE_DEVICE_REVOKED,
            "This device was removed from your account, so Aster Bridge signed it out.",
        )
        .with_hint("To link it again, run: aster-bridge login")
    }

    pub fn secret_store(message: impl Into<String>) -> Self {
        Self::new(EXIT_SECRET_STORE, CODE_SECRET_STORE, message)
    }

    pub fn locked(message: impl Into<String>) -> Self {
        Self::new(EXIT_LOCKED, CODE_LOCKED, message)
    }

    pub fn to_json(&self) -> Value {
        json!({
            "code": self.code,
            "reference": self.reference(),
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
                .and_then(|c| i32::try_from(c).ok())
                .filter(|c| (EXIT_OK..=EXIT_LOCKED).contains(c))
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
    fn every_catalog_entry_is_unique_and_matches_its_exit_code() {
        for doc in CATALOG {
            assert_eq!(
                CATALOG.iter().filter(|other| other.code == doc.code).count(),
                1,
                "duplicate code {}",
                doc.code
            );
            assert_eq!(
                CATALOG
                    .iter()
                    .filter(|other| other.reference == doc.reference)
                    .count(),
                1,
                "duplicate reference {}",
                doc.reference
            );
            let leading = doc.reference["ASTER-".len()..doc.reference.len() - 3]
                .parse::<i32>()
                .unwrap();
            assert_eq!(leading, doc.exit_code, "{} is filed under the wrong exit code", doc.reference);
            assert!(!doc.summary.is_empty() && !doc.resolution.is_empty());
        }
    }

    #[test]
    fn a_code_or_a_reference_finds_the_same_entry() {
        let by_code = lookup("not_signed_in").unwrap();
        let by_reference = lookup("aster-3001").unwrap();
        assert_eq!(by_code, by_reference);
        assert_eq!(by_code.exit_code, EXIT_NOT_READY);
        assert!(lookup("nothing_like_this").is_none());
    }

    #[test]
    fn a_coded_error_takes_its_exit_code_and_resolution_from_the_catalog() {
        let err = CliError::coded(CODE_SYNC, "Sync didn't finish: timed out");
        assert_eq!(err.exit_code, EXIT_ERROR);
        assert_eq!(err.reference(), Some("ASTER-1005"));
        assert!(err.hint.is_some());
    }

    #[test]
    fn json_round_trip_keeps_exit_code_and_hint() {
        let original = CliError::access_required("Your plan doesn't include Aster Bridge.");
        let restored = CliError::from_json(&original.to_json());
        assert_eq!(restored.exit_code, EXIT_ACCESS);
        assert_eq!(restored.code, "bridge_access_required");
        assert_eq!(restored.hint, original.hint);
    }
}
