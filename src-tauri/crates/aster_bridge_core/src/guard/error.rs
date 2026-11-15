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
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde_json::Value;
use uuid::Uuid;

pub const GUARD_HEADER: &str = "x-aster-guard";
pub const CODE_REQUIRED: &str = "GUARD_REQUIRED";
pub const CODE_DEVICE_PENDING: &str = "GUARD_DEVICE_PENDING";
pub const CODE_HELD: &str = "GUARD_HELD";
pub const CODE_PAUSED: &str = "GUARD_PAUSED";
pub const CODE_TOO_MANY_REQUESTS: &str = "GUARD_TOO_MANY_REQUESTS";

const MESSAGE_MAX: usize = 200;
const RETRY_AFTER_MAX_SECS: u64 = 24 * 60 * 60;
pub const REQUIRED_TEXT: &str =
    "Aster Guard needs to approve this sign-in. Update Aster Bridge or your Aster app, then sign in again.";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardSignal {
    Required {
        message: String,
    },
    Pending {
        device_id: Uuid,
        activates_at: DateTime<Utc>,
        change_id: Option<Uuid>,
    },
    Throttled {
        message: String,
        retry_after_secs: Option<u64>,
    },
    Other {
        message: String,
    },
}

fn field<'a>(parsed: &'a Value, name: &str) -> Option<&'a Value> {
    parsed
        .get("details")
        .and_then(|details| details.get(name))
        .filter(|value| !value.is_null())
        .or_else(|| parsed.get(name).filter(|value| !value.is_null()))
}

fn uuid_field(parsed: &Value, name: &str) -> Option<Uuid> {
    field(parsed, name)
        .and_then(Value::as_str)
        .and_then(|raw| Uuid::parse_str(raw).ok())
}

fn time_field(parsed: &Value, name: &str) -> Option<DateTime<Utc>> {
    field(parsed, name)
        .and_then(Value::as_str)
        .and_then(|raw| DateTime::parse_from_rfc3339(raw).ok())
        .map(|time| time.with_timezone(&Utc))
}

fn message_of(parsed: &Value, fallback: &str) -> String {
    parsed
        .get("error")
        .and_then(Value::as_str)
        .unwrap_or(fallback)
        .chars()
        .take(MESSAGE_MAX)
        .collect()
}

pub fn parse_guard_signal(body: &str, retry_after_header: Option<u64>) -> Option<GuardSignal> {
    let parsed: Value = serde_json::from_str(body).ok()?;
    let code = parsed.get("code").and_then(Value::as_str)?;
    if !code.starts_with("GUARD_") {
        return None;
    }
    let signal = match code {
        CODE_REQUIRED => match uuid_field(&parsed, "request_id") {
            Some(_) => GuardSignal::Required {
                message: message_of(&parsed, REQUIRED_TEXT),
            },
            None => GuardSignal::Other {
                message: message_of(&parsed, code),
            },
        },
        CODE_DEVICE_PENDING => match (
            uuid_field(&parsed, "device_id"),
            time_field(&parsed, "activates_at"),
        ) {
            (Some(device_id), Some(activates_at)) => GuardSignal::Pending {
                device_id,
                activates_at,
                change_id: uuid_field(&parsed, "change_id"),
            },
            _ => GuardSignal::Other {
                message: message_of(&parsed, code),
            },
        },
        CODE_PAUSED | CODE_TOO_MANY_REQUESTS => GuardSignal::Throttled {
            message: message_of(&parsed, code),
            retry_after_secs: field(&parsed, "retry_after_secs")
                .and_then(Value::as_u64)
                .or(retry_after_header),
        },
        _ => GuardSignal::Other {
            message: message_of(&parsed, code),
        },
    };
    Some(signal)
}

pub fn parse_retry_after_header(value: Option<&str>) -> Option<u64> {
    value.and_then(|raw| raw.trim().parse::<u64>().ok())
}

static RETRY_NOT_BEFORE: AtomicI64 = AtomicI64::new(0);

pub fn note_retry_after(secs: u64) {
    let secs = i64::try_from(secs.min(RETRY_AFTER_MAX_SECS)).unwrap_or(0);
    let until = Utc::now().timestamp().saturating_add(secs);
    RETRY_NOT_BEFORE.fetch_max(until, Ordering::SeqCst);
}

pub fn retry_wait() -> Option<Duration> {
    let until = RETRY_NOT_BEFORE.load(Ordering::SeqCst);
    let now = Utc::now().timestamp();
    (until > now).then(|| Duration::from_secs(u64::try_from(until - now).unwrap_or(0)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const REQUEST_ID: &str = "00112233-4455-6677-8899-aabbccddeeff";
    const DEVICE_ID: &str = "8d4f2b1e-3c6a-4e5f-9a7b-1c2d3e4f5a6b";

    #[test]
    fn required_reads_details_and_drops_the_token() {
        let body = serde_json::json!({
            "error": REQUIRED_TEXT,
            "code": "GUARD_REQUIRED",
            "details": {"request_id": REQUEST_ID, "guard_token": "tok-should-not-leak", "expires_at": "2026-11-15T10:00:00Z", "methods": ["number"]},
            "request_id": REQUEST_ID,
            "guard_token": "tok-should-not-leak",
        })
        .to_string();
        let signal = parse_guard_signal(&body, None).unwrap();
        assert!(matches!(&signal, GuardSignal::Required { message } if message == REQUIRED_TEXT));
        assert!(!format!("{:?}", signal).contains("tok-should-not-leak"));
    }

    #[test]
    fn pending_reads_top_level_copy_when_details_are_missing() {
        let body = serde_json::json!({
            "error": "pending",
            "code": "GUARD_DEVICE_PENDING",
            "device_id": DEVICE_ID,
            "activates_at": "2026-11-15T11:00:00Z",
            "change_id": null,
        })
        .to_string();
        match parse_guard_signal(&body, None).unwrap() {
            GuardSignal::Pending { device_id, activates_at, change_id } => {
                assert_eq!(device_id.to_string(), DEVICE_ID);
                assert_eq!(activates_at.to_rfc3339(), "2026-11-15T11:00:00+00:00");
                assert_eq!(change_id, None);
            }
            other => panic!("unexpected {:?}", other),
        }
    }

    #[test]
    fn malformed_details_fall_back_to_other() {
        for body in [
            r#"{"code":"GUARD_DEVICE_PENDING","details":{"device_id":"nope","activates_at":"later"}}"#,
            r#"{"code":"GUARD_DEVICE_PENDING","details":"oops"}"#,
            r#"{"code":"GUARD_REQUIRED","details":[1,2,3]}"#,
        ] {
            assert!(matches!(
                parse_guard_signal(body, None),
                Some(GuardSignal::Other { .. })
            ));
        }
    }

    #[test]
    fn throttled_prefers_details_then_header() {
        let with_details = r#"{"error":"paused","code":"GUARD_PAUSED","details":{"retry_after_secs":90}}"#;
        assert_eq!(
            parse_guard_signal(with_details, Some(5)),
            Some(GuardSignal::Throttled { message: "paused".to_string(), retry_after_secs: Some(90) })
        );
        let header_only = r#"{"error":"slow down","code":"GUARD_TOO_MANY_REQUESTS"}"#;
        assert_eq!(
            parse_guard_signal(header_only, Some(30)),
            Some(GuardSignal::Throttled { message: "slow down".to_string(), retry_after_secs: Some(30) })
        );
    }

    #[test]
    fn non_guard_bodies_are_ignored() {
        assert_eq!(parse_guard_signal(r#"{"code":"ACCOUNT_SUSPENDED"}"#, None), None);
        assert_eq!(parse_guard_signal("not json", None), None);
        assert_eq!(parse_guard_signal(r#"{"error":"x"}"#, None), None);
    }

    #[test]
    fn retry_after_header_parses_seconds_only() {
        assert_eq!(parse_retry_after_header(Some(" 120 ")), Some(120));
        assert_eq!(parse_retry_after_header(Some("Wed, 21 Oct 2026 07:28:00 GMT")), None);
        assert_eq!(parse_retry_after_header(None), None);
    }

    #[test]
    fn noted_retry_after_holds_off_retries() {
        note_retry_after(120);
        let wait = retry_wait().expect("a wait is noted");
        assert!(wait.as_secs() >= 110 && wait.as_secs() <= 120);
        note_retry_after(1);
        assert!(retry_wait().unwrap().as_secs() >= 110);
    }
}
