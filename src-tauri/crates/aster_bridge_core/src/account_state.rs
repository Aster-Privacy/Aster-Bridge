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
use std::sync::atomic::{AtomicI64, AtomicU8, Ordering};

use chrono::{DateTime, Utc};

use crate::error::BridgeError;

#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum AccountState {
    #[default]
    Active,
    Suspended,
    DeletionScheduled,
    FamilyPolicy,
    UpdateRequired,
    GuardPending,
    SignInAgain,
}

impl AccountState {
    pub fn as_str(self) -> &'static str {
        match self {
            AccountState::Active => "active",
            AccountState::Suspended => "suspended",
            AccountState::DeletionScheduled => "deletion_scheduled",
            AccountState::FamilyPolicy => "family_policy",
            AccountState::UpdateRequired => "update_required",
            AccountState::GuardPending => "guard_pending",
            AccountState::SignInAgain => "sign_in_again",
        }
    }

    fn to_u8(self) -> u8 {
        match self {
            AccountState::Active => 0,
            AccountState::Suspended => 1,
            AccountState::DeletionScheduled => 2,
            AccountState::FamilyPolicy => 3,
            AccountState::UpdateRequired => 4,
            AccountState::GuardPending => 5,
            AccountState::SignInAgain => 6,
        }
    }

    fn from_u8(value: u8) -> Self {
        match value {
            1 => AccountState::Suspended,
            2 => AccountState::DeletionScheduled,
            3 => AccountState::FamilyPolicy,
            4 => AccountState::UpdateRequired,
            5 => AccountState::GuardPending,
            6 => AccountState::SignInAgain,
            _ => AccountState::Active,
        }
    }
}

static CURRENT: AtomicU8 = AtomicU8::new(0);
static ACTIVATES_AT: AtomicI64 = AtomicI64::new(0);

pub fn classify(error: &str) -> Option<AccountState> {
    if error.contains("ACCOUNT_SUSPENDED") {
        Some(AccountState::Suspended)
    } else if error.contains("scheduled for deletion") {
        Some(AccountState::DeletionScheduled)
    } else if error.contains("FAMILY_2FA_REQUIRED") {
        Some(AccountState::FamilyPolicy)
    } else if error.contains("CLIENT_UPGRADE_REQUIRED") || error.contains("client_upgrade_required") {
        Some(AccountState::UpdateRequired)
    } else if error.contains("GUARD_DEVICE_PENDING") || error.contains("guard_device_pending") {
        Some(AccountState::GuardPending)
    } else if error.contains("GUARD_REQUIRED") || error.contains("guard_required") {
        Some(AccountState::SignInAgain)
    } else {
        None
    }
}

pub fn classify_error(error: &BridgeError) -> Option<AccountState> {
    match error {
        BridgeError::GuardPending { .. } => Some(AccountState::GuardPending),
        BridgeError::GuardRequired(_) => Some(AccountState::SignInAgain),
        BridgeError::ClientUpgradeRequired(_) => Some(AccountState::UpdateRequired),
        other => classify(&other.to_string()),
    }
}

pub fn activates_at() -> Option<DateTime<Utc>> {
    if current() != AccountState::GuardPending {
        return None;
    }
    DateTime::from_timestamp(ACTIVATES_AT.load(Ordering::SeqCst), 0)
        .filter(|time| time.timestamp() > 0)
}

pub fn record_pending(activates_at: DateTime<Utc>) -> bool {
    let previous = ACTIVATES_AT.swap(activates_at.timestamp(), Ordering::SeqCst);
    let changed = record(AccountState::GuardPending);
    if !changed && previous != activates_at.timestamp() {
        crate::events::emit(|sink| sink.account_state_changed(AccountState::GuardPending));
        return true;
    }
    changed
}

pub fn record_error(error: &BridgeError) -> Option<AccountState> {
    if let BridgeError::GuardPending { activates_at, .. } = error {
        record_pending(*activates_at);
        return Some(AccountState::GuardPending);
    }
    let state = classify_error(error)?;
    record(state);
    Some(state)
}

pub fn clear_guard_state() {
    if matches!(current(), AccountState::GuardPending | AccountState::SignInAgain) {
        record(AccountState::Active);
    }
}

pub fn current() -> AccountState {
    AccountState::from_u8(CURRENT.load(Ordering::SeqCst))
}

pub fn record(state: AccountState) -> bool {
    let previous = CURRENT.swap(state.to_u8(), Ordering::SeqCst);
    let changed = previous != state.to_u8();
    if changed {
        if state != AccountState::GuardPending {
            ACTIVATES_AT.store(0, Ordering::SeqCst);
        }
        match state {
            AccountState::Active => tracing::info!("account state is active again"),
            AccountState::GuardPending => {
                tracing::info!("this device is waiting for activation")
            }
            AccountState::SignInAgain => {
                tracing::warn!("this device needs to sign in again")
            }
            other => tracing::error!(
                "the server refused requests for this account ({})",
                other.as_str()
            ),
        }
        crate::events::emit(|sink| sink.account_state_changed(state));
    }
    changed
}

fn state_after_success(current: AccountState) -> AccountState {
    match current {
        AccountState::UpdateRequired => AccountState::UpdateRequired,
        _ => AccountState::Active,
    }
}

pub fn observe<T>(result: &Result<T, String>) {
    match result {
        Ok(_) => {
            record(state_after_success(current()));
        }
        Err(e) => {
            if let Some(state) = classify(e) {
                record(state);
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) static STATE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    pub(crate) fn state_lock() -> std::sync::MutexGuard<'static, ()> {
        STATE_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn at(raw: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(raw).unwrap().with_timezone(&Utc)
    }

    #[test]
    fn classify_reads_guard_codes_in_both_forms() {
        assert_eq!(
            classify(r#"403 Forbidden: {"code":"GUARD_DEVICE_PENDING"}"#),
            Some(AccountState::GuardPending)
        );
        assert_eq!(
            classify("guard_device_pending: activates at 2026-11-15 11:00:00 UTC"),
            Some(AccountState::GuardPending)
        );
        assert_eq!(
            classify(r#"403 Forbidden: {"code":"GUARD_REQUIRED"}"#),
            Some(AccountState::SignInAgain)
        );
        assert_eq!(
            classify("guard_required: Aster Guard needs to approve this sign-in."),
            Some(AccountState::SignInAgain)
        );
    }

    #[test]
    fn classify_error_maps_guard_variants() {
        let pending = BridgeError::GuardPending {
            device_id: uuid::Uuid::nil(),
            activates_at: at("2026-11-15T11:00:00Z"),
            change_id: None,
        };
        assert_eq!(classify_error(&pending), Some(AccountState::GuardPending));
        assert_eq!(
            classify_error(&BridgeError::GuardRequired("x".to_string())),
            Some(AccountState::SignInAgain)
        );
        assert_eq!(classify_error(&BridgeError::Api("500 boom".to_string())), None);
    }

    #[test]
    fn pending_state_keeps_the_activation_time_until_cleared() {
        let _lock = state_lock();
        record(AccountState::Active);
        assert_eq!(activates_at(), None);
        let pending = BridgeError::GuardPending {
            device_id: uuid::Uuid::nil(),
            activates_at: at("2026-11-15T11:00:00Z"),
            change_id: None,
        };
        assert_eq!(record_error(&pending), Some(AccountState::GuardPending));
        assert_eq!(current(), AccountState::GuardPending);
        assert_eq!(activates_at(), Some(at("2026-11-15T11:00:00Z")));
        assert!(record_pending(at("2026-11-15T11:30:00Z")));
        assert_eq!(activates_at(), Some(at("2026-11-15T11:30:00Z")));
        clear_guard_state();
        assert_eq!(current(), AccountState::Active);
        assert_eq!(activates_at(), None);
    }

    #[test]
    fn sign_in_again_clears_on_success_but_update_required_stays() {
        let _lock = state_lock();
        record(AccountState::Active);
        record_error(&BridgeError::GuardRequired("x".to_string()));
        assert_eq!(current(), AccountState::SignInAgain);
        observe(&Ok(()));
        assert_eq!(current(), AccountState::Active);
        record(AccountState::UpdateRequired);
        clear_guard_state();
        assert_eq!(current(), AccountState::UpdateRequired);
        record(AccountState::Active);
    }

    #[test]
    fn guard_states_round_trip_and_serialize() {
        for state in [AccountState::GuardPending, AccountState::SignInAgain] {
            assert_eq!(AccountState::from_u8(state.to_u8()), state);
            assert_eq!(
                serde_json::to_string(&state).unwrap(),
                format!("\"{}\"", state.as_str())
            );
        }
    }

    #[test]
    fn classify_reads_backend_error_bodies() {
        assert_eq!(
            classify(r#"403 Forbidden: {"error":"Your account has been suspended for violating our Terms of Service.","code":"ACCOUNT_SUSPENDED"}"#),
            Some(AccountState::Suspended)
        );
        assert_eq!(
            classify(r#"403 Forbidden: {"error":"this account is scheduled for deletion"}"#),
            Some(AccountState::DeletionScheduled)
        );
        assert_eq!(
            classify(r#"403 Forbidden: {"error":"two-factor required","code":"FAMILY_2FA_REQUIRED"}"#),
            Some(AccountState::FamilyPolicy)
        );
        assert_eq!(
            classify(r#"426 Upgrade Required: {"error":"Update the app.","code":"CLIENT_UPGRADE_REQUIRED"}"#),
            Some(AccountState::UpdateRequired)
        );
        assert_eq!(
            classify("client_upgrade_required: Update the app."),
            Some(AccountState::UpdateRequired)
        );
        assert_eq!(classify("500 Internal Server Error: boom"), None);
        assert_eq!(classify("network error: timed out"), None);
    }

    #[test]
    fn observe_tracks_transitions_and_ignores_transient_errors() {
        let _lock = state_lock();
        record(AccountState::Active);
        observe::<()>(&Err("403 Forbidden: {\"code\":\"ACCOUNT_SUSPENDED\"}".to_string()));
        assert_eq!(current(), AccountState::Suspended);
        observe::<()>(&Err("network error: reset".to_string()));
        assert_eq!(current(), AccountState::Suspended);
        observe(&Ok(()));
        assert_eq!(current(), AccountState::Active);
    }

    #[test]
    fn success_does_not_clear_update_required() {
        assert_eq!(
            state_after_success(AccountState::UpdateRequired),
            AccountState::UpdateRequired
        );
        assert_eq!(state_after_success(AccountState::Suspended), AccountState::Active);
        assert_eq!(
            AccountState::from_u8(AccountState::UpdateRequired.to_u8()),
            AccountState::UpdateRequired
        );
        assert_eq!(AccountState::UpdateRequired.as_str(), "update_required");
    }

    #[test]
    fn serializes_as_snake_case() {
        assert_eq!(
            serde_json::to_string(&AccountState::DeletionScheduled).unwrap(),
            "\"deletion_scheduled\""
        );
        assert_eq!(AccountState::FamilyPolicy.as_str(), "family_policy");
    }
}
