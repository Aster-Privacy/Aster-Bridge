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
use std::sync::atomic::{AtomicU8, Ordering};

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
}

impl AccountState {
    pub fn as_str(self) -> &'static str {
        match self {
            AccountState::Active => "active",
            AccountState::Suspended => "suspended",
            AccountState::DeletionScheduled => "deletion_scheduled",
            AccountState::FamilyPolicy => "family_policy",
        }
    }

    fn to_u8(self) -> u8 {
        match self {
            AccountState::Active => 0,
            AccountState::Suspended => 1,
            AccountState::DeletionScheduled => 2,
            AccountState::FamilyPolicy => 3,
        }
    }

    fn from_u8(value: u8) -> Self {
        match value {
            1 => AccountState::Suspended,
            2 => AccountState::DeletionScheduled,
            3 => AccountState::FamilyPolicy,
            _ => AccountState::Active,
        }
    }
}

static CURRENT: AtomicU8 = AtomicU8::new(0);

pub fn classify(error: &str) -> Option<AccountState> {
    if error.contains("ACCOUNT_SUSPENDED") {
        Some(AccountState::Suspended)
    } else if error.contains("scheduled for deletion") {
        Some(AccountState::DeletionScheduled)
    } else if error.contains("FAMILY_2FA_REQUIRED") {
        Some(AccountState::FamilyPolicy)
    } else {
        None
    }
}

pub fn current() -> AccountState {
    AccountState::from_u8(CURRENT.load(Ordering::SeqCst))
}

pub fn record(state: AccountState) -> bool {
    let previous = CURRENT.swap(state.to_u8(), Ordering::SeqCst);
    let changed = previous != state.to_u8();
    if changed {
        match state {
            AccountState::Active => tracing::info!("account state is active again"),
            other => tracing::error!(
                "the server refused requests for this account ({})",
                other.as_str()
            ),
        }
        crate::events::emit(|sink| sink.account_state_changed(state));
    }
    changed
}

pub fn observe<T>(result: &Result<T, String>) {
    match result {
        Ok(_) => {
            record(AccountState::Active);
        }
        Err(e) => {
            if let Some(state) = classify(e) {
                record(state);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(classify("500 Internal Server Error: boom"), None);
        assert_eq!(classify("network error: timed out"), None);
    }

    #[test]
    fn observe_tracks_transitions_and_ignores_transient_errors() {
        record(AccountState::Active);
        observe::<()>(&Err("403 Forbidden: {\"code\":\"ACCOUNT_SUSPENDED\"}".to_string()));
        assert_eq!(current(), AccountState::Suspended);
        observe::<()>(&Err("network error: reset".to_string()));
        assert_eq!(current(), AccountState::Suspended);
        observe(&Ok(()));
        assert_eq!(current(), AccountState::Active);
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
