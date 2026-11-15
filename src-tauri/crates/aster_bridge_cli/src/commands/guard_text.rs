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
pub const PENDING_LABEL: &str = "Waiting for activation";
pub const SIGN_IN_AGAIN_LABEL: &str = "Sign in again";
pub const PENDING_MESSAGE: &str = "This device is waiting for activation.";
pub const SIGN_IN_AGAIN_MESSAGE: &str = "Aster Bridge needs you to sign in again.";
pub const SIGN_IN_AGAIN_HINT: &str =
    "To continue, run: aster-bridge login. Then approve the sign-in on one of your Aster devices.";

pub fn pending_hint(activates_at: Option<chrono::DateTime<chrono::Utc>>) -> String {
    match activates_at {
        Some(at) => format!(
            "Mail apps can connect after {} UTC. Aster Bridge keeps checking, so you don't need to sign in again.",
            at.format("%Y-%m-%d %H:%M")
        ),
        None => "Mail apps can connect about one hour after you approved this sign-in. Aster Bridge keeps checking, so you don't need to sign in again.".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_hint_names_the_activation_time_in_utc() {
        let at = chrono::DateTime::parse_from_rfc3339("2026-11-15T11:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let hint = pending_hint(Some(at));
        assert!(hint.contains("2026-11-15 11:00 UTC"));
        assert!(pending_hint(None).contains("one hour"));
    }
}
