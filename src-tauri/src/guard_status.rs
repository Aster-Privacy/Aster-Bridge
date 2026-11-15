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

use std::path::Path;

use aster_bridge_core::guard::pending;

pub fn held_activation(data_dir: &Path, signed_in: bool) -> Option<String> {
    if signed_in {
        return None;
    }
    pending::load(data_dir).map(|held| held.activates_at.to_rfc3339())
}

pub fn ends_setup(status: &str) -> bool {
    matches!(status, "denied" | "rejected")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn held_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let record = serde_json::json!({
            "device_id": "6f2c1e64-0d55-4a8e-9a3b-2f6f7b0c9e11",
            "activates_at": "2030-01-01T10:00:00Z",
        });
        let saved: pending::PendingActivation = serde_json::from_value(record).unwrap();
        pending::save(dir.path(), &saved).unwrap();
        dir
    }

    #[test]
    fn a_held_device_reports_its_activation_time() {
        let dir = held_dir();
        assert_eq!(
            held_activation(dir.path(), false).as_deref(),
            Some("2030-01-01T10:00:00+00:00")
        );
    }

    #[test]
    fn a_signed_in_device_is_never_reported_as_held() {
        let dir = held_dir();
        assert_eq!(held_activation(dir.path(), true), None);
        let empty = tempfile::tempdir().unwrap();
        assert_eq!(held_activation(empty.path(), false), None);
    }

    #[test]
    fn only_a_refusal_ends_the_code_flow_early() {
        assert!(ends_setup("denied"));
        assert!(ends_setup("rejected"));
        assert!(!ends_setup("pending"));
        assert!(!ends_setup("awaiting_confirmation"));
    }
}
