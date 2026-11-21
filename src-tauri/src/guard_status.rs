// SPDX-License-Identifier: AGPL-3.0-or-later
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
use std::sync::atomic::{AtomicU64, Ordering};

use aster_bridge_core::guard::pending;

pub fn held_activation(data_dir: &Path, signed_in: bool) -> Option<String> {
    if signed_in {
        return None;
    }
    pending::load(data_dir).map(|held| held.activates_at.to_rfc3339())
}

pub fn is_held(data_dir: &Path, signed_in: bool) -> bool {
    !signed_in && pending::load(data_dir).is_some()
}

pub struct SignInGeneration(AtomicU64);

impl SignInGeneration {
    pub const fn new() -> Self {
        Self(AtomicU64::new(0))
    }

    pub fn current(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }

    pub fn advance(&self) -> u64 {
        self.0.fetch_add(1, Ordering::SeqCst) + 1
    }

    pub fn is_current(&self, generation: u64) -> bool {
        self.current() == generation
    }
}

pub static SIGN_IN_GENERATION: SignInGeneration = SignInGeneration::new();

pub fn may_adopt(generation_current: bool, has_device_id: bool, signed_in: bool) -> bool {
    generation_current && has_device_id && !signed_in
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
        assert!(is_held(dir.path(), false));
    }

    #[test]
    fn a_signed_in_device_is_never_reported_as_held() {
        let dir = held_dir();
        assert_eq!(held_activation(dir.path(), true), None);
        assert!(!is_held(dir.path(), true));
        let empty = tempfile::tempdir().unwrap();
        assert_eq!(held_activation(empty.path(), false), None);
        assert!(!is_held(empty.path(), false));
    }

    #[test]
    fn a_newer_sign_in_makes_an_older_one_stale() {
        let generation = SignInGeneration::new();
        let first = generation.advance();
        assert!(generation.is_current(first));
        let second = generation.advance();
        assert!(!generation.is_current(first));
        assert!(generation.is_current(second));
    }

    #[test]
    fn only_the_current_sign_in_on_a_device_that_kept_its_id_adopts_a_session() {
        assert!(may_adopt(true, true, false));
        assert!(!may_adopt(false, true, false));
        assert!(!may_adopt(true, false, false));
        assert!(!may_adopt(true, true, true));
    }

    #[test]
    fn the_license_header_ends_with_a_blank_comment_line() {
        let source = include_str!("guard_status.rs").replace("\r\n", "\n");
        let header_end = source.find("use std::path::Path;").unwrap();
        assert!(source[..header_end].trim_end().ends_with("<https://www.gnu.org/licenses/>.\n//"));
    }
}
