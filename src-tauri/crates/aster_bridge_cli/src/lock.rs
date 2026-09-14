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
use std::fs::{File, OpenOptions, TryLockError};
use std::path::Path;

use crate::exit::{CliError, CliResult};

const LOCK_FILE: &str = "bridge.lock";

pub struct InstanceLock {
    _file: File,
}

pub enum LockAttempt {
    Acquired(InstanceLock),
    Held,
}

impl InstanceLock {
    pub fn try_acquire(data_dir: &Path) -> CliResult<LockAttempt> {
        let path = data_dir.join(LOCK_FILE);
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&path)
            .map_err(|e| {
                CliError::general(format!("Couldn't open {}: {}", path.display(), e))
            })?;
        match file.try_lock() {
            Ok(()) => Ok(LockAttempt::Acquired(InstanceLock { _file: file })),
            Err(TryLockError::WouldBlock) => Ok(LockAttempt::Held),
            Err(TryLockError::Error(e)) => Err(CliError::general(format!(
                "Couldn't lock {}: {}",
                path.display(),
                e
            ))),
        }
    }

    pub fn acquire(data_dir: &Path) -> CliResult<Self> {
        match Self::try_acquire(data_dir)? {
            LockAttempt::Acquired(lock) => Ok(lock),
            LockAttempt::Held => Err(held_error()),
        }
    }

    pub async fn acquire_within(data_dir: &Path, wait: std::time::Duration) -> CliResult<Self> {
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            if let LockAttempt::Acquired(lock) = Self::try_acquire(data_dir)? {
                return Ok(lock);
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(held_error());
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
    }
}

pub fn held_error() -> CliError {
    CliError::locked("Another aster-bridge process is using this data folder.").with_hint(
        "To continue, wait for it to finish or stop it. To run a separate copy, choose another folder with --data-dir.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn second_lock_on_same_folder_is_refused_until_release() {
        let dir = tempfile::tempdir().unwrap();
        let first = InstanceLock::acquire(dir.path()).unwrap();
        assert!(matches!(
            InstanceLock::try_acquire(dir.path()).unwrap(),
            LockAttempt::Held
        ));
        drop(first);
        assert!(matches!(
            InstanceLock::try_acquire(dir.path()).unwrap(),
            LockAttempt::Acquired(_)
        ));
    }
}
