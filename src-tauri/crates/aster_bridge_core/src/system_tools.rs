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
use std::path::{Path, PathBuf};

const DEFAULT_SYSTEM_ROOT: &str = "C:\\Windows";

pub fn system_tool_path(system_root: Option<&Path>, tool: &str) -> PathBuf {
    let root = system_root
        .filter(|p| p.is_absolute())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_SYSTEM_ROOT));
    root.join("System32").join(tool)
}

pub fn icacls_path() -> PathBuf {
    let system_root = std::env::var_os("SystemRoot").map(PathBuf::from);
    system_tool_path(system_root.as_deref(), "icacls.exe")
}

pub fn icacls_command() -> std::process::Command {
    std::process::Command::new(icacls_path())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uses_system_root_when_absolute() {
        let root = if cfg!(windows) { "D:\\Win" } else { "/win" };
        let path = system_tool_path(Some(Path::new(root)), "icacls.exe");
        assert_eq!(path, Path::new(root).join("System32").join("icacls.exe"));
    }

    #[test]
    fn falls_back_when_system_root_missing_or_relative() {
        let expected = PathBuf::from(DEFAULT_SYSTEM_ROOT)
            .join("System32")
            .join("icacls.exe");
        assert_eq!(system_tool_path(None, "icacls.exe"), expected);
        assert_eq!(
            system_tool_path(Some(Path::new("Windows")), "icacls.exe"),
            expected
        );
    }

    #[cfg(windows)]
    #[test]
    fn resolves_to_the_real_icacls() {
        let path = icacls_path();
        assert!(path.is_absolute());
        assert!(path.is_file(), "{}", path.display());
    }
}
