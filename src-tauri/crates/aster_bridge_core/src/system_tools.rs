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

pub fn system32_tool(tool: &str) -> PathBuf {
    let system_root = std::env::var_os("SystemRoot").map(PathBuf::from);
    system_tool_path(system_root.as_deref(), tool)
}

pub fn icacls_path() -> PathBuf {
    system32_tool("icacls.exe")
}

pub fn reg_path() -> PathBuf {
    system32_tool("reg.exe")
}

pub fn icacls_command() -> std::process::Command {
    std::process::Command::new(icacls_path())
}

pub fn whoami_command() -> std::process::Command {
    std::process::Command::new(system32_tool("whoami.exe"))
}

pub fn parse_account_sid(output: &str) -> Option<String> {
    let sid = output.trim().rsplit(',').next()?.trim().trim_matches('"');
    let well_formed = sid.starts_with("S-1-")
        && sid.len() <= 184
        && sid[2..]
            .split('-')
            .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()));

    well_formed.then(|| sid.to_string())
}

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

#[cfg(windows)]
fn current_account_sid() -> Option<&'static str> {
    use std::os::windows::process::CommandExt;
    static SID: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();

    SID.get_or_init(|| {
        let out = whoami_command()
            .args(["/user", "/fo", "csv", "/nh"])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .ok()?;

        if !out.status.success() {
            return None;
        }
        parse_account_sid(&String::from_utf8_lossy(&out.stdout))
    })
    .as_deref()
}

#[cfg(windows)]
fn grant_only(path: &Path, trustee: &str) -> Result<(), String> {
    use std::os::windows::process::CommandExt;
    let out = icacls_command()
        .arg(path)
        .args(["/inheritance:r", "/grant:r"])
        .arg(format!("{}:(F)", trustee))
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| format!("icacls could not run: {}", e))?;

    if out.status.success() {
        return Ok(());
    }
    Err(format!(
        "{} {}",
        String::from_utf8_lossy(&out.stdout).trim(),
        String::from_utf8_lossy(&out.stderr).trim()
    )
    .trim()
    .to_string())
}

#[cfg(windows)]
fn restrict_to_current_account(path: &Path) -> Result<(), String> {
    let mut failure = "the current account could not be resolved".to_string();

    if let Some(sid) = current_account_sid() {
        match grant_only(path, &format!("*{}", sid)) {
            Ok(()) => return Ok(()),
            Err(e) => failure = e,
        }
    }

    let user = whoami::fallible::username()
        .unwrap_or_else(|_| std::env::var("USERNAME").unwrap_or_default());

    if !user.is_empty() {
        match grant_only(path, &user) {
            Ok(()) => return Ok(()),
            Err(e) => failure = e,
        }
    }

    Err(format!(
        "could not restrict {} to the current account: {}",
        path.display(),
        failure
    ))
}

pub fn restrict_to_current_user(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("could not restrict {}: {}", path.display(), e))?;
    }
    #[cfg(windows)]
    restrict_to_current_account(path)?;
    #[cfg(not(any(unix, windows)))]
    let _ = path;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_account_sid_from_the_last_field() {
        assert_eq!(
            parse_account_sid("\"desk\\sam\",\"S-1-5-21-1-2-3-1001\"\r\n").as_deref(),
            Some("S-1-5-21-1-2-3-1001")
        );
        assert_eq!(
            parse_account_sid("\"a,b\",\"S-1-5-18\"").as_deref(),
            Some("S-1-5-18")
        );
    }

    #[test]
    fn refuses_output_that_is_not_a_sid() {
        for bad in [
            "",
            "\"sam\"",
            "\"sam\",\"S-1-\"",
            "\"sam\",\"S-1-5-x\"",
            "\"sam\",\"Everyone:(F)\"",
            "\"sam\",\"S-1-5-21 /grant x\"",
        ] {
            assert!(parse_account_sid(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn fails_when_the_file_cannot_be_restricted() {
        let missing = std::env::temp_dir()
            .join(format!("aster_absent_{}", std::process::id()))
            .join("none.bin");

        assert!(restrict_to_current_user(&missing).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn leaves_the_file_readable_by_its_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.bin");
        std::fs::write(&path, b"x").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        restrict_to_current_user(&path).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[cfg(windows)]
    #[test]
    fn restricts_a_real_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.bin");
        std::fs::write(&path, b"x").unwrap();

        restrict_to_current_user(&path).unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), b"x");
    }

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

    #[cfg(windows)]
    #[test]
    fn resolves_to_the_real_reg() {
        let path = reg_path();
        assert!(path.is_absolute());
        assert!(path.is_file(), "{}", path.display());
    }
}
