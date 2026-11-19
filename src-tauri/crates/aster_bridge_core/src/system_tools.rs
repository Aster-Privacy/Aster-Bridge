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

#[cfg(any(windows, test))]
fn run_grant(mut command: std::process::Command, path: &Path, trustee: &str) -> Result<(), String> {
    let out = command
        .arg(path)
        .args(["/inheritance:r", "/grant:r"])
        .arg(format!("{}:(F)", trustee))
        .output()
        .map_err(|e| format!("icacls could not run: {}", e))?;

    if out.status.success() {
        return Ok(());
    }
    let detail = format!(
        "{} {}",
        String::from_utf8_lossy(&out.stdout).trim(),
        String::from_utf8_lossy(&out.stderr).trim()
    )
    .trim()
    .to_string();
    if detail.is_empty() {
        return Err(format!("icacls exited with {}", out.status));
    }
    Err(detail)
}

#[cfg(windows)]
fn grant_only(path: &Path, trustee: &str) -> Result<(), String> {
    use std::os::windows::process::CommandExt;
    let mut command = icacls_command();
    command.creation_flags(CREATE_NO_WINDOW);
    run_grant(command, path, trustee)
}

#[cfg(any(windows, test))]
fn restrict_through<U, G>(path: &Path, sid: Option<&str>, user: U, grant: G) -> Result<(), String>
where
    U: FnOnce() -> String,
    G: Fn(&Path, &str) -> Result<(), String>,
{
    let mut failure = "the current account could not be resolved".to_string();

    if let Some(sid) = sid {
        match grant(path, &format!("*{}", sid)) {
            Ok(()) => return Ok(()),
            Err(e) => failure = e,
        }
    }

    let user = user();
    if !user.is_empty() {
        match grant(path, &user) {
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

#[cfg(windows)]
fn restrict_to_current_account(path: &Path) -> Result<(), String> {
    restrict_through(
        path,
        current_account_sid(),
        || whoami::fallible::username().unwrap_or_else(|_| std::env::var("USERNAME").unwrap_or_default()),
        grant_only,
    )
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

pub fn limit_or_discard<F>(path: &Path, restrict: F) -> Result<(), String>
where
    F: FnOnce(&Path) -> Result<(), String>,
{
    match restrict(path) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(path);
            Err(format!(
                "{} was not saved because access to it could not be limited to your account: {}",
                path.display(),
                e
            ))
        }
    }
}

pub fn write_limited_file<F>(path: &Path, bytes: &[u8], restrict: F) -> Result<(), String>
where
    F: FnOnce(&Path) -> Result<(), String>,
{
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    drop(
        options
            .open(path)
            .map_err(|e| format!("cannot create {}: {}", path.display(), e))?,
    );
    limit_or_discard(path, restrict)?;
    let written = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)
        .and_then(|mut file| {
            file.write_all(bytes)?;
            file.sync_all()
        });
    if let Err(e) = written {
        let _ = std::fs::remove_file(path);
        return Err(format!("cannot write {}: {}", path.display(), e));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_file_whose_access_cannot_be_limited_is_not_written() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.bin");
        let err = write_limited_file(&path, b"top secret", |_| {
            Err("icacls exited with status 5".to_string())
        })
        .unwrap_err();
        assert!(err.contains("could not be limited to your account"), "{err}");
        assert!(err.contains("icacls exited with status 5"), "{err}");
        assert!(!path.exists(), "a file left behind after the restriction failed");
    }

    #[test]
    fn a_file_is_restricted_before_its_contents_are_written() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.bin");
        let mut seen = None;
        write_limited_file(&path, b"top secret", |p| {
            seen = Some(std::fs::read(p).unwrap());
            restrict_to_current_user(p)
        })
        .unwrap();
        assert_eq!(seen.as_deref(), Some(&b""[..]));
        assert_eq!(std::fs::read(&path).unwrap(), b"top secret");
        assert!(write_limited_file(&path, b"again", restrict_to_current_user).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"top secret");
    }

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

    #[cfg(unix)]
    fn fake_icacls(dir: &Path, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let script = dir.join("icacls");
        std::fs::write(&script, format!("#!/bin/sh\n{}\n", body)).unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        script
    }

    #[cfg(unix)]
    #[test]
    fn a_failing_or_missing_icacls_is_reported_as_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("secret.bin");
        std::fs::write(&target, b"x").unwrap();

        let denied = fake_icacls(dir.path(), "echo 'Access is denied.' >&2\nexit 5");
        let err = run_grant(std::process::Command::new(&denied), &target, "*S-1-5-21-1-2-3-1001").unwrap_err();
        assert!(err.contains("Access is denied."), "{err}");

        let silent = fake_icacls(dir.path(), "exit 5");
        let err = run_grant(std::process::Command::new(&silent), &target, "*S-1-5-21-1-2-3-1001").unwrap_err();
        assert!(err.contains("icacls exited with"), "{err}");

        let missing = dir.path().join("no_such_icacls");
        let err = run_grant(std::process::Command::new(&missing), &target, "sam").unwrap_err();
        assert!(err.contains("icacls could not run"), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn a_working_icacls_receives_the_grant_for_the_account() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("secret.bin");
        std::fs::write(&target, b"x").unwrap();
        let record = dir.path().join("args.txt");
        let ok = fake_icacls(dir.path(), &format!("printf '%s\n' \"$@\" > '{}'\nexit 0", record.display()));
        run_grant(std::process::Command::new(&ok), &target, "*S-1-5-21-1-2-3-1001").unwrap();
        let args = std::fs::read_to_string(&record).unwrap();
        assert_eq!(
            args.lines().collect::<Vec<_>>(),
            vec![
                target.to_str().unwrap(),
                "/inheritance:r",
                "/grant:r",
                "*S-1-5-21-1-2-3-1001:(F)"
            ]
        );
    }

    #[test]
    fn the_account_is_not_left_open_when_every_grant_fails() {
        let path = Path::new("secret.bin");
        let tried = std::cell::RefCell::new(Vec::new());
        let failing = |_: &Path, trustee: &str| {
            tried.borrow_mut().push(trustee.to_string());
            Err("icacls exited with status 5".to_string())
        };
        let err = restrict_through(path, Some("S-1-5-21-1-2-3-1001"), || "sam".to_string(), failing).unwrap_err();
        assert!(err.contains("could not restrict"), "{err}");
        assert!(err.contains("status 5"), "{err}");
        assert_eq!(*tried.borrow(), vec!["*S-1-5-21-1-2-3-1001".to_string(), "sam".to_string()]);

        let err = restrict_through(path, None, String::new, |_: &Path, _: &str| Ok(())).unwrap_err();
        assert!(err.contains("could not be resolved"), "{err}");

        let by_name = restrict_through(path, Some("S-1-5-21-1-2-3-1001"), || "sam".to_string(), |_: &Path, trustee: &str| {
            if trustee == "sam" {
                Ok(())
            } else {
                Err("no mapping".to_string())
            }
        });
        assert!(by_name.is_ok());
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
