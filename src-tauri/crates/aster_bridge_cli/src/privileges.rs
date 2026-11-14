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
#![cfg_attr(not(unix), allow(dead_code, unused_imports))]

use std::path::Path;

use crate::exit::{CliError, CliResult, CODE_DATA_DIR};

pub const DEFAULT_ID: u32 = 10001;
pub const USER_ENV: &str = "PUID";
pub const GROUP_ENV: &str = "PGID";

#[cfg(unix)]
pub fn drop_root(data_dir: Option<&Path>) -> CliResult<Option<String>> {
    if unsafe { libc::geteuid() } != 0 || !crate::container::in_container() {
        return Ok(None);
    }
    let uid = id_from_env(USER_ENV, std::env::var(USER_ENV).ok())?;
    let gid = id_from_env(GROUP_ENV, std::env::var(GROUP_ENV).ok())?;
    let notice = match data_dir {
        Some(dir) => take_ownership(dir, uid, gid)?,
        None => None,
    };
    switch_user(uid, gid)?;
    Ok(notice)
}

#[cfg(not(unix))]
pub fn drop_root(_data_dir: Option<&Path>) -> CliResult<Option<String>> {
    Ok(None)
}

pub fn id_from_env(name: &str, value: Option<String>) -> CliResult<u32> {
    let Some(value) = value.map(|v| v.trim().to_string()).filter(|v| !v.is_empty()) else {
        return Ok(DEFAULT_ID);
    };
    match value.parse::<u32>() {
        Ok(0) => Err(CliError::usage(format!(
            "{} is 0, but Aster Bridge doesn't run as root.",
            name
        ))
        .with_hint(format!(
            "Set {} to the ID that owns your data folder, such as 1000, or remove it to use {}.",
            name, DEFAULT_ID
        ))),
        Ok(id) => Ok(id),
        Err(_) => Err(CliError::usage(format!(
            "{} must be a number, such as 1000, but it's set to {}.",
            name, value
        ))),
    }
}

#[cfg(unix)]
fn take_ownership(dir: &Path, uid: u32, gid: u32) -> CliResult<Option<String>> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    let meta = match std::fs::metadata(dir) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(dir)
                .map_err(|e| ownership_error(dir, uid, gid, &e.to_string(), None))?;
            std::fs::metadata(dir)
                .map_err(|e| ownership_error(dir, uid, gid, &e.to_string(), None))?
        }
        Err(e) => return Err(ownership_error(dir, uid, gid, &e.to_string(), None)),
    };
    let found = (meta.uid(), meta.gid());
    if found == (uid, gid) {
        return Ok(None);
    }
    chown_tree(dir, uid, gid, meta.dev())
        .map_err(|e| ownership_error(dir, uid, gid, &e.to_string(), Some(found)))?;
    Ok(Some(format!(
        "Changed the owner of {} from {}:{} to {}:{} so Aster Bridge can use it. To keep a different owner, set {} and {} to it.",
        dir.display(),
        found.0,
        found.1,
        uid,
        gid,
        USER_ENV,
        GROUP_ENV
    )))
}

#[cfg(unix)]
fn chown_tree(path: &Path, uid: u32, gid: u32, device: u64) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::symlink_metadata(path)?;
    if meta.dev() != device {
        return Ok(());
    }
    std::os::unix::fs::lchown(path, Some(uid), Some(gid))?;
    if meta.is_dir() {
        for entry in std::fs::read_dir(path)? {
            chown_tree(&entry?.path(), uid, gid, device)?;
        }
    }
    Ok(())
}

#[cfg(unix)]
fn ownership_error(dir: &Path, uid: u32, gid: u32, detail: &str, found: Option<(u32, u32)>) -> CliError {
    let owner = match found {
        Some((o, g)) => format!(
            "The folder belongs to user {} and group {}. To run Aster Bridge as that user instead, set {}={} and {}={}. ",
            o, g, USER_ENV, o, GROUP_ENV, g
        ),
        None => String::new(),
    };
    CliError::coded(
        CODE_DATA_DIR,
        format!(
            "Couldn't give user {} and group {} the data folder {}: {}",
            uid,
            gid,
            dir.display(),
            detail
        ),
    )
    .with_hint(format!(
        "{}Otherwise, change the owner on the host with: sudo chown -R {}:{} <folder>",
        owner, uid, gid
    ))
}

#[cfg(unix)]
fn switch_user(uid: u32, gid: u32) -> CliResult<()> {
    let failed = |step: &str| {
        CliError::coded(
            CODE_DATA_DIR,
            format!(
                "Aster Bridge couldn't switch to user {} and group {} ({}: {}), so it stopped instead of running as root.",
                uid,
                gid,
                step,
                std::io::Error::last_os_error()
            ),
        )
        .with_hint("Give the container the SETUID and SETGID capabilities, or run it as that user with user: in your Compose file.")
    };
    unsafe {
        let groups = [gid as libc::gid_t];
        if libc::setgroups(1, groups.as_ptr()) != 0 {
            return Err(failed("setgroups"));
        }
        if libc::setgid(gid as libc::gid_t) != 0 {
            return Err(failed("setgid"));
        }
        if libc::setuid(uid as libc::uid_t) != 0 {
            return Err(failed("setuid"));
        }
        let dropped = libc::getuid() == uid
            && libc::geteuid() == uid
            && libc::getgid() == gid
            && libc::getegid() == gid
            && libc::setuid(0) != 0;
        if !dropped {
            return Err(failed("verify"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_default_and_refuse_root() {
        assert_eq!(id_from_env("PUID", None).unwrap(), DEFAULT_ID);
        assert_eq!(id_from_env("PUID", Some(" ".into())).unwrap(), DEFAULT_ID);
        assert_eq!(id_from_env("PUID", Some("1000".into())).unwrap(), 1000);
        assert!(id_from_env("PUID", Some("0".into())).is_err());
        assert!(id_from_env("PGID", Some("abc".into())).is_err());
        assert!(id_from_env("PGID", Some("-1".into())).is_err());
    }
}
