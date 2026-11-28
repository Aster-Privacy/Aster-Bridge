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
#![cfg_attr(any(not(windows), debug_assertions), allow(dead_code))]

use std::io;

pub const APPROVED_ENABLED: [u8; 12] = [0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hive {
    User,
    Machine,
    Machine32,
}

const ALL_HIVES: [Hive; 3] = [Hive::User, Hive::Machine, Hive::Machine32];
const MACHINE_HIVES: [Hive; 2] = [Hive::Machine, Hive::Machine32];

pub trait StartupRegistry {
    fn run_value(&self, hive: Hive, name: &str) -> io::Result<Option<String>>;
    fn approval(&self, hive: Hive, name: &str) -> io::Result<Option<Vec<u8>>>;
    fn set_run_value(&self, hive: Hive, name: &str, command: &str) -> io::Result<()>;
    fn set_approval(&self, hive: Hive, name: &str, bytes: &[u8]) -> io::Result<()>;
    fn delete_run_value(&self, hive: Hive, name: &str) -> io::Result<()>;
    fn delete_approval(&self, hive: Hive, name: &str) -> io::Result<()>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AutostartError {
    MachineWide,
    AccessDenied,
    NotApplied,
    Failed(String),
}

impl AutostartError {
    pub fn code(&self) -> &'static str {
        match self {
            AutostartError::MachineWide => "autostart_machine_wide",
            AutostartError::AccessDenied => "autostart_access_denied",
            AutostartError::NotApplied | AutostartError::Failed(_) => "autostart_failed",
        }
    }

    pub fn detail(&self) -> String {
        match self {
            AutostartError::MachineWide => "entry is registered for all users".to_string(),
            AutostartError::AccessDenied => "access denied".to_string(),
            AutostartError::NotApplied => "system state did not change".to_string(),
            AutostartError::Failed(message) => redact_home(message),
        }
    }

    pub fn from_message(message: &str) -> Self {
        let lower = message.to_ascii_lowercase();
        if lower.contains("permission denied")
            || lower.contains("access is denied")
            || lower.contains("operation not permitted")
            || lower.contains("os error 13")
            || lower.contains("os error 5)")
        {
            AutostartError::AccessDenied
        } else {
            AutostartError::Failed(message.to_string())
        }
    }
}

impl From<io::Error> for AutostartError {
    fn from(error: io::Error) -> Self {
        if error.kind() == io::ErrorKind::PermissionDenied {
            AutostartError::AccessDenied
        } else {
            AutostartError::Failed(error.to_string())
        }
    }
}

pub fn redact_home(message: &str) -> String {
    ["HOME", "USERPROFILE"]
        .iter()
        .filter_map(|var| std::env::var(var).ok())
        .filter(|home| home.len() > 1)
        .fold(message.to_string(), |acc, home| acc.replace(&home, "~"))
}

fn ignore_missing(result: io::Result<()>) -> io::Result<()> {
    match result {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        other => other,
    }
}

pub fn approval_allows(bytes: Option<&[u8]>) -> bool {
    match bytes {
        Some([first, ..]) => first & 1 == 0,
        _ => true,
    }
}

pub fn launch_command(exe: &str, args: &[&str]) -> String {
    std::iter::once(format!("\"{}\"", exe.trim_matches('"')))
        .chain(args.iter().map(|arg| arg.to_string()))
        .collect::<Vec<_>>()
        .join(" ")
}

fn hive_enabled(registry: &dyn StartupRegistry, hive: Hive, name: &str) -> io::Result<bool> {
    if registry.run_value(hive, name)?.is_none() {
        return Ok(false);
    }
    Ok(approval_allows(registry.approval(hive, name)?.as_deref()))
}

pub fn is_enabled(registry: &dyn StartupRegistry, name: &str) -> Result<bool, AutostartError> {
    for hive in ALL_HIVES {
        if hive_enabled(registry, hive, name)? {
            return Ok(true);
        }
    }
    Ok(false)
}

pub fn enable(registry: &dyn StartupRegistry, name: &str, command: &str) -> Result<(), AutostartError> {
    registry.set_run_value(Hive::User, name, command)?;
    registry.set_approval(Hive::User, name, &APPROVED_ENABLED)?;
    if is_enabled(registry, name)? {
        Ok(())
    } else {
        Err(AutostartError::NotApplied)
    }
}

pub fn disable(registry: &dyn StartupRegistry, name: &str) -> Result<(), AutostartError> {
    ignore_missing(registry.delete_run_value(Hive::User, name))?;
    ignore_missing(registry.delete_approval(Hive::User, name))?;
    for hive in MACHINE_HIVES {
        if !hive_enabled(registry, hive, name)? {
            continue;
        }
        match ignore_missing(registry.delete_run_value(hive, name)) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                return Err(AutostartError::MachineWide)
            }
            Err(error) => return Err(error.into()),
        }
    }
    if is_enabled(registry, name)? {
        Err(AutostartError::NotApplied)
    } else {
        Ok(())
    }
}

pub fn refresh(registry: &dyn StartupRegistry, name: &str, command: &str) -> Result<bool, AutostartError> {
    match registry.run_value(Hive::User, name)? {
        Some(current) if current != command => {
            registry.set_run_value(Hive::User, name, command)?;
            Ok(true)
        }
        _ => Ok(false),
    }
}

#[cfg(windows)]
pub mod windows_registry {
    use super::{Hive, StartupRegistry};
    use std::io;
    use winreg::enums::{
        RegType::REG_BINARY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_SET_VALUE,
        KEY_WOW64_32KEY, KEY_WOW64_64KEY,
    };
    use winreg::{RegKey, RegValue};

    const RUN_KEY: &str = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
    const APPROVED_RUN_KEY: &str = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run";
    const APPROVED_RUN32_KEY: &str = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run32";

    pub struct WindowsRegistry;

    fn root(hive: Hive) -> RegKey {
        match hive {
            Hive::User => RegKey::predef(HKEY_CURRENT_USER),
            Hive::Machine | Hive::Machine32 => RegKey::predef(HKEY_LOCAL_MACHINE),
        }
    }

    fn run_view(hive: Hive) -> u32 {
        match hive {
            Hive::Machine32 => KEY_WOW64_32KEY,
            _ => KEY_WOW64_64KEY,
        }
    }

    fn approved_key(hive: Hive) -> &'static str {
        match hive {
            Hive::Machine32 => APPROVED_RUN32_KEY,
            _ => APPROVED_RUN_KEY,
        }
    }

    fn missing_as_none<T>(result: io::Result<T>) -> io::Result<Option<T>> {
        match result {
            Ok(value) => Ok(Some(value)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn open(hive: Hive, path: &str, flags: u32, view: u32) -> io::Result<Option<RegKey>> {
        missing_as_none(root(hive).open_subkey_with_flags(path, flags | view))
    }

    impl StartupRegistry for WindowsRegistry {
        fn run_value(&self, hive: Hive, name: &str) -> io::Result<Option<String>> {
            match open(hive, RUN_KEY, KEY_READ, run_view(hive))? {
                Some(key) => missing_as_none(key.get_value::<String, _>(name)),
                None => Ok(None),
            }
        }

        fn approval(&self, hive: Hive, name: &str) -> io::Result<Option<Vec<u8>>> {
            match open(hive, approved_key(hive), KEY_READ, KEY_WOW64_64KEY)? {
                Some(key) => Ok(missing_as_none(key.get_raw_value(name))?.map(|value| value.bytes)),
                None => Ok(None),
            }
        }

        fn set_run_value(&self, hive: Hive, name: &str, command: &str) -> io::Result<()> {
            let (key, _) = root(hive).create_subkey_with_flags(RUN_KEY, KEY_SET_VALUE | run_view(hive))?;
            key.set_value(name, &command.to_string())
        }

        fn set_approval(&self, hive: Hive, name: &str, bytes: &[u8]) -> io::Result<()> {
            let (key, _) = root(hive).create_subkey_with_flags(approved_key(hive), KEY_SET_VALUE | KEY_WOW64_64KEY)?;
            key.set_raw_value(
                name,
                &RegValue {
                    vtype: REG_BINARY,
                    bytes: bytes.to_vec(),
                },
            )
        }

        fn delete_run_value(&self, hive: Hive, name: &str) -> io::Result<()> {
            match open(hive, RUN_KEY, KEY_SET_VALUE, run_view(hive))? {
                Some(key) => key.delete_value(name),
                None => Ok(()),
            }
        }

        fn delete_approval(&self, hive: Hive, name: &str) -> io::Result<()> {
            match open(hive, approved_key(hive), KEY_SET_VALUE, KEY_WOW64_64KEY)? {
                Some(key) => key.delete_value(name),
                None => Ok(()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::{HashMap, HashSet};

    #[derive(Default)]
    struct FakeRegistry {
        run: RefCell<HashMap<(u8, String), String>>,
        approved: RefCell<HashMap<(u8, String), Vec<u8>>>,
        read_only: HashSet<u8>,
    }

    fn slot(hive: Hive) -> u8 {
        match hive {
            Hive::User => 0,
            Hive::Machine => 1,
            Hive::Machine32 => 2,
        }
    }

    impl FakeRegistry {
        fn check_write(&self, hive: Hive) -> io::Result<()> {
            if self.read_only.contains(&slot(hive)) {
                Err(io::Error::from(io::ErrorKind::PermissionDenied))
            } else {
                Ok(())
            }
        }

        fn put_run(&self, hive: Hive, name: &str, command: &str) {
            self.run.borrow_mut().insert((slot(hive), name.to_string()), command.to_string());
        }

        fn put_approval(&self, hive: Hive, name: &str, bytes: &[u8]) {
            self.approved.borrow_mut().insert((slot(hive), name.to_string()), bytes.to_vec());
        }
    }

    impl StartupRegistry for FakeRegistry {
        fn run_value(&self, hive: Hive, name: &str) -> io::Result<Option<String>> {
            Ok(self.run.borrow().get(&(slot(hive), name.to_string())).cloned())
        }

        fn approval(&self, hive: Hive, name: &str) -> io::Result<Option<Vec<u8>>> {
            Ok(self.approved.borrow().get(&(slot(hive), name.to_string())).cloned())
        }

        fn set_run_value(&self, hive: Hive, name: &str, command: &str) -> io::Result<()> {
            self.check_write(hive)?;
            self.put_run(hive, name, command);
            Ok(())
        }

        fn set_approval(&self, hive: Hive, name: &str, bytes: &[u8]) -> io::Result<()> {
            self.check_write(hive)?;
            self.put_approval(hive, name, bytes);
            Ok(())
        }

        fn delete_run_value(&self, hive: Hive, name: &str) -> io::Result<()> {
            self.check_write(hive)?;
            self.run
                .borrow_mut()
                .remove(&(slot(hive), name.to_string()))
                .map(|_| ())
                .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
        }

        fn delete_approval(&self, hive: Hive, name: &str) -> io::Result<()> {
            self.check_write(hive)?;
            self.approved
                .borrow_mut()
                .remove(&(slot(hive), name.to_string()))
                .map(|_| ())
                .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
        }
    }

    const NAME: &str = "Aster Bridge";
    const COMMAND: &str = "\"C:\\Apps\\Aster Bridge\\aster-bridge-desktop.exe\" --service";
    const DISABLED: [u8; 12] = [0x03, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8];

    #[test]
    fn disable_when_nothing_is_registered_succeeds() {
        let registry = FakeRegistry::default();
        registry.put_approval(Hive::User, NAME, &APPROVED_ENABLED);
        assert_eq!(disable(&registry, NAME), Ok(()));
        assert_eq!(is_enabled(&registry, NAME), Ok(false));
        assert!(registry.approval(Hive::User, NAME).unwrap().is_none());
    }

    #[test]
    fn enable_then_disable_round_trips() {
        let registry = FakeRegistry::default();
        assert_eq!(enable(&registry, NAME, COMMAND), Ok(()));
        assert_eq!(is_enabled(&registry, NAME), Ok(true));
        assert_eq!(registry.run_value(Hive::User, NAME).unwrap().as_deref(), Some(COMMAND));
        assert_eq!(disable(&registry, NAME), Ok(()));
        assert_eq!(is_enabled(&registry, NAME), Ok(false));
        assert_eq!(disable(&registry, NAME), Ok(()));
    }

    #[test]
    fn enable_overrides_a_startup_apps_disable() {
        let registry = FakeRegistry::default();
        registry.put_run(Hive::User, NAME, COMMAND);
        registry.put_approval(Hive::User, NAME, &DISABLED);
        assert_eq!(is_enabled(&registry, NAME), Ok(false));
        assert_eq!(enable(&registry, NAME, COMMAND), Ok(()));
        assert_eq!(is_enabled(&registry, NAME), Ok(true));
    }

    #[test]
    fn approval_flags_follow_startup_apps_values() {
        assert!(approval_allows(None));
        assert!(approval_allows(Some(&[])));
        assert!(approval_allows(Some(&APPROVED_ENABLED)));
        assert!(approval_allows(Some(&[0x06, 0, 0, 0])));
        assert!(!approval_allows(Some(&DISABLED)));
        assert!(!approval_allows(Some(&[0x07, 0, 0, 0])));
    }

    #[test]
    fn machine_entry_counts_as_enabled_and_is_removed_when_writable() {
        let registry = FakeRegistry::default();
        registry.put_run(Hive::Machine, NAME, COMMAND);
        assert_eq!(is_enabled(&registry, NAME), Ok(true));
        assert_eq!(disable(&registry, NAME), Ok(()));
        assert_eq!(is_enabled(&registry, NAME), Ok(false));
    }

    #[test]
    fn read_only_machine_entry_reports_machine_wide() {
        let registry = FakeRegistry {
            read_only: [slot(Hive::Machine32)].into_iter().collect(),
            ..Default::default()
        };
        registry.put_run(Hive::Machine32, NAME, COMMAND);
        registry.put_run(Hive::User, NAME, COMMAND);
        assert_eq!(disable(&registry, NAME), Err(AutostartError::MachineWide));
        assert!(registry.run_value(Hive::User, NAME).unwrap().is_none());
        assert_eq!(is_enabled(&registry, NAME), Ok(true));
    }

    #[test]
    fn machine_entry_turned_off_in_startup_apps_is_left_alone() {
        let registry = FakeRegistry {
            read_only: [slot(Hive::Machine)].into_iter().collect(),
            ..Default::default()
        };
        registry.put_run(Hive::Machine, NAME, COMMAND);
        registry.put_approval(Hive::Machine, NAME, &DISABLED);
        assert_eq!(is_enabled(&registry, NAME), Ok(false));
        assert_eq!(disable(&registry, NAME), Ok(()));
    }

    #[test]
    fn denied_user_write_reports_access_denied() {
        let registry = FakeRegistry {
            read_only: [slot(Hive::User)].into_iter().collect(),
            ..Default::default()
        };
        assert_eq!(enable(&registry, NAME, COMMAND), Err(AutostartError::AccessDenied));
        assert_eq!(enable(&registry, NAME, COMMAND).unwrap_err().code(), "autostart_access_denied");
    }

    #[test]
    fn refresh_rewrites_a_stale_path_only() {
        let registry = FakeRegistry::default();
        assert_eq!(refresh(&registry, NAME, COMMAND), Ok(false));
        assert!(registry.run_value(Hive::User, NAME).unwrap().is_none());
        registry.put_run(Hive::User, NAME, "C:\\Old\\aster-bridge-desktop.exe --service");
        assert_eq!(refresh(&registry, NAME, COMMAND), Ok(true));
        assert_eq!(registry.run_value(Hive::User, NAME).unwrap().as_deref(), Some(COMMAND));
        assert_eq!(refresh(&registry, NAME, COMMAND), Ok(false));
    }

    #[test]
    fn launch_command_quotes_the_executable() {
        assert_eq!(
            launch_command("C:\\Apps\\Aster Bridge\\aster-bridge-desktop.exe", &["--service"]),
            COMMAND
        );
        assert_eq!(launch_command("\"C:\\a b\\x.exe\"", &[]), "\"C:\\a b\\x.exe\"");
    }

    #[test]
    fn messages_map_to_plain_codes() {
        assert_eq!(
            AutostartError::from_message("Permission denied (os error 13)"),
            AutostartError::AccessDenied
        );
        assert_eq!(AutostartError::from_message("boom").code(), "autostart_failed");
        assert_eq!(AutostartError::MachineWide.code(), "autostart_machine_wide");
    }
}
