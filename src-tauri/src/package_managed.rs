//
// Aster Communications Inc.
//
// Copyright (c) 2026 Aster Communications Inc.
//
// This file is part of this project.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the AGPLv3 as published by
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
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::ffi::OsStr;

use tauri::plugin::TauriPlugin;
use tauri::Runtime;

pub const DISABLE_UPDATER_VAR: &str = "ASTER_DISABLE_UPDATER";
pub const LAUNCH_COMMAND_VAR: &str = "ASTER_LAUNCH_COMMAND";
pub const AUTOSTART_ARGS: [&str; 1] = ["--service"];

const PLUGIN_NAME: &str = "aster-package-managed";
const UPDATES_MANAGED_SCRIPT: &str = "window.__ASTER_UPDATES_MANAGED__ = true;";

pub fn updater_disabled_by(value: Option<&OsStr>) -> bool {
    value.is_some_and(|v| !v.is_empty() && v != OsStr::new("0"))
}

pub fn updater_disabled() -> bool {
    updater_disabled_by(std::env::var_os(DISABLE_UPDATER_VAR).as_deref())
}

pub fn launch_command_from(value: Option<&OsStr>) -> Option<String> {
    value
        .and_then(OsStr::to_str)
        .filter(|v| !v.is_empty())
        .map(str::to_string)
}

pub fn launch_command() -> Option<String> {
    launch_command_from(std::env::var_os(LAUNCH_COMMAND_VAR).as_deref())
}

pub fn updates_managed_plugin<R: Runtime>() -> TauriPlugin<R> {
    tauri::plugin::Builder::new(PLUGIN_NAME)
        .js_init_script(UPDATES_MANAGED_SCRIPT)
        .build()
}

#[cfg(target_os = "linux")]
pub fn launcher(app_name: &str, launch_command: &str) -> Result<auto_launch::AutoLaunch, String> {
    auto_launch::AutoLaunchBuilder::new()
        .set_app_name(app_name)
        .set_app_path(launch_command)
        .set_args(&AUTOSTART_ARGS)
        .build()
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn updater_disabled_needs_a_value_other_than_zero() {
        assert!(!updater_disabled_by(None));
        assert!(!updater_disabled_by(Some(OsStr::new(""))));
        assert!(!updater_disabled_by(Some(OsStr::new("0"))));
        assert!(updater_disabled_by(Some(OsStr::new("1"))));
        assert!(updater_disabled_by(Some(OsStr::new("true"))));
    }

    #[test]
    fn launch_command_ignores_empty_values() {
        assert_eq!(launch_command_from(None), None);
        assert_eq!(launch_command_from(Some(OsStr::new(""))), None);
        assert_eq!(
            launch_command_from(Some(OsStr::new("/run/current-system/sw/bin/aster-bridge-desktop"))),
            Some("/run/current-system/sw/bin/aster-bridge-desktop".to_string())
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn launcher_uses_the_launch_command_and_service_flag() {
        let launcher = launcher("Aster Bridge", "/etc/profiles/per-user/me/bin/aster-bridge-desktop").unwrap();
        assert_eq!(launcher.get_app_name(), "Aster Bridge");
        assert_eq!(launcher.get_app_path(), "/etc/profiles/per-user/me/bin/aster-bridge-desktop");
        assert_eq!(launcher.get_args(), ["--service".to_string()]);
    }
}
