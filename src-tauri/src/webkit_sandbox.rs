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
#![cfg_attr(not(all(unix, not(target_os = "macos"))), allow(dead_code))]

use serde::Serialize;

pub const OVERRIDE_VAR: &str = "ASTER_WEBKIT_SANDBOX";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OverrideMode {
    Auto,
    On,
    Off,
    Invalid,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BwrapProbe {
    Works,
    Missing,
    Failed,
    TimedOut,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxReason {
    PlatformDefault,
    ForcedOn,
    ForcedOff,
    DisabledByEnvironment,
    FlatpakPortal,
    ProbePassed,
    BwrapMissing,
    BwrapFailed,
    BwrapTimedOut,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct SandboxStatus {
    pub enabled: bool,
    pub reason: SandboxReason,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SandboxInputs {
    pub override_mode: OverrideMode,
    pub webkit_disable_preset: bool,
    pub inside_flatpak: bool,
}

pub fn parse_override(value: Option<&str>) -> OverrideMode {
    let Some(value) = value else {
        return OverrideMode::Auto;
    };
    match value.trim().to_ascii_lowercase().as_str() {
        "" | "auto" => OverrideMode::Auto,
        "on" | "1" | "true" | "yes" => OverrideMode::On,
        "off" | "0" | "false" | "no" => OverrideMode::Off,
        _ => OverrideMode::Invalid,
    }
}

pub fn decide(inputs: &SandboxInputs, probe: impl FnOnce() -> BwrapProbe) -> SandboxStatus {
    let status = |enabled, reason| SandboxStatus { enabled, reason };
    match inputs.override_mode {
        OverrideMode::On => return status(true, SandboxReason::ForcedOn),
        OverrideMode::Off => return status(false, SandboxReason::ForcedOff),
        OverrideMode::Auto | OverrideMode::Invalid => {}
    }
    if inputs.webkit_disable_preset {
        return status(false, SandboxReason::DisabledByEnvironment);
    }
    if inputs.inside_flatpak {
        return status(true, SandboxReason::FlatpakPortal);
    }
    match probe() {
        BwrapProbe::Works => status(true, SandboxReason::ProbePassed),
        BwrapProbe::Missing => status(false, SandboxReason::BwrapMissing),
        BwrapProbe::Failed => status(false, SandboxReason::BwrapFailed),
        BwrapProbe::TimedOut => status(false, SandboxReason::BwrapTimedOut),
    }
}

pub fn describe(status: &SandboxStatus) -> String {
    let state = if status.enabled { "on" } else { "OFF" };
    format!("webkit sandbox: {state} ({:?})", status.reason)
}

#[cfg(all(unix, not(target_os = "macos")))]
mod linux {
    use super::*;
    use std::path::Path;
    use std::process::{Command, Stdio};
    use std::sync::OnceLock;
    use std::time::{Duration, Instant};

    const WEBKIT_DISABLE_VAR: &str = "WEBKIT_DISABLE_SANDBOX_THIS_IS_DANGEROUS";
    const PROBE_TIMEOUT: Duration = Duration::from_secs(3);
    const PROBE_POLL: Duration = Duration::from_millis(20);

    static STATUS: OnceLock<SandboxStatus> = OnceLock::new();

    fn inside_flatpak() -> bool {
        Path::new("/.flatpak-info").exists()
    }

    fn run_bwrap_probe() -> BwrapProbe {
        let child = Command::new("bwrap")
            .args([
                "--die-with-parent",
                "--unshare-user",
                "--unshare-pid",
                "--ro-bind",
                "/",
                "/",
                "--dev",
                "/dev",
                "--proc",
                "/proc",
                "true",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();

        let mut child = match child {
            Ok(child) => child,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return BwrapProbe::Missing
            }
            Err(_) => return BwrapProbe::Failed,
        };

        let started = Instant::now();
        loop {
            match child.try_wait() {
                Ok(Some(status)) if status.success() => return BwrapProbe::Works,
                Ok(Some(_)) => return BwrapProbe::Failed,
                Ok(None) if started.elapsed() < PROBE_TIMEOUT => std::thread::sleep(PROBE_POLL),
                Ok(None) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return BwrapProbe::TimedOut;
                }
                Err(_) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return BwrapProbe::Failed;
                }
            }
        }
    }

    pub fn apply_policy() {
        let raw_override = std::env::var(OVERRIDE_VAR).ok();
        let override_mode = parse_override(raw_override.as_deref());
        if override_mode == OverrideMode::Invalid {
            eprintln!("aster-bridge: ignoring {OVERRIDE_VAR}, expected on, off or auto");
        }

        let inputs = SandboxInputs {
            override_mode,
            webkit_disable_preset: std::env::var_os(WEBKIT_DISABLE_VAR).is_some(),
            inside_flatpak: inside_flatpak(),
        };
        let status = decide(&inputs, run_bwrap_probe);

        if status.reason == SandboxReason::ForcedOn {
            std::env::remove_var(WEBKIT_DISABLE_VAR);
        } else if !status.enabled && std::env::var_os(WEBKIT_DISABLE_VAR).is_none() {
            std::env::set_var(WEBKIT_DISABLE_VAR, "1");
        }

        if !status.enabled {
            eprintln!("aster-bridge: {}", describe(&status));
        }
        let _ = STATUS.set(status);
    }

    pub fn current_status() -> SandboxStatus {
        STATUS.get().copied().unwrap_or(SandboxStatus {
            enabled: std::env::var_os(WEBKIT_DISABLE_VAR).is_none(),
            reason: SandboxReason::PlatformDefault,
        })
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
pub use linux::{apply_policy, current_status};

#[cfg(not(all(unix, not(target_os = "macos"))))]
pub fn current_status() -> SandboxStatus {
    SandboxStatus {
        enabled: true,
        reason: SandboxReason::PlatformDefault,
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
pub fn log_status() {
    let status = current_status();
    if status.enabled {
        tracing::info!("{}", describe(&status));
    } else {
        tracing::warn!("{}", describe(&status));
    }
}

#[tauri::command]
pub fn webkit_sandbox_status() -> SandboxStatus {
    current_status()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auto_inputs() -> SandboxInputs {
        SandboxInputs {
            override_mode: OverrideMode::Auto,
            webkit_disable_preset: false,
            inside_flatpak: false,
        }
    }

    fn probe_not_expected() -> BwrapProbe {
        panic!("the bwrap probe must not run for this decision")
    }

    #[test]
    fn override_values_parse_case_insensitively() {
        assert_eq!(parse_override(None), OverrideMode::Auto);
        assert_eq!(parse_override(Some(" AUTO ")), OverrideMode::Auto);
        assert_eq!(parse_override(Some("On")), OverrideMode::On);
        assert_eq!(parse_override(Some("0")), OverrideMode::Off);
        assert_eq!(parse_override(Some("maybe")), OverrideMode::Invalid);
    }

    #[test]
    fn forced_on_keeps_the_sandbox_without_probing() {
        let inputs = SandboxInputs {
            override_mode: OverrideMode::On,
            webkit_disable_preset: true,
            ..auto_inputs()
        };
        let status = decide(&inputs, probe_not_expected);
        assert!(status.enabled);
        assert_eq!(status.reason, SandboxReason::ForcedOn);
    }

    #[test]
    fn forced_off_and_a_preset_variable_are_reported_as_off() {
        let forced = SandboxInputs {
            override_mode: OverrideMode::Off,
            ..auto_inputs()
        };
        assert_eq!(
            decide(&forced, probe_not_expected),
            SandboxStatus {
                enabled: false,
                reason: SandboxReason::ForcedOff
            }
        );
        let preset = SandboxInputs {
            webkit_disable_preset: true,
            ..auto_inputs()
        };
        assert_eq!(
            decide(&preset, probe_not_expected).reason,
            SandboxReason::DisabledByEnvironment
        );
    }

    #[test]
    fn a_working_probe_or_flatpak_keeps_the_sandbox_on() {
        assert!(decide(&auto_inputs(), || BwrapProbe::Works).enabled);
        let flatpak = SandboxInputs {
            inside_flatpak: true,
            ..auto_inputs()
        };
        assert_eq!(
            decide(&flatpak, probe_not_expected).reason,
            SandboxReason::FlatpakPortal
        );
    }

    #[test]
    fn every_probe_failure_is_reported_with_its_own_reason() {
        for (probe, reason) in [
            (BwrapProbe::Missing, SandboxReason::BwrapMissing),
            (BwrapProbe::Failed, SandboxReason::BwrapFailed),
            (BwrapProbe::TimedOut, SandboxReason::BwrapTimedOut),
        ] {
            let status = decide(&auto_inputs(), || probe);
            assert!(!status.enabled);
            assert_eq!(status.reason, reason);
            assert!(describe(&status).contains("OFF"));
        }
    }

    #[test]
    fn the_status_serializes_for_the_window() {
        let status = SandboxStatus {
            enabled: false,
            reason: SandboxReason::BwrapMissing,
        };
        assert_eq!(
            serde_json::to_string(&status).unwrap(),
            r#"{"enabled":false,"reason":"bwrap_missing"}"#
        );
    }
}
