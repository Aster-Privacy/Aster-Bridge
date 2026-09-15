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
use std::io::IsTerminal;
use std::path::PathBuf;
use std::time::Duration;

use aster_bridge_core::api_client::ApiClient;
use aster_bridge_core::config::BridgeConfig;
use aster_bridge_core::runtime::RuntimeTuning;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::filter::{LevelFilter, Targets};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::Layer;

use crate::cli::{GlobalArgs, LogLevel};
use crate::exit::{CliError, CliResult};
use crate::output::Output;

pub const DATA_DIR_NAME: &str = "com.astermail.bridge.cli";
const LOGIN_POLL_INTERVAL: Duration = Duration::from_secs(3);

pub struct Context {
    pub data_dir: PathBuf,
    pub global: GlobalArgs,
    pub out: Output,
}

pub fn default_data_dir() -> Option<PathBuf> {
    dirs::data_local_dir().map(|dir| dir.join(DATA_DIR_NAME))
}

pub fn folder_tag(data_dir: &std::path::Path) -> Option<String> {
    if default_data_dir().as_deref() == Some(data_dir) {
        return None;
    }
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in data_dir.to_string_lossy().as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    Some(format!("{:016x}", hash))
}

pub fn service_retry_delay() -> Duration {
    #[cfg(feature = "test-support")]
    if let Some(ms) = env_u64("ASTER_BRIDGE_TEST_SERVICE_RETRY_MS") {
        return Duration::from_millis(ms);
    }
    Duration::from_secs(10)
}

impl Context {
    pub fn new(global: GlobalArgs, out: Output) -> CliResult<Self> {
        let requested = global
            .data_dir
            .clone()
            .filter(|dir| !dir.as_os_str().is_empty());
        let dir = match requested {
            Some(dir) => dir,
            None => default_data_dir().ok_or_else(|| {
                CliError::usage("Aster Bridge can't find a folder for its data on this system.")
                    .with_hint("To choose one, pass --data-dir or set ASTER_BRIDGE_DATA_DIR.")
            })?,
        };
        let dir = std::path::absolute(&dir).map_err(|e| {
            CliError::usage(format!("The data folder {} isn't valid: {}", dir.display(), e))
        })?;
        let existed = dir.is_dir();
        std::fs::create_dir_all(&dir).map_err(|e| {
            CliError::general(format!(
                "Couldn't create the data folder {}: {}",
                dir.display(),
                e
            ))
        })?;
        if !existed {
            aster_bridge_core::secrets::restrict_permissions(&dir, true);
        }
        aster_bridge_core::secrets::set_data_dir_override(Some(dir.clone()));
        Ok(Self {
            data_dir: dir,
            global,
            out,
        })
    }
}

#[cfg(feature = "test-support")]
fn env_u64(name: &str) -> Option<u64> {
    std::env::var(name).ok().and_then(|v| v.trim().parse().ok())
}

pub fn api_client() -> ApiClient {
    #[cfg(feature = "test-support")]
    if let Some(base) = std::env::var("ASTER_BRIDGE_TEST_API_BASE")
        .ok()
        .filter(|v| !v.is_empty())
    {
        return ApiClient::new_with_base_url(&base);
    }
    ApiClient::new()
}

pub fn tuning(config: &BridgeConfig) -> RuntimeTuning {
    #[allow(unused_mut)]
    let mut tuning = RuntimeTuning::for_config(config);
    #[cfg(feature = "test-support")]
    {
        if let Some(ms) = env_u64("ASTER_BRIDGE_TEST_POLL_MS") {
            tuning.poll.interval = Duration::from_millis(ms);
        }
        if let Some(every) = env_u64("ASTER_BRIDGE_TEST_PLAN_EVERY") {
            tuning.poll.plan_check_every = every as u32;
        }
        if let Some(ms) = env_u64("ASTER_BRIDGE_TEST_PLAN_RETRY_MS") {
            tuning.plan_retry_delay = Duration::from_millis(ms);
        }
        if let Some(ms) = env_u64("ASTER_BRIDGE_TEST_TOKEN_REFRESH_MS") {
            tuning.token_refresh_interval = Duration::from_millis(ms);
            tuning.token_retry_interval = Duration::from_millis(ms);
        }
    }
    tuning
}

pub fn login_poll_interval() -> Duration {
    #[cfg(feature = "test-support")]
    if let Some(ms) = env_u64("ASTER_BRIDGE_TEST_LOGIN_POLL_MS") {
        return Duration::from_millis(ms);
    }
    LOGIN_POLL_INTERVAL
}

pub fn refresh_rate_limit() -> Duration {
    #[cfg(feature = "test-support")]
    if let Some(ms) = env_u64("ASTER_BRIDGE_TEST_REFRESH_LIMIT_MS") {
        return Duration::from_millis(ms);
    }
    Duration::from_secs(30)
}

pub fn service_failure_delay() -> Duration {
    #[cfg(feature = "test-support")]
    if let Some(ms) = env_u64("ASTER_BRIDGE_TEST_SERVICE_DELAY_MS") {
        return Duration::from_millis(ms);
    }
    Duration::from_secs(60)
}

pub fn drain_timeout() -> Duration {
    #[cfg(feature = "test-support")]
    if let Some(ms) = env_u64("ASTER_BRIDGE_TEST_DRAIN_MS") {
        return Duration::from_millis(ms);
    }
    Duration::from_secs(8)
}

fn level_filter(level: LogLevel) -> LevelFilter {
    match level {
        LogLevel::Error => LevelFilter::ERROR,
        LogLevel::Warn => LevelFilter::WARN,
        LogLevel::Info => LevelFilter::INFO,
        LogLevel::Debug => LevelFilter::DEBUG,
        LogLevel::Trace => LevelFilter::TRACE,
    }
}

pub struct LogGuard {
    _file: Option<WorkerGuard>,
}

const NOISY_DEPENDENCY_TARGETS: [&str; 1] = ["pgp"];

fn dependency_noise_filter(level: LevelFilter) -> Targets {
    let mut targets = Targets::new().with_default(level);
    for target in NOISY_DEPENDENCY_TARGETS {
        targets = targets.with_target(target, LevelFilter::ERROR);
    }
    targets
}

pub fn init_logging(ctx: &Context, write_file: bool) -> LogGuard {
    let stderr_level = ctx.global.log_level.map(level_filter).unwrap_or(if write_file {
        LevelFilter::INFO
    } else {
        LevelFilter::ERROR
    });
    let no_color = std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty());
    let stderr_layer = tracing_subscriber::fmt::layer()
        .with_writer(std::io::stderr)
        .with_ansi(!no_color && std::io::stderr().is_terminal())
        .with_target(false)
        .with_filter(dependency_noise_filter(stderr_level));

    let mut guard = None;
    let file_layer = if write_file {
        match aster_bridge_core::diagnostics::ensure_log_dir(&ctx.data_dir) {
            Ok(dir) => {
                aster_bridge_core::diagnostics::prune_old_logs(&ctx.data_dir);
                let appender = tracing_appender::rolling::daily(dir, "bridge.log");
                let (writer, file_guard) = tracing_appender::non_blocking(appender);
                guard = Some(file_guard);
                let file_level = std::cmp::max(stderr_level, LevelFilter::INFO);
                Some(
                    tracing_subscriber::fmt::layer()
                        .with_writer(writer)
                        .with_ansi(false)
                        .with_filter(dependency_noise_filter(file_level)),
                )
            }
            Err(e) => {
                ctx.out
                    .warn(format!("Couldn't create the log folder, so logs go to stderr only: {}", e));
                None
            }
        }
    } else {
        None
    };

    let _ = tracing_subscriber::registry()
        .with(stderr_layer)
        .with(file_layer)
        .try_init();
    LogGuard { _file: guard }
}

#[cfg(test)]
mod noise_filter_tests {
    use super::*;
    use tracing::Level;

    #[test]
    fn the_pgp_dependency_cannot_warn_on_the_terminal() {
        let filter = dependency_noise_filter(LevelFilter::INFO);
        assert!(!filter.would_enable("pgp::composed::message::types", &Level::WARN));
        assert!(filter.would_enable("pgp::composed::message::types", &Level::ERROR));
    }

    #[test]
    fn our_own_targets_keep_their_level() {
        let filter = dependency_noise_filter(LevelFilter::INFO);
        assert!(filter.would_enable("aster_bridge_core::sync::poller", &Level::INFO));
        assert!(!filter.would_enable("aster_bridge_core::sync::poller", &Level::DEBUG));
    }
}
