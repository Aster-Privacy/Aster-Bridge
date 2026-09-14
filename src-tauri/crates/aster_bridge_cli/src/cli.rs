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
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

#[derive(Parser, Debug)]
#[command(
    name = "aster-bridge",
    version,
    about = "Aster Bridge for servers and terminals",
    long_about = "Aster Bridge connects email apps to your Aster Mail account over IMAP, SMTP, POP3, JMAP, and CardDAV on this computer.",
    propagate_version = true,
    disable_help_subcommand = true
)]
pub struct Cli {
    #[command(flatten)]
    pub global: GlobalArgs,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Args, Debug, Clone)]
pub struct GlobalArgs {
    #[arg(long, global = true, env = "ASTER_BRIDGE_DATA_DIR", value_name = "PATH", help = "Folder that stores the account, cache, and settings")]
    pub data_dir: Option<PathBuf>,
    #[arg(long, global = true, help = "Print machine-readable JSON")]
    pub json: bool,
    #[arg(long, global = true, value_enum, value_name = "LEVEL", help = "Log detail written to stderr")]
    pub log_level: Option<LogLevel>,
    #[arg(long, global = true, value_enum, env = "ASTER_BRIDGE_SECRET_BACKEND", default_value_t = SecretBackendChoice::Auto, help = "Where to keep encryption keys")]
    pub secret_backend: SecretBackendChoice,
}

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretBackendChoice {
    Auto,
    Keyring,
    File,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    #[command(about = "Link this device to your Aster Mail account")]
    Login {
        #[arg(long, help = "Print the code and exit without waiting for confirmation")]
        no_wait: bool,
    },
    #[command(about = "Sign this device out")]
    Logout {
        #[arg(long, help = "Keep the local mail cache")]
        keep_cache: bool,
    },
    #[command(about = "Run the mail servers in the foreground")]
    Serve {
        #[arg(long, help = "Print events as JSON lines on stdout")]
        json_events: bool,
        #[arg(long, help = "Behave as a background service")]
        service: bool,
    },
    #[command(about = "Show account, plan, and server status")]
    Status {
        #[arg(long, help = "Check the plan with Aster Mail")]
        refresh: bool,
        #[arg(long, conflicts_with = "refresh", help = "Keep the status on screen and update it")]
        live: bool,
    },
    #[command(subcommand, about = "Manage passwords for email apps")]
    AppPassword(AppPasswordCommand),
    #[command(subcommand, about = "Inspect and retry outgoing mail")]
    Outbox(OutboxCommand),
    #[command(subcommand, about = "Sync mail")]
    Sync(SyncCommand),
    #[command(subcommand, about = "Show TLS certificate details")]
    Tls(TlsCommand),
    #[command(subcommand, about = "Read and change settings")]
    Config(ConfigCommand),
    #[command(about = "Rebuild the local mail cache")]
    RepairCache,
    #[command(subcommand, about = "Run Aster Bridge in the background at sign-in")]
    Service(ServiceCommand),
    #[command(about = "Show version and platform")]
    Version,
}

#[derive(Subcommand, Debug)]
pub enum AppPasswordCommand {
    #[command(about = "Create a password for an email app")]
    Create {
        #[arg(long, help = "Name that helps you recognize the app")]
        label: Option<String>,
    },
    #[command(about = "List app passwords")]
    List,
    #[command(about = "Revoke an app password")]
    Revoke { id: String },
}

#[derive(Subcommand, Debug)]
pub enum OutboxCommand {
    #[command(about = "List messages waiting to send")]
    List,
    #[command(about = "Try sending queued messages again")]
    Retry { id: Option<i64> },
}

#[derive(Subcommand, Debug)]
pub enum SyncCommand {
    #[command(about = "Sync mail now")]
    Now,
}

#[derive(Subcommand, Debug)]
pub enum TlsCommand {
    #[command(about = "Print the certificate SHA-256 fingerprint")]
    Fingerprint,
}

#[derive(Subcommand, Debug)]
pub enum ConfigCommand {
    #[command(about = "Print one setting or all settings")]
    Get { key: Option<String> },
    #[command(about = "Change a setting")]
    Set { key: String, value: String },
}

#[derive(Subcommand, Debug)]
pub enum ServiceCommand {
    #[command(about = "Install and start the background service")]
    Install,
    #[command(about = "Stop and remove the background service")]
    Uninstall,
    #[command(about = "Show the background service state")]
    Status,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn live_and_refresh_conflict() {
        assert!(Cli::try_parse_from(["aster-bridge", "status", "--live", "--refresh"]).is_err());
    }

    #[test]
    fn global_flags_work_after_subcommand() {
        let cli = Cli::try_parse_from(["aster-bridge", "status", "--json", "--data-dir", "x"]).unwrap();
        assert!(cli.global.json);
        assert_eq!(cli.global.data_dir, Some(PathBuf::from("x")));
    }
}
