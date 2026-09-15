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
pub mod app_password;
pub mod common;
pub mod login;
pub mod logout;
pub mod misc;
pub mod outbox;
pub mod serve;
pub mod service;
pub mod status;

use crate::cli::{Cli, Command, SyncCommand, TlsCommand};
use crate::context::{self, Context};
use crate::exit::CliResult;
use crate::output::Output;

pub async fn dispatch(cli: Cli, out: Output) -> CliResult<i32> {
    let Cli { global, command } = cli;
    if matches!(command, Command::Version) {
        return misc::version(&out);
    }
    if let Command::Errors { code } = &command {
        return misc::errors(&out, code.as_deref());
    }
    let ctx = Context::new(global, out)?;
    let _log = match command {
        Command::Serve { .. } => None,
        _ => Some(context::init_logging(&ctx, false)),
    };
    match command {
        Command::Login { no_wait } => login::run(&ctx, no_wait).await,
        Command::Logout { keep_cache } => logout::run(&ctx, keep_cache).await,
        Command::Serve {
            json_events,
            service,
        } => serve::run(&ctx, json_events, service).await,
        Command::Status { refresh, live } => status::run(&ctx, refresh, live).await,
        Command::AppPassword(command) => app_password::run(&ctx, command).await,
        Command::Outbox(command) => outbox::run(&ctx, command).await,
        Command::Sync(SyncCommand::Now) => misc::sync_now(&ctx).await,
        Command::Tls(TlsCommand::Fingerprint) => misc::tls_fingerprint(&ctx),
        Command::Config(command) => misc::config(&ctx, command).await,
        Command::RepairCache => misc::repair_cache(&ctx).await,
        Command::Service(command) => service::run(&ctx, command).await,
        Command::Errors { code } => misc::errors(&ctx.out, code.as_deref()),
        Command::Version => misc::version(&ctx.out),
    }
}
