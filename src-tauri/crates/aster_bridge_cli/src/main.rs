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
mod cli;
mod commands;
mod context;
mod control;
mod events;
mod exit;
mod lock;
mod output;
mod secret_backend;
mod signals;
mod state;

use std::time::Duration;

use clap::error::ErrorKind;
use clap::Parser;

fn main() {
    std::process::exit(run());
}

fn run() -> i32 {
    let cli = match cli::Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            let code = match error.kind() {
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => exit::EXIT_OK,
                _ => exit::EXIT_USAGE,
            };
            let _ = error.print();
            return code;
        }
    };
    let out = output::Output::new(cli.global.json);
    let runtime = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(runtime) => runtime,
        Err(e) => {
            out.error(&exit::CliError::general(format!(
                "Aster Bridge couldn't start: {}",
                e
            )));
            return exit::EXIT_ERROR;
        }
    };
    let result = runtime.block_on(commands::dispatch(cli, out));
    runtime.shutdown_timeout(Duration::from_secs(1));
    match result {
        Ok(code) => code,
        Err(error) => {
            out.error(&error);
            error.exit_code
        }
    }
}
