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
use std::time::Duration;

use serde_json::Value;

use crate::context::Context;
use crate::control;
use crate::exit::{CliError, CliResult, EXIT_OK};
use crate::lock::InstanceLock;
use crate::output::Tone;
use crate::spinner;

const STOP_WAIT: Duration = Duration::from_secs(30);

pub async fn run(ctx: &Context) -> CliResult<i32> {
    let dir = &ctx.data_dir;
    let out = &ctx.out;
    let Some(client) = control::running(dir).await else {
        return Err(CliError::not_running());
    };
    let pid = client.pid;
    let stopped = spinner::while_working(out, out.json, "Stopping Aster Bridge", async move {
        let _ = client.call("stop", Value::Null).await;
        InstanceLock::acquire_within(dir, STOP_WAIT).await
    })
    .await;
    stopped.map(drop)?;
    if out.json {
        out.json(serde_json::json!({ "stopped": true, "pid": pid }));
        return Ok(EXIT_OK);
    }
    out.line(format!(
        "{} Stopped Aster Bridge. Email apps on this computer can't reach your mailbox until you start it again.",
        out.mark(Tone::Good)
    ));
    Ok(EXIT_OK)
}
