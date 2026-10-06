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
use serde_json::json;

use super::common;
use crate::cli::RecipientKeyCommand;
use crate::context::Context;
use crate::exit::{CliResult, EXIT_OK};
use crate::output::Tone;

pub async fn run(ctx: &Context, command: RecipientKeyCommand) -> CliResult<i32> {
    common::require_account(&ctx.data_dir)?;
    match command {
        RecipientKeyCommand::Accept { address } => accept(ctx, address).await,
    }
}

async fn accept(ctx: &Context, address: String) -> CliResult<i32> {
    let out = &ctx.out;
    let requested = address.clone();
    let result = common::call_or_offline(
        ctx,
        "recipient_key_accept",
        json!({ "address": address }),
        move |offline| common::recipient_key_accept(&offline.db, &offline.state, &requested),
    )
    .await?;
    if out.json {
        out.json(result);
        return Ok(EXIT_OK);
    }
    let address = result["address"].as_str().unwrap_or_default();
    if result["accepted"].as_bool() == Some(true) {
        out.banner(Tone::Good, &format!("Accepted the new key for {}", address));
        out.line(out.dim(
            "Aster Bridge saves the key that this recipient publishes the next time you send to them.",
        ));
    } else {
        out.banner(Tone::Good, &format!("No saved key for {}", address));
        out.line(out.dim("There is nothing to accept, so you can send to this recipient now."));
    }
    Ok(EXIT_OK)
}
