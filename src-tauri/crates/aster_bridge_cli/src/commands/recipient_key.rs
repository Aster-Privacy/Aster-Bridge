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
use aster_bridge_core::crypto::recipient_trust::RECIPIENT_TRUST_PROTOCOL;
use serde_json::{json, Value};

use super::common;
use crate::cli::RecipientKeyCommand;
use crate::context::Context;
use crate::control;
use crate::exit::{CliResult, EXIT_OK};
use crate::output::Tone;

pub async fn run(ctx: &Context, command: RecipientKeyCommand) -> CliResult<i32> {
    common::require_account(&ctx.data_dir)?;
    match command {
        RecipientKeyCommand::Show { address } => show(ctx, address).await,
        RecipientKeyCommand::Accept { address, fingerprint } => accept(ctx, address, fingerprint).await,
    }
}

async fn call(ctx: &Context, address: String, fingerprint: Option<String>) -> CliResult<Value> {
    let running = match &fingerprint {
        Some(fingerprint) => {
            control::call_running_recipient_trust(
                &ctx.data_dir,
                "recipient_key_accept_v2",
                json!({ "address": address, "fingerprint": fingerprint }),
                RECIPIENT_TRUST_PROTOCOL,
            )
            .await?
        }
        None => {
            control::call_running(&ctx.data_dir, "recipient_key_show", json!({ "address": address }))
                .await?
        }
    };
    if let Some(value) = running {
        return Ok(value);
    }
    let offline = common::open_offline(ctx)?;
    let (client, session) = common::sign_in_offline(ctx).await?;
    match fingerprint {
        Some(fingerprint) => {
            common::recipient_key_accept(
                &offline.db,
                &offline.state,
                &client,
                &session.access_token,
                &session.username,
                &address,
                &fingerprint,
            )
            .await
        }
        None => {
            common::recipient_key_show(&client, &session.access_token, &session.username, &address)
                .await
        }
    }
}

async fn show(ctx: &Context, address: String) -> CliResult<i32> {
    let out = &ctx.out;
    let address = common::recipient_address(&address)?;
    let result = call(ctx, address, None).await?;
    if out.json {
        out.json(result);
        return Ok(EXIT_OK);
    }
    let address = result["address"].as_str().unwrap_or_default();
    let fingerprint = result["fingerprint"].as_str().unwrap_or_default();
    out.banner(Tone::Accent, &format!("Key for {}", address));
    out.fields(&[("Fingerprint", fingerprint.to_string())]);
    out.line(out.dim(&format!(
        "Confirm this fingerprint with the recipient in person or by phone. To accept this key, run: aster-bridge recipient-key accept {} --fingerprint {}",
        address,
        fingerprint.replace(' ', "")
    )));
    Ok(EXIT_OK)
}

async fn accept(ctx: &Context, address: String, fingerprint: String) -> CliResult<i32> {
    let out = &ctx.out;
    let address = common::recipient_address(&address)?;
    let result = call(ctx, address, Some(fingerprint)).await?;
    if out.json {
        out.json(result);
        return Ok(EXIT_OK);
    }
    let address = result["address"].as_str().unwrap_or_default();
    let fingerprint = result["fingerprint"].as_str().unwrap_or_default();
    out.banner(Tone::Good, &format!("Accepted the key for {}", address));
    out.fields(&[("Fingerprint", fingerprint.to_string())]);
    out.line(out.dim(
        "Aster Bridge now sends to this recipient only while they publish the key with this fingerprint.",
    ));
    Ok(EXIT_OK)
}
