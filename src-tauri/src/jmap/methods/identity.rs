//
// Aster Communications Inc.
//
// Copyright (c) 2026 Aster Communications Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//
use std::sync::Arc;

use serde_json::{json, Value};

use crate::jmap::dispatcher::MethodError;
use crate::jmap::state::JmapContext;

pub async fn get(ctx: &Arc<JmapContext>, args: Value) -> Result<Value, MethodError> {
    let account_id = ctx.require_account(&args).await?;
    let email = ctx.email().await;
    let name = email.split('@').next().unwrap_or(&email).to_string();
    let id = format!("identity-{}", account_id);
    let identity = json!({
        "id": id,
        "name": name,
        "email": email,
        "replyTo": null,
        "bcc": null,
        "textSignature": "",
        "htmlSignature": "",
        "mayDelete": false
    });
    let state = ctx.db.jmap_state_get("Identity").unwrap_or(0);
    Ok(json!({
        "accountId": account_id,
        "state": state.to_string(),
        "list": [identity],
        "notFound": []
    }))
}
