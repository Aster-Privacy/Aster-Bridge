//
// Aster Communications Inc.
//
// Copyright (c) 2026 Aster Communications Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//
use std::convert::Infallible;
use std::time::Duration;

use axum::extract::{Query, State};
use axum::response::sse::{Event, KeepAlive, Sse};
use futures_util::stream::Stream;
use serde::Deserialize;
use serde_json::json;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;

use super::auth::AuthedAccount;
use super::server::AppState;
use super::state::snapshot_all_states;

#[derive(Deserialize)]
pub struct SseParams {
    #[serde(default)]
    pub types: String,
    #[serde(default)]
    pub closeafter: String,
    #[serde(default)]
    pub ping: Option<u64>,
}

pub async fn eventsource(
    _auth: AuthedAccount,
    State(state): State<AppState>,
    Query(params): Query<SseParams>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let account_id = state.ctx.account_id().await;
    let initial = snapshot_all_states(&state.ctx.db);
    let initial_event = Event::default().event("state").data(
        json!({
            "@type": "StateChange",
            "changed": { account_id.clone(): initial },
        })
        .to_string(),
    );

    let rx = state.ctx.broadcaster.subscribe();
    let close_after_first = params.closeafter == "state";
    let db = state.ctx.db.clone();
    let acct = account_id.clone();

    let live = BroadcastStream::new(rx).map(move |msg| {
        let changed = match msg {
            Ok(ch) => ch.changed,
            Err(_) => snapshot_all_states(&db),
        };
        Event::default().event("state").data(
            json!({
                "@type": "StateChange",
                "changed": { acct.clone(): changed },
            })
            .to_string(),
        )
    });

    let stream = async_stream::stream! {
        yield Ok::<_, Infallible>(initial_event);
        if close_after_first {
            return;
        }
        let mut live = Box::pin(live);
        while let Some(ev) = live.next().await {
            yield Ok::<_, Infallible>(ev);
        }
    };

    let ping_secs = params.ping.unwrap_or(30).clamp(5, 300);
    let keepalive = KeepAlive::new()
        .interval(Duration::from_secs(ping_secs))
        .text("ping");

    Sse::new(stream).keep_alive(keepalive)
}
