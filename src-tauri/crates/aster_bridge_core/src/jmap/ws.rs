//
// Aster Communications Inc.
//
// Copyright (c) 2026 Aster Communications Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//
use std::collections::HashSet;
use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::sync::{mpsc, Mutex};

#[derive(Default)]
struct PushFilter {
    configured: bool,
    enabled: bool,
    types: HashSet<String>,
}

use super::auth::AuthedAccount;
use super::dispatcher::{dispatch_request, DispatchError};
use super::server::AppState;
use super::state::snapshot_all_states;

pub async fn ws_upgrade(
    _auth: AuthedAccount,
    State(state): State<AppState>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    if !subprotocol_offered(&headers, "jmap") {
        return (
            StatusCode::BAD_REQUEST,
            "WebSocket subprotocol 'jmap' required (RFC 8887)",
        )
            .into_response();
    }
    ws.protocols(["jmap"])
        .max_message_size(MAX_WS_MESSAGE_BYTES)
        .max_frame_size(MAX_WS_MESSAGE_BYTES)
        .on_upgrade(move |socket| serve(socket, state))
}

const MAX_WS_MESSAGE_BYTES: usize = 10 * 1024 * 1024;

fn subprotocol_offered(headers: &HeaderMap, want: &str) -> bool {
    headers
        .get("sec-websocket-protocol")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(',').any(|p| p.trim().eq_ignore_ascii_case(want)))
        .unwrap_or(false)
}

async fn serve(socket: WebSocket, state: AppState) {
    let (sender, receiver) = socket.split();
    let (out_tx, out_rx) = mpsc::channel::<Message>(64);
    let account_id = state.ctx.account_id().await;
    let push_filter = Arc::new(Mutex::new(PushFilter::default()));

    let send_task = tokio::spawn(send_loop(
        sender,
        out_rx,
        state.clone(),
        account_id.clone(),
        push_filter.clone(),
    ));
    let recv_task = tokio::spawn(recv_loop(receiver, state, account_id, out_tx, push_filter));

    tokio::select! {
        _ = send_task => {},
        _ = recv_task => {},
    }
}

async fn send_loop(
    mut sender: SplitSink<WebSocket, Message>,
    mut out_rx: mpsc::Receiver<Message>,
    state: AppState,
    account_id: String,
    push_filter: Arc<Mutex<PushFilter>>,
) {
    use tokio::sync::broadcast::error::RecvError;
    let mut bcast = state.ctx.broadcaster.subscribe();
    loop {
        tokio::select! {
            Some(msg) = out_rx.recv() => {
                if sender.send(msg).await.is_err() {
                    return;
                }
            }
            ev = bcast.recv() => {
                let changed = match ev {
                    Ok(ch) => ch.changed,
                    Err(RecvError::Lagged(_)) => snapshot_all_states(&state.ctx.db),
                    Err(RecvError::Closed) => return,
                };
                let decision = {
                    let f = push_filter.lock().await;
                    apply_push_filter(&f, changed)
                };
                let Some(changed) = decision else {
                    continue;
                };
                let payload = json!({
                    "@type": "StateChange",
                    "changed": { account_id.clone(): changed },
                });
                if sender
                    .send(Message::Text(payload.to_string()))
                    .await
                    .is_err()
                {
                    return;
                }
            }
            else => return,
        }
    }
}

async fn recv_loop(
    mut receiver: SplitStream<WebSocket>,
    state: AppState,
    account_id: String,
    out_tx: mpsc::Sender<Message>,
    push_filter: Arc<Mutex<PushFilter>>,
) {
    let ctx = state.ctx.clone();

    while let Some(Ok(msg)) = receiver.next().await {
        match msg {
            Message::Text(text) => {
                let Ok(parsed): Result<Value, _> = serde_json::from_str(&text) else {
                    let _ = out_tx
                        .send(Message::Text(
                            json!({"@type":"RequestError","type":"invalidJson"})
                                .to_string(),
                        ))
                        .await;
                    continue;
                };
                let typ = parsed.get("@type").and_then(|v| v.as_str()).unwrap_or("");
                let request_id = parsed
                    .get("id")
                    .and_then(|v| v.as_str())
                    .map(String::from);

                match typ {
                    "Request" | "WebSocketRequest" => {
                        let resp = match dispatch_request(&ctx, parsed.clone()).await {
                            Ok(mut v) => {
                                if let Some(obj) = v.as_object_mut() {
                                    obj.insert("@type".to_string(), json!("Response"));
                                }
                                v
                            }
                            Err(DispatchError::UnknownCapability(cap)) => json!({
                                "@type": "RequestError",
                                "type": "urn:ietf:params:jmap:error:unknownCapability",
                                "detail": format!("unknown capability: {}", cap),
                            }),
                            Err(DispatchError::BadRequest(m)) => json!({
                                "@type": "RequestError",
                                "type": "urn:ietf:params:jmap:error:notRequest",
                                "detail": m,
                            }),
                            Err(DispatchError::TooLarge(m)) => json!({
                                "@type": "RequestError",
                                "type": "urn:ietf:params:jmap:error:limit",
                                "detail": m,
                            }),
                        };
                        let mut envelope = resp;
                        if let Some(id) = request_id {
                            if let Some(obj) = envelope.as_object_mut() {
                                obj.insert("requestId".to_string(), json!(id));
                            }
                        }
                        if out_tx
                            .send(Message::Text(envelope.to_string()))
                            .await
                            .is_err()
                        {
                            return;
                        }
                    }
                    "WebSocketPushEnable" => {
                        let types: HashSet<String> = parsed
                            .get("dataTypes")
                            .and_then(|v| v.as_array())
                            .map(|a| {
                                a.iter()
                                    .filter_map(|x| x.as_str().map(String::from))
                                    .collect()
                            })
                            .unwrap_or_default();
                        {
                            let mut f = push_filter.lock().await;
                            f.configured = true;
                            f.enabled = true;
                            f.types = types.clone();
                        }
                        let mut initial = snapshot_all_states(&ctx.db);
                        if !types.is_empty() {
                            initial.retain(|k, _| types.contains(k));
                        }
                        let payload = json!({
                            "@type": "StateChange",
                            "changed": { account_id.clone(): initial },
                        });
                        let _ = out_tx.send(Message::Text(payload.to_string())).await;
                    }
                    "WebSocketPushDisable" => {
                        let mut f = push_filter.lock().await;
                        f.configured = true;
                        f.enabled = false;
                        f.types.clear();
                    }
                    _ => {
                        let _ = out_tx
                            .send(Message::Text(
                                json!({
                                    "@type": "RequestError",
                                    "type": "urn:ietf:params:jmap:error:notRequest",
                                    "detail": format!("unknown @type: {}", typ),
                                })
                                .to_string(),
                            ))
                            .await;
                    }
                }
            }
            Message::Ping(p) => {
                let _ = out_tx.send(Message::Pong(p)).await;
            }
            Message::Close(_) => return,
            _ => {}
        }
    }
}

fn apply_push_filter(
    filter: &PushFilter,
    mut changed: std::collections::HashMap<String, String>,
) -> Option<std::collections::HashMap<String, String>> {
    if filter.configured && !filter.enabled {
        return None;
    }
    if filter.configured && !filter.types.is_empty() {
        changed.retain(|k, _| filter.types.contains(k));
    }
    if changed.is_empty() {
        None
    } else {
        Some(changed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn changed_email_mailbox() -> HashMap<String, String> {
        let mut m = HashMap::new();
        m.insert("Email".to_string(), "5".to_string());
        m.insert("Mailbox".to_string(), "2".to_string());
        m
    }

    #[test]
    fn unconfigured_filter_passes_everything() {
        let f = PushFilter::default();
        let out = apply_push_filter(&f, changed_email_mailbox()).unwrap();
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn enabled_without_types_passes_everything() {
        let f = PushFilter {
            configured: true,
            enabled: true,
            types: HashSet::new(),
        };
        let out = apply_push_filter(&f, changed_email_mailbox()).unwrap();
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn enabled_with_types_retains_only_subscribed() {
        let f = PushFilter {
            configured: true,
            enabled: true,
            types: ["Email".to_string()].into_iter().collect(),
        };
        let out = apply_push_filter(&f, changed_email_mailbox()).unwrap();
        assert_eq!(out.len(), 1);
        assert!(out.contains_key("Email"));
        assert!(!out.contains_key("Mailbox"));
    }

    #[test]
    fn disabled_drops_all_pushes() {
        let f = PushFilter {
            configured: true,
            enabled: false,
            types: HashSet::new(),
        };
        assert!(apply_push_filter(&f, changed_email_mailbox()).is_none());
    }

    #[test]
    fn filter_removing_everything_yields_none() {
        let f = PushFilter {
            configured: true,
            enabled: true,
            types: ["Thread".to_string()].into_iter().collect(),
        };
        assert!(apply_push_filter(&f, changed_email_mailbox()).is_none());
    }
}
