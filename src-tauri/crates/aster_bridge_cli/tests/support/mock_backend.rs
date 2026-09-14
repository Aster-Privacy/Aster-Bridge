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
use std::sync::atomic::{AtomicU16, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use aster_bridge_core::auth::device_identity::seal_vault_envelope;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde_json::{json, Value};
use uuid::Uuid;

pub const TEST_EMAIL: &str = "tester@astermail.org";
pub const TEST_USERNAME: &str = "tester";
pub const DEVICE_CODE: &str = "WXYZ-2345";
const VAULT_PASSPHRASE: &[u8] = b"mock-vault-passphrase";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodeStatus {
    Confirm,
    Pending,
    Expired,
    Gone,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Plan {
    Allow,
    Deny,
    Fail,
    DenyAfter(usize),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyncMode {
    Empty,
    UpgradeRequired,
}

#[derive(Clone, Debug)]
pub struct CodeRequest {
    pub body: Value,
    pub client_header: Option<String>,
    pub user_agent: Option<String>,
}

struct Inner {
    code_status: Mutex<CodeStatus>,
    plan: Mutex<Plan>,
    sync: Mutex<SyncMode>,
    login_status: AtomicU16,
    expires_in: AtomicU64,
    plan_calls: AtomicUsize,
    sync_calls: AtomicUsize,
    code_requests: Mutex<Vec<CodeRequest>>,
    user_id: Uuid,
    device_id: Uuid,
}

#[derive(Clone)]
pub struct Mock {
    pub base: String,
    inner: Arc<Inner>,
}

impl Mock {
    pub fn start() -> Self {
        let inner = Arc::new(Inner {
            code_status: Mutex::new(CodeStatus::Confirm),
            plan: Mutex::new(Plan::Allow),
            sync: Mutex::new(SyncMode::Empty),
            login_status: AtomicU16::new(200),
            expires_in: AtomicU64::new(600),
            plan_calls: AtomicUsize::new(0),
            sync_calls: AtomicUsize::new(0),
            code_requests: Mutex::new(Vec::new()),
            user_id: Uuid::new_v4(),
            device_id: Uuid::new_v4(),
        });
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let app = router(inner.clone());
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                let _ = axum::serve(listener, app).await;
            });
        });
        Self { base, inner }
    }

    pub fn set_code_status(&self, status: CodeStatus) {
        *self.inner.code_status.lock().unwrap() = status;
    }

    pub fn set_plan(&self, plan: Plan) {
        self.inner.plan_calls.store(0, Ordering::SeqCst);
        *self.inner.plan.lock().unwrap() = plan;
    }

    pub fn set_sync(&self, mode: SyncMode) {
        *self.inner.sync.lock().unwrap() = mode;
    }

    pub fn set_login_status(&self, status: u16) {
        self.inner.login_status.store(status, Ordering::SeqCst);
    }

    pub fn set_expires_in(&self, secs: u64) {
        self.inner.expires_in.store(secs, Ordering::SeqCst);
    }

    pub fn plan_calls(&self) -> usize {
        self.inner.plan_calls.load(Ordering::SeqCst)
    }

    pub fn sync_calls(&self) -> usize {
        self.inner.sync_calls.load(Ordering::SeqCst)
    }

    pub fn code_requests(&self) -> Vec<CodeRequest> {
        self.inner.code_requests.lock().unwrap().clone()
    }

    pub fn user_id(&self) -> Uuid {
        self.inner.user_id
    }
}

fn router(inner: Arc<Inner>) -> Router {
    Router::new()
        .route("/core/v1/auth/device/code", post(device_code))
        .route("/core/v1/auth/device/code/status", get(device_code_status))
        .route("/core/v1/auth/device/challenge", post(device_challenge))
        .route("/core/v1/auth/device/login", post(device_login))
        .route("/core/v1/auth/refresh", post(refresh))
        .route("/core/v1/auth/me", get(profile))
        .route("/core/v1/billing/plan", get(plan))
        .route("/bridge/v1/messages/sync", get(sync))
        .route("/bridge/v1/messages", get(list_mail))
        .route("/mail/v1/drafts", get(list_drafts))
        .route("/addresses/v1/aliases", get(list_aliases))
        .route("/addresses/v1/domains", get(list_domains))
        .fallback(not_found)
        .with_state(inner)
}

fn header(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
}

async fn device_code(
    State(inner): State<Arc<Inner>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Json<Value> {
    inner.code_requests.lock().unwrap().push(CodeRequest {
        body,
        client_header: header(&headers, "x-aster-client"),
        user_agent: header(&headers, "user-agent"),
    });
    Json(json!({
        "code": DEVICE_CODE,
        "expires_in": inner.expires_in.load(Ordering::SeqCst),
    }))
}

async fn device_code_status(State(inner): State<Arc<Inner>>) -> Response {
    let status = *inner.code_status.lock().unwrap();
    match status {
        CodeStatus::Pending => Json(json!({ "status": "pending" })).into_response(),
        CodeStatus::Expired => Json(json!({ "status": "expired" })).into_response(),
        CodeStatus::Gone => (StatusCode::GONE, Json(json!({ "error": "gone" }))).into_response(),
        CodeStatus::Confirm => {
            let Some(request) = inner.code_requests.lock().unwrap().last().cloned() else {
                return not_found().await;
            };
            let mlkem_pk = request.body["mlkem_pk"].as_str().unwrap_or_default().to_string();
            let x25519_pk = request.body["x25519_pk"].as_str().unwrap_or_default().to_string();
            match seal_vault_envelope(&mlkem_pk, &x25519_pk, VAULT_PASSPHRASE) {
                Ok(envelope) => Json(json!({
                    "status": "confirmed",
                    "device_id": inner.device_id,
                    "sealed_envelope": envelope,
                }))
                .into_response(),
                Err(_) => StatusCode::BAD_REQUEST.into_response(),
            }
        }
    }
}

async fn device_challenge() -> Json<Value> {
    Json(json!({
        "challenge_id": Uuid::new_v4(),
        "nonce": URL_SAFE_NO_PAD.encode([1u8; 32]),
        "expires_in": 60,
    }))
}

async fn device_login(State(inner): State<Arc<Inner>>) -> Response {
    let status = inner.login_status.load(Ordering::SeqCst);
    if status != 200 {
        let code = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        return (code, Json(json!({ "error": "device_login_failed" }))).into_response();
    }
    Json(json!({
        "user_id": inner.user_id,
        "username": TEST_USERNAME,
        "email": TEST_EMAIL,
        "access_token": "mock-access-token",
        "refresh_token": "mock-refresh-token",
        "encrypted_vault": "AAAA",
        "vault_nonce": "AAAA",
    }))
    .into_response()
}

async fn refresh() -> Json<Value> {
    Json(json!({
        "access_token": "mock-access-token",
        "refresh_token": "mock-refresh-token",
    }))
}

async fn profile(State(inner): State<Arc<Inner>>) -> Json<Value> {
    Json(json!({
        "user_id": inner.user_id,
        "username": TEST_USERNAME,
        "email": TEST_EMAIL,
        "display_name": "Test User",
    }))
}

async fn plan(State(inner): State<Arc<Inner>>) -> Response {
    let call = inner.plan_calls.fetch_add(1, Ordering::SeqCst) + 1;
    let mode = *inner.plan.lock().unwrap();
    let allowed = match mode {
        Plan::Allow => true,
        Plan::Deny => false,
        Plan::DenyAfter(allowed_calls) => call <= allowed_calls,
        Plan::Fail => {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "unavailable" })))
                .into_response()
        }
    };
    let body = if allowed {
        json!({ "plan_code": "star", "has_bridge_access": true })
    } else {
        json!({ "plan_code": "free", "has_bridge_access": false })
    };
    Json(body).into_response()
}

fn sync_response(inner: &Inner, empty: Value) -> Response {
    inner.sync_calls.fetch_add(1, Ordering::SeqCst);
    let mode = *inner.sync.lock().unwrap();
    match mode {
        SyncMode::Empty => Json(empty).into_response(),
        SyncMode::UpgradeRequired => (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "plan_upgrade_required",
                "message": "Aster Bridge requires a Star plan or higher.",
            })),
        )
            .into_response(),
    }
}

async fn sync(State(inner): State<Arc<Inner>>) -> Response {
    sync_response(&inner, json!({ "items": [] }))
}

async fn list_mail(State(inner): State<Arc<Inner>>) -> Response {
    sync_response(
        &inner,
        json!({ "items": [], "total": 0, "has_more": false, "next_cursor": null }),
    )
}

async fn list_drafts(State(inner): State<Arc<Inner>>) -> Response {
    sync_response(&inner, json!({ "items": [], "has_more": false, "next_cursor": null }))
}

async fn list_aliases() -> Json<Value> {
    Json(json!({ "aliases": [], "total": 0, "has_more": false, "max_aliases": 0 }))
}

async fn list_domains() -> Json<Value> {
    Json(json!({ "domains": [], "total": 0, "max_domains": 0 }))
}

async fn not_found() -> Response {
    (StatusCode::NOT_FOUND, Json(json!({ "error": "not_found" }))).into_response()
}
