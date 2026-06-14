//
// Aster Communications Inc.
//
// Copyright (c) 2026 Aster Communications Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use axum::extract::FromRequestParts;
use axum::http::{header, request::Parts, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use tokio::sync::RwLock;

use crate::auth::app_passwords::AppPasswords;
use crate::auth::session::Session;

const AUTH_FAIL_WINDOW: Duration = Duration::from_secs(60);
const AUTH_FAIL_FREE: u32 = 5;
const AUTH_FAIL_STEP_MS: u64 = 200;
const AUTH_FAIL_MAX_STEPS: u32 = 20;

fn auth_throttle() -> &'static Mutex<(u32, Instant)> {
    static STATE: OnceLock<Mutex<(u32, Instant)>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new((0, Instant::now())))
}

async fn register_auth_failure() {
    let delay = {
        let mut guard = auth_throttle().lock().unwrap();
        let (count, start) = &mut *guard;
        if start.elapsed() > AUTH_FAIL_WINDOW {
            *count = 0;
            *start = Instant::now();
        }
        *count = count.saturating_add(1);
        if *count > AUTH_FAIL_FREE {
            let steps = (*count - AUTH_FAIL_FREE).min(AUTH_FAIL_MAX_STEPS) as u64;
            Some(Duration::from_millis(AUTH_FAIL_STEP_MS * steps))
        } else {
            None
        }
    };
    if let Some(d) = delay {
        tokio::time::sleep(d).await;
    }
}

fn register_auth_success() {
    let mut guard = auth_throttle().lock().unwrap();
    *guard = (0, Instant::now());
}

pub struct AuthedAccount {
    pub email: String,
}

pub struct JmapAuth {
    pub passwords: Arc<AppPasswords>,
    pub session: Arc<RwLock<Session>>,
}

#[axum::async_trait]
impl<S> FromRequestParts<S> for AuthedAccount
where
    S: Send + Sync,
    Arc<JmapAuth>: axum::extract::FromRef<S>,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let auth_state: Arc<JmapAuth> = axum::extract::FromRef::from_ref(state);
        let header_value = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let Some(value) = header_value else {
            return Err(unauthorized());
        };

        let Some(b64) = value.strip_prefix("Basic ") else {
            return Err(unauthorized());
        };

        let decoded = base64::engine::general_purpose::STANDARD
            .decode(b64.trim())
            .map_err(|_| unauthorized())?;
        let decoded_str = String::from_utf8(decoded).map_err(|_| unauthorized())?;
        let (user, pass) = decoded_str
            .split_once(':')
            .ok_or_else(unauthorized)?;

        let expected_email = auth_state.session.read().await.email.clone();
        if expected_email.is_empty() || !user.eq_ignore_ascii_case(&expected_email) {
            register_auth_failure().await;
            return Err(unauthorized());
        }

        let password_id = match auth_state.passwords.verify_and_id_async(pass).await {
            Some(id) => id,
            None => {
                register_auth_failure().await;
                return Err(unauthorized());
            }
        };
        register_auth_success();

        let user_agent = parts
            .headers
            .get(header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        auth_state
            .passwords
            .record_use(&password_id, user_agent.as_deref());

        Ok(AuthedAccount {
            email: expected_email,
        })
    }
}

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, r#"Basic realm="Aster Bridge""#)],
        "unauthorized",
    )
        .into_response()
}
