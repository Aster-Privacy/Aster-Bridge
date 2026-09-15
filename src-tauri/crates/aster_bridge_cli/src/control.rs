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
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use aster_bridge_core::runtime::LOOPBACK_HOST;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use zeroize::Zeroizing;

use crate::exit::{CliError, CODE_CONTROL_TIMEOUT, CODE_CONTROL_UNREACHABLE, EXIT_ERROR};

const CONTROL_FILE: &str = "control.json";
const MAX_REQUEST_BYTES: u64 = 64 * 1024;
const MAX_RESPONSE_BYTES: u64 = 32 * 1024 * 1024;
const REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const RESPONSE_READ_TIMEOUT: Duration = Duration::from_secs(45);
const LONG_RESPONSE_READ_TIMEOUT: Duration = Duration::from_secs(4 * 60 * 60);
const LONG_RUNNING_OPS: [&str; 3] = ["sync_now", "repair_cache", "outbox_retry"];

fn response_read_timeout(op: &str) -> Duration {
    if LONG_RUNNING_OPS.contains(&op) {
        LONG_RESPONSE_READ_TIMEOUT
    } else {
        RESPONSE_READ_TIMEOUT
    }
}

pub type HandlerFuture = Pin<Box<dyn Future<Output = Result<Value, CliError>> + Send>>;
pub type Handler = Arc<dyn Fn(String, Value) -> HandlerFuture + Send + Sync>;

#[derive(Serialize, Deserialize)]
struct ControlFile {
    port: u16,
    token: String,
    pid: u32,
}

#[derive(Serialize, Deserialize)]
struct Request {
    token: String,
    op: String,
    #[serde(default)]
    args: Value,
}

pub fn control_path(data_dir: &Path) -> PathBuf {
    data_dir.join(CONTROL_FILE)
}

pub struct ControlServer {
    path: PathBuf,
    pid: u32,
    accept_loop: tokio::task::JoinHandle<()>,
}

impl Drop for ControlServer {
    fn drop(&mut self) {
        self.accept_loop.abort();
        let owned = std::fs::read(&self.path)
            .ok()
            .and_then(|b| serde_json::from_slice::<ControlFile>(&b).ok())
            .is_some_and(|f| f.pid == self.pid);
        if owned {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

pub async fn start(data_dir: &Path, handler: Handler) -> std::io::Result<ControlServer> {
    let listener = TcpListener::bind((LOOPBACK_HOST, 0)).await?;
    let port = listener.local_addr()?.port();
    let token = Zeroizing::new(format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    ));
    let pid = std::process::id();
    let path = control_path(data_dir);
    let body = Zeroizing::new(
        serde_json::to_vec(&ControlFile {
            port,
            token: token.to_string(),
            pid,
        })
        .map_err(std::io::Error::other)?,
    );
    crate::state::write_private(&path, &body).map_err(std::io::Error::other)?;
    aster_bridge_core::secrets::restrict_permissions(&path, false);

    let token = Arc::new(token);
    let accept_loop = tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let (token, handler) = (token.clone(), handler.clone());
                    tokio::spawn(async move {
                        let _ = serve_connection(stream, token.as_str(), handler).await;
                    });
                }
                Err(e) => {
                    tracing::debug!("control accept failed: {}", e);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    });
    Ok(ControlServer {
        path,
        pid,
        accept_loop,
    })
}

async fn serve_connection(stream: TcpStream, token: &str, handler: Handler) -> std::io::Result<()> {
    let (read, mut write) = stream.into_split();
    let mut reader = BufReader::new(read.take(MAX_REQUEST_BYTES));
    let mut line = Zeroizing::new(String::new());
    match tokio::time::timeout(REQUEST_READ_TIMEOUT, reader.read_line(&mut line)).await {
        Ok(Ok(n)) if n > 0 => {}
        _ => return Ok(()),
    }
    let response = match serde_json::from_str::<Request>(line.trim()) {
        Ok(request) if constant_time_eq(request.token.as_bytes(), token.as_bytes()) => {
            match handler(request.op, request.args).await {
                Ok(data) => json!({ "ok": true, "data": data }),
                Err(err) => json!({ "ok": false, "error": err.to_json() }),
            }
        }
        Ok(_) => json!({ "ok": false, "error": { "code": "unauthorized", "message": "unauthorized", "exit_code": EXIT_ERROR } }),
        Err(_) => json!({ "ok": false, "error": { "code": "bad_request", "message": "bad request", "exit_code": EXIT_ERROR } }),
    };
    let mut bytes = serde_json::to_vec(&response).map_err(std::io::Error::other)?;
    bytes.push(b'\n');
    write.write_all(&bytes).await?;
    write.shutdown().await
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

pub enum CallError {
    Unreachable,
    TimedOut,
    Remote(CliError),
}

pub struct ControlClient {
    port: u16,
    token: Zeroizing<String>,
    pub pid: u32,
}

impl ControlClient {
    pub fn discover(data_dir: &Path) -> Option<Self> {
        let bytes = Zeroizing::new(std::fs::read(control_path(data_dir)).ok()?);
        let file: ControlFile = serde_json::from_slice(&bytes).ok()?;
        Some(Self {
            port: file.port,
            token: Zeroizing::new(file.token),
            pid: file.pid,
        })
    }

    pub async fn call(&self, op: &str, args: Value) -> Result<Value, CallError> {
        let stream = match tokio::time::timeout(
            CONNECT_TIMEOUT,
            TcpStream::connect((LOOPBACK_HOST, self.port)),
        )
        .await
        {
            Ok(Ok(s)) => s,
            _ => return Err(CallError::Unreachable),
        };
        let (read, mut write) = stream.into_split();
        let request = Request {
            token: self.token.to_string(),
            op: op.to_string(),
            args,
        };
        let mut bytes = Zeroizing::new(serde_json::to_vec(&request).map_err(|_| CallError::Unreachable)?);
        bytes.push(b'\n');
        if write.write_all(&bytes).await.is_err() {
            return Err(CallError::Unreachable);
        }
        let mut reader = BufReader::new(read.take(MAX_RESPONSE_BYTES));
        let mut line = String::new();
        match tokio::time::timeout(response_read_timeout(op), reader.read_line(&mut line)).await {
            Ok(Ok(n)) if n > 0 => {}
            Err(_) => return Err(CallError::TimedOut),
            _ => return Err(CallError::Unreachable),
        }
        let response: Value = serde_json::from_str(line.trim()).map_err(|_| CallError::Unreachable)?;
        if response.get("ok").and_then(Value::as_bool) == Some(true) {
            return Ok(response.get("data").cloned().unwrap_or(Value::Null));
        }
        let error = response.get("error").cloned().unwrap_or(Value::Null);
        if error.get("code").and_then(Value::as_str) == Some("unauthorized") {
            return Err(CallError::Unreachable);
        }
        Err(CallError::Remote(CliError::from_json(&error)))
    }
}

pub async fn running(data_dir: &Path) -> Option<ControlClient> {
    let client = ControlClient::discover(data_dir)?;
    match tokio::time::timeout(Duration::from_secs(3), client.call("ping", Value::Null)).await {
        Ok(Ok(_)) => Some(client),
        _ => None,
    }
}

pub async fn call_running(data_dir: &Path, op: &str, args: Value) -> Result<Option<Value>, CliError> {
    let Some(client) = running(data_dir).await else {
        return Ok(None);
    };
    match client.call(op, args).await {
        Ok(value) => Ok(Some(value)),
        Err(CallError::Remote(err)) => Err(err),
        Err(CallError::TimedOut) => Err(CliError::coded(
            CODE_CONTROL_TIMEOUT,
            "Aster Bridge is taking longer than expected to finish the request.",
        )),
        Err(CallError::Unreachable) => Err(CliError::coded(
            CODE_CONTROL_UNREACHABLE,
            "Aster Bridge stopped responding while handling the request.",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn echo_handler() -> Handler {
        Arc::new(|op, args| {
            Box::pin(async move {
                match op.as_str() {
                    "ping" => Ok(json!({ "pong": true })),
                    "echo" => Ok(args),
                    _ => Err(CliError::usage("unknown operation")),
                }
            })
        })
    }

    #[tokio::test]
    async fn authenticated_calls_reach_the_handler() {
        let dir = tempfile::tempdir().unwrap();
        let _server = start(dir.path(), echo_handler()).await.unwrap();
        let client = running(dir.path()).await.expect("server should answer ping");
        match client.call("echo", json!({ "value": 7 })).await {
            Ok(v) => assert_eq!(v["value"], 7),
            Err(_) => panic!("echo failed"),
        }
        match client.call("nope", Value::Null).await {
            Err(CallError::Remote(e)) => assert_eq!(e.exit_code, crate::exit::EXIT_USAGE),
            _ => panic!("expected a remote error"),
        }
    }

    #[tokio::test]
    async fn slow_operations_get_a_longer_deadline() {
        assert_eq!(response_read_timeout("status"), RESPONSE_READ_TIMEOUT);
        assert!(LONG_RESPONSE_READ_TIMEOUT > RESPONSE_READ_TIMEOUT);
        assert_eq!(response_read_timeout("sync_now"), LONG_RESPONSE_READ_TIMEOUT);
        assert_eq!(response_read_timeout("repair_cache"), LONG_RESPONSE_READ_TIMEOUT);
        assert_eq!(response_read_timeout("outbox_retry"), LONG_RESPONSE_READ_TIMEOUT);
    }

    #[tokio::test]
    async fn wrong_token_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let _server = start(dir.path(), echo_handler()).await.unwrap();
        let mut client = ControlClient::discover(dir.path()).unwrap();
        client.token = Zeroizing::new("0".repeat(64));
        assert!(matches!(
            client.call("ping", Value::Null).await,
            Err(CallError::Unreachable)
        ));
    }

    #[tokio::test]
    async fn control_file_is_removed_when_server_drops() {
        let dir = tempfile::tempdir().unwrap();
        let server = start(dir.path(), echo_handler()).await.unwrap();
        assert!(control_path(dir.path()).exists());
        drop(server);
        assert!(!control_path(dir.path()).exists());
    }

    #[test]
    fn constant_time_eq_compares_lengths_and_bytes() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
    }
}
