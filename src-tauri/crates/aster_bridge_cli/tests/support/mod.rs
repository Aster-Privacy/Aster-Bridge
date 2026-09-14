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
#![allow(dead_code)]

pub mod mock_backend;

use std::io::{BufRead, BufReader, Read};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aster_bridge_core::config::{save_config, BridgeConfig};
use serde_json::Value;
use tempfile::TempDir;

use mock_backend::Mock;

pub const COMMAND_TIMEOUT: Duration = Duration::from_secs(60);
pub const READY_TIMEOUT: Duration = Duration::from_secs(90);
pub const STOP_TIMEOUT: Duration = Duration::from_secs(45);

pub struct Run {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl Run {
    pub fn json(&self) -> Value {
        let line = self
            .stdout
            .lines()
            .rev()
            .find(|line| !line.trim().is_empty())
            .unwrap_or_else(|| panic!("no JSON on stdout\nstderr: {}", self.stderr));
        let value: Value = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("stdout is not JSON ({}): {}\nstderr: {}", e, line, self.stderr));
        assert_eq!(value["schema"], 1, "missing schema in {}", line);
        value
    }

    pub fn error_code(&self) -> String {
        self.json()["error"]["code"].as_str().unwrap_or_default().to_string()
    }

    pub fn expect(&self, code: i32) -> &Self {
        assert_eq!(
            self.code, code,
            "unexpected exit code\nstdout: {}\nstderr: {}",
            self.stdout, self.stderr
        );
        self
    }
}

pub struct Env {
    pub mock: Mock,
    pub data: PathBuf,
    key_file: PathBuf,
    _root: TempDir,
}

impl Env {
    pub fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("data");
        std::fs::create_dir_all(&data).unwrap();
        let key_file = root.path().join("secret.key");
        let key = format!(
            "{}{}",
            uuid::Uuid::new_v4().simple(),
            uuid::Uuid::new_v4().simple()
        );
        std::fs::write(&key_file, key).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        write_config(&data);
        Self {
            mock: Mock::start(),
            data,
            key_file,
            _root: root,
        }
    }

    pub fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_aster-bridge"));
        for (name, _) in std::env::vars_os() {
            if name.to_string_lossy().starts_with("ASTER_BRIDGE_") {
                command.env_remove(name);
            }
        }
        command
            .args(args)
            .current_dir(self._root.path())
            .env_remove("CREDENTIALS_DIRECTORY")
            .env("NO_COLOR", "1")
            .env("ASTER_BRIDGE_DATA_DIR", &self.data)
            .env("ASTER_BRIDGE_SECRET_BACKEND", "file")
            .env("ASTER_BRIDGE_SECRET_KEY_FILE", &self.key_file)
            .env("ASTER_BRIDGE_TEST_API_BASE", &self.mock.base)
            .env("ASTER_BRIDGE_TEST_LOGIN_POLL_MS", "50")
            .env("ASTER_BRIDGE_TEST_PLAN_RETRY_MS", "10")
            .env("ASTER_BRIDGE_TEST_POLL_MS", "200")
            .env("ASTER_BRIDGE_TEST_PLAN_EVERY", "2")
            .env("ASTER_BRIDGE_TEST_DRAIN_MS", "500")
            .env("ASTER_BRIDGE_TEST_SERVICE_DELAY_MS", "50")
            .env("ASTER_BRIDGE_TEST_SERVICE_RETRY_MS", "100")
            .stdin(Stdio::null());
        command
    }

    pub fn run(&self, args: &[&str]) -> Run {
        let mut child = self
            .command(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stdout = collect(child.stdout.take().unwrap());
        let stderr = collect(child.stderr.take().unwrap());
        let deadline = Instant::now() + COMMAND_TIMEOUT;
        let code = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status.code().unwrap_or(-1);
            }
            if Instant::now() > deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("aster-bridge {:?} timed out", args);
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        Run {
            code,
            stdout: stdout.join().unwrap(),
            stderr: stderr.join().unwrap(),
        }
    }

    pub fn json(&self, args: &[&str]) -> Run {
        let mut full = vec!["--json"];
        full.extend_from_slice(args);
        self.run(&full)
    }

    pub fn login(&self) {
        let run = self.json(&["login"]);
        run.expect(0);
        assert_eq!(run.json()["status"], "signed_in");
    }

    pub fn serve(&self, args: &[&str]) -> Serve {
        let mut full = vec!["--json", "serve"];
        full.extend_from_slice(args);
        let mut child = self
            .command(&full)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let (sender, lines) = mpsc::channel();
        let stdout = child.stdout.take().unwrap();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if sender.send(line).is_err() {
                    break;
                }
            }
        });
        let stderr = Arc::new(Mutex::new(String::new()));
        let sink = stderr.clone();
        let mut pipe = child.stderr.take().unwrap();
        std::thread::spawn(move || {
            let mut buffer = [0u8; 4096];
            while let Ok(read) = pipe.read(&mut buffer) {
                if read == 0 {
                    break;
                }
                sink.lock()
                    .unwrap()
                    .push_str(&String::from_utf8_lossy(&buffer[..read]));
            }
        });
        Serve {
            child,
            lines,
            stderr,
            seen: Vec::new(),
            code: None,
        }
    }

    pub fn config_port(&self, key: &str) -> u16 {
        let text = std::fs::read_to_string(self.data.join("config.toml")).unwrap();
        text.lines()
            .find_map(|line| {
                let (name, value) = line.split_once('=')?;
                (name.trim() == key).then(|| value.trim().parse().ok()).flatten()
            })
            .unwrap_or_else(|| panic!("{} missing from config.toml", key))
    }

    pub fn log_text(&self) -> String {
        let mut text = String::new();
        let Ok(entries) = std::fs::read_dir(self.data.join("logs")) else {
            return text;
        };
        for entry in entries.flatten() {
            if let Ok(content) = std::fs::read_to_string(entry.path()) {
                text.push_str(&content);
            }
        }
        text
    }
}

fn collect<R: Read + Send + 'static>(mut reader: R) -> std::thread::JoinHandle<String> {
    std::thread::spawn(move || {
        let mut text = String::new();
        let _ = reader.read_to_string(&mut text);
        text
    })
}

fn write_config(data: &Path) {
    let listeners: Vec<TcpListener> = (0..8)
        .map(|_| TcpListener::bind("127.0.0.1:0").unwrap())
        .collect();
    let ports: Vec<u16> = listeners
        .iter()
        .map(|l| l.local_addr().unwrap().port())
        .collect();
    let config = BridgeConfig {
        imap_port: ports[0],
        smtp_port: ports[1],
        imap_implicit_tls_port: ports[2],
        smtp_implicit_tls_port: ports[3],
        jmap_port: ports[4],
        pop3_port: ports[5],
        pop3s_port: ports[6],
        carddav_port: ports[7],
        data_dir: data.to_path_buf(),
        ..BridgeConfig::default()
    };
    drop(listeners);
    save_config(&config).unwrap();
}

pub fn port_open(port: u16) -> bool {
    let addr: SocketAddr = ([127, 0, 0, 1], port).into();
    TcpStream::connect_timeout(&addr, Duration::from_millis(500)).is_ok()
}

pub fn wait_until(timeout: Duration, mut check: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if check() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    check()
}

pub struct Serve {
    child: Child,
    lines: Receiver<String>,
    stderr: Arc<Mutex<String>>,
    pub seen: Vec<Value>,
    code: Option<i32>,
}

impl Serve {
    fn context(&self) -> String {
        format!(
            "stdout: {:?}\nstderr: {}",
            self.seen,
            self.stderr.lock().unwrap()
        )
    }

    fn record(&mut self, line: &str) -> Option<Value> {
        let value: Value = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("serve printed a line that isn't JSON ({}): {}", e, line));
        assert_eq!(value["schema"], 1, "missing schema in {}", line);
        self.seen.push(value.clone());
        Some(value)
    }

    pub fn wait_event(&mut self, name: &str, timeout: Duration) -> Value {
        let deadline = Instant::now() + timeout;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.lines.recv_timeout(left) {
                Ok(line) => {
                    let Some(value) = self.record(&line) else { continue };
                    if value["event"] == name {
                        return value;
                    }
                    if value.get("error").is_some() {
                        panic!("serve failed before {}: {}\n{}", name, value, self.context());
                    }
                }
                Err(RecvTimeoutError::Timeout) => {
                    panic!("no {} event within {:?}\n{}", name, timeout, self.context())
                }
                Err(RecvTimeoutError::Disconnected) => {
                    panic!("serve exited before {}\n{}", name, self.context())
                }
            }
        }
    }

    pub fn wait_exit(&mut self, timeout: Duration) -> i32 {
        if let Some(code) = self.code {
            return code;
        }
        let deadline = Instant::now() + timeout;
        let code = loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                break status.code().unwrap_or(-1);
            }
            if Instant::now() > deadline {
                panic!("serve still running after {:?}\n{}", timeout, self.context());
            }
            std::thread::sleep(Duration::from_millis(50));
        };
        while let Ok(line) = self.lines.recv_timeout(Duration::from_secs(2)) {
            self.record(&line);
        }
        self.code = Some(code);
        code
    }

    pub fn error_code(&self) -> String {
        self.seen
            .iter()
            .find_map(|v| v["error"]["code"].as_str().map(str::to_string))
            .unwrap_or_default()
    }

    pub fn expect_exit(&mut self, code: i32, error: Option<&str>) {
        let actual = self.wait_exit(STOP_TIMEOUT);
        assert_eq!(actual, code, "unexpected serve exit code\n{}", self.context());
        if let Some(error) = error {
            assert_eq!(self.error_code(), error, "unexpected error\n{}", self.context());
        }
    }
}

impl Drop for Serve {
    fn drop(&mut self) {
        if self.code.is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}
