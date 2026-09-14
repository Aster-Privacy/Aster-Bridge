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
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use serde_json::{json, Value};

use super::common;
use crate::cli::ServiceCommand;
use crate::context::Context;
use crate::control;
use crate::exit::{CliError, CliResult, EXIT_NOT_READY, EXIT_OK};
use crate::lock::InstanceLock;
use crate::output::Tone;
use crate::secret_backend;

const STOP_WAIT: Duration = Duration::from_secs(30);
const START_WAIT: Duration = Duration::from_secs(15);

pub struct Spec {
    pub exe: PathBuf,
    pub data_dir: PathBuf,
    #[cfg_attr(windows, allow(dead_code))]
    pub key_file: Option<PathBuf>,
}

impl Spec {
    fn args(&self) -> Vec<String> {
        vec![
            self.exe.display().to_string(),
            "serve".to_string(),
            "--service".to_string(),
            "--data-dir".to_string(),
            self.data_dir.display().to_string(),
        ]
    }
}

pub async fn run(ctx: &Context, command: ServiceCommand) -> CliResult<i32> {
    match command {
        ServiceCommand::Install => install(ctx).await,
        ServiceCommand::Uninstall => uninstall(ctx).await,
        ServiceCommand::Status => status(ctx).await,
    }
}

pub fn is_installed(data_dir: &Path) -> bool {
    platform::exists(data_dir)
}

fn current_exe() -> CliResult<PathBuf> {
    let exe = std::env::current_exe()
        .map_err(|e| CliError::general(format!("Couldn't find the aster-bridge program: {}", e)))?;
    let text = exe.display().to_string();
    Ok(match text.strip_prefix(r"\\?\") {
        Some(stripped) if !stripped.starts_with("UNC\\") => PathBuf::from(stripped),
        _ => exe,
    })
}

fn key_file_for_service(data_dir: &Path) -> CliResult<Option<PathBuf>> {
    if secret_backend::recorded_name(data_dir) != Some("file") {
        return Ok(None);
    }
    if cfg!(windows) {
        return Err(CliError::secret_store(
            "The background service on Windows needs keys stored in Windows Credential Manager, but this data folder uses a secret key file.",
        )
        .with_hint("To run with a key file, start Aster Bridge with: aster-bridge serve"));
    }
    let path = secret_backend::key_file_path().ok_or_else(|| {
        CliError::secret_store("This data folder uses a secret key file, but ASTER_BRIDGE_SECRET_KEY_FILE isn't set.")
            .with_hint("Set ASTER_BRIDGE_SECRET_KEY_FILE to the key file and run the command again.")
    })?;
    let path = std::path::absolute(&path)
        .map_err(|e| CliError::secret_store(format!("The key file path isn't valid: {}", e)))?;
    Ok(Some(path))
}

async fn stop_running(ctx: &Context) -> CliResult<()> {
    let dir = &ctx.data_dir;
    if let Some(client) = control::running(dir).await {
        if !ctx.out.json {
            ctx.out.line("Stopping Aster Bridge...");
        }
        let _ = client.call("stop", Value::Null).await;
        drop(InstanceLock::acquire_within(dir, STOP_WAIT).await?);
    }
    Ok(())
}

async fn wait_for_start(data_dir: &Path) -> Option<u32> {
    let deadline = tokio::time::Instant::now() + START_WAIT;
    loop {
        if let Some(client) = control::running(data_dir).await {
            return Some(client.pid);
        }
        if tokio::time::Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

async fn install(ctx: &Context) -> CliResult<i32> {
    let dir = &ctx.data_dir;
    let out = &ctx.out;
    platform::supported()?;
    let state = common::require_account(dir)?;
    common::ensure_plan_allows_bridge(&state)?;
    let key_file = key_file_for_service(dir)?;

    let installed = platform::exists(dir);
    if control::running(dir).await.is_some() {
        if !installed {
            return Err(CliError::locked("Aster Bridge is already running in this data folder.")
                .with_hint("To install the background service, stop that copy first, then run the command again."));
        }
        stop_running(ctx).await?;
    } else {
        drop(InstanceLock::acquire(dir)?);
    }

    let spec = Spec {
        exe: current_exe()?,
        data_dir: dir.clone(),
        key_file,
    };
    platform::install(&spec)?;
    let pid = wait_for_start(dir).await;

    if out.json {
        out.json(json!({
            "installed": true,
            "manager": platform::MANAGER,
            "location": platform::location(dir),
            "running": pid.is_some(),
            "pid": pid,
        }));
        return Ok(EXIT_OK);
    }
    out.line(format!(
        "{} Installed the background service. Aster Bridge starts when you sign in to this computer.",
        out.dot(Tone::Good)
    ));
    out.fields(&[
        ("Manager", platform::MANAGER.to_string()),
        ("Location", platform::location(dir)),
    ]);
    out.blank();
    match pid {
        Some(pid) => out.line(format!("Aster Bridge is running as process {}.", pid)),
        None => {
            out.warn("The service is still starting. To check on it, run: aster-bridge service status");
        }
    }
    if let Some(hint) = platform::extra_hint() {
        out.line(hint);
    }
    Ok(EXIT_OK)
}

async fn uninstall(ctx: &Context) -> CliResult<i32> {
    let dir = &ctx.data_dir;
    let out = &ctx.out;
    platform::supported()?;
    if !platform::exists(dir) {
        if out.json {
            out.json(json!({ "installed": false, "removed": false }));
        } else {
            out.line("The background service isn't installed for this data folder.");
        }
        return Ok(EXIT_OK);
    }
    platform::before_uninstall(dir);
    stop_running(ctx).await?;
    platform::uninstall(dir)?;
    if out.json {
        out.json(json!({ "installed": false, "removed": true }));
    } else {
        out.line(format!(
            "{} Removed the background service. Aster Bridge no longer starts on its own.",
            out.dot(Tone::Muted)
        ));
    }
    Ok(EXIT_OK)
}

async fn status(ctx: &Context) -> CliResult<i32> {
    let dir = &ctx.data_dir;
    let out = &ctx.out;
    let installed = platform::exists(dir);
    let manager_state = if installed { platform::state(dir) } else { None };
    let pid = control::running(dir).await.map(|client| client.pid);
    let running = pid.is_some();
    let code = if installed && running { EXIT_OK } else { EXIT_NOT_READY };

    if out.json {
        out.json(json!({
            "installed": installed,
            "manager": platform::MANAGER,
            "location": platform::location(dir),
            "state": manager_state,
            "running": running,
            "pid": pid,
        }));
        return Ok(code);
    }
    if !installed {
        out.line(format!("{} {}", out.dot(Tone::Muted), out.bold("Not installed")));
        out.blank();
        out.line("To start Aster Bridge when you sign in to this computer, run: aster-bridge service install");
        return Ok(code);
    }
    let (tone, label) = if running {
        (Tone::Good, "Running")
    } else {
        (Tone::Warn, "Installed, not running")
    };
    out.line(format!("{} {}", out.dot(tone), out.bold(label)));
    let mut rows = vec![
        ("Manager", platform::MANAGER.to_string()),
        ("Location", platform::location(dir)),
    ];
    if let Some(state) = manager_state {
        rows.push(("Manager state", state));
    }
    if let Some(pid) = pid {
        rows.push(("Process", pid.to_string()));
    }
    out.fields(&rows);
    if !running {
        out.blank();
        out.line("To see why it stopped, run: aster-bridge status");
    }
    Ok(code)
}

#[allow(dead_code)]
fn run_tool(program: &str, args: &[&str]) -> CliResult<String> {
    let output = tool_command(program, args)
        .output()
        .map_err(|e| CliError::general(format!("Couldn't run {}: {}", program, e)))?;
    if output.status.success() {
        return Ok(String::from_utf8_lossy(&output.stdout).into_owned());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let detail = if stderr.trim().is_empty() { stdout.trim() } else { stderr.trim() };
    Err(CliError::general(format!(
        "{} {} failed: {}",
        program,
        args.first().copied().unwrap_or_default(),
        detail
    )))
}

#[allow(dead_code)]
fn probe_tool(program: &str, args: &[&str]) -> Option<(bool, String)> {
    let output = tool_command(program, args).output().ok()?;
    Some((
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
    ))
}

fn tool_command(program: &str, args: &[&str]) -> Command {
    let mut command = Command::new(program);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000);
    }
    command
}

#[allow(dead_code)]
fn service_suffix(data_dir: &Path) -> String {
    crate::context::folder_tag(data_dir)
        .map(|tag| format!("-{}", tag))
        .unwrap_or_default()
}

#[allow(dead_code)]
fn reject_newlines(value: &str) -> CliResult<()> {
    if value.contains(['\n', '\r']) {
        return Err(CliError::usage(
            "The background service can't use a path that contains a line break.",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
mod platform {
    use super::*;

    pub const MANAGER: &str = "systemd (user)";

    pub fn supported() -> CliResult<()> {
        if probe_tool("systemctl", &["--user", "--version"]).is_none() {
            return Err(CliError::general("systemd isn't available on this system.")
                .with_hint("To keep Aster Bridge running, start it with your own process manager: aster-bridge serve --service"));
        }
        Ok(())
    }

    fn unit_name(data_dir: &Path) -> String {
        format!("aster-bridge{}.service", service_suffix(data_dir))
    }

    fn unit_path(data_dir: &Path) -> Option<PathBuf> {
        Some(dirs::config_dir()?.join("systemd").join("user").join(unit_name(data_dir)))
    }

    pub fn location(data_dir: &Path) -> String {
        unit_path(data_dir)
            .map(|p| p.display().to_string())
            .unwrap_or_default()
    }

    pub fn exists(data_dir: &Path) -> bool {
        unit_path(data_dir).is_some_and(|p| p.exists())
    }

    pub fn quote(value: &str) -> CliResult<String> {
        reject_newlines(value)?;
        let escaped = value
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('%', "%%")
            .replace('$', "$$");
        Ok(format!("\"{}\"", escaped))
    }

    pub fn unit(spec: &Spec) -> CliResult<String> {
        let exec = spec
            .args()
            .iter()
            .map(|arg| quote(arg))
            .collect::<CliResult<Vec<_>>>()?
            .join(" ");
        let mut text = String::new();
        text.push_str("[Unit]\nDescription=Aster Bridge\nDocumentation=https://github.com/Aster-Privacy/Aster-Bridge\n\n");
        text.push_str("[Service]\nType=simple\n");
        text.push_str(&format!("ExecStart={}\n", exec));
        if let Some(key_file) = &spec.key_file {
            let assignment = format!("ASTER_BRIDGE_SECRET_KEY_FILE={}", key_file.display());
            text.push_str(&format!("Environment={}\n", quote(&assignment)?));
        }
        text.push_str("Restart=on-failure\nRestartSec=10\nRestartPreventExitStatus=3 4 5 6 7\nTimeoutStopSec=30\n\n");
        text.push_str("[Install]\nWantedBy=default.target\n");
        Ok(text)
    }

    pub fn install(spec: &Spec) -> CliResult<()> {
        let path = unit_path(&spec.data_dir)
            .ok_or_else(|| CliError::general("Couldn't find the systemd user folder."))?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                CliError::general(format!("Couldn't create {}: {}", parent.display(), e))
            })?;
        }
        std::fs::write(&path, unit(spec)?)
            .map_err(|e| CliError::general(format!("Couldn't write {}: {}", path.display(), e)))?;
        let name = unit_name(&spec.data_dir);
        run_tool("systemctl", &["--user", "daemon-reload"])?;
        run_tool("systemctl", &["--user", "enable", &name])?;
        run_tool("systemctl", &["--user", "restart", &name])?;
        Ok(())
    }

    pub fn before_uninstall(_data_dir: &Path) {}

    pub fn uninstall(data_dir: &Path) -> CliResult<()> {
        let name = unit_name(data_dir);
        let _ = run_tool("systemctl", &["--user", "disable", "--now", &name]);
        if let Some(path) = unit_path(data_dir) {
            std::fs::remove_file(&path).map_err(|e| {
                CliError::general(format!("Couldn't remove {}: {}", path.display(), e))
            })?;
        }
        let _ = run_tool("systemctl", &["--user", "daemon-reload"]);
        Ok(())
    }

    pub fn state(data_dir: &Path) -> Option<String> {
        let (_, stdout) = probe_tool("systemctl", &["--user", "is-active", &unit_name(data_dir)])?;
        let state = stdout.trim();
        (!state.is_empty()).then(|| state.to_string())
    }

    pub fn extra_hint() -> Option<String> {
        let user = std::env::var("USER").ok().filter(|u| !u.is_empty())?;
        if Path::new("/var/lib/systemd/linger").join(&user).exists() {
            return None;
        }
        Some(format!(
            "The service stops when you sign out. To keep it running after you sign out, run: sudo loginctl enable-linger {}",
            user
        ))
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use super::*;

    pub const MANAGER: &str = "launchd";
    const BOOTSTRAP_ATTEMPTS: u32 = 5;

    pub fn supported() -> CliResult<()> {
        Ok(())
    }

    fn label(data_dir: &Path) -> String {
        match crate::context::folder_tag(data_dir) {
            Some(tag) => format!("org.astermail.bridge.cli.{}", tag),
            None => "org.astermail.bridge.cli".to_string(),
        }
    }

    fn plist_path(data_dir: &Path) -> Option<PathBuf> {
        Some(
            dirs::home_dir()?
                .join("Library")
                .join("LaunchAgents")
                .join(format!("{}.plist", label(data_dir))),
        )
    }

    pub fn location(data_dir: &Path) -> String {
        plist_path(data_dir)
            .map(|p| p.display().to_string())
            .unwrap_or_default()
    }

    pub fn exists(data_dir: &Path) -> bool {
        plist_path(data_dir).is_some_and(|p| p.exists())
    }

    pub fn escape(value: &str) -> String {
        value
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&apos;")
    }

    fn uid() -> CliResult<String> {
        Ok(run_tool("id", &["-u"])?.trim().to_string())
    }

    pub fn plist(spec: &Spec, log_dir: &Path) -> CliResult<String> {
        let mut text = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n");
        text.push_str(&format!(
            "  <key>Label</key>\n  <string>{}</string>\n",
            escape(&label(&spec.data_dir))
        ));
        text.push_str("  <key>ProgramArguments</key>\n  <array>\n");
        for arg in spec.args() {
            reject_newlines(&arg)?;
            text.push_str(&format!("    <string>{}</string>\n", escape(&arg)));
        }
        text.push_str("  </array>\n");
        text.push_str("  <key>RunAtLoad</key>\n  <true/>\n");
        text.push_str("  <key>KeepAlive</key>\n  <dict>\n    <key>SuccessfulExit</key>\n    <false/>\n  </dict>\n");
        text.push_str("  <key>ThrottleInterval</key>\n  <integer>10</integer>\n");
        text.push_str("  <key>ProcessType</key>\n  <string>Background</string>\n");
        text.push_str(&format!(
            "  <key>StandardOutPath</key>\n  <string>{}</string>\n",
            escape(&log_dir.join("service.out.log").display().to_string())
        ));
        text.push_str(&format!(
            "  <key>StandardErrorPath</key>\n  <string>{}</string>\n",
            escape(&log_dir.join("service.err.log").display().to_string())
        ));
        if let Some(key_file) = &spec.key_file {
            let value = key_file.display().to_string();
            reject_newlines(&value)?;
            text.push_str(&format!(
                "  <key>EnvironmentVariables</key>\n  <dict>\n    <key>ASTER_BRIDGE_SECRET_KEY_FILE</key>\n    <string>{}</string>\n  </dict>\n",
                escape(&value)
            ));
        }
        text.push_str("</dict>\n</plist>\n");
        Ok(text)
    }

    pub fn install(spec: &Spec) -> CliResult<()> {
        let path = plist_path(&spec.data_dir)
            .ok_or_else(|| CliError::general("Couldn't find the LaunchAgents folder."))?;
        let log_dir = aster_bridge_core::diagnostics::ensure_log_dir(&spec.data_dir)
            .map_err(|e| CliError::general(format!("Couldn't create the log folder: {}", e)))?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                CliError::general(format!("Couldn't create {}: {}", parent.display(), e))
            })?;
        }
        std::fs::write(&path, plist(spec, &log_dir)?)
            .map_err(|e| CliError::general(format!("Couldn't write {}: {}", path.display(), e)))?;
        let domain = format!("gui/{}", uid()?);
        let target = format!("{}/{}", domain, label(&spec.data_dir));
        let _ = run_tool("launchctl", &["bootout", &target]);
        let plist = path.display().to_string();
        let mut last_error = None;
        for attempt in 0..BOOTSTRAP_ATTEMPTS {
            if attempt > 0 {
                std::thread::sleep(Duration::from_secs(1));
            }
            match run_tool("launchctl", &["bootstrap", &domain, &plist]) {
                Ok(_) => return Ok(()),
                Err(e) => last_error = Some(e),
            }
        }
        Err(last_error.unwrap_or_else(|| CliError::general("launchctl bootstrap failed.")))
    }

    pub fn before_uninstall(data_dir: &Path) {
        if let Ok(uid) = uid() {
            let _ = run_tool("launchctl", &["bootout", &format!("gui/{}/{}", uid, label(data_dir))]);
        }
    }

    pub fn uninstall(data_dir: &Path) -> CliResult<()> {
        if let Some(path) = plist_path(data_dir) {
            std::fs::remove_file(&path).map_err(|e| {
                CliError::general(format!("Couldn't remove {}: {}", path.display(), e))
            })?;
        }
        Ok(())
    }

    pub fn state(data_dir: &Path) -> Option<String> {
        let uid = uid().ok()?;
        let (ok, stdout) = probe_tool("launchctl", &["print", &format!("gui/{}/{}", uid, label(data_dir))])?;
        if !ok {
            return Some("not loaded".to_string());
        }
        stdout
            .lines()
            .map(str::trim)
            .find_map(|line| line.strip_prefix("state = "))
            .map(str::to_string)
    }

    pub fn extra_hint() -> Option<String> {
        None
    }
}

#[cfg(windows)]
mod platform {
    use super::*;

    pub const MANAGER: &str = "Windows sign-in startup";
    const RUN_KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";
    const DETACHED_PROCESS: u32 = 0x0000_0008;
    const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    pub fn supported() -> CliResult<()> {
        Ok(())
    }

    fn value_name(data_dir: &Path) -> String {
        match crate::context::folder_tag(data_dir) {
            Some(tag) => format!("Aster Bridge CLI {}", tag),
            None => "Aster Bridge CLI".to_string(),
        }
    }

    pub fn location(data_dir: &Path) -> String {
        format!("{}\\{}", RUN_KEY, value_name(data_dir))
    }

    pub fn exists(data_dir: &Path) -> bool {
        probe_tool("reg", &["query", RUN_KEY, "/v", &value_name(data_dir)]).is_some_and(|(ok, _)| ok)
    }

    fn quote_arg(value: &str) -> String {
        let mut text = value.to_string();
        if text.ends_with('\\') {
            text.push('.');
        }
        format!("\"{}\"", text)
    }

    pub fn command_line(spec: &Spec) -> CliResult<String> {
        let args = spec.args();
        for arg in &args {
            reject_newlines(arg)?;
            if arg.contains('"') {
                return Err(CliError::usage(
                    "The background service can't use a path that contains a quotation mark.",
                ));
            }
        }
        Ok(format!(
            "{} serve --service --data-dir {}",
            quote_arg(&args[0]),
            quote_arg(&args[4])
        ))
    }

    pub fn install(spec: &Spec) -> CliResult<()> {
        let line = command_line(spec)?;
        run_tool(
            "reg",
            &["add", RUN_KEY, "/v", &value_name(&spec.data_dir), "/t", "REG_SZ", "/d", &line, "/f"],
        )?;
        use std::os::windows::process::CommandExt;
        Command::new(&spec.exe)
            .args(["serve", "--service", "--data-dir"])
            .arg(&spec.data_dir)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW)
            .spawn()
            .map_err(|e| CliError::general(format!("Couldn't start Aster Bridge: {}", e)))?;
        Ok(())
    }

    pub fn before_uninstall(_data_dir: &Path) {}

    pub fn uninstall(data_dir: &Path) -> CliResult<()> {
        run_tool("reg", &["delete", RUN_KEY, "/v", &value_name(data_dir), "/f"])?;
        Ok(())
    }

    pub fn state(_data_dir: &Path) -> Option<String> {
        Some("registered".to_string())
    }

    pub fn extra_hint() -> Option<String> {
        None
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
mod platform {
    use super::*;

    pub const MANAGER: &str = "none";

    pub fn supported() -> CliResult<()> {
        Err(CliError::general("The background service isn't available on this system.")
            .with_hint("To keep Aster Bridge running, start it with your own process manager: aster-bridge serve --service"))
    }

    pub fn location(_data_dir: &Path) -> String {
        String::new()
    }

    pub fn exists(_data_dir: &Path) -> bool {
        false
    }

    pub fn install(_spec: &Spec) -> CliResult<()> {
        supported()
    }

    pub fn before_uninstall(_data_dir: &Path) {}

    pub fn uninstall(_data_dir: &Path) -> CliResult<()> {
        supported()
    }

    pub fn state(_data_dir: &Path) -> Option<String> {
        None
    }

    pub fn extra_hint() -> Option<String> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> Spec {
        Spec {
            exe: PathBuf::from("/opt/aster bridge/aster-bridge"),
            data_dir: PathBuf::from("/home/me/100% data$"),
            key_file: Some(PathBuf::from("/etc/aster/secret-key")),
        }
    }

    #[test]
    fn newlines_are_rejected() {
        assert!(reject_newlines("a\nb").is_err());
        assert!(reject_newlines("plain").is_ok());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn unit_escapes_specifiers() {
        let text = platform::unit(&spec()).unwrap();
        assert!(text.contains("ExecStart=\"/opt/aster bridge/aster-bridge\" \"serve\" \"--service\""));
        assert!(text.contains("\"/home/me/100%% data$$\""));
        assert!(text.contains("Environment=\"ASTER_BRIDGE_SECRET_KEY_FILE=/etc/aster/secret-key\""));
        assert!(text.contains("RestartPreventExitStatus=3 4 5 6 7"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn plist_escapes_xml() {
        let mut spec = spec();
        spec.data_dir = PathBuf::from("/Users/me/a&b<c>");
        let text = platform::plist(&spec, Path::new("/tmp/logs")).unwrap();
        assert!(text.contains("<string>/Users/me/a&amp;b&lt;c&gt;</string>"));
        assert!(text.contains("<key>SuccessfulExit</key>"));
    }

    #[cfg(windows)]
    #[test]
    fn command_line_quotes_paths() {
        let spec = Spec {
            exe: PathBuf::from(r"C:\Program Files\Aster\aster-bridge.exe"),
            data_dir: PathBuf::from(r"D:\"),
            key_file: None,
        };
        assert_eq!(
            platform::command_line(&spec).unwrap(),
            r#""C:\Program Files\Aster\aster-bridge.exe" serve --service --data-dir "D:\.""#
        );
    }

    #[test]
    fn spec_args_run_serve_as_service() {
        let args = spec().args();
        assert_eq!(&args[1..4], ["serve", "--service", "--data-dir"]);
    }
}
