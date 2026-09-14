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
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

#[cfg(target_os = "macos")]
mod dock_icon;
mod shell;

use aster_bridge_core::{api_client, auth, config, crypto, db, diagnostics, imap, ops, runtime, sync, tls};

use std::sync::Arc;
use tauri::{Emitter, Manager, State, WindowEvent};
use tauri_plugin_autostart::MacosLauncher;
use tokio::sync::{Mutex as AsyncMutex, RwLock};
use tracing_subscriber::EnvFilter;

struct BridgeState {
    config: config::BridgeConfig,
    session: Option<Arc<RwLock<auth::session::Session>>>,
    db: Arc<db::Database>,
    client: Arc<api_client::ApiClient>,
    passwords: Option<Arc<auth::app_passwords::AppPasswords>>,
    runtime: Option<runtime::RunningBridge>,
    tls_server_config: Option<Arc<rustls::ServerConfig>>,
    identity: auth::device_identity::DeviceIdentity,
    pending_code: Option<String>,
    pending_code_normalized: Option<String>,
    pending_expires_in: Option<u64>,
    display_name: Option<String>,
    profile_picture: Option<String>,
    profile_color: Option<String>,
    plan_code: Option<String>,
    has_bridge_access: bool,
    plan_info_loaded: bool,
}

impl BridgeState {
    fn running(&self) -> bool {
        self.runtime.as_ref().map_or(false, |r| r.is_running())
    }

    fn bound_ports(&self) -> runtime::BoundPorts {
        self.runtime
            .as_ref()
            .filter(|r| r.is_running())
            .map(|r| r.bound_ports())
            .unwrap_or_default()
    }

    fn service_running(&self, service: runtime::Service) -> bool {
        self.runtime
            .as_ref()
            .map_or(false, |r| r.service_running(service))
    }

    fn stop_runtime(&mut self, reason: runtime::StopReason) {
        if let Some(running) = self.runtime.take() {
            running.stop(reason);
        }
    }
}

type SharedBridgeState = Arc<AsyncMutex<BridgeState>>;

struct AppState(SharedBridgeState);

struct TrayState(std::sync::Mutex<Option<tauri::tray::TrayIcon>>);

struct PendingDeepLink(std::sync::Mutex<Option<String>>);

#[cfg(windows)]
fn read_text_scale_factor() -> f64 {
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;
    RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey("Software\\Microsoft\\Accessibility")
        .and_then(|key| key.get_value::<u32, _>("TextScaleFactor"))
        .map(|pct| (pct as f64 / 100.0).clamp(1.0, 2.25))
        .unwrap_or(1.0)
}

#[derive(serde::Serialize)]
struct BridgeStatusResponse {
    connected: bool,
    imap_running: bool,
    smtp_running: bool,
    jmap_running: bool,
    pop3_running: bool,
    carddav_running: bool,
    email: String,
    display_name: Option<String>,
    profile_picture: Option<String>,
    profile_color: Option<String>,
    plan_code: Option<String>,
    has_bridge_access: bool,
    plan_info_loaded: bool,
    import_progress: Option<imap::append::ImportProgress>,
}

#[derive(serde::Serialize, Default)]
struct UserPreferencesResponse {
    theme: Option<String>,
    color_theme: Option<String>,
    accent_color: Option<String>,
    accent_color_hover: Option<String>,
    custom_theme_seed: Option<String>,
    custom_theme_overrides: std::collections::HashMap<String, String>,
    font_choice: Option<String>,
    font_size_scale: Option<serde_json::Value>,
    reduce_motion: Option<bool>,
    compact_mode: Option<bool>,
    high_contrast: Option<bool>,
    reduce_transparency: Option<bool>,
    link_underlines: Option<bool>,
    dyslexia_font: Option<bool>,
    text_spacing: Option<bool>,
    color_vision_mode: Option<String>,
    toast_position: Option<String>,
}

#[derive(serde::Serialize)]
struct SetupStatusResponse {
    status: String,
    done: bool,
}

#[derive(serde::Serialize)]
struct ConnectionInfoResponse {
    imap_host: String,
    imap_port: u16,
    smtp_host: String,
    smtp_port: u16,
    jmap_host: String,
    jmap_port: u16,
    jmap_url: String,
    jmap_enabled: bool,
    tls_enabled: bool,
    imap_implicit_tls_port: u16,
    smtp_implicit_tls_port: u16,
    jmap_https_enabled: bool,
    pop3_port: u16,
    pop3s_port: u16,
    carddav_port: u16,
    carddav_url: String,
    carddav_enabled: bool,
    carddav_https_enabled: bool,
}

#[derive(serde::Serialize)]
struct TlsInfoResponse {
    tls_enabled: bool,
    fingerprint_sha256: Option<String>,
    cert_path: String,
    imap_implicit_tls_port: u16,
    smtp_implicit_tls_port: u16,
    jmap_https_enabled: bool,
}

#[derive(serde::Serialize)]
struct AppPasswordEntry {
    id: String,
    label: String,
    created_at: String,
    last_used_at: Option<i64>,
    last_client: Option<String>,
    use_count: i64,
}

#[tauri::command]
async fn get_bridge_status(state: State<'_, AppState>) -> Result<BridgeStatusResponse, String> {
    let guard = state.0.lock().await;

    let mut email = String::new();
    let mut connected = false;

    if let Some(ref session) = guard.session {
        let session_guard = session.read().await;
        email = session_guard.email.clone();
        connected = true;
    }

    let imap_running = guard.service_running(runtime::Service::Imap);
    let smtp_running = guard.service_running(runtime::Service::Smtp);
    let jmap_running = guard.service_running(runtime::Service::Jmap);
    let pop3_running = guard.service_running(runtime::Service::Pop3);
    let carddav_running = guard.service_running(runtime::Service::Carddav);

    Ok(BridgeStatusResponse {
        connected,
        imap_running,
        smtp_running,
        jmap_running,
        pop3_running,
        carddav_running,
        email,
        display_name: guard.display_name.clone(),
        profile_picture: guard.profile_picture.clone(),
        profile_color: guard.profile_color.clone(),
        plan_code: guard.plan_code.clone(),
        has_bridge_access: guard.has_bridge_access,
        plan_info_loaded: guard.plan_info_loaded,
        import_progress: imap::append::current_import_progress(),
    })
}

#[tauri::command]
async fn start_bridge(app: tauri::AppHandle, state: State<'_, AppState>) -> Result<(), String> {
    let result = start_bridge_inner(&state).await;
    shell::refresh_tray(&app);
    result
}

async fn start_bridge_inner(state: &State<'_, AppState>) -> Result<(), String> {
    start_runtime(&state.0).await.map_err(|e| e.to_string())
}

async fn start_runtime(shared: &SharedBridgeState) -> Result<(), runtime::StartError> {
    let (session, client, retry_delay) = {
        let guard = shared.lock().await;
        if guard.running() {
            return Ok(());
        }
        let session = guard
            .session
            .clone()
            .ok_or(runtime::StartError::NotSignedIn)?;
        let tuning = runtime::RuntimeTuning::for_config(&guard.config);
        (session, guard.client.clone(), tuning.plan_retry_delay)
    };

    let plan_result = runtime::check_bridge_access(&client, &session, retry_delay).await;

    let mut guard = shared.lock().await;
    if guard.running() {
        return Ok(());
    }
    let grant = match plan_result {
        Ok(grant) => {
            guard.has_bridge_access = true;
            guard.plan_code = Some(grant.plan_code().to_string());
            guard.plan_info_loaded = true;
            grant
        }
        Err(e) => {
            if let runtime::StartError::BridgeAccessRequired { plan_code } = &e {
                guard.has_bridge_access = false;
                if plan_code.is_some() {
                    guard.plan_code = plan_code.clone();
                }
                guard.plan_info_loaded = true;
            }
            return Err(e);
        }
    };
    if !guard
        .session
        .as_ref()
        .map_or(false, |current| Arc::ptr_eq(current, &session))
    {
        return Err(runtime::StartError::NotSignedIn);
    }
    let device_id = guard
        .identity
        .device_id
        .ok_or(runtime::StartError::NotSignedIn)?;

    let passwords = match guard.passwords.as_ref() {
        Some(p) => p.clone(),
        None => {
            let pw = Arc::new(auth::app_passwords::AppPasswords::new(guard.db.clone()));
            guard.passwords = Some(pw.clone());
            pw
        }
    };

    let deps = runtime::RuntimeDeps {
        session,
        db: guard.db.clone(),
        client,
        passwords,
    };
    let opts = runtime::StartOptions {
        config: guard.config.clone(),
        tls: guard.tls_server_config.clone(),
        device_id,
        signing_key: guard.identity.ed25519_signing_key.clone(),
        profile: runtime::ClientProfile::Desktop,
        tuning: runtime::RuntimeTuning::for_config(&guard.config),
    };
    let running = runtime::BridgeRuntime::start(grant, deps, opts).await?;
    if running.bound_ports().apply_to_config(&mut guard.config) {
        let _ = config::save_config(&guard.config);
    }
    guard.runtime = Some(running);
    Ok(())
}

#[tauri::command]
async fn stop_bridge(app: tauri::AppHandle, state: State<'_, AppState>) -> Result<(), String> {
    let result = stop_bridge_inner(&state).await;
    shell::refresh_tray(&app);
    result
}

async fn stop_bridge_inner(state: &State<'_, AppState>) -> Result<(), String> {
    let mut guard = state.0.lock().await;

    guard.stop_runtime(runtime::StopReason::UserRequested);

    tracing::info!("bridge stopped");

    Ok(())
}

#[tauri::command]
async fn sign_out(state: State<'_, AppState>, app_handle: tauri::AppHandle) -> Result<(), String> {
    let mut guard = state.0.lock().await;

    guard.stop_runtime(runtime::StopReason::UserRequested);

    guard.session = None;
    guard.passwords = None;
    guard.display_name = None;
    guard.profile_picture = None;
    guard.profile_color = None;
    guard.plan_code = None;
    guard.has_bridge_access = false;
    guard.plan_info_loaded = false;
    guard.pending_code = None;
    guard.pending_code_normalized = None;
    guard.pending_expires_in = None;

    let _ = guard.db.clear_all_user_data();

    let data_dir = guard.config.data_dir.clone();
    auth::device_identity::clear_identity(&data_dir);
    auth::device_identity::clear_passphrase(&data_dir);
    guard.identity.device_id = None;

    drop(guard);
    let _ = app_handle.emit("state_updated", ());

    tracing::info!("signed out");

    Ok(())
}

#[tauri::command]
async fn reset_bridge_data(state: State<'_, AppState>) -> Result<(), String> {
    let guard = state.0.lock().await;
    guard.db.clear_all_user_data().map_err(|e| e.to_string())?;
    tracing::info!("bridge data reset");
    Ok(())
}

#[tauri::command]
async fn refresh_plan_info(state: State<'_, AppState>) -> Result<(), String> {
    let guard = state.0.lock().await;
    let session_arc = match &guard.session {
        Some(s) => s.clone(),
        None => return Err("not authenticated".to_string()),
    };
    let client = guard.client.clone();
    drop(guard);

    let plan_token = {
        let s = session_arc.read().await;
        (*s.access_token).clone()
    };

    let mut plan_result = client.get_plan_info(&plan_token).await;
    for attempt in 0..2u8 {
        if plan_result.is_ok() {
            break;
        }
        tracing::warn!("refresh_plan_info attempt {} failed, retrying", attempt + 1);
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        plan_result = client.get_plan_info(&plan_token).await;
    }

    let plan_info = plan_result.map_err(|e| e.to_string())?;

    let mut guard = state.0.lock().await;
    guard.has_bridge_access = plan_info.has_bridge_access;
    guard.plan_code = Some(plan_info.plan_code);
    guard.plan_info_loaded = true;

    Ok(())
}

#[tauri::command]
async fn get_user_preferences(
    state: State<'_, AppState>,
) -> Result<UserPreferencesResponse, String> {
    let guard = state.0.lock().await;
    let session_arc = match &guard.session {
        Some(s) => s.clone(),
        None => return Ok(UserPreferencesResponse::default()),
    };
    let client = guard.client.clone();
    drop(guard);

    let (token, identity_key) = {
        let s = session_arc.read().await;
        match &s.identity_key {
            Some(k) => ((*s.access_token).clone(), k.clone()),
            None => return Ok(UserPreferencesResponse::default()),
        }
    };

    let prefs = match client.get_preferences(&token).await {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!("get_user_preferences: preferences fetch failed: {}", e);
            return Ok(UserPreferencesResponse::default());
        }
    };

    let (encrypted, nonce) = match (prefs.encrypted_preferences, prefs.preferences_nonce) {
        (Some(e), Some(n)) if !e.is_empty() && !n.is_empty() => (e, n),
        _ => return Ok(UserPreferencesResponse::default()),
    };

    match crypto::preferences::decrypt_preferences(&identity_key, &encrypted, &nonce) {
        Ok(p) => Ok(UserPreferencesResponse {
            theme: p.theme,
            color_theme: p.color_theme,
            accent_color: p.accent_color,
            accent_color_hover: p.accent_color_hover,
            custom_theme_seed: p.custom_theme_seed,
            custom_theme_overrides: p.custom_theme_overrides,
            font_choice: p.font_choice,
            font_size_scale: p.font_size_scale,
            reduce_motion: p.reduce_motion,
            compact_mode: p.compact_mode,
            high_contrast: p.high_contrast,
            reduce_transparency: p.reduce_transparency,
            link_underlines: p.link_underlines,
            dyslexia_font: p.dyslexia_font,
            text_spacing: p.text_spacing,
            color_vision_mode: p.color_vision_mode,
            toast_position: p.toast_position,
        }),
        Err(e) => {
            tracing::warn!("get_user_preferences: preferences decrypt failed: {}", e);
            Ok(UserPreferencesResponse::default())
        }
    }
}

#[tauri::command]
async fn get_setup_code(state: State<'_, AppState>) -> Result<String, String> {
    let mut guard = state.0.lock().await;
    let code = ops::request_device_code(
        &guard.client,
        &guard.identity,
        runtime::ClientProfile::Desktop,
    )
    .await
    .map_err(|e| e.to_string())?;
    guard.pending_code = Some(code.code.clone());
    guard.pending_code_normalized = Some(code.normalized);
    guard.pending_expires_in = Some(code.expires_in);
    Ok(code.code)
}

#[tauri::command]
async fn check_setup_status(state: State<'_, AppState>) -> Result<SetupStatusResponse, String> {
    let mut guard = state.0.lock().await;

    let code_normalized = guard
        .pending_code_normalized
        .as_ref()
        .ok_or_else(|| "no pending setup code - call get_setup_code first".to_string())?
        .clone();
    let client = guard.client.clone();
    let data_dir = guard.config.data_dir.clone();

    let poll = ops::poll_device_sign_in(&client, &mut guard.identity, &data_dir, &code_normalized)
        .await
        .map_err(|e| e.to_string())?;

    match poll {
        ops::SignInPoll::Confirmed(session) => {
            let token = session.access_token.clone();
            guard.session = Some(Arc::new(RwLock::new(*session)));

            if let Ok(profile) = client.get_user_profile(&token).await {
                guard.display_name = profile.display_name;
                guard.profile_picture = profile.profile_picture;
                guard.profile_color = profile.profile_color;
            }

            let plan_token = (*token).clone();
            drop(guard);
            let mut plan_result = client.get_plan_info(&plan_token).await;
            for attempt in 0..2u8 {
                if plan_result.is_ok() {
                    break;
                }
                tracing::warn!(
                    "plan check attempt {} failed during setup, retrying",
                    attempt + 1
                );
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                plan_result = client.get_plan_info(&plan_token).await;
            }
            let mut guard = state.0.lock().await;
            if let Ok(plan_info) = plan_result {
                guard.has_bridge_access = plan_info.has_bridge_access;
                guard.plan_code = Some(plan_info.plan_code);
            } else {
                guard.has_bridge_access = false;
            }
            guard.plan_info_loaded = true;

            let passwords = Arc::new(auth::app_passwords::AppPasswords::new(guard.db.clone()));
            guard.passwords = Some(passwords);

            guard.pending_code = None;
            guard.pending_code_normalized = None;
            guard.pending_expires_in = None;

            Ok(SetupStatusResponse {
                status: "confirmed".to_string(),
                done: true,
            })
        }
        ops::SignInPoll::Expired => {
            guard.pending_code = None;
            guard.pending_code_normalized = None;
            guard.pending_expires_in = None;

            Ok(SetupStatusResponse {
                status: "expired".to_string(),
                done: true,
            })
        }
        ops::SignInPoll::Pending(status) => Ok(SetupStatusResponse {
            status,
            done: false,
        }),
    }
}

#[derive(serde::Serialize)]
struct SendIdentityEntry {
    address: String,
    kind: String,
    display_name: Option<String>,
    enabled: bool,
    sender_id: String,
}

#[tauri::command]
async fn list_send_identities(
    state: State<'_, AppState>,
) -> Result<Vec<SendIdentityEntry>, String> {
    let guard = state.0.lock().await;
    let session = guard
        .session
        .as_ref()
        .ok_or_else(|| "not authenticated".to_string())?
        .clone();
    drop(guard);

    let s = session.read().await;
    Ok(s.send_identities
        .iter()
        .map(|i| SendIdentityEntry {
            address: i.address.clone(),
            kind: i.kind.as_str().to_string(),
            display_name: i.display_name.clone(),
            enabled: i.enabled,
            sender_id: i.sender_id.clone(),
        })
        .collect())
}

#[tauri::command]
async fn get_default_sender(state: State<'_, AppState>) -> Result<Option<String>, String> {
    let guard = state.0.lock().await;
    let session_arc = match &guard.session {
        Some(s) => s.clone(),
        None => return Err("not authenticated".to_string()),
    };
    let client = guard.client.clone();
    drop(guard);

    let token = { (*session_arc.read().await.access_token).clone() };
    client
        .get_default_sender(&token)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command(rename_all = "snake_case")]
async fn set_default_sender(
    state: State<'_, AppState>,
    sender_id: Option<String>,
) -> Result<(), String> {
    let guard = state.0.lock().await;
    let session_arc = match &guard.session {
        Some(s) => s.clone(),
        None => return Err("not authenticated".to_string()),
    };
    let client = guard.client.clone();
    drop(guard);

    let token = { (*session_arc.read().await.access_token).clone() };
    client
        .set_default_sender(&token, sender_id.as_deref())
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn get_app_passwords(state: State<'_, AppState>) -> Result<Vec<AppPasswordEntry>, String> {
    let guard = state.0.lock().await;

    let passwords = guard
        .passwords
        .as_ref()
        .ok_or_else(|| "not authenticated".to_string())?;

    let entries = passwords.list();

    Ok(entries
        .into_iter()
        .map(|e| AppPasswordEntry {
            id: e.id,
            label: e.label,
            created_at: e.created_at,
            last_used_at: e.last_used_at,
            last_client: e.last_client,
            use_count: e.use_count,
        })
        .collect())
}

#[tauri::command]
async fn generate_app_password(
    label: String,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let guard = state.0.lock().await;

    let passwords = guard
        .passwords
        .as_ref()
        .ok_or_else(|| "not authenticated".to_string())?;

    let password = auth::app_passwords::generate_app_password();
    let store_label = if label.trim().is_empty() {
        "App Password"
    } else {
        label.trim()
    };
    passwords.store(store_label, &password)?;

    Ok(password)
}

#[tauri::command]
async fn delete_app_password(id: String, state: State<'_, AppState>) -> Result<(), String> {
    let guard = state.0.lock().await;

    let passwords = guard
        .passwords
        .as_ref()
        .ok_or_else(|| "not authenticated".to_string())?;

    passwords.delete(&id)
}

#[tauri::command]
async fn get_connection_info(state: State<'_, AppState>) -> Result<ConnectionInfoResponse, String> {
    let guard = state.0.lock().await;

    let imap_port = if guard.running() {
        guard.bound_ports().imap
    } else {
        guard.config.imap_port
    };
    let smtp_port = if guard.running() {
        guard.bound_ports().smtp
    } else {
        guard.config.smtp_port
    };
    let jmap_port = if guard.running() {
        guard.bound_ports().jmap
    } else {
        guard.config.jmap_port
    };
    let carddav_port = if guard.running() && guard.bound_ports().carddav != 0 {
        guard.bound_ports().carddav
    } else {
        guard.config.carddav_port
    };

    let tls_enabled = guard.config.tls_enabled && guard.tls_server_config.is_some();
    let jmap_https_enabled = guard.config.jmap_https_enabled && tls_enabled;
    let jmap_scheme = if jmap_https_enabled { "https" } else { "http" };
    let carddav_https_enabled = guard.config.carddav_https_enabled && tls_enabled;
    let carddav_scheme = if carddav_https_enabled {
        "https"
    } else {
        "http"
    };
    let pop3_port = if guard.running() && guard.bound_ports().pop3 != 0 {
        guard.bound_ports().pop3
    } else {
        guard.config.pop3_port
    };
    let pop3s_port = if guard.running() && guard.bound_ports().pop3s != 0 {
        guard.bound_ports().pop3s
    } else {
        guard.config.pop3s_port
    };
    Ok(ConnectionInfoResponse {
        imap_host: "127.0.0.1".to_string(),
        imap_port,
        smtp_host: "127.0.0.1".to_string(),
        smtp_port,
        jmap_host: "127.0.0.1".to_string(),
        jmap_port,
        jmap_url: format!("{}://127.0.0.1:{}/jmap/session", jmap_scheme, jmap_port),
        jmap_enabled: guard.config.jmap_enabled,
        tls_enabled,
        imap_implicit_tls_port: if tls_enabled && guard.running() && guard.bound_ports().imaps != 0 {
            guard.bound_ports().imaps
        } else {
            guard.config.imap_implicit_tls_port
        },
        smtp_implicit_tls_port: if tls_enabled && guard.running() && guard.bound_ports().smtps != 0 {
            guard.bound_ports().smtps
        } else {
            guard.config.smtp_implicit_tls_port
        },
        jmap_https_enabled,
        pop3_port,
        pop3s_port,
        carddav_port,
        carddav_url: format!("{}://127.0.0.1:{}/", carddav_scheme, carddav_port),
        carddav_enabled: guard.config.carddav_enabled,
        carddav_https_enabled,
    })
}

#[tauri::command]
async fn get_tls_info(state: State<'_, AppState>) -> Result<TlsInfoResponse, String> {
    let guard = state.0.lock().await;
    let tls_enabled = guard.config.tls_enabled && guard.tls_server_config.is_some();
    let jmap_https_enabled = guard.config.jmap_https_enabled && tls_enabled;
    let cert_path = tls::cert_pem_path(&guard.config.data_dir)
        .to_string_lossy()
        .to_string();
    let fingerprint = if tls_enabled {
        tls::cert_fingerprint_sha256(&guard.config.data_dir)
    } else {
        None
    };
    Ok(TlsInfoResponse {
        tls_enabled,
        fingerprint_sha256: fingerprint,
        cert_path,
        imap_implicit_tls_port: if tls_enabled && guard.running() && guard.bound_ports().imaps != 0 {
            guard.bound_ports().imaps
        } else {
            guard.config.imap_implicit_tls_port
        },
        smtp_implicit_tls_port: if tls_enabled && guard.running() && guard.bound_ports().smtps != 0 {
            guard.bound_ports().smtps
        } else {
            guard.config.smtp_implicit_tls_port
        },
        jmap_https_enabled,
    })
}

#[tauri::command]
async fn open_tls_cert(state: State<'_, AppState>) -> Result<(), String> {
    let dir = {
        let guard = state.0.lock().await;
        let cert_path = tls::cert_pem_path(&guard.config.data_dir);
        cert_path
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| guard.config.data_dir.clone())
    };
    open::that(dir).map_err(|e| e.to_string())
}

#[tauri::command]
async fn set_tls_enabled(state: State<'_, AppState>, enabled: bool) -> Result<(), String> {
    let mut guard = state.0.lock().await;
    guard.config.tls_enabled = enabled;
    if enabled && guard.tls_server_config.is_none() {
        match tls::ensure_cert(&guard.config.data_dir) {
            Ok((certs, key)) => {
                if let Ok(sc) = tls::server_config(certs, key) {
                    guard.tls_server_config = Some(sc);
                }
            }
            Err(e) => tracing::warn!("ensure_cert failed: {}", e),
        }
    }
    config::save_config(&guard.config)
}

#[tauri::command]
async fn get_data_directory(state: State<'_, AppState>) -> Result<String, String> {
    let guard = state.0.lock().await;
    Ok(guard.config.data_dir.to_string_lossy().to_string())
}

#[tauri::command]
async fn open_data_directory(state: State<'_, AppState>) -> Result<(), String> {
    let guard = state.0.lock().await;
    let dir = guard.config.data_dir.clone();
    drop(guard);
    let canonical = std::fs::canonicalize(&dir).map_err(|e| e.to_string())?;
    if !canonical.is_dir() {
        return Err("data_dir is not a directory".to_string());
    }
    open::that(&canonical).map_err(|e| e.to_string())
}

#[tauri::command(rename_all = "snake_case")]
async fn update_connection_settings(
    state: State<'_, AppState>,
    imap_port: u16,
    smtp_port: u16,
) -> Result<(), String> {
    ops::validate_port(imap_port).map_err(|e| format!("imap_port: {}", e))?;
    ops::validate_port(smtp_port).map_err(|e| format!("smtp_port: {}", e))?;
    let mut guard = state.0.lock().await;
    let mut candidate = guard.config.clone();
    candidate.imap_port = imap_port;
    candidate.smtp_port = smtp_port;
    config::validate_ports(&candidate)?;
    guard.config.imap_port = imap_port;
    guard.config.smtp_port = smtp_port;
    config::save_config(&guard.config)
}

#[derive(serde::Serialize)]
struct ProvisionBundle {
    email: String,
    app_password: String,
    label: String,
    imap_host: String,
    imap_port: u16,
    smtp_host: String,
    smtp_port: u16,
    jmap_host: String,
    jmap_port: u16,
    jmap_url: String,
    jmap_enabled: bool,
    carddav_port: u16,
    carddav_url: String,
    carddav_enabled: bool,
}

#[tauri::command]
fn take_pending_deep_link(state: State<'_, PendingDeepLink>) -> Option<String> {
    state.0.lock().ok().and_then(|mut pending| pending.take())
}

#[tauri::command]
async fn provision_bundle(
    state: State<'_, AppState>,
    label: String,
) -> Result<ProvisionBundle, String> {
    let guard = state.0.lock().await;
    let passwords = guard
        .passwords
        .as_ref()
        .ok_or_else(|| "not authenticated".to_string())?;
    let session = guard
        .session
        .as_ref()
        .ok_or_else(|| "not authenticated".to_string())?;
    let email = session.read().await.email.clone();

    let trimmed = label.trim();
    let store_label = if trimmed.is_empty() {
        "Auto-provisioned"
    } else {
        trimmed
    };
    let password = auth::app_passwords::generate_app_password();
    passwords.store(store_label, &password)?;

    let imap_port = if guard.running() {
        guard.bound_ports().imap
    } else {
        guard.config.imap_port
    };
    let smtp_port = if guard.running() {
        guard.bound_ports().smtp
    } else {
        guard.config.smtp_port
    };
    let jmap_port = if guard.running() {
        guard.bound_ports().jmap
    } else {
        guard.config.jmap_port
    };
    let carddav_port = if guard.running() && guard.bound_ports().carddav != 0 {
        guard.bound_ports().carddav
    } else {
        guard.config.carddav_port
    };

    Ok(ProvisionBundle {
        email,
        app_password: password,
        label: store_label.to_string(),
        imap_host: "127.0.0.1".to_string(),
        imap_port,
        smtp_host: "127.0.0.1".to_string(),
        smtp_port,
        jmap_host: "127.0.0.1".to_string(),
        jmap_port,
        jmap_url: format!(
            "{}://127.0.0.1:{}/jmap/session",
            if guard.config.jmap_https_enabled
                && guard.config.tls_enabled
                && guard.tls_server_config.is_some()
            {
                "https"
            } else {
                "http"
            },
            jmap_port
        ),
        jmap_enabled: guard.config.jmap_enabled,
        carddav_port,
        carddav_url: format!(
            "{}://127.0.0.1:{}/",
            if guard.config.carddav_https_enabled
                && guard.config.tls_enabled
                && guard.tls_server_config.is_some()
            {
                "https"
            } else {
                "http"
            },
            carddav_port
        ),
        carddav_enabled: guard.config.carddav_enabled,
    })
}

#[derive(serde::Serialize)]
struct ServiceSettingsResponse {
    service_mode: bool,
    autostart: bool,
}

#[tauri::command]
async fn get_service_settings(
    state: State<'_, AppState>,
) -> Result<ServiceSettingsResponse, String> {
    let guard = state.0.lock().await;
    Ok(ServiceSettingsResponse {
        service_mode: guard.config.service_mode,
        autostart: guard.config.autostart,
    })
}

#[tauri::command]
async fn set_service_mode(state: State<'_, AppState>, enabled: bool) -> Result<(), String> {
    let mut guard = state.0.lock().await;
    guard.config.service_mode = enabled;
    config::save_config(&guard.config)
}

#[tauri::command]
async fn set_autostart(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    enabled: bool,
) -> Result<(), String> {
    use tauri_plugin_autostart::ManagerExt;
    let manager = app.autolaunch();
    if enabled {
        manager.enable().map_err(|e| e.to_string())?;
    } else {
        manager.disable().map_err(|e| e.to_string())?;
    }
    let mut guard = state.0.lock().await;
    guard.config.autostart = enabled;
    config::save_config(&guard.config)
}

#[tauri::command]
async fn trigger_sync(state: State<'_, AppState>) -> Result<(), String> {
    let trigger = {
        let guard = state.0.lock().await;
        guard.runtime.as_ref().and_then(|r| r.sync_trigger()).ok_or_else(|| "bridge is not running".to_string())?
            .clone()
    };
    let (tx, rx) = tokio::sync::oneshot::channel();
    trigger
        .send(sync::poller::SyncTrigger { done: tx })
        .await
        .map_err(|_| "sync worker not available".to_string())?;
    match rx.await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(e),
        Err(_) => Err("sync worker dropped completion channel".to_string()),
    }
}

#[tauri::command]
async fn repair_cache(state: State<'_, AppState>) -> Result<(), String> {
    let (db, trigger) = {
        let guard = state.0.lock().await;
        if guard.session.is_none() {
            return Err("not authenticated".to_string());
        }
        (guard.db.clone(), guard.runtime.as_ref().and_then(|r| r.sync_trigger()))
    };
    db.repair_cache()?;
    if let Some(trigger) = trigger {
        let (tx, rx) = tokio::sync::oneshot::channel();
        trigger
            .send(sync::poller::SyncTrigger { done: tx })
            .await
            .map_err(|_| "sync worker not available".to_string())?;
        match rx.await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(e),
            Err(_) => Err("sync worker dropped completion channel".to_string()),
        }
    } else {
        Ok(())
    }
}

#[tauri::command]
async fn get_recent_logs(state: State<'_, AppState>) -> Result<Vec<String>, String> {
    let dir = {
        let guard = state.0.lock().await;
        guard.config.data_dir.clone()
    };
    Ok(diagnostics::read_recent_lines(&dir))
}

#[derive(serde::Serialize)]
struct RedactedConfig {
    imap_port: u16,
    smtp_port: u16,
    jmap_port: u16,
    jmap_enabled: bool,
    service_mode: bool,
    autostart: bool,
    poll_interval_secs: u64,
}

#[derive(serde::Serialize)]
struct DbStats {
    messages: i64,
    passwords: i64,
    last_sync_ts: Option<String>,
}

#[derive(serde::Serialize)]
struct DiagnosticBundle {
    version: String,
    os: String,
    arch: String,
    config: RedactedConfig,
    recent_log_lines: Vec<String>,
    db_stats: DbStats,
}

#[derive(serde::Serialize)]
struct OutboxItem {
    id: i64,
    envelope_from: String,
    envelope_to: String,
    queued_at: i64,
    attempts: i64,
    last_attempt_at: Option<i64>,
    last_error: Option<String>,
    status: String,
    subject: Option<String>,
    size: i64,
}

fn parse_subject(raw_mime: &[u8]) -> Option<String> {
    use mail_parser::MessageParser;
    MessageParser::default()
        .parse(raw_mime)
        .and_then(|p| p.subject().map(|s| s.to_string()))
}

#[tauri::command]
async fn outbox_list(state: State<'_, AppState>) -> Result<Vec<OutboxItem>, String> {
    let db = {
        let guard = state.0.lock().await;
        if guard.session.is_none() {
            return Err("not authenticated".to_string());
        }
        guard.db.clone()
    };
    let rows = db.outbox_list_pending()?;
    Ok(rows
        .into_iter()
        .map(|r| OutboxItem {
            id: r.id,
            envelope_from: r.envelope_from,
            envelope_to: r.envelope_to,
            queued_at: r.queued_at,
            attempts: r.attempts,
            last_attempt_at: r.last_attempt_at,
            last_error: r.last_error,
            status: r.status,
            subject: parse_subject(&r.raw_mime),
            size: r.raw_mime.len() as i64,
        })
        .collect())
}

#[tauri::command]
async fn outbox_retry_now(state: State<'_, AppState>, id: i64) -> Result<(), String> {
    let trigger = {
        let guard = state.0.lock().await;
        guard.runtime.as_ref().and_then(|r| r.outbox_trigger()).ok_or_else(|| "bridge is not running".to_string())?
            .clone()
    };
    trigger
        .send(id)
        .await
        .map_err(|_| "outbox worker not available".to_string())
}

#[tauri::command]
async fn copy_diagnostic_bundle(state: State<'_, AppState>) -> Result<String, String> {
    let (cfg_clone, data_dir, db) = {
        let guard = state.0.lock().await;
        (
            guard.config.clone(),
            guard.config.data_dir.clone(),
            guard.db.clone(),
        )
    };
    let (messages, passwords, last_sync_ts) = db.db_stats().unwrap_or((0, 0, None));
    let bundle = DiagnosticBundle {
        version: env!("CARGO_PKG_VERSION").to_string(),
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        config: RedactedConfig {
            imap_port: cfg_clone.imap_port,
            smtp_port: cfg_clone.smtp_port,
            jmap_port: cfg_clone.jmap_port,
            jmap_enabled: cfg_clone.jmap_enabled,
            service_mode: cfg_clone.service_mode,
            autostart: cfg_clone.autostart,
            poll_interval_secs: cfg_clone.poll_interval_secs,
        },
        recent_log_lines: diagnostics::read_recent_lines(&data_dir),
        db_stats: DbStats {
            messages,
            passwords,
            last_sync_ts,
        },
    };
    let serialized = serde_json::to_string_pretty(&bundle).map_err(|e| e.to_string())?;
    Ok(serialized)
}

struct TauriEvents(tauri::AppHandle);

impl aster_bridge_core::events::BridgeEvents for TauriEvents {
    fn sync_progress(&self, progress: &aster_bridge_core::events::SyncProgress) {
        let _ = self.0.emit("sync_progress", progress);
    }

    fn sync_done(&self, failed: bool) {
        let _ = self.0.emit("sync_done", serde_json::json!({ "failed": failed }));
    }

    fn import_progress(&self, progress: &imap::append::ImportProgress) {
        let _ = self.0.emit("import_progress", progress.clone());
    }

    fn send_failed(&self) {
        use tauri_plugin_notification::NotificationExt;
        let _ = self
            .0
            .notification()
            .builder()
            .title("Message not sent")
            .body("Aster Bridge couldn't send a message. Open Aster Bridge to retry it.")
            .show();
    }

    fn access_revoked(&self) {
        let handle = self.0.clone();
        tauri::async_runtime::spawn(async move {
            let state: State<AppState> = handle.state();
            {
                let mut guard = state.0.lock().await;
                guard.has_bridge_access = false;
                guard.plan_info_loaded = true;
                guard.stop_runtime(runtime::StopReason::AccessRevoked);
            }
            shell::refresh_tray(&handle);
        });
        let _ = self.0.emit("bridge_access_revoked", serde_json::Value::Null);
    }

    fn session_expired(&self) {
        let _ = self.0.emit("session_expired", serde_json::Value::Null);
    }

    fn state_changed(&self) {
        let _ = self.0.emit("state_updated", ());
    }
}

fn main() {
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        std::env::set_var("WEBKIT_DISABLE_DMABUF_RENDERER", "1");
        std::env::set_var("WEBKIT_DISABLE_COMPOSITING_MODE", "1");
        std::env::set_var("WEBKIT_DISABLE_THREADED_COMPOSITOR", "1");
        if std::env::var("WEBKIT_DISABLE_SANDBOX_THIS_IS_DANGEROUS").is_err() {
            std::env::set_var("WEBKIT_DISABLE_SANDBOX_THIS_IS_DANGEROUS", "1");
        }
    }

    let preliminary_cfg = config::load_config();
    let log_guard = match &preliminary_cfg {
        Ok(c) => {
            let _ = diagnostics::ensure_log_dir(&c.data_dir);
            diagnostics::prune_old_logs(&c.data_dir);
            let file_appender =
                tracing_appender::rolling::daily(diagnostics::log_dir(&c.data_dir), "bridge.log");
            let (file_writer, file_guard) = tracing_appender::non_blocking(file_appender);
            let filter =
                EnvFilter::from_default_env().add_directive("aster_bridge=info".parse().unwrap());
            use tracing_subscriber::layer::SubscriberExt;
            use tracing_subscriber::util::SubscriberInitExt;
            let stdout_layer = tracing_subscriber::fmt::layer();
            let file_layer = tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_writer(file_writer);
            tracing_subscriber::registry()
                .with(filter)
                .with(stdout_layer)
                .with(file_layer)
                .init();
            Some(file_guard)
        }
        Err(_) => {
            tracing_subscriber::fmt()
                .with_env_filter(
                    EnvFilter::from_default_env()
                        .add_directive("aster_bridge=info".parse().unwrap()),
                )
                .init();
            None
        }
    };
    let _log_guard = log_guard;
    tracing::info!(
        "Aster Bridge {} starting (pid {})",
        env!("CARGO_PKG_VERSION"),
        std::process::id()
    );

    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, argv, _cwd| {
            shell::show_main_window(app);
            for arg in argv.iter().skip(1) {
                if arg.starts_with("aster-mail://") {
                    tracing::info!("deep-link forwarded from second instance: {}", arg);
                    let _ = app.emit("deep_link", arg.clone());
                }
            }
        }))
        .plugin(tauri_plugin_window_state::Builder::new().build())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_autostart::init(
            MacosLauncher::LaunchAgent,
            Some(vec!["--service"]),
        ))
        .plugin(tauri_plugin_deep_link::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .manage(TrayState(std::sync::Mutex::new(None)))
        .manage(shell::TrayMenuState(std::sync::Mutex::new(None)))
        .manage(shell::QuitState(std::sync::atomic::AtomicBool::new(false)))
        .manage(PendingDeepLink(std::sync::Mutex::new(None)))
        .invoke_handler(tauri::generate_handler![
            get_bridge_status,
            start_bridge,
            stop_bridge,
            sign_out,
            reset_bridge_data,
            refresh_plan_info,
            get_user_preferences,
            get_setup_code,
            check_setup_status,
            list_send_identities,
            get_default_sender,
            set_default_sender,
            get_app_passwords,
            generate_app_password,
            delete_app_password,
            get_connection_info,
            update_connection_settings,
            get_data_directory,
            open_data_directory,
            get_service_settings,
            set_service_mode,
            set_autostart,
            provision_bundle,
            take_pending_deep_link,
            trigger_sync,
            repair_cache,
            get_recent_logs,
            copy_diagnostic_bundle,
            outbox_list,
            outbox_retry_now,
            get_tls_info,
            open_tls_cert,
            set_tls_enabled,
        ])
        .setup(move |app| {
        let mut cfg = match preliminary_cfg {
            Ok(c) => c,
            Err(e) => {
                eprintln!("failed to load config: {}", e);
                std::process::exit(1);
            }
        };

        if std::env::args().any(|a| a == "--service") {
            cfg.service_mode = true;
        }
        let service_mode = cfg.service_mode;

        let db = match db::Database::open(&cfg.data_dir) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("failed to open database: {}", e);
                std::process::exit(1);
            }
        };

        let identity = match auth::device_identity::get_or_create_identity(&cfg.data_dir) {
            Ok(id) => id,
            Err(e) => {
                eprintln!("failed to load device identity: {}", e);
                std::process::exit(1);
            }
        };

        let client = Arc::new(api_client::ApiClient::new());
        let shared_db = Arc::new(db);

        tls::install_default_crypto_provider();
        let tls_server_config: Option<Arc<rustls::ServerConfig>> = if cfg.tls_enabled {
            match tls::ensure_cert(&cfg.data_dir) {
                Ok((certs, key)) => match tls::server_config(certs, key) {
                    Ok(sc) => Some(sc),
                    Err(e) => {
                        tracing::warn!("TLS server config build failed, disabling TLS: {}", e);
                        None
                    }
                },
                Err(e) => {
                    tracing::warn!("TLS cert generation failed, disabling TLS: {}", e);
                    None
                }
            }
        } else {
            None
        };

        let has_device_id = identity.device_id.is_some();

        let bridge_state = Arc::new(AsyncMutex::new(BridgeState {
            config: cfg,
            session: None,
            db: shared_db,
            client,
            passwords: None,
            runtime: None,
            tls_server_config,
            identity,
            pending_code: None,
            pending_code_normalized: None,
            pending_expires_in: None,
            display_name: None,
            profile_picture: None,
            profile_color: None,
            plan_code: None,
            has_bridge_access: false,
            plan_info_loaded: false,
        }));
            app.manage(AppState(bridge_state));

            aster_bridge_core::events::set_event_sink(Some(Arc::new(TauriEvents(app.handle().clone()))));

            #[cfg(target_os = "macos")]
            dock_icon::apply(
                app.get_webview_window("main")
                    .and_then(|w| w.theme().ok())
                    .unwrap_or(tauri::Theme::Light),
            );

            if service_mode {
                shell::hide_main_window(app.handle());
                tracing::info!("running in service mode: tray disabled, window hidden");
            }

            #[cfg(windows)]
            {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.set_zoom(read_text_scale_factor());
                }
                let watcher_handle = app.handle().clone();
                std::thread::spawn(move || {
                    let mut last = read_text_scale_factor();
                    loop {
                        std::thread::sleep(std::time::Duration::from_millis(1000));
                        let current = read_text_scale_factor();
                        if (current - last).abs() > f64::EPSILON {
                            last = current;
                            let apply_handle = watcher_handle.clone();
                            let _ = watcher_handle.run_on_main_thread(move || {
                                if let Some(window) = apply_handle.get_webview_window("main") {
                                    let _ = window.set_zoom(current);
                                }
                            });
                        }
                    }
                });
            }

            {
                use tauri_plugin_deep_link::DeepLinkExt;
                let handle = app.handle().clone();
                if let Ok(Some(urls)) = app.deep_link().get_current() {
                    if let Some(url) = urls
                        .iter()
                        .map(|url| url.to_string())
                        .find(|url| url.starts_with("aster-mail://"))
                    {
                        tracing::info!("deep-link present at startup: {}", url);
                        if let Ok(mut pending) = app.state::<PendingDeepLink>().0.lock() {
                            *pending = Some(url);
                        }
                    }
                }

                app.deep_link().on_open_url(move |event| {
                    for url in event.urls() {
                        let url_str = url.to_string();
                        if !url_str.starts_with("aster-mail://") {
                            continue;
                        }
                        tracing::info!("deep-link received: {}", url_str);
                        if let Some(window) = handle.get_webview_window("main") {
                            let _ = window.show();
                            let _ = window.unminimize();
                            let _ = window.set_focus();
                        }
                        let _ = handle.emit("deep_link", url_str);
                    }
                });
            }


            if !service_mode {
                #[cfg(target_os = "macos")]
                shell::install_app_menu(app)?;
                app.on_menu_event(|app, event| shell::handle_menu_action(app, event.id.as_ref()));
                let tray = shell::build_tray(app)?;
                let tray_state: State<TrayState> = app.state();
                if let Ok(mut tray_guard) = tray_state.0.lock() {
                    *tray_guard = Some(tray);
                }
                shell::start_tray_refresh_loop(app.handle());
            }

            if has_device_id {
                let app_handle = app.handle().clone();
                tauri::async_runtime::spawn(async move {
                    let app_state: State<AppState> = app_handle.state();
                    let mut guard = app_state.0.lock().await;

                    let restore_result = auth::session::restore_or_login(
                        &guard.config,
                        &guard.identity,
                        &guard.client,
                    )
                    .await;

                    match restore_result {
                        Ok(session) => {
                            let session_arc = Arc::new(RwLock::new(session));
                            guard.session = Some(session_arc.clone());

                            {
                                let s = session_arc.read().await;
                                if let Ok(profile) = guard.client.get_user_profile(&s.access_token).await {
                                    guard.display_name = profile.display_name;
                                    guard.profile_picture = profile.profile_picture;
                                    guard.profile_color = profile.profile_color;
                                }
                            }

                            drop(guard);
                            let shared = app_state.0.clone();
                            match start_runtime(&shared).await {
                                Ok(()) => tracing::info!("auto-started bridge"),
                                Err(runtime::StartError::PlanCheckFailed(e)) => {
                                    tracing::warn!("bridge auto-start could not confirm the plan: {}", e);
                                    let mut guard = shared.lock().await;
                                    guard.has_bridge_access = false;
                                    guard.plan_info_loaded = true;
                                }
                                Err(e) => tracing::warn!("bridge auto-start did not start: {}", e),
                            }
                            let _ = app_handle.emit("state_updated", ());
                            shell::refresh_tray(&app_handle);
                        }
                        Err(e) => {
                            let msg = e.to_string();
                            tracing::warn!("auto-login failed, setup required: {}", msg);
                            if msg.contains("401") || msg.to_lowercase().contains("unauthorized") {
                                let data_dir = guard.config.data_dir.clone();
                                let _ = auth::device_identity::clear_device_id(&data_dir);
                                auth::device_identity::clear_passphrase(&data_dir);
                                guard.identity.device_id = None;
                                guard.session = None;
                                guard.display_name = None;
                                guard.profile_picture = None;
                                guard.profile_color = None;
                                guard.plan_code = None;
                                guard.has_bridge_access = false;
                                guard.passwords = None;
                                guard.stop_runtime(runtime::StopReason::UserRequested);
                                drop(guard);
                                let _ = app_handle.emit("session_expired", ());
                            }
                        }
                    }
                });
            }

            Ok(())
        })
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                shell::hide_main_window(window.app_handle());
            }
            #[cfg(target_os = "macos")]
            if let WindowEvent::ThemeChanged(theme) = event {
                dock_icon::apply(*theme);
            }
        })
        .build(tauri::generate_context!())
        .expect("failed to start aster bridge desktop")
        .run(|app, event| match event {
            tauri::RunEvent::ExitRequested { api, code, .. } => {
                if code.is_none() {
                    api.prevent_exit();
                    shell::request_quit(app);
                }
            }
            #[cfg(target_os = "macos")]
            tauri::RunEvent::Reopen { .. } => shell::show_main_window(app),
            _ => {}
        });
}
