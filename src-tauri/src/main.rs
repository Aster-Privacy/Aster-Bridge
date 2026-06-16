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

mod api_client;
mod auth;
mod config;
mod conn_limit;
mod crypto;
mod db;
mod diagnostics;
mod error;
mod imap;
mod jmap;
mod pop3;
mod outbox;
mod port_picker;
#[cfg(test)]
mod protocol_harness;
mod smtp;
mod sync;
mod tls;

use std::sync::Arc;
use tauri::{
    menu::{Menu, MenuItem, PredefinedMenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    Emitter, Manager, State, WindowEvent,
};
use tauri_plugin_autostart::MacosLauncher;
use tokio::sync::{Mutex as AsyncMutex, RwLock};
use tracing_subscriber::EnvFilter;

struct BridgeState {
    config: config::BridgeConfig,
    session: Option<Arc<RwLock<auth::session::Session>>>,
    db: Arc<db::Database>,
    client: Arc<api_client::ApiClient>,
    passwords: Option<Arc<auth::app_passwords::AppPasswords>>,
    running: bool,
    imap_handle: Option<tokio::task::JoinHandle<()>>,
    imaps_handle: Option<tokio::task::JoinHandle<()>>,
    smtp_handle: Option<tokio::task::JoinHandle<()>>,
    smtps_handle: Option<tokio::task::JoinHandle<()>>,
    jmap_handle: Option<tokio::task::JoinHandle<()>>,
    pop3_handle: Option<tokio::task::JoinHandle<()>>,
    pop3s_handle: Option<tokio::task::JoinHandle<()>>,
    sync_handle: Option<tokio::task::JoinHandle<()>>,
    gc_handle: Option<tokio::task::JoinHandle<()>>,
    outbox_handle: Option<tokio::task::JoinHandle<()>>,
    token_refresh_handle: Option<tokio::task::JoinHandle<()>>,
    sync_trigger: Option<sync::poller::SyncTriggerTx>,
    outbox_trigger: Option<tokio::sync::mpsc::Sender<i64>>,
    bound_imap_port: u16,
    bound_smtp_port: u16,
    bound_jmap_port: u16,
    bound_imaps_port: u16,
    bound_smtps_port: u16,
    bound_pop3_port: u16,
    bound_pop3s_port: u16,
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

type SharedBridgeState = Arc<AsyncMutex<BridgeState>>;

struct AppState(SharedBridgeState);

struct TrayState(std::sync::Mutex<Option<tauri::tray::TrayIcon>>);

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
    email: String,
    display_name: Option<String>,
    profile_picture: Option<String>,
    profile_color: Option<String>,
    plan_code: Option<String>,
    has_bridge_access: bool,
    plan_info_loaded: bool,
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

    let imap_running = guard.imap_handle.as_ref().map_or(false, |h| !h.is_finished());
    let smtp_running = guard.smtp_handle.as_ref().map_or(false, |h| !h.is_finished());
    let jmap_running = guard.jmap_handle.as_ref().map_or(false, |h| !h.is_finished());
    let pop3_running = guard.pop3_handle.as_ref().map_or(false, |h| !h.is_finished());

    Ok(BridgeStatusResponse {
        connected,
        imap_running,
        smtp_running,
        jmap_running,
        pop3_running,
        email,
        display_name: guard.display_name.clone(),
        profile_picture: guard.profile_picture.clone(),
        profile_color: guard.profile_color.clone(),
        plan_code: guard.plan_code.clone(),
        has_bridge_access: guard.has_bridge_access,
        plan_info_loaded: guard.plan_info_loaded,
    })
}

#[tauri::command]
async fn start_bridge(state: State<'_, AppState>) -> Result<(), String> {
    let mut guard = state.0.lock().await;

    if guard.running {
        return Ok(());
    }

    if guard.plan_info_loaded && !guard.has_bridge_access {
        return Err("bridge_access_required".to_string());
    }

    let session = guard
        .session
        .as_ref()
        .ok_or_else(|| "not authenticated - run setup first".to_string())?
        .clone();

    let db = guard.db.clone();
    let client = guard.client.clone();

    let passwords = match guard.passwords.as_ref() {
        Some(p) => p.clone(),
        None => {
            let pw = Arc::new(auth::app_passwords::AppPasswords::new(db.clone()));
            guard.passwords = Some(pw.clone());
            pw
        }
    };

    let host = "127.0.0.1";
    let imap_port = port_picker::pick_available_port(host, guard.config.imap_port)?;
    let smtp_port = port_picker::pick_available_port(host, guard.config.smtp_port)?;
    let jmap_port = port_picker::pick_available_port(host, guard.config.jmap_port)?;
    let imap_addr = format!("{}:{}", host, imap_port);
    let smtp_addr = format!("{}:{}", host, smtp_port);
    let jmap_addr = format!("{}:{}", host, jmap_port);
    let jmap_enabled = guard.config.jmap_enabled;
    let tls_enabled = guard.config.tls_enabled;
    let jmap_https_enabled = guard.config.jmap_https_enabled && tls_enabled;
    let poll_interval_secs = guard.config.poll_interval_secs;

    let mut config_dirty = false;
    if imap_port != guard.config.imap_port {
        guard.config.imap_port = imap_port;
        config_dirty = true;
    }
    if smtp_port != guard.config.smtp_port {
        guard.config.smtp_port = smtp_port;
        config_dirty = true;
    }
    if jmap_port != guard.config.jmap_port {
        guard.config.jmap_port = jmap_port;
        config_dirty = true;
    }
    if config_dirty {
        let _ = config::save_config(&guard.config);
    }
    guard.bound_imap_port = imap_port;
    guard.bound_smtp_port = smtp_port;
    guard.bound_jmap_port = jmap_port;

    let tls_cfg_opt: Option<Arc<rustls::ServerConfig>> = if tls_enabled {
        guard.tls_server_config.clone()
    } else {
        None
    };
    let imaps_port = if tls_cfg_opt.is_some() {
        port_picker::pick_available_port(host, guard.config.imap_implicit_tls_port).unwrap_or(0)
    } else { 0 };
    let smtps_port = if tls_cfg_opt.is_some() {
        port_picker::pick_available_port(host, guard.config.smtp_implicit_tls_port).unwrap_or(0)
    } else { 0 };
    guard.bound_imaps_port = imaps_port;
    guard.bound_smtps_port = smtps_port;

    let jmap_broadcaster = jmap::state::broadcaster();

    let imap_session = session.clone();
    let imap_db = db.clone();
    let imap_client = client.clone();
    let imap_passwords = passwords.clone();
    let imap_broadcaster = jmap_broadcaster.clone();
    let imap_tls = tls_cfg_opt.clone();
    let imap_handle = tokio::spawn(async move {
        if let Err(e) = imap::server::run(
            &imap_addr,
            imap_session,
            imap_db,
            imap_client,
            imap_passwords,
            imap_broadcaster,
            imap_tls,
        )
        .await
        {
            tracing::error!("IMAP server error: {}", e);
        }
    });

    let imaps_handle = if let Some(cfg) = tls_cfg_opt.clone() {
        if imaps_port != 0 {
            let s = session.clone();
            let d = db.clone();
            let c = client.clone();
            let p = passwords.clone();
            let b = jmap_broadcaster.clone();
            let addr = format!("{}:{}", host, imaps_port);
            Some(tokio::spawn(async move {
                if let Err(e) = imap::server::run_implicit_tls(&addr, s, d, c, p, b, cfg).await {
                    tracing::error!("IMAPS server error: {}", e);
                }
            }))
        } else { None }
    } else { None };

    let smtp_session = session.clone();
    let smtp_client = client.clone();
    let smtp_passwords = passwords.clone();
    let smtp_db = db.clone();
    let smtp_tls = tls_cfg_opt.clone();
    let smtp_handle = tokio::spawn(async move {
        if let Err(e) = smtp::server::run(&smtp_addr, smtp_session, smtp_client, smtp_passwords, smtp_db, smtp_tls).await
        {
            tracing::error!("SMTP server error: {}", e);
        }
    });

    let smtps_handle = if let Some(cfg) = tls_cfg_opt.clone() {
        if smtps_port != 0 {
            let s = session.clone();
            let c = client.clone();
            let p = passwords.clone();
            let d = db.clone();
            let addr = format!("{}:{}", host, smtps_port);
            Some(tokio::spawn(async move {
                if let Err(e) = smtp::server::run_implicit_tls(&addr, s, c, p, d, cfg).await {
                    tracing::error!("SMTPS server error: {}", e);
                }
            }))
        } else { None }
    } else { None };

    let jmap_handle = if jmap_enabled {
        let jmap_session = session.clone();
        let jmap_db = db.clone();
        let jmap_client = client.clone();
        let jmap_passwords = passwords.clone();
        let jmap_tx = jmap_broadcaster.clone();
        let jmap_tls = if jmap_https_enabled { tls_cfg_opt.clone() } else { None };
        Some(tokio::spawn(async move {
            if let Err(e) = jmap::server::run(
                &jmap_addr,
                jmap_session,
                jmap_db,
                jmap_client,
                jmap_passwords,
                jmap_tx,
                jmap_tls,
            )
            .await
            {
                tracing::error!("JMAP server error: {}", e);
            }
        }))
    } else {
        None
    };

    let pop3_port = port_picker::pick_available_port(host, guard.config.pop3_port).unwrap_or(0);
    let pop3s_port = if tls_cfg_opt.is_some() {
        port_picker::pick_available_port(host, guard.config.pop3s_port).unwrap_or(0)
    } else { 0 };
    guard.bound_pop3_port = pop3_port;
    guard.bound_pop3s_port = pop3s_port;

    let pop3_handle = if pop3_port != 0 {
        let p3_session = session.clone();
        let p3_db = db.clone();
        let p3_passwords = passwords.clone();
        let p3_tls = tls_cfg_opt.clone();
        let p3_addr = format!("{}:{}", host, pop3_port);
        Some(tokio::spawn(async move {
            if let Err(e) = pop3::server::run(&p3_addr, p3_session, p3_db, p3_passwords, p3_tls).await {
                tracing::error!("POP3 server error: {}", e);
            }
        }))
    } else { None };

    let pop3s_handle = if let Some(cfg) = tls_cfg_opt.clone() {
        if pop3s_port != 0 {
            let p3s_session = session.clone();
            let p3s_db = db.clone();
            let p3s_passwords = passwords.clone();
            let p3s_addr = format!("{}:{}", host, pop3s_port);
            Some(tokio::spawn(async move {
                if let Err(e) = pop3::server::run_implicit_tls(&p3s_addr, p3s_session, p3s_db, p3s_passwords, cfg).await {
                    tracing::error!("POP3S server error: {}", e);
                }
            }))
        } else { None }
    } else { None };

    let sync_session = session.clone();
    let sync_client = client.clone();
    let sync_db = db.clone();
    let sync_broadcaster = Some(jmap_broadcaster);
    let (sync_tx, sync_rx) = sync::poller::sync_trigger_channel();
    let sync_handle = tokio::spawn(async move {
        sync::poller::run_poll_loop(
            sync_session,
            sync_client,
            sync_db,
            sync_broadcaster,
            sync_rx,
            Some(poll_interval_secs),
        )
        .await;
    });
    sync::poller::set_global_sync_trigger(Some(sync_tx.clone()));
    guard.sync_trigger = Some(sync_tx);

    let gc_db = db.clone();
    let gc_handle = tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(3600));
        loop {
            tick.tick().await;
            match gc_db.jmap_blob_gc(24 * 3600) {
                Ok(0) => {}
                Ok(n) => tracing::debug!("jmap_blob GC removed {} expired blobs", n),
                Err(e) => tracing::warn!("jmap_blob GC failed: {}", e),
            }
        }
    });

    let _ = db.outbox_reset_stale_sending();

    let outbox_session = session.clone();
    let outbox_client = client.clone();
    let outbox_db = db.clone();
    let (outbox_tx, outbox_rx) = outbox::outbox_trigger_channel();
    let outbox_handle = tokio::spawn(async move {
        outbox::run_outbox_loop(outbox_session, outbox_client, outbox_db, outbox_rx).await;
    });
    guard.outbox_trigger = Some(outbox_tx);

    let refresh_session = session.clone();
    let refresh_client = client.clone();
    let refresh_state = state.0.clone();
    let token_refresh_handle = tokio::spawn(async move {
        let mut consecutive_failures: u32 = 0;
        loop {
            let wait_secs = if consecutive_failures == 0 { 50 * 60 } else { 60 };
            tokio::time::sleep(std::time::Duration::from_secs(wait_secs)).await;
            let (device_id, signing_key) = {
                let guard = refresh_state.lock().await;
                match guard.identity.device_id {
                    Some(did) => (did, guard.identity.ed25519_signing_key.clone()),
                    None => continue,
                }
            };
            match auth::session::refresh_access_token(
                &refresh_session,
                device_id,
                &signing_key,
                &refresh_client,
            ).await {
                Ok(()) => {
                    if consecutive_failures > 0 {
                        tracing::info!("access token refresh recovered");
                    }
                    consecutive_failures = 0;
                }
                Err(e) => {
                    consecutive_failures = consecutive_failures.saturating_add(1);
                    tracing::warn!("proactive token refresh failed (attempt {}): {}", consecutive_failures, e);
                    if consecutive_failures == 5 {
                        sync::poller::emit_session_expired();
                    }
                }
            }
        }
    });

    guard.imap_handle = Some(imap_handle);
    guard.imaps_handle = imaps_handle;
    guard.smtp_handle = Some(smtp_handle);
    guard.smtps_handle = smtps_handle;
    guard.jmap_handle = jmap_handle;
    guard.pop3_handle = pop3_handle;
    guard.pop3s_handle = pop3s_handle;
    guard.sync_handle = Some(sync_handle);
    guard.gc_handle = Some(gc_handle);
    guard.outbox_handle = Some(outbox_handle);
    guard.token_refresh_handle = Some(token_refresh_handle);
    guard.running = true;

    tracing::info!(
        "bridge started - IMAP on 127.0.0.1:{}, SMTP on 127.0.0.1:{}, JMAP on 127.0.0.1:{} (enabled={}, tls={})",
        imap_port,
        smtp_port,
        jmap_port,
        jmap_enabled,
        tls_enabled,
    );

    Ok(())
}

#[tauri::command]
async fn stop_bridge(state: State<'_, AppState>) -> Result<(), String> {
    let mut guard = state.0.lock().await;

    if let Some(handle) = guard.imap_handle.take() {
        handle.abort();
    }

    if let Some(handle) = guard.imaps_handle.take() {
        handle.abort();
    }

    if let Some(handle) = guard.smtp_handle.take() {
        handle.abort();
    }

    if let Some(handle) = guard.smtps_handle.take() {
        handle.abort();
    }

    if let Some(handle) = guard.jmap_handle.take() {
        handle.abort();
    }

    if let Some(handle) = guard.pop3_handle.take() {
        handle.abort();
    }

    if let Some(handle) = guard.pop3s_handle.take() {
        handle.abort();
    }

    if let Some(handle) = guard.sync_handle.take() {
        handle.abort();
    }

    if let Some(handle) = guard.gc_handle.take() {
        handle.abort();
    }

    if let Some(handle) = guard.outbox_handle.take() {
        handle.abort();
    }

    if let Some(handle) = guard.token_refresh_handle.take() {
        handle.abort();
    }

    guard.sync_trigger = None;
    guard.outbox_trigger = None;
    sync::poller::set_global_sync_trigger(None);
    guard.running = false;

    tracing::info!("bridge stopped");

    Ok(())
}

#[tauri::command]
async fn sign_out(state: State<'_, AppState>, app_handle: tauri::AppHandle) -> Result<(), String> {
    let mut guard = state.0.lock().await;

    if let Some(handle) = guard.imap_handle.take() {
        handle.abort();
    }
    if let Some(handle) = guard.imaps_handle.take() {
        handle.abort();
    }
    if let Some(handle) = guard.smtp_handle.take() {
        handle.abort();
    }
    if let Some(handle) = guard.smtps_handle.take() {
        handle.abort();
    }
    if let Some(handle) = guard.jmap_handle.take() {
        handle.abort();
    }
    if let Some(handle) = guard.pop3_handle.take() {
        handle.abort();
    }
    if let Some(handle) = guard.pop3s_handle.take() {
        handle.abort();
    }
    if let Some(handle) = guard.sync_handle.take() {
        handle.abort();
    }
    if let Some(handle) = guard.gc_handle.take() {
        handle.abort();
    }
    if let Some(handle) = guard.outbox_handle.take() {
        handle.abort();
    }
    if let Some(handle) = guard.token_refresh_handle.take() {
        handle.abort();
    }
    guard.sync_trigger = None;
    guard.outbox_trigger = None;
    sync::poller::set_global_sync_trigger(None);
    guard.running = false;

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
    let _ = auth::device_identity::clear_device_id(&data_dir);
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
        if plan_result.is_ok() { break; }
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
async fn get_setup_code(state: State<'_, AppState>) -> Result<String, String> {
    let mut guard = state.0.lock().await;

    let (ed25519_pk, mlkem_pk, x25519_pk) =
        auth::device_identity::get_pubkeys(&guard.identity);
    let machine_name = whoami::devicename();

    let code_resp = guard
        .client
        .generate_device_code(&api_client::DeviceCodeRequest {
            ed25519_pk,
            mlkem_pk,
            x25519_pk,
            machine_name,
            device_type: "bridge".to_string(),
        })
        .await
        .map_err(|e| e.to_string())?;

    let code = code_resp.code.clone();
    guard.pending_code = Some(code_resp.code.clone());
    guard.pending_code_normalized = Some(code_resp.code.replace('-', ""));
    guard.pending_expires_in = Some(code_resp.expires_in);

    Ok(code)
}

#[tauri::command]
async fn check_setup_status(state: State<'_, AppState>) -> Result<SetupStatusResponse, String> {
    let mut guard = state.0.lock().await;

    let code_normalized = guard
        .pending_code_normalized
        .as_ref()
        .ok_or_else(|| "no pending setup code - call get_setup_code first".to_string())?
        .clone();

    let status = guard
        .client
        .poll_device_code_status(&code_normalized)
        .await
        .map_err(|e| e.to_string())?;

    match status.status.as_str() {
        "confirmed" => {
            let device_id = status
                .device_id
                .ok_or_else(|| "no device_id in confirmation".to_string())?;

            let sealed_envelope = status
                .sealed_envelope
                .ok_or_else(|| "no sealed envelope in confirmation".to_string())?;

            let passphrase =
                auth::device_identity::unseal_vault_envelope(&guard.identity, &sealed_envelope)
                    .map_err(|e| e.to_string())?;

            auth::device_identity::set_device_id(&guard.config.data_dir, device_id)
                .map_err(|e| e.to_string())?;

            auth::device_identity::store_passphrase(&guard.config.data_dir, &passphrase)
                .map_err(|e| e.to_string())?;

            let challenge = guard
                .client
                .device_challenge(device_id)
                .await
                .map_err(|e| e.to_string())?;

            let signature =
                auth::device_identity::sign_challenge(&guard.identity, &challenge.nonce)
                    .map_err(|e| e.to_string())?;

            let login_resp = guard
                .client
                .device_login(&api_client::DeviceLoginRequest {
                    challenge_id: challenge.challenge_id,
                    signature,
                })
                .await
                .map_err(|e| e.to_string())?;

            let access_token = zeroize::Zeroizing::new(login_resp
                .access_token
                .ok_or_else(|| "no access token in login response".to_string())?);

            let token_for_profile = access_token.clone();
            let token_for_plan = access_token.clone();

            let (identity_key, ratchet_keys) = match crypto::vault::decrypt_vault(
                &login_resp.encrypted_vault,
                &login_resp.vault_nonce,
                &passphrase,
            ) {
                Ok(v) => (
                    Some(v.identity_key.clone()),
                    crypto::ratchet::build_receiver_key_sets(&v),
                ),
                Err(e) => {
                    tracing::warn!("vault decrypt failed at setup: {}", e);
                    (None, Vec::new())
                }
            };

            let send_identities = auth::session::build_send_identities(
                &guard.client,
                &access_token,
                &login_resp.email,
                None,
                &passphrase,
            )
            .await;

            let session = auth::session::Session {
                user_id: login_resp.user_id,
                username: login_resp.username,
                email: login_resp.email,
                access_token,
                vault_passphrase: passphrase,
                identity_key,
                ratchet_keys,
                send_identities,
            };

            let session_arc = Arc::new(RwLock::new(session));
            guard.session = Some(session_arc);

            if let Ok(profile) = guard.client.get_user_profile(&token_for_profile).await {
                guard.display_name = profile.display_name;
                guard.profile_picture = profile.profile_picture;
                guard.profile_color = profile.profile_color;
            }

            let plan_client = guard.client.clone();
            let plan_token = (*token_for_plan).clone();
            drop(guard);
            let mut plan_result = plan_client.get_plan_info(&plan_token).await;
            for attempt in 0..2u8 {
                if plan_result.is_ok() { break; }
                tracing::warn!("plan check attempt {} failed during setup, retrying", attempt + 1);
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                plan_result = plan_client.get_plan_info(&plan_token).await;
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
        "expired" => {
            guard.pending_code = None;
            guard.pending_code_normalized = None;
            guard.pending_expires_in = None;

            Ok(SetupStatusResponse {
                status: "expired".to_string(),
                done: true,
            })
        }
        other => Ok(SetupStatusResponse {
            status: other.to_string(),
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
    client.get_default_sender(&token).await.map_err(|e| e.to_string())
}

#[tauri::command]
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
async fn delete_app_password(
    id: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let guard = state.0.lock().await;

    let passwords = guard
        .passwords
        .as_ref()
        .ok_or_else(|| "not authenticated".to_string())?;

    passwords.delete(&id)
}

#[tauri::command]
async fn get_connection_info(
    state: State<'_, AppState>,
) -> Result<ConnectionInfoResponse, String> {
    let guard = state.0.lock().await;

    let imap_port = if guard.running { guard.bound_imap_port } else { guard.config.imap_port };
    let smtp_port = if guard.running { guard.bound_smtp_port } else { guard.config.smtp_port };
    let jmap_port = if guard.running { guard.bound_jmap_port } else { guard.config.jmap_port };

    let tls_enabled = guard.config.tls_enabled && guard.tls_server_config.is_some();
    let jmap_https_enabled = guard.config.jmap_https_enabled && tls_enabled;
    let jmap_scheme = if jmap_https_enabled { "https" } else { "http" };
    let pop3_port = if guard.running && guard.bound_pop3_port != 0 {
        guard.bound_pop3_port
    } else { guard.config.pop3_port };
    let pop3s_port = if guard.running && guard.bound_pop3s_port != 0 {
        guard.bound_pop3s_port
    } else { guard.config.pop3s_port };
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
        imap_implicit_tls_port: if tls_enabled && guard.running && guard.bound_imaps_port != 0 {
            guard.bound_imaps_port
        } else { guard.config.imap_implicit_tls_port },
        smtp_implicit_tls_port: if tls_enabled && guard.running && guard.bound_smtps_port != 0 {
            guard.bound_smtps_port
        } else { guard.config.smtp_implicit_tls_port },
        jmap_https_enabled,
        pop3_port,
        pop3s_port,
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
    } else { None };
    Ok(TlsInfoResponse {
        tls_enabled,
        fingerprint_sha256: fingerprint,
        cert_path,
        imap_implicit_tls_port: if tls_enabled && guard.running && guard.bound_imaps_port != 0 {
            guard.bound_imaps_port
        } else { guard.config.imap_implicit_tls_port },
        smtp_implicit_tls_port: if tls_enabled && guard.running && guard.bound_smtps_port != 0 {
            guard.bound_smtps_port
        } else { guard.config.smtp_implicit_tls_port },
        jmap_https_enabled,
    })
}

#[tauri::command]
async fn open_tls_cert(state: State<'_, AppState>) -> Result<(), String> {
    let dir = {
        let guard = state.0.lock().await;
        let cert_path = tls::cert_pem_path(&guard.config.data_dir);
        cert_path.parent()
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
async fn get_data_directory(
    state: State<'_, AppState>,
) -> Result<String, String> {
    let guard = state.0.lock().await;
    Ok(guard.config.data_dir.to_string_lossy().to_string())
}

#[tauri::command]
async fn open_data_directory(
    state: State<'_, AppState>,
) -> Result<(), String> {
    let guard = state.0.lock().await;
    let dir = guard.config.data_dir.clone();
    drop(guard);
    let canonical = std::fs::canonicalize(&dir).map_err(|e| e.to_string())?;
    if !canonical.is_dir() {
        return Err("data_dir is not a directory".to_string());
    }
    open::that(&canonical).map_err(|e| e.to_string())
}

#[tauri::command]
async fn update_connection_settings(
    state: State<'_, AppState>,
    imap_port: u16,
    smtp_port: u16,
) -> Result<(), String> {
    validate_port(imap_port).map_err(|e| format!("imap_port: {}", e))?;
    validate_port(smtp_port).map_err(|e| format!("smtp_port: {}", e))?;
    if imap_port == smtp_port {
        return Err("imap_port and smtp_port must differ".to_string());
    }
    let mut guard = state.0.lock().await;
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
    let store_label = if trimmed.is_empty() { "Auto-provisioned" } else { trimmed };
    let password = auth::app_passwords::generate_app_password();
    passwords.store(store_label, &password)?;

    let imap_port = if guard.running { guard.bound_imap_port } else { guard.config.imap_port };
    let smtp_port = if guard.running { guard.bound_smtp_port } else { guard.config.smtp_port };
    let jmap_port = if guard.running { guard.bound_jmap_port } else { guard.config.jmap_port };

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
            if guard.config.jmap_https_enabled && guard.config.tls_enabled && guard.tls_server_config.is_some() {
                "https"
            } else {
                "http"
            },
            jmap_port
        ),
        jmap_enabled: guard.config.jmap_enabled,
    })
}

#[derive(serde::Serialize)]
struct ServiceSettingsResponse {
    service_mode: bool,
    autostart: bool,
}

#[tauri::command]
async fn get_service_settings(state: State<'_, AppState>) -> Result<ServiceSettingsResponse, String> {
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
        guard
            .sync_trigger
            .as_ref()
            .ok_or_else(|| "bridge is not running".to_string())?
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
        (
            guard.db.clone(),
            guard.sync_trigger.as_ref().cloned(),
        )
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
        guard
            .outbox_trigger
            .as_ref()
            .ok_or_else(|| "bridge is not running".to_string())?
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
        (guard.config.clone(), guard.config.data_dir.clone(), guard.db.clone())
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
        db_stats: DbStats { messages, passwords, last_sync_ts },
    };
    let serialized = serde_json::to_string_pretty(&bundle).map_err(|e| e.to_string())?;
    Ok(serialized)
}

fn validate_port(port: u16) -> Result<(), &'static str> {
    if port < 1024 {
        return Err("port must be >= 1024");
    }
    match port {
        3306 | 5432 | 6379 | 27017 => Err("well-known service port not allowed"),
        _ => Ok(()),
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
            let file_appender = tracing_appender::rolling::daily(
                diagnostics::log_dir(&c.data_dir),
                "bridge.log",
            );
            let (file_writer, file_guard) = tracing_appender::non_blocking(file_appender);
            let filter = EnvFilter::from_default_env()
                .add_directive("aster_bridge=info".parse().unwrap());
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

    let imap_port_initial = cfg.imap_port;
    let smtp_port_initial = cfg.smtp_port;
    let jmap_port_initial = cfg.jmap_port;
    let bridge_state = Arc::new(AsyncMutex::new(BridgeState {
        config: cfg,
        session: None,
        db: shared_db,
        client,
        passwords: None,
        running: false,
        imap_handle: None,
        imaps_handle: None,
        smtp_handle: None,
        smtps_handle: None,
        jmap_handle: None,
        pop3_handle: None,
        pop3s_handle: None,
        sync_handle: None,
        gc_handle: None,
        outbox_handle: None,
        sync_trigger: None,
        outbox_trigger: None,
        bound_imap_port: imap_port_initial,
        bound_smtp_port: smtp_port_initial,
        bound_jmap_port: jmap_port_initial,
        bound_imaps_port: 0,
        bound_smtps_port: 0,
        bound_pop3_port: 0,
        bound_pop3s_port: 0,
        tls_server_config,
        token_refresh_handle: None,
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

    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
                let _ = window.unminimize();
                let _ = window.set_focus();
            }
        }))
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_autostart::init(
            MacosLauncher::LaunchAgent,
            Some(vec!["--service"]),
        ))
        .plugin(tauri_plugin_deep_link::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_process::init())
        .manage(AppState(bridge_state))
        .manage(TrayState(std::sync::Mutex::new(None)))
        .invoke_handler(tauri::generate_handler![
            get_bridge_status,
            start_bridge,
            stop_bridge,
            sign_out,
            reset_bridge_data,
            refresh_plan_info,
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
            sync::poller::set_global_app_handle(Some(app.handle().clone()));

            #[cfg(target_os = "macos")]
            let icon_bytes = include_bytes!("../icons/icon.icns");
            #[cfg(not(target_os = "macos"))]
            let icon_bytes = include_bytes!("../icons/128x128.png");

            let icon =
                tauri::image::Image::from_bytes(icon_bytes).expect("failed to load tray icon");

            if service_mode {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.hide();
                }
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

            if service_mode {
                tracing::info!("running in service mode: tray disabled, window hidden");
            } else {

            let status = MenuItem::with_id(app, "status", "Aster Bridge", false, None::<&str>)?;
            let sep1 = PredefinedMenuItem::separator(app)?;
            let show = MenuItem::with_id(app, "show", "Show Window", true, None::<&str>)?;
            let sep2 = PredefinedMenuItem::separator(app)?;
            let quit = MenuItem::with_id(app, "quit", "Quit Aster Bridge", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&status, &sep1, &show, &sep2, &quit])?;

            let tray = TrayIconBuilder::new()
                .icon(icon)
                .menu(&menu)
                .tooltip("Aster Bridge")
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "show" => {
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.show();
                            let _ = window.unminimize();
                            let _ = window.set_focus();
                        }
                    }
                    "quit" => {
                        app.exit(0);
                    }
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        let app = tray.app_handle();
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.show();
                            let _ = window.set_focus();
                        }
                    }
                })
                .build(app)?;

            let tray_state: State<TrayState> = app.state();
            if let Ok(mut tray_guard) = tray_state.0.lock() {
                *tray_guard = Some(tray);
            };

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

                            let plan_client = guard.client.clone();
                            let plan_token = {
                                let s = session_arc.read().await;
                                (*s.access_token).clone()
                            };
                            drop(guard);
                            let mut plan_result = plan_client.get_plan_info(&plan_token).await;
                            for attempt in 0..2u8 {
                                if plan_result.is_ok() { break; }
                                tracing::warn!("plan check attempt {} failed during restore, retrying", attempt + 1);
                                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                                plan_result = plan_client.get_plan_info(&plan_token).await;
                            }
                            let mut guard = app_state.0.lock().await;
                            if let Ok(plan_info) = plan_result {
                                guard.has_bridge_access = plan_info.has_bridge_access;
                                guard.plan_code = Some(plan_info.plan_code);
                            } else {
                                guard.has_bridge_access = false;
                            }
                            guard.plan_info_loaded = true;
                            if !guard.has_bridge_access {
                                drop(guard);
                                let _ = app_handle.emit("state_updated", ());
                                return;
                            }

                            let passwords = Arc::new(auth::app_passwords::AppPasswords::new(
                                guard.db.clone(),
                            ));
                            guard.passwords = Some(passwords.clone());

                            let host = "127.0.0.1";
                            let imap_port = match port_picker::pick_available_port(host, guard.config.imap_port) {
                                Ok(p) => p,
                                Err(e) => { tracing::error!("imap port pick failed: {}", e); return; }
                            };
                            let smtp_port = match port_picker::pick_available_port(host, guard.config.smtp_port) {
                                Ok(p) => p,
                                Err(e) => { tracing::error!("smtp port pick failed: {}", e); return; }
                            };
                            let jmap_port = match port_picker::pick_available_port(host, guard.config.jmap_port) {
                                Ok(p) => p,
                                Err(e) => { tracing::error!("jmap port pick failed: {}", e); return; }
                            };
                            let imap_addr = format!("{}:{}", host, imap_port);
                            let smtp_addr = format!("{}:{}", host, smtp_port);
                            let jmap_addr = format!("{}:{}", host, jmap_port);
                            let mut config_dirty = false;
                            if imap_port != guard.config.imap_port { guard.config.imap_port = imap_port; config_dirty = true; }
                            if smtp_port != guard.config.smtp_port { guard.config.smtp_port = smtp_port; config_dirty = true; }
                            if jmap_port != guard.config.jmap_port { guard.config.jmap_port = jmap_port; config_dirty = true; }
                            if config_dirty { let _ = config::save_config(&guard.config); }
                            guard.bound_imap_port = imap_port;
                            guard.bound_smtp_port = smtp_port;
                            guard.bound_jmap_port = jmap_port;
                            let jmap_enabled = guard.config.jmap_enabled;
                            let poll_interval_secs_inner = guard.config.poll_interval_secs;
                            let db = guard.db.clone();
                            let client = guard.client.clone();

                            let jmap_broadcaster = jmap::state::broadcaster();

                            let tls_enabled = guard.config.tls_enabled;
                            let jmap_https_enabled = guard.config.jmap_https_enabled && tls_enabled;
                            let tls_cfg_opt: Option<Arc<rustls::ServerConfig>> = if tls_enabled {
                                guard.tls_server_config.clone()
                            } else {
                                None
                            };
                            let imaps_port = if tls_cfg_opt.is_some() {
                                port_picker::pick_available_port(host, guard.config.imap_implicit_tls_port).unwrap_or(0)
                            } else { 0 };
                            let smtps_port = if tls_cfg_opt.is_some() {
                                port_picker::pick_available_port(host, guard.config.smtp_implicit_tls_port).unwrap_or(0)
                            } else { 0 };
                            guard.bound_imaps_port = imaps_port;
                            guard.bound_smtps_port = smtps_port;

                            let imap_session = session_arc.clone();
                            let imap_db = db.clone();
                            let imap_client = client.clone();
                            let imap_passwords = passwords.clone();
                            let imap_broadcaster = jmap_broadcaster.clone();
                            let imap_tls = tls_cfg_opt.clone();
                            let imap_handle = tokio::spawn(async move {
                                if let Err(e) = imap::server::run(
                                    &imap_addr,
                                    imap_session,
                                    imap_db,
                                    imap_client,
                                    imap_passwords,
                                    imap_broadcaster,
                                    imap_tls,
                                )
                                .await
                                {
                                    tracing::error!("IMAP server error: {}", e);
                                }
                            });

                            let imaps_handle = if let Some(cfg) = tls_cfg_opt.clone() {
                                if imaps_port != 0 {
                                    let s = session_arc.clone();
                                    let d = db.clone();
                                    let c = client.clone();
                                    let p = passwords.clone();
                                    let b = jmap_broadcaster.clone();
                                    let addr = format!("{}:{}", host, imaps_port);
                                    Some(tokio::spawn(async move {
                                        if let Err(e) = imap::server::run_implicit_tls(&addr, s, d, c, p, b, cfg).await {
                                            tracing::error!("IMAPS server error: {}", e);
                                        }
                                    }))
                                } else { None }
                            } else { None };

                            let smtp_session = session_arc.clone();
                            let smtp_client = client.clone();
                            let smtp_passwords = passwords.clone();
                            let smtp_db = db.clone();
                            let smtp_tls = tls_cfg_opt.clone();
                            let smtp_handle = tokio::spawn(async move {
                                if let Err(e) = smtp::server::run(
                                    &smtp_addr,
                                    smtp_session,
                                    smtp_client,
                                    smtp_passwords,
                                    smtp_db,
                                    smtp_tls,
                                )
                                .await
                                {
                                    tracing::error!("SMTP server error: {}", e);
                                }
                            });

                            let smtps_handle = if let Some(cfg) = tls_cfg_opt.clone() {
                                if smtps_port != 0 {
                                    let s = session_arc.clone();
                                    let c = client.clone();
                                    let p = passwords.clone();
                                    let d = db.clone();
                                    let addr = format!("{}:{}", host, smtps_port);
                                    Some(tokio::spawn(async move {
                                        if let Err(e) = smtp::server::run_implicit_tls(&addr, s, c, p, d, cfg).await {
                                            tracing::error!("SMTPS server error: {}", e);
                                        }
                                    }))
                                } else { None }
                            } else { None };

                            let jmap_handle = if jmap_enabled {
                                let jmap_session = session_arc.clone();
                                let jmap_db = db.clone();
                                let jmap_client = client.clone();
                                let jmap_passwords = passwords.clone();
                                let jmap_tx = jmap_broadcaster.clone();
                                let jmap_tls = if jmap_https_enabled { tls_cfg_opt.clone() } else { None };
                                Some(tokio::spawn(async move {
                                    if let Err(e) = jmap::server::run(
                                        &jmap_addr,
                                        jmap_session,
                                        jmap_db,
                                        jmap_client,
                                        jmap_passwords,
                                        jmap_tx,
                                        jmap_tls,
                                    )
                                    .await
                                    {
                                        tracing::error!("JMAP server error: {}", e);
                                    }
                                }))
                            } else {
                                None
                            };

                            let sync_session = session_arc.clone();
                            let sync_client = client.clone();
                            let sync_db = db.clone();
                            let sync_broadcaster = Some(jmap_broadcaster);
                            let (sync_tx, sync_rx) = sync::poller::sync_trigger_channel();
                            let sync_handle = tokio::spawn(async move {
                                sync::poller::run_poll_loop(
                                    sync_session,
                                    sync_client,
                                    sync_db,
                                    sync_broadcaster,
                                    sync_rx,
                                    Some(poll_interval_secs_inner),
                                )
                                .await;
                            });
                            sync::poller::set_global_sync_trigger(Some(sync_tx.clone()));
                            guard.sync_trigger = Some(sync_tx);

                            let gc_db = db.clone();
                            let gc_handle = tokio::spawn(async move {
                                let mut tick = tokio::time::interval(std::time::Duration::from_secs(3600));
                                loop {
                                    tick.tick().await;
                                    match gc_db.jmap_blob_gc(24 * 3600) {
                                        Ok(0) => {}
                                        Ok(n) => tracing::debug!("jmap_blob GC removed {} expired blobs", n),
                                        Err(e) => tracing::warn!("jmap_blob GC failed: {}", e),
                                    }
                                }
                            });

                            let _ = db.outbox_reset_stale_sending();

                            let outbox_session = session_arc.clone();
                            let outbox_client = client.clone();
                            let outbox_db = db.clone();
                            let (outbox_tx, outbox_rx) = outbox::outbox_trigger_channel();
                            let outbox_handle = tokio::spawn(async move {
                                outbox::run_outbox_loop(outbox_session, outbox_client, outbox_db, outbox_rx).await;
                            });
                            guard.outbox_trigger = Some(outbox_tx);

                            let pop3_port = port_picker::pick_available_port(host, guard.config.pop3_port).unwrap_or(0);
                            let pop3s_port = if tls_cfg_opt.is_some() {
                                port_picker::pick_available_port(host, guard.config.pop3s_port).unwrap_or(0)
                            } else { 0 };
                            guard.bound_pop3_port = pop3_port;
                            guard.bound_pop3s_port = pop3s_port;

                            let pop3_handle = if pop3_port != 0 {
                                let p3_session = session_arc.clone();
                                let p3_db = db.clone();
                                let p3_passwords = passwords.clone();
                                let p3_tls = tls_cfg_opt.clone();
                                let p3_addr = format!("{}:{}", host, pop3_port);
                                Some(tokio::spawn(async move {
                                    if let Err(e) = pop3::server::run(&p3_addr, p3_session, p3_db, p3_passwords, p3_tls).await {
                                        tracing::error!("POP3 server error: {}", e);
                                    }
                                }))
                            } else { None };

                            let pop3s_handle = if let Some(cfg) = tls_cfg_opt.clone() {
                                if pop3s_port != 0 {
                                    let p3s_session = session_arc.clone();
                                    let p3s_db = db.clone();
                                    let p3s_passwords = passwords.clone();
                                    let p3s_addr = format!("{}:{}", host, pop3s_port);
                                    Some(tokio::spawn(async move {
                                        if let Err(e) = pop3::server::run_implicit_tls(&p3s_addr, p3s_session, p3s_db, p3s_passwords, cfg).await {
                                            tracing::error!("POP3S server error: {}", e);
                                        }
                                    }))
                                } else { None }
                            } else { None };

                            let refresh_session_inner = session_arc.clone();
                            let refresh_client_inner = client.clone();
                            let refresh_device_id = guard.identity.device_id;
                            let refresh_signing_key = guard.identity.ed25519_signing_key.clone();
                            let token_refresh_handle = tokio::spawn(async move {
                                let Some(device_id) = refresh_device_id else { return; };
                                let mut consecutive_failures: u32 = 0;
                                loop {
                                    let wait_secs = if consecutive_failures == 0 { 50 * 60 } else { 60 };
                                    tokio::time::sleep(std::time::Duration::from_secs(wait_secs)).await;
                                    match auth::session::refresh_access_token(
                                        &refresh_session_inner,
                                        device_id,
                                        &refresh_signing_key,
                                        &refresh_client_inner,
                                    ).await {
                                        Ok(()) => {
                                            if consecutive_failures > 0 {
                                                tracing::info!("access token refresh recovered");
                                            }
                                            consecutive_failures = 0;
                                        }
                                        Err(e) => {
                                            consecutive_failures = consecutive_failures.saturating_add(1);
                                            tracing::warn!("proactive token refresh failed (attempt {}): {}", consecutive_failures, e);
                                            if consecutive_failures == 5 {
                                                sync::poller::emit_session_expired();
                                            }
                                        }
                                    }
                                }
                            });

                            guard.imap_handle = Some(imap_handle);
                            guard.imaps_handle = imaps_handle;
                            guard.smtp_handle = Some(smtp_handle);
                            guard.smtps_handle = smtps_handle;
                            guard.jmap_handle = jmap_handle;
                            guard.pop3_handle = pop3_handle;
                            guard.pop3s_handle = pop3s_handle;
                            guard.sync_handle = Some(sync_handle);
                            guard.gc_handle = Some(gc_handle);
                            guard.outbox_handle = Some(outbox_handle);
                            guard.token_refresh_handle = Some(token_refresh_handle);
                            guard.running = true;
                            drop(guard);
                            let _ = app_handle.emit("state_updated", ());

                            tracing::info!(
                                "auto-started bridge - IMAP on 127.0.0.1:{}, SMTP on 127.0.0.1:{}, JMAP on 127.0.0.1:{} (enabled={})",
                                imap_port,
                                smtp_port,
                                jmap_port,
                                jmap_enabled,
                            );
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
                                if let Some(h) = guard.imap_handle.take() { h.abort(); }
                                if let Some(h) = guard.imaps_handle.take() { h.abort(); }
                                if let Some(h) = guard.smtp_handle.take() { h.abort(); }
                                if let Some(h) = guard.smtps_handle.take() { h.abort(); }
                                if let Some(h) = guard.jmap_handle.take() { h.abort(); }
                                if let Some(h) = guard.pop3_handle.take() { h.abort(); }
                                if let Some(h) = guard.pop3s_handle.take() { h.abort(); }
                                if let Some(h) = guard.sync_handle.take() { h.abort(); }
                                if let Some(h) = guard.gc_handle.take() { h.abort(); }
                                if let Some(h) = guard.outbox_handle.take() { h.abort(); }
                                guard.outbox_trigger = None;
                                guard.running = false;
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
                let _ = window.hide();
            }
        })
        .run(tauri::generate_context!())
        .expect("failed to start aster bridge desktop");
}
