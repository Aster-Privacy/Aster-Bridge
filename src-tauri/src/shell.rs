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
use std::sync::Mutex;
use tauri::{
    menu::{Menu, MenuItem, PredefinedMenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    AppHandle, Emitter, Manager, Wry,
};

use crate::{AppState, SharedBridgeState};

pub const HELP_URL: &str = "https://astermail.org/help";
pub const ISSUE_URL: &str = "https://astermail.org/issue";
const QUIT_DRAIN_TIMEOUT_SECS: u64 = 8;

pub struct TrayItems {
    status: MenuItem<Wry>,
    toggle: MenuItem<Wry>,
    sync: MenuItem<Wry>,
}

pub struct TrayMenuState(pub Mutex<Option<TrayItems>>);

pub struct QuitState(pub std::sync::atomic::AtomicBool);

pub fn show_main_window(app: &AppHandle) {
    #[cfg(target_os = "macos")]
    let _ = app.set_activation_policy(tauri::ActivationPolicy::Regular);
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

pub fn hide_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.hide();
    }
    #[cfg(target_os = "macos")]
    let _ = app.set_activation_policy(tauri::ActivationPolicy::Accessory);
}

fn emit_action(app: &AppHandle, action: &str) {
    if matches!(action, "settings" | "status" | "passwords" | "check_updates") {
        show_main_window(app);
    }
    let _ = app.emit("menu_action", action);
}

pub fn open_external(url: &str) {
    let _ = open::that(url);
}

#[cfg(target_os = "macos")]
pub fn install_app_menu(app: &tauri::App) -> tauri::Result<()> {
    use tauri::menu::{AboutMetadataBuilder, Submenu};

    let about_metadata = AboutMetadataBuilder::new()
        .name(Some("Aster Bridge"))
        .version(Some(env!("CARGO_PKG_VERSION")))
        .copyright(Some("Copyright 2026 Aster Communications Inc."))
        .website(Some("https://astermail.org/bridge"))
        .license(Some("AGPL-3.0-or-later"))
        .build();

    let app_menu = Submenu::with_items(
        app,
        "Aster Bridge",
        true,
        &[
            &PredefinedMenuItem::about(app, Some("About Aster Bridge"), Some(about_metadata))?,
            &PredefinedMenuItem::separator(app)?,
            &MenuItem::with_id(app, "check_updates", "Check for Updates…", true, None::<&str>)?,
            &PredefinedMenuItem::separator(app)?,
            &MenuItem::with_id(app, "settings", "Settings…", true, Some("CmdOrCtrl+,"))?,
            &PredefinedMenuItem::separator(app)?,
            &PredefinedMenuItem::services(app, None)?,
            &PredefinedMenuItem::separator(app)?,
            &PredefinedMenuItem::hide(app, Some("Hide Aster Bridge"))?,
            &PredefinedMenuItem::hide_others(app, None)?,
            &PredefinedMenuItem::show_all(app, None)?,
            &PredefinedMenuItem::separator(app)?,
            &MenuItem::with_id(app, "quit", "Quit Aster Bridge", true, Some("CmdOrCtrl+Q"))?,
        ],
    )?;

    let edit_menu = Submenu::with_items(
        app,
        "Edit",
        true,
        &[
            &PredefinedMenuItem::undo(app, None)?,
            &PredefinedMenuItem::redo(app, None)?,
            &PredefinedMenuItem::separator(app)?,
            &PredefinedMenuItem::cut(app, None)?,
            &PredefinedMenuItem::copy(app, None)?,
            &PredefinedMenuItem::paste(app, None)?,
            &PredefinedMenuItem::select_all(app, None)?,
        ],
    )?;

    let view_menu = Submenu::with_items(
        app,
        "View",
        true,
        &[
            &MenuItem::with_id(app, "status", "Status", true, Some("CmdOrCtrl+1"))?,
            &MenuItem::with_id(app, "passwords", "App Passwords", true, Some("CmdOrCtrl+2"))?,
            &MenuItem::with_id(app, "settings", "Settings", true, Some("CmdOrCtrl+3"))?,
            &PredefinedMenuItem::separator(app)?,
            &MenuItem::with_id(app, "sync_now", "Sync Now", true, Some("CmdOrCtrl+R"))?,
            &MenuItem::with_id(app, "toggle_bridge", "Start or Stop Bridge", true, None::<&str>)?,
            &PredefinedMenuItem::separator(app)?,
            &PredefinedMenuItem::fullscreen(app, None)?,
        ],
    )?;

    let window_menu = Submenu::with_items(
        app,
        "Window",
        true,
        &[
            &PredefinedMenuItem::minimize(app, None)?,
            &PredefinedMenuItem::maximize(app, Some("Zoom"))?,
            &PredefinedMenuItem::separator(app)?,
            &MenuItem::with_id(app, "show", "Aster Bridge", true, None::<&str>)?,
            &PredefinedMenuItem::separator(app)?,
            &PredefinedMenuItem::close_window(app, None)?,
        ],
    )?;

    let help_menu = Submenu::with_items(
        app,
        "Help",
        true,
        &[
            &MenuItem::with_id(app, "help", "Aster Bridge Help", true, None::<&str>)?,
            &MenuItem::with_id(app, "report_issue", "Report an Issue…", true, None::<&str>)?,
            &PredefinedMenuItem::separator(app)?,
            &MenuItem::with_id(app, "open_logs", "Open Data Folder", true, None::<&str>)?,
        ],
    )?;

    let menu = Menu::with_items(app, &[&app_menu, &edit_menu, &view_menu, &window_menu, &help_menu])?;
    app.set_menu(menu)?;
    Ok(())
}

pub fn handle_menu_action(app: &AppHandle, id: &str) {
    match id {
        "show" => show_main_window(app),
        "quit" => request_quit(app),
        "help" => open_external(HELP_URL),
        "report_issue" => open_external(ISSUE_URL),
        "open_logs" => {
            let handle = app.clone();
            tauri::async_runtime::spawn(async move {
                let state: tauri::State<AppState> = handle.state();
                let dir = state.0.lock().await.config.data_dir.clone();
                let _ = open::that(dir);
            });
        }
        "settings" | "status" | "passwords" | "check_updates" | "sync_now" | "toggle_bridge" => {
            emit_action(app, id)
        }
        _ => {}
    }
}

pub fn build_tray(app: &tauri::App) -> tauri::Result<tauri::tray::TrayIcon> {
    let status = MenuItem::with_id(app, "tray_status", "Bridge: Starting…", false, None::<&str>)?;
    let toggle = MenuItem::with_id(app, "toggle_bridge", "Start Bridge", false, None::<&str>)?;
    let sync = MenuItem::with_id(app, "sync_now", "Sync Now", false, None::<&str>)?;
    let show = MenuItem::with_id(app, "show", "Open Aster Bridge", true, None::<&str>)?;
    let settings = MenuItem::with_id(app, "settings", "Settings…", true, None::<&str>)?;
    let updates = MenuItem::with_id(app, "check_updates", "Check for Updates…", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit Aster Bridge", true, None::<&str>)?;
    let menu = Menu::with_items(
        app,
        &[
            &status,
            &PredefinedMenuItem::separator(app)?,
            &toggle,
            &sync,
            &PredefinedMenuItem::separator(app)?,
            &show,
            &settings,
            &updates,
            &PredefinedMenuItem::separator(app)?,
            &quit,
        ],
    )?;

    #[cfg(target_os = "macos")]
    let icon_bytes: &[u8] = include_bytes!("../icons/tray_template.png");
    #[cfg(not(target_os = "macos"))]
    let icon_bytes: &[u8] = include_bytes!("../icons/128x128.png");
    let icon = tauri::image::Image::from_bytes(icon_bytes)?;

    let builder = TrayIconBuilder::new()
        .icon(icon)
        .icon_as_template(cfg!(target_os = "macos"))
        .menu(&menu)
        .show_menu_on_left_click(cfg!(target_os = "macos"))
        .tooltip("Aster Bridge")
        .on_menu_event(|app, event| handle_menu_action(app, event.id.as_ref()))
        .on_tray_icon_event(|tray, event| {
            if cfg!(target_os = "macos") {
                return;
            }
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                show_main_window(tray.app_handle());
            }
        });

    let tray = builder.build(app)?;
    let items: tauri::State<TrayMenuState> = app.state();
    if let Ok(mut guard) = items.0.lock() {
        *guard = Some(TrayItems { status, toggle, sync });
    }
    Ok(tray)
}

pub fn refresh_tray(app: &AppHandle) {
    let handle = app.clone();
    tauri::async_runtime::spawn(async move {
        let state: tauri::State<AppState> = handle.state();
        let (signed_in, running, port, pending) = {
            let guard = state.0.lock().await;
            let pending = guard.db.outbox_list_pending().map(|r| r.len()).unwrap_or(0);
            (guard.session.is_some(), guard.running, guard.bound_imap_port, pending)
        };
        let status_text = if !signed_in {
            "Bridge: Not signed in".to_string()
        } else if running && pending > 0 {
            format!("Bridge: Running, {} message(s) waiting to send", pending)
        } else if running {
            format!("Bridge: Running on port {}", port)
        } else {
            "Bridge: Stopped".to_string()
        };
        let toggle_text = if running { "Stop Bridge" } else { "Start Bridge" };
        let menu_state: tauri::State<TrayMenuState> = handle.state();
        let guard = menu_state.0.lock();
        if let Ok(guard) = guard {
            if let Some(items) = guard.as_ref() {
                let _ = items.status.set_text(&status_text);
                let _ = items.toggle.set_text(toggle_text);
                let _ = items.toggle.set_enabled(signed_in);
                let _ = items.sync.set_enabled(running);
            }
        }
    });
}

pub fn start_tray_refresh_loop(app: &AppHandle) {
    let handle = app.clone();
    tauri::async_runtime::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(5));
        loop {
            tick.tick().await;
            refresh_tray(&handle);
        }
    });
}

async fn outbox_pending(state: &SharedBridgeState) -> usize {
    let guard = state.lock().await;
    if !guard.running {
        return 0;
    }
    guard.db.outbox_list_pending().map(|r| r.len()).unwrap_or(0)
}

pub fn request_quit(app: &AppHandle) {
    use std::sync::atomic::Ordering;
    let quitting: tauri::State<QuitState> = app.state();
    if quitting.0.swap(true, Ordering::SeqCst) {
        return;
    }
    let handle = app.clone();
    tauri::async_runtime::spawn(async move {
        let state: tauri::State<AppState> = handle.state();
        let shared = state.0.clone();
        let deadline =
            tokio::time::Instant::now() + std::time::Duration::from_secs(QUIT_DRAIN_TIMEOUT_SECS);
        let mut waited = false;
        while outbox_pending(&shared).await > 0 && tokio::time::Instant::now() < deadline {
            if !waited {
                tracing::info!("quit: waiting for queued messages to send");
                waited = true;
                refresh_tray(&handle);
            }
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        }
        {
            use tauri_plugin_window_state::{AppHandleExt, StateFlags};
            let _ = handle.save_window_state(StateFlags::all());
        }
        tracing::info!("quit: exiting");
        handle.exit(0);
    });
}
