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

interface AppPassword {
  id: string;
  label: string;
  created_at: string;
  last_used_at: number | null;
  last_client: string | null;
  use_count: number;
}

export interface BridgeState {
  enrolled: boolean;
  email: string | null;
  running: boolean;
  passwords: AppPassword[];
  display_name: string | null;
  profile_picture: string | null;
  profile_color: string | null;
  plan_code: string | null;
  has_bridge_access: boolean;
  plan_info_loaded: boolean;
}

async function tauri_invoke<T>(
  cmd: string,
  args?: Record<string, unknown>,
): Promise<T> {
  const { invoke } = await import("@tauri-apps/api/core");
  return invoke<T>(cmd, args);
}

export async function get_bridge_state(): Promise<BridgeState> {
  const status = await tauri_invoke<{
    connected: boolean;
    email: string;
    imap_running: boolean;
    smtp_running: boolean;
    jmap_running: boolean;
    pop3_running: boolean;
    display_name: string | null;
    profile_picture: string | null;
    profile_color: string | null;
    plan_code: string | null;
    has_bridge_access: boolean;
    plan_info_loaded: boolean;
  }>("get_bridge_status");

  let passwords: AppPassword[] = [];
  if (status.connected) {
    try {
      passwords = await tauri_invoke<AppPassword[]>("get_app_passwords");
    } catch {
      passwords = [];
    }
  }

  return {
    enrolled: status.connected,
    email: status.email || null,
    running: status.imap_running || status.smtp_running || (status.jmap_running ?? false) || (status.pop3_running ?? false),
    passwords,
    display_name: status.display_name,
    profile_picture: status.profile_picture,
    profile_color: status.profile_color,
    plan_code: status.plan_code,
    has_bridge_access: status.has_bridge_access,
    plan_info_loaded: status.plan_info_loaded ?? false,
  };
}

export interface UserPreferences {
  theme: string | null;
  color_theme: string | null;
  accent_color: string | null;
  accent_color_hover: string | null;
  custom_theme_seed: string | null;
  custom_theme_overrides: Record<string, string>;
  font_choice: string | null;
  font_size_scale: number | string | null;
  reduce_motion: boolean | null;
  compact_mode: boolean | null;
  high_contrast: boolean | null;
  reduce_transparency: boolean | null;
  link_underlines: boolean | null;
  dyslexia_font: boolean | null;
  text_spacing: boolean | null;
  color_vision_mode: string | null;
  toast_position: string | null;
}

export async function get_user_preferences(): Promise<UserPreferences> {
  return tauri_invoke<UserPreferences>("get_user_preferences");
}

export async function get_setup_code(): Promise<string> {
  return tauri_invoke<string>("get_setup_code");
}

export async function check_setup_confirmation(): Promise<"confirmed" | "expired" | "pending"> {
  const result = await tauri_invoke<{ status: string; done: boolean }>(
    "check_setup_status",
  );
  if (result.status === "confirmed" && result.done) return "confirmed";
  if (result.status === "expired") return "expired";
  return "pending";
}

export async function start_bridge(): Promise<void> {
  return tauri_invoke("start_bridge");
}

export async function stop_bridge(): Promise<void> {
  return tauri_invoke("stop_bridge");
}

export async function sign_out(): Promise<void> {
  return tauri_invoke("sign_out");
}

export async function reset_bridge_data(): Promise<void> {
  return tauri_invoke("reset_bridge_data");
}

export async function refresh_plan_info(): Promise<void> {
  return tauri_invoke("refresh_plan_info");
}

export async function generate_app_password(label: string): Promise<string> {
  return tauri_invoke<string>("generate_app_password", { label });
}

export async function delete_app_password(id: string): Promise<void> {
  return tauri_invoke("delete_app_password", { id });
}

export interface ConnectionInfo {
  imap_host: string;
  imap_port: number;
  smtp_host: string;
  smtp_port: number;
  jmap_host: string;
  jmap_port: number;
  jmap_url: string;
  jmap_enabled: boolean;
  tls_enabled: boolean;
  imap_implicit_tls_port: number;
  smtp_implicit_tls_port: number;
  jmap_https_enabled: boolean;
  pop3_port: number;
  pop3s_port: number;
}

export async function get_connection_info(): Promise<ConnectionInfo> {
  return tauri_invoke<ConnectionInfo>("get_connection_info");
}

export interface TlsInfo {
  tls_enabled: boolean;
  fingerprint_sha256: string | null;
  cert_path: string;
  imap_implicit_tls_port: number;
  smtp_implicit_tls_port: number;
  jmap_https_enabled: boolean;
}

export async function get_tls_info(): Promise<TlsInfo> {
  return tauri_invoke<TlsInfo>("get_tls_info");
}

export async function set_tls_enabled(enabled: boolean): Promise<void> {
  return tauri_invoke("set_tls_enabled", { enabled });
}

export async function update_connection_settings(imap_port: number, smtp_port: number): Promise<void> {
  return tauri_invoke("update_connection_settings", { imap_port, smtp_port });
}

export async function get_data_directory(): Promise<string> {
  return tauri_invoke<string>("get_data_directory");
}

export async function open_data_directory(): Promise<void> {
  return tauri_invoke("open_data_directory");
}

export interface ServiceSettings {
  service_mode: boolean;
  autostart: boolean;
}

export async function get_service_settings(): Promise<ServiceSettings> {
  return tauri_invoke<ServiceSettings>("get_service_settings");
}

export async function set_service_mode(enabled: boolean): Promise<void> {
  return tauri_invoke("set_service_mode", { enabled });
}

export async function get_autostart_enabled(): Promise<boolean> {
  const s = await get_service_settings();
  return s.autostart;
}

export async function set_autostart_enabled(enabled: boolean): Promise<void> {
  return tauri_invoke("set_autostart", { enabled });
}

export interface ProvisionBundle {
  email: string;
  app_password: string;
  label: string;
  imap_host: string;
  imap_port: number;
  smtp_host: string;
  smtp_port: number;
  jmap_host: string;
  jmap_port: number;
  jmap_url: string;
  jmap_enabled: boolean;
}

export async function provision_bundle(label: string): Promise<ProvisionBundle> {
  return tauri_invoke<ProvisionBundle>("provision_bundle", { label });
}

const ALLOWED_OPEN_SCHEMES = ["https:", "http:", "mailto:"];

export async function open_url(url: string): Promise<void> {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error("refusing to open malformed url");
  }
  if (!ALLOWED_OPEN_SCHEMES.includes(parsed.protocol)) {
    throw new Error(`refusing to open url with scheme ${parsed.protocol}`);
  }
  const { open } = await import("@tauri-apps/plugin-shell");
  await open(parsed.toString());
}

export async function trigger_sync(): Promise<void> {
  return tauri_invoke("trigger_sync");
}

export async function repair_cache(): Promise<void> {
  return tauri_invoke("repair_cache");
}

export async function get_recent_logs(): Promise<string[]> {
  return tauri_invoke<string[]>("get_recent_logs");
}

export async function copy_diagnostic_bundle(): Promise<string> {
  return tauri_invoke<string>("copy_diagnostic_bundle");
}

export interface OutboxItem {
  id: number;
  envelope_from: string;
  envelope_to: string;
  queued_at: number;
  attempts: number;
  last_attempt_at: number | null;
  last_error: string | null;
  status: string;
  subject: string | null;
  size: number;
}

export async function outbox_list(): Promise<OutboxItem[]> {
  return tauri_invoke<OutboxItem[]>("outbox_list");
}

export async function outbox_retry_now(id: number): Promise<void> {
  return tauri_invoke("outbox_retry_now", { id });
}

export async function open_tls_cert(): Promise<void> {
  return tauri_invoke("open_tls_cert");
}

export interface SendIdentity {
  address: string;
  kind: "primary" | "alias" | "custom_domain";
  display_name: string | null;
  enabled: boolean;
  sender_id: string;
}

export async function list_send_identities(): Promise<SendIdentity[]> {
  return tauri_invoke<SendIdentity[]>("list_send_identities");
}

export async function get_default_sender(): Promise<string | null> {
  return tauri_invoke<string | null>("get_default_sender");
}

export async function set_default_sender(sender_id: string | null): Promise<void> {
  return tauri_invoke("set_default_sender", { sender_id });
}
