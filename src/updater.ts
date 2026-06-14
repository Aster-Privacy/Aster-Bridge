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

export interface UpdateInfo {
  version: string;
  current_version: string;
  notes?: string;
  date?: string;
}

const LAST_NOTIFIED_VERSION_KEY = "aster_bridge_last_notified_version";

export function is_desktop_runtime(): boolean {
  if (typeof window === "undefined") return false;
  const w = window as unknown as { __TAURI_INTERNALS__?: unknown };
  return Boolean(w.__TAURI_INTERNALS__);
}

export function get_last_notified_version(): string | null {
  try {
    return localStorage.getItem(LAST_NOTIFIED_VERSION_KEY);
  } catch {
    return null;
  }
}

export function mark_version_notified(version: string): void {
  try {
    localStorage.setItem(LAST_NOTIFIED_VERSION_KEY, version);
  } catch {
    // Storage unavailable, notification will repeat next session.
  }
}

interface TauriUpdate {
  version: string;
  currentVersion: string;
  body?: string;
  date?: string;
  downloadAndInstall: (
    on_event?: (event: {
      event: "Started" | "Progress" | "Finished";
      data?: { contentLength?: number; chunkLength?: number };
    }) => void,
  ) => Promise<void>;
}

async function load_updater(): Promise<{ check: () => Promise<TauriUpdate | null> }> {
  const mod = await import("@tauri-apps/plugin-updater");
  return { check: mod.check as () => Promise<TauriUpdate | null> };
}

async function load_process(): Promise<{ relaunch: () => Promise<void> }> {
  const mod = await import("@tauri-apps/plugin-process");
  return { relaunch: mod.relaunch as () => Promise<void> };
}

export async function check_for_update(): Promise<UpdateInfo | null> {
  try {
    const { check } = await load_updater();
    const result = await check();
    if (!result) return null;
    return {
      version: result.version,
      current_version: result.currentVersion,
      notes: result.body,
      date: result.date,
    };
  } catch {
    return null;
  }
}

export async function download_and_install(): Promise<void> {
  const { check } = await load_updater();
  const update = await check();
  if (!update) return;
  await update.downloadAndInstall();
  const { relaunch } = await load_process();
  await relaunch();
}
