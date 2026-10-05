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

import type { EventCallback } from "@tauri-apps/api/event";

export interface TauriSubscription {
  ready: Promise<void>;
  unlisten: () => void;
}

export function listen_tauri<T>(event: string, handler: EventCallback<T>): TauriSubscription {
  let stopped = false;
  let unlisten_fn: (() => void) | null = null;
  const ready = import("@tauri-apps/api/event")
    .then(({ listen }) => listen<T>(event, (e) => { if (!stopped) handler(e); }))
    .then((fn) => {
      if (stopped) fn();
      else unlisten_fn = fn;
    });
  return {
    ready,
    unlisten: () => {
      stopped = true;
      if (unlisten_fn) { unlisten_fn(); unlisten_fn = null; }
    },
  };
}
