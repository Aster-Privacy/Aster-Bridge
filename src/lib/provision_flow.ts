//
// Aster Communications Inc.
//
// Copyright (c) 2026 Aster Communications Inc.
//
// This file is part of this project.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the AGPLv3 as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// AGPLv3 for more details.
//
// You should have received a copy of the AGPLv3
// along with this program. If not, see <https://www.gnu.org/licenses/>.

import type { ProvisionBundle } from "@/api";

export interface ProvisionFlowDeps {
  provision_bundle: (label: string) => Promise<ProvisionBundle>;
}

export async function request_provision_bundle(label: string, deps: ProvisionFlowDeps): Promise<ProvisionBundle> {
  return deps.provision_bundle(label);
}

export const PROVISION_LABEL_LIMIT = 64;

export const HIDDEN_LABEL_CHARACTER = /[\u0000-\u001f\u007f-\u009f\u00ad\u061c\u200b-\u200f\u2028-\u202e\u2060-\u2069\ufeff]/;

export function clean_provision_label(raw_label: string, fallback: string): string {
  const visible = [...raw_label].filter((ch) => !HIDDEN_LABEL_CHARACTER.test(ch)).join("").trim();
  return [...visible].slice(0, PROVISION_LABEL_LIMIT).join("").trim() || fallback;
}

export function parse_provision_link(payload: string, fallback: string): string | null {
  let url: URL;
  try {
    url = new URL(payload);
  } catch {
    return null;
  }
  if (url.protocol !== "aster-mail:") return null;
  if (url.hostname !== "provision" && url.pathname !== "//provision" && url.pathname !== "/provision") return null;
  return clean_provision_label(url.searchParams.get("label") || "", fallback);
}
