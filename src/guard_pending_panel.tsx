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

import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { Button } from "@aster/ui";

export function seconds_until(activates_at: string | null, now_ms: number): number | null {
  if (!activates_at) return null;
  const target = Date.parse(activates_at);
  if (Number.isNaN(target)) return null;
  return Math.max(0, Math.ceil((target - now_ms) / 1000));
}

export function format_countdown(seconds: number): string {
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const rest = seconds % 60;
  const padded = `${minutes.toString().padStart(hours > 0 ? 2 : 1, "0")}:${rest.toString().padStart(2, "0")}`;
  return hours > 0 ? `${hours}:${padded}` : padded;
}

export function format_local_time(activates_at: string, locale?: string): string {
  return new Date(activates_at).toLocaleTimeString(locale, { hour: "numeric", minute: "2-digit" });
}

export function GuardPendingPanel({
  activates_at,
  on_cancel,
  initial_now_ms,
}: {
  activates_at: string | null;
  on_cancel: () => void;
  initial_now_ms?: number;
}) {
  const { t } = useTranslation();
  const [now_ms, set_now_ms] = useState(() => initial_now_ms ?? Date.now());

  useEffect(() => {
    const timer = setInterval(() => set_now_ms(Date.now()), 1000);
    return () => clearInterval(timer);
  }, []);

  const seconds = seconds_until(activates_at, now_ms);
  const minute_mark = seconds === null ? null : Math.max(1, Math.round(seconds / 60));
  const announced =
    seconds === null || activates_at === null
      ? t("guard_activation_unknown")
      : seconds > 0
        ? t("guard_activation_wait", { count: minute_mark ?? 0, local_time: format_local_time(activates_at) })
        : t("guard_activation_finishing");

  return (
    <div className="fixed inset-0 overflow-y-auto" style={{ backgroundColor: "var(--bg-secondary)" }}>
      <div className="min-h-full flex items-center justify-center px-4 py-8">
        <div className="flex flex-col items-center w-full max-w-sm px-4">
          <div className="flex items-center gap-3">
            <img alt="" className="w-12 h-12 select-none rounded-[var(--aster-radius-item)]" decoding="async" draggable={false} src="/mail_logo.webp" />
            <span className="text-[26px] font-bold tracking-tight text-txt-primary">{t("app_name")}</span>
          </div>
          <h1 className="text-xl font-semibold mt-6 text-txt-primary text-center">{t("guard_pending_title")}</h1>
          <p className="text-sm mt-2 leading-relaxed text-txt-tertiary text-center">{t("guard_pending_body")}</p>
          {seconds !== null && seconds > 0 && (
            <div className="w-full mt-6 rounded-[var(--aster-radius-item)] bg-[var(--aster-field-bg)] py-4 text-center">
              <span className="block text-xs font-medium text-txt-muted">{t("guard_countdown_label")}</span>
              <span aria-hidden="true" className="block mt-1 text-3xl font-mono font-bold tabular-nums text-txt-primary">
                {format_countdown(seconds)}
              </span>
            </div>
          )}
          <p aria-live="polite" role="status" className="text-sm mt-4 leading-relaxed text-txt-secondary text-center">
            {announced}
          </p>
          <p className="text-xs mt-2 leading-relaxed text-txt-muted text-center">{t("guard_pending_skip_hint")}</p>
          <Button className="w-full mt-6" size="xl" variant="secondary" onClick={on_cancel}>{t("cancel")}</Button>
        </div>
      </div>
    </div>
  );
}
