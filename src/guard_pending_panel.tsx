// SPDX-License-Identifier: AGPL-3.0-or-later
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

import { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { InformationCircleIcon } from "@heroicons/react/24/outline";
import { ShieldCheckIcon } from "@heroicons/react/20/solid";
import { Button, Popover, PopoverContent, PopoverTrigger } from "@aster/ui";

const INFO_CLOSE_DELAY_MS = 150;

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

export function GuardInfoButton() {
  const { t } = useTranslation();
  const [open, set_open] = useState(false);
  const close_timer = useRef<number | null>(null);

  const cancel_close = () => {
    if (close_timer.current !== null) {
      window.clearTimeout(close_timer.current);
      close_timer.current = null;
    }
  };
  const show = () => {
    cancel_close();
    set_open(true);
  };
  const hide_soon = () => {
    cancel_close();
    close_timer.current = window.setTimeout(() => set_open(false), INFO_CLOSE_DELAY_MS);
  };

  useEffect(() => cancel_close, []);

  return (
    <Popover
      open={open}
      onOpenChange={(next) => {
        cancel_close();
        set_open(next);
      }}
    >
      <PopoverTrigger asChild>
        <button
          aria-label={t("guard_info_label")}
          className="-m-1 inline-flex items-center justify-center p-1 rounded-full text-txt-muted hover:text-txt-secondary transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-brand"
          type="button"
          onBlur={hide_soon}
          onClick={(event) => {
            event.preventDefault();
            show();
          }}
          onFocus={show}
          onMouseEnter={show}
          onMouseLeave={hide_soon}
        >
          <InformationCircleIcon aria-hidden="true" className="w-4 h-4" />
        </button>
      </PopoverTrigger>
      <PopoverContent
        align="center"
        className="aster_info_popover text-left"
        collisionPadding={12}
        sideOffset={6}
        onMouseEnter={show}
        onMouseLeave={hide_soon}
        onOpenAutoFocus={(event) => event.preventDefault()}
      >
        <p className="aster_info_popover_title">
          <ShieldCheckIcon aria-hidden="true" />
          <span>{t("guard_info_title")}</span>
        </p>
        <p className="aster_info_popover_body">{t("guard_info_body")}</p>
      </PopoverContent>
    </Popover>
  );
}

export function GuardProtectedBadge() {
  const { t } = useTranslation();
  return (
    <span className="inline-flex items-center gap-1.5 rounded-full bg-[var(--aster-field-bg)] px-3 py-1 text-xs font-medium text-txt-secondary">
      <ShieldCheckIcon aria-hidden="true" className="w-3.5 h-3.5 text-txt-muted" />
      {t("guard_protected_badge")}
    </span>
  );
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
            <img alt="" className="w-9 h-9 select-none" decoding="async" draggable={false} src="/bridge_mark.svg" />
            <span className="text-[20px] font-semibold tracking-tight text-txt-primary">{t("app_name")}</span>
          </div>
          <h1 className="text-xl font-semibold mt-6 text-txt-primary text-center">{t("guard_pending_title")}</h1>
          <p className="text-sm mt-2 leading-relaxed text-txt-tertiary text-center">{t("guard_pending_body")}</p>
          {seconds !== null && seconds > 0 && (
            <div className="w-full mt-6 rounded-[var(--aster-radius-item)] bg-[var(--aster-field-bg)] py-4 text-center">
              <span className="flex items-center justify-center gap-1.5 text-xs font-medium text-txt-muted">
                {t("guard_countdown_label")}
                <GuardInfoButton />
              </span>
              <span aria-hidden="true" className="block mt-1 text-3xl font-mono font-bold tabular-nums text-txt-primary">
                {format_countdown(seconds)}
              </span>
            </div>
          )}
          <div className={seconds !== null && seconds > 0 ? "mt-3" : "mt-6"}>
            <GuardProtectedBadge />
          </div>
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
