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

import { useState, useEffect, useCallback, useRef } from "react";
import type { ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { motion, AnimatePresence } from "framer-motion";
import { CheckIcon, XMarkIcon, InformationCircleIcon, ArrowDownTrayIcon, SignalIcon, SignalSlashIcon } from "@heroicons/react/24/outline";
import i18next from "./i18n";
import * as api from "@/api";
import type { ConnectionInfo } from "@/api";
import {
  check_for_update,
  download_and_install,
  is_desktop_runtime,
  get_last_notified_version,
  mark_version_notified,
  type UpdateInfo,
} from "./updater";
import {
  Button,
  UpgradeBtn,
  Modal,
  ModalBody,
  ModalActions,
} from "@aster/ui";

type SetupState =
  | "idle"
  | "requesting_code"
  | "showing_code"
  | "expired"
  | "error";

const UPGRADE_URL = "https://app.astermail.org/settings/billing";


type View = "loading" | "setup" | "dashboard";
type Tab = "status" | "passwords" | "settings";
type ToastType = "success" | "error" | "info";

const LINK_DEVICE_URL = "https://app.astermail.org/link-device";

const GRADIENT_CONFIGS: Record<
  string,
  { top_left: string; bottom_right: string }
> = {
  "#6366f1": { top_left: "#6366f1", bottom_right: "#312e81" },
  "#3b82f6": { top_left: "#3b82f6", bottom_right: "#312e81" },
  "#8b5cf6": { top_left: "#7c3aed", bottom_right: "#1e3a5f" },
  "#ec4899": { top_left: "#ec4899", bottom_right: "#581c87" },
  "#ef4444": { top_left: "#d97706", bottom_right: "#7f1d1d" },
  "#f97316": { top_left: "#eab308", bottom_right: "#78350f" },
  "#22c55e": { top_left: "#4ade80", bottom_right: "#064e3b" },
  "#14b8a6": { top_left: "#2dd4bf", bottom_right: "#134e4a" },
  "#6b7280": { top_left: "#9ca3af", bottom_right: "#111827" },
};

// Wipe a copied secret from the clipboard after 30s, but only if the user has
// not since copied something else (avoids clobbering an unrelated later copy).
function clear_clipboard_if_unchanged(value: string): void {
  window.setTimeout(() => {
    navigator.clipboard
      .readText()
      .then((current) => {
        if (current === value) {
          navigator.clipboard.writeText("").catch(() => {});
        }
      })
      .catch(() => {});
  }, 30_000);
}

const HEX_COLOR = /^#[0-9a-f]{6}$/i;

function get_gradient_background(color: string): string {
  const fallback = HEX_COLOR.test(color) ? color : "#6b7280";
  const config = GRADIENT_CONFIGS[color] || {
    top_left: fallback,
    bottom_right: fallback,
  };
  return `linear-gradient(135deg, ${config.top_left} 0%, ${config.bottom_right} 100%)`;
}

function format_date(iso: string): string {
  return new Date(iso).toLocaleDateString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
}

function format_time(seconds: number): string {
  const m = Math.floor(seconds / 60);
  const s = seconds % 60;
  return `${m}:${s.toString().padStart(2, "0")}`;
}

function format_relative_time(unix_ts: number): string {
  const t = i18next.t.bind(i18next);
  const now = Math.floor(Date.now() / 1000);
  const diff = now - unix_ts;
  if (diff < 0) return t("time_just_now");
  if (diff < 60) return t("time_seconds_ago", { n: diff });
  if (diff < 3600) return t("time_minutes_ago", { n: Math.floor(diff / 60) });
  if (diff < 86400) return t("time_hours_ago", { n: Math.floor(diff / 3600) });
  if (diff < 2592000) return t("time_days_ago", { n: Math.floor(diff / 86400) });
  return new Date(unix_ts * 1000).toLocaleDateString();
}

// Holds the last non-null value so modal content stays rendered through the
// close animation instead of clearing the instant the trigger state goes null.
function use_frozen<T>(value: T | null): T | null {
  const ref = useRef<T | null>(value);
  if (value != null) ref.current = value;
  return value != null ? value : ref.current;
}

function use_theme() {
  const [is_dark, set_is_dark] = useState(() =>
    typeof window !== "undefined" && window.matchMedia("(prefers-color-scheme: dark)").matches
  );
  useEffect(() => {
    const mq = window.matchMedia("(prefers-color-scheme: dark)");
    const handler = (e: MediaQueryListEvent) => set_is_dark(e.matches);
    mq.addEventListener("change", handler);
    return () => mq.removeEventListener("change", handler);
  }, []);
  useEffect(() => {
    document.documentElement.classList.toggle("dark", is_dark);
  }, [is_dark]);
  return is_dark;
}

interface ToastState {
  id: string;
  message: string;
  type: ToastType;
}

const MAX_TOASTS = 5;

let toast_listeners: ((toasts: ToastState[]) => void)[] = [];
let toast_stack: ToastState[] = [];
const toast_timeouts: Map<string, ReturnType<typeof setTimeout>> = new Map();

function dismiss_toast(id: string) {
  const existing = toast_timeouts.get(id);
  if (existing) { clearTimeout(existing); toast_timeouts.delete(id); }
  toast_stack = toast_stack.filter((t) => t.id !== id);
  toast_listeners.forEach((l) => l([...toast_stack]));
}

function show_toast(message: string, type: ToastType = "info", duration = 2000) {
  const id = Math.random().toString(36).slice(2);
  const new_toast: ToastState = { id, message, type };
  toast_stack = [new_toast, ...toast_stack].slice(0, MAX_TOASTS);
  toast_listeners.forEach((l) => l([...toast_stack]));
  const timeout = setTimeout(() => {
    toast_timeouts.delete(id);
    toast_stack = toast_stack.filter((t) => t.id !== id);
    toast_listeners.forEach((l) => l([...toast_stack]));
  }, duration);
  toast_timeouts.set(id, timeout);
}

function get_toast_icon(type: ToastType) {
  const c = "w-4 h-4";
  if (type === "success") return <CheckIcon className={c} />;
  if (type === "error") return <XMarkIcon className={c} />;
  return <InformationCircleIcon className={c} />;
}

function ToastContainer() {
  const [toasts, set_toasts] = useState<ToastState[]>([]);
  const reduce_motion = typeof window !== "undefined" && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  useEffect(() => {
    const listener = (new_toasts: ToastState[]) => set_toasts(new_toasts);
    toast_listeners.push(listener);
    return () => {
      toast_listeners = toast_listeners.filter((l) => l !== listener);
    };
  }, []);

  return (
    <div
      aria-atomic="false"
      aria-live="polite"
      role="status"
      className="fixed left-1/2 -translate-x-1/2 z-[100] flex flex-col-reverse gap-2 pointer-events-none"
      style={{ bottom: "24px" }}
    >
      <AnimatePresence>
        {toasts.map((toast) => (
          <motion.div
            key={toast.id}
            className="pointer-events-auto"
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, scale: 0.95 }}
            initial={reduce_motion ? false : { opacity: 0, y: 20, scale: 0.95 }}
            layout={!reduce_motion}
            transition={{ duration: reduce_motion ? 0 : 0.15 }}
          >
            <div className="px-4 py-2.5 rounded-xl shadow-lg flex items-center gap-2 bg-modal-bg border border-edge-secondary">
              <span className="flex-shrink-0 text-txt-primary">
                {get_toast_icon(toast.type)}
              </span>
              <span className="text-[13px] font-medium text-txt-primary whitespace-nowrap">
                {toast.message}
              </span>
              <button
                aria-label={i18next.t("dismiss")}
                className="ml-1 flex-shrink-0 text-txt-muted hover:text-txt-primary"
                onClick={() => dismiss_toast(toast.id)}
              >
                <XMarkIcon className="w-3.5 h-3.5" />
              </button>
            </div>
          </motion.div>
        ))}
      </AnimatePresence>
    </div>
  );
}

const UPDATE_CHECK_INTERVAL_MS = 6 * 60 * 60 * 1000;

function UpdateBanner() {
  const [info, set_info] = useState<UpdateInfo | null>(null);
  const [dismissed, set_dismissed] = useState(false);
  const [installing, set_installing] = useState(false);

  useEffect(() => {
    if (!is_desktop_runtime()) return;
    let cancelled = false;
    const run = async () => {
      try {
        const result = await check_for_update();
        if (cancelled || !result) return;
        if (get_last_notified_version() !== result.version) set_info(result);
      } catch {
        // Offline or endpoint unreachable - retry on next interval.
      }
    };
    run();
    const id = window.setInterval(run, UPDATE_CHECK_INTERVAL_MS);
    return () => {
      cancelled = true;
      window.clearInterval(id);
    };
  }, []);

  if (!info || dismissed) return null;

  const handle_install = async () => {
    set_installing(true);
    try {
      await download_and_install();
    } catch {
      set_installing(false);
      show_toast(i18next.t("toast_update_failed"), "error");
    }
  };

  const handle_dismiss = () => {
    mark_version_notified(info.version);
    set_dismissed(true);
  };

  return (
    <div
      className="fixed bottom-4 right-4 z-[9999] max-w-sm rounded-xl border shadow-2xl p-3"
      style={{
        backgroundColor: "var(--bg-primary)",
        borderColor: "var(--border-primary)",
        color: "var(--text-primary)",
      }}
    >
      <div className="flex items-start gap-3">
        <ArrowDownTrayIcon className="w-5 h-5 mt-0.5 text-txt-primary flex-shrink-0" />
        <div className="flex-1 min-w-0">
          <p className="text-sm font-medium text-txt-primary">
            {i18next.t("update_available", { version: info.version })}
          </p>
          <div className="mt-2 flex items-center gap-2">
            <button
              className="h-7 px-3 rounded-lg bg-indigo-600 text-xs font-medium text-white hover:bg-indigo-700 disabled:opacity-50 disabled:cursor-not-allowed"
              disabled={installing}
              onClick={handle_install}
            >
              {installing ? i18next.t("update_installing") : i18next.t("update_install")}
            </button>
            <button
              className="h-7 px-3 rounded-lg border border-edge-secondary bg-surf-tertiary text-xs font-medium text-txt-primary hover:opacity-80"
              disabled={installing}
              onClick={handle_dismiss}
            >
              {i18next.t("update_dismiss")}
            </button>
          </div>
        </div>
        <button
          aria-label={i18next.t("dismiss")}
          className="p-1 text-txt-muted hover:text-txt-primary"
          onClick={handle_dismiss}
        >
          <XMarkIcon className="w-4 h-4" />
        </button>
      </div>
    </div>
  );
}

function Spinner({ class_name = "" }: { class_name?: string }) {
  return (
    <svg
      className={`animate-spin ${class_name}`}
      fill="none"
      viewBox="0 0 24 24"
    >
      <circle
        className="opacity-25"
        cx="12"
        cy="12"
        r="10"
        stroke="currentColor"
        strokeWidth="4"
      />
      <path
        className="opacity-75"
        d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"
        fill="currentColor"
      />
    </svg>
  );
}

function CopyIcon({ copied }: { copied: boolean }) {
  if (copied) {
    return (
      <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
        <path d="M5 13l4 4L19 7" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
    );
  }
  return (
    <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
      <rect height="13" rx="2" width="13" x="9" y="9" />
      <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function CopyValue({ value, mono = true }: { value: string; mono?: boolean }) {
  const { t } = useTranslation();
  const on_copy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      show_toast(t("copied_to_clipboard"), "success");
    } catch {
      show_toast(t("failed_to_copy"), "error");
    }
  };
  return (
    <button
      type="button"
      onClick={on_copy}
      title={t("copy_to_clipboard")}
      aria-label={t("copy_to_clipboard")}
      className="group ml-auto inline-flex items-center justify-end gap-1.5 max-w-full min-w-0 rounded-md px-2 py-1 cursor-pointer hover:bg-black/[0.05] dark:hover:bg-white/[0.07] focus:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-edge-primary"
    >
      <span title={value} className={`truncate text-txt-primary ${mono ? "font-mono" : ""}`}>{value}</span>
      <span className="flex-shrink-0 text-txt-muted group-hover:text-txt-primary">
        <CopyIcon copied={false} />
      </span>
    </button>
  );
}

function ChevronRightIcon() {
  return (
    <svg className="w-4 h-4 flex-shrink-0 text-txt-muted opacity-60 group-hover:opacity-100" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
      <path d="M9 5l7 7-7 7" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function SettingsGroup({ title, hint, children }: { title?: string; hint?: ReactNode; children: ReactNode }) {
  return (
    <section className="mb-5">
      {title && (
        <h3 className="text-[11px] font-semibold uppercase tracking-[0.08em] text-txt-tertiary px-1 mb-2">{title}</h3>
      )}
      <div
        className="rounded-xl border border-edge-secondary overflow-hidden [&>*:not(:first-child)]:border-t [&>*:not(:first-child)]:border-edge-secondary"
        style={{ backgroundColor: "color-mix(in srgb, var(--text-primary) 3%, var(--bg-primary))", boxShadow: "0 1px 2px rgba(0, 0, 0, 0.04)" }}
      >
        {children}
      </div>
      {hint && <p className="text-[11px] text-txt-muted px-1 mt-2 leading-relaxed">{hint}</p>}
    </section>
  );
}

function SettingRow({ icon, label, sublabel, danger, children }: { icon?: ReactNode; label: ReactNode; sublabel?: ReactNode; danger?: boolean; children?: ReactNode }) {
  return (
    <div className="flex items-center gap-3 px-3.5 py-3 min-h-[52px]">
      {icon && <span className={`w-[18px] h-[18px] flex-shrink-0 ${danger ? "text-aster-danger" : "text-txt-muted"}`}>{icon}</span>}
      <div className="min-w-0 flex-1">
        <p className={`text-[14px] leading-tight ${danger ? "text-aster-danger" : "text-txt-primary"}`}>{label}</p>
        {sublabel && <p className="text-[12px] text-txt-muted mt-0.5 leading-snug">{sublabel}</p>}
      </div>
      {children && <div className="flex-shrink-0">{children}</div>}
    </div>
  );
}

function ActionRow({ icon, label, sublabel, on_click, disabled, right, danger }: { icon?: ReactNode; label: ReactNode; sublabel?: ReactNode; on_click: () => void; disabled?: boolean; right?: ReactNode; danger?: boolean }) {
  return (
    <button
      type="button"
      onClick={on_click}
      disabled={disabled}
      className="group w-full flex items-center gap-3 px-3.5 py-3 min-h-[52px] text-left hover:bg-black/[0.035] dark:hover:bg-white/[0.05] disabled:opacity-50 disabled:pointer-events-none"
    >
      {icon && <span className={`w-[18px] h-[18px] flex-shrink-0 ${danger ? "text-aster-danger" : "text-txt-muted group-hover:text-txt-secondary"}`}>{icon}</span>}
      <div className="min-w-0 flex-1">
        <p className={`text-[14px] leading-tight ${danger ? "text-aster-danger" : "text-txt-primary"}`}>{label}</p>
        {sublabel && <p className="text-[12px] text-txt-muted mt-0.5 leading-snug truncate">{sublabel}</p>}
      </div>
      {right !== undefined ? right : <ChevronRightIcon />}
    </button>
  );
}

function Toggle({ checked, disabled, on_click }: { checked: boolean; disabled?: boolean; on_click: () => void }) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      disabled={disabled}
      onClick={on_click}
      className={`relative w-9 h-5 rounded-full flex-shrink-0 transition-colors disabled:opacity-50 ${checked ? "bg-brand" : "bg-edge-secondary"}`}
    >
      <span className={`absolute top-0.5 left-0.5 w-4 h-4 rounded-full bg-white shadow-sm transition-transform ${checked ? "translate-x-4" : ""}`} />
    </button>
  );
}

function InfoRow({ label, value, copy = true, mono = true }: { label: string; value: string; copy?: boolean; mono?: boolean }) {
  return (
    <div className="flex items-center justify-between gap-3 px-3.5 min-h-[42px] py-1.5">
      <span className="text-[13px] text-txt-muted flex-shrink-0">{label}</span>
      {copy
        ? <CopyValue value={value} mono={mono} />
        : <span className={`text-[13px] text-right text-txt-primary truncate ${mono ? "font-mono" : ""}`} title={value}>{value}</span>}
    </div>
  );
}

function SetupStep({ n, title, children }: { n: number; title: string; children: ReactNode }) {
  return (
    <div className="flex gap-3">
      <div className="flex-shrink-0 w-4 text-txt-muted text-sm font-semibold tabular-nums mt-px">{n}</div>
      <div className="flex-1 min-w-0 space-y-2">
        <p className="text-sm font-semibold text-txt-primary">{title}</p>
        {children}
      </div>
    </div>
  );
}

function SetupNote({ children }: { children: ReactNode }) {
  return <p className="text-txt-tertiary text-[13px] leading-relaxed">{children}</p>;
}

function SetupBox({ children }: { children: ReactNode }) {
  return <div className="space-y-0.5">{children}</div>;
}

function SetupGroupLabel({ children }: { children: ReactNode }) {
  return <p className="text-[11px] font-semibold uppercase tracking-wide text-txt-muted pt-1">{children}</p>;
}

function SetupRow({ label, value, hint, mono = true }: { label: string; value?: string; hint?: string; mono?: boolean }) {
  return (
    <div className="flex items-center justify-between gap-3 text-sm min-h-[30px]">
      <span className="text-txt-muted flex-shrink-0">{label}</span>
      {value
        ? <CopyValue value={value} mono={mono} />
        : <span className="text-txt-tertiary text-xs italic text-right">{hint}</span>}
    </div>
  );
}

function UptimeCounter({ since }: { since: number }) {
  const { t } = useTranslation();
  const [, tick] = useState(0);
  useEffect(() => {
    const timer = setInterval(() => tick(n => n + 1), 30_000);
    return () => clearInterval(timer);
  }, []);
  const ms = Date.now() - since;
  const h = Math.floor(ms / 3_600_000);
  const m = Math.floor((ms % 3_600_000) / 60_000);
  if (h > 0) return <>{h}h {m}m</>;
  if (m > 0) return <>{m}m</>;
  return <>{t("time_just_now")}</>;
}

function UserAvatar({
  email,
  profile_picture,
  profile_color,
  display_name,
  size = 32,
}: {
  email: string;
  profile_picture: string | null;
  profile_color: string | null;
  display_name: string | null;
  size?: number;
}) {
  const [img_error, set_img_error] = useState(false);

  if (profile_picture && !img_error) {
    return (
      <div
        className="rounded-full flex-shrink-0 overflow-hidden"
        style={{ width: size, height: size, minWidth: size, minHeight: size }}
      >
        <img
          alt={display_name || email}
          className="w-full h-full object-cover"
          crossOrigin="anonymous"
          decoding="async"
          draggable={false}
          referrerPolicy="no-referrer"
          src={profile_picture}
          onError={() => set_img_error(true)}
        />
      </div>
    );
  }

  const color = profile_color || "#6366f1";
  const logo_size = Math.round(size * 0.55);

  return (
    <div
      className="rounded-full flex-shrink-0 flex items-center justify-center"
      style={{ width: size, height: size, minWidth: size, minHeight: size, background: get_gradient_background(color) }}
    >
      <img
        alt={email}
        draggable={false}
        src="/aster.webp"
        style={{
          width: logo_size, height: logo_size,
          filter: "brightness(0) invert(1)",
          objectFit: "contain" as const, userSelect: "none" as const, pointerEvents: "none" as const,
        }}
      />
    </div>
  );
}

function SetupView({
  on_enrolled,
  can_go_back,
  on_back,
}: {
  on_enrolled: () => void;
  can_go_back: boolean;
  on_back: () => void;
}) {
  const { t } = useTranslation();
  const [state, set_state] = useState<SetupState>("idle");
  const [code, set_code] = useState<string | null>(null);
  const [time_left, set_time_left] = useState(0);
  const [code_copied, set_code_copied] = useState(false);
  const [link_copied, set_link_copied] = useState(false);

  const poll_ref = useRef<ReturnType<typeof setTimeout> | null>(null);
  const countdown_ref = useRef<ReturnType<typeof setInterval> | null>(null);
  const poll_count_ref = useRef(0);
  const active_ref = useRef(true);

  const stop_polling = useCallback(() => {
    if (poll_ref.current) { clearTimeout(poll_ref.current); poll_ref.current = null; }
    if (countdown_ref.current) { clearInterval(countdown_ref.current); countdown_ref.current = null; }
    poll_count_ref.current = 0;
  }, []);

  useEffect(() => {
    return () => { active_ref.current = false; stop_polling(); };
  }, [stop_polling]);

  const start_code_flow = useCallback(async () => {
    set_state("requesting_code");
    stop_polling();
    active_ref.current = true;

    try {
      const result = await api.get_setup_code();
      set_code(result);
      const expiry = Date.now() + 300 * 1000;
      set_time_left(300);
      set_state("showing_code");

      countdown_ref.current = setInterval(() => {
        const remaining = Math.max(0, Math.round((expiry - Date.now()) / 1000));
        set_time_left(remaining);
        if (remaining <= 0) { stop_polling(); set_state("expired"); }
      }, 1000);

      const get_poll_delay = (count: number): number => {
        if (count < 10) return 3000;
        if (count < 20) return 5000;
        return 8000;
      };

      const schedule_poll = () => {
        poll_count_ref.current += 1;
        if (poll_count_ref.current > 60) { stop_polling(); set_state("expired"); return; }
        poll_ref.current = setTimeout(async () => {
          if (!active_ref.current) return;
          try {
            const status = await api.check_setup_confirmation();
            if (status === "confirmed") { stop_polling(); on_enrolled(); return; }
            if (status === "expired") { stop_polling(); set_state("expired"); return; }
          } catch {
            /* keep polling on transient errors */
          }
          schedule_poll();
        }, get_poll_delay(poll_count_ref.current));
      };

      schedule_poll();
    } catch {
      set_state("error");
    }
  }, [stop_polling, on_enrolled]);

  const handle_copy_code = async () => {
    if (!code) return;
    try {
      await navigator.clipboard.writeText(code.replace(/-/g, ""));
      show_toast(t("copied_to_clipboard"), "success");
      set_code_copied(true);
      setTimeout(() => set_code_copied(false), 1500);
    } catch {
      show_toast(t("failed_to_copy"), "error");
    }
  };

  const handle_copy_link = async () => {
    try {
      await navigator.clipboard.writeText(LINK_DEVICE_URL);
      show_toast(t("copied_to_clipboard"), "success");
      set_link_copied(true);
      setTimeout(() => set_link_copied(false), 1500);
    } catch {
      show_toast(t("failed_to_copy"), "error");
    }
  };

  const handle_back = () => { stop_polling(); set_state("idle"); set_code(null); on_back(); };
  const code_chars = code ? code.replace(/-/g, "").split("") : [];

  return (
    <div className="fixed inset-0 overflow-y-auto" style={{ backgroundColor: "var(--bg-secondary)" }}>
      <div className="min-h-full flex items-center justify-center px-4 py-8">
        <div className="flex flex-col items-center w-full max-w-sm px-4">
          <img alt="Aster" className="h-12" decoding="async" draggable={false} src="/text_logo.png" />

          {state === "idle" && (
            <>
              <h1 className="text-xl font-semibold mt-6 text-txt-primary text-center">{t("setup_title")}</h1>
              <p className="text-sm mt-2 leading-relaxed text-txt-tertiary text-center">
                {t("setup_subtitle")}
              </p>
              <Button className="w-full mt-6" size="xl" variant="depth" onClick={start_code_flow}>{t("setup_get_started")}</Button>
              {can_go_back && (
                <button className="mt-3 text-sm text-txt-muted hover:text-txt-tertiary transition-colors" onClick={handle_back}>
                  {t("setup_back_to_dashboard")}
                </button>
              )}
            </>
          )}

          {state === "requesting_code" && <div className="mt-8"><Spinner class_name="w-6 h-6 text-txt-muted" /></div>}

          {state === "showing_code" && (
            <>
              <h1 className="text-xl font-semibold mt-6 text-txt-primary text-center">{t("setup_title")}</h1>
              <p className="text-sm mt-2 leading-relaxed text-txt-tertiary text-center">
                {t("setup_code_subtitle")}
              </p>
              <div className="w-full mt-6">
                <div className="flex items-center justify-between mb-3">
                  <span className="text-xs font-medium text-txt-muted">{t("setup_expires_in", { time: format_time(time_left) })}</span>
                  <button className="p-1.5 rounded-md transition-colors hover:bg-black/[0.06] dark:hover:bg-white/[0.08] text-txt-muted" onClick={handle_copy_code}>
                    <CopyIcon copied={code_copied} />
                  </button>
                </div>
                <div className="grid grid-cols-8 gap-2 cursor-pointer" onClick={handle_copy_code}>
                  {code_chars.map((char, i) => (
                    <div key={i} className="relative overflow-hidden rounded-lg py-2.5 border text-center transition-colors hover:opacity-80 bg-surf-tertiary border-edge-secondary">
                      <span className="text-base font-mono font-bold text-txt-primary">{char}</span>
                    </div>
                  ))}
                </div>
              </div>
              <div className="flex items-center gap-3 w-full mt-6">
                <Button className="flex-1" size="xl" variant="secondary" onClick={handle_copy_code}>{t("setup_copy_code")}</Button>
                <Button className="flex-1" size="xl" variant="depth" onClick={() => api.open_url(LINK_DEVICE_URL)}>{t("setup_open_browser")}</Button>
              </div>
              <button className="mt-4 flex items-center gap-1.5 text-xs text-txt-muted hover:text-txt-tertiary transition-colors" onClick={handle_copy_link}>
                <span className="underline underline-offset-2">{LINK_DEVICE_URL}</span>
                <CopyIcon copied={link_copied} />
              </button>
              <div className="mt-6 flex items-center gap-2">
                <Spinner class_name="w-4 h-4 text-txt-muted" />
                <span className="text-xs text-txt-muted">{t("setup_listening")}</span>
              </div>
              {can_go_back && (
                <button className="mt-4 text-sm text-txt-muted hover:text-txt-tertiary transition-colors" onClick={handle_back}>{t("cancel")}</button>
              )}
            </>
          )}

          {state === "expired" && (
            <>
              <h1 className="text-xl font-semibold mt-6 text-txt-primary text-center">{t("setup_expired_title")}</h1>
              <p className="text-sm mt-2 leading-relaxed text-txt-tertiary text-center">{t("setup_expired_subtitle")}</p>
              <Button className="w-full mt-6" size="xl" variant="depth" onClick={start_code_flow}>{t("setup_get_new_code")}</Button>
              {can_go_back && <button className="mt-3 text-sm text-txt-muted hover:text-txt-tertiary transition-colors" onClick={handle_back}>{t("setup_back_to_dashboard")}</button>}
            </>
          )}

          {state === "error" && (
            <>
              <h1 className="text-xl font-semibold mt-6 text-txt-primary text-center">{t("setup_error_title")}</h1>
              <p className="text-sm mt-2 leading-relaxed text-txt-tertiary text-center">{t("setup_error_subtitle")}</p>
              <Button className="w-full mt-6" size="xl" variant="depth" onClick={start_code_flow}>{t("setup_try_again")}</Button>
              {can_go_back && <button className="mt-3 text-sm text-txt-muted hover:text-txt-tertiary transition-colors" onClick={handle_back}>{t("setup_back_to_dashboard")}</button>}
            </>
          )}
        </div>
      </div>
    </div>
  );
}

function SidebarNavButton({
  label,
  icon,
  active,
  on_click,
  badge,
}: {
  label: string;
  icon: React.ReactNode;
  active: boolean;
  on_click: () => void;
  badge?: number;
}) {
  return (
    <button
      className={`sidebar-nav-btn relative w-full flex items-center gap-2.5 rounded-[12px] px-2.5 h-8 text-[14px] ${
        active ? "sidebar-active" : ""
      }`}
      style={{
        zIndex: 1,
        color: active ? "var(--text-primary)" : "var(--text-secondary)",
      }}
      onClick={on_click}
    >
      <span
        className="w-4 h-4 flex-shrink-0 flex items-center justify-center"
        style={{ color: active ? "var(--text-primary)" : "var(--text-secondary)" }}
      >
        {icon}
      </span>
      <span className="flex-1 text-left">{label}</span>
      {badge != null && badge > 0 && (
        <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-[#ef4444]/15 text-[#ef4444] font-mono font-medium min-w-[18px] text-center">
          {badge}
        </span>
      )}
    </button>
  );
}

function Sidebar({
  email,
  display_name,
  profile_picture,
  profile_color,
  bridge_running,
  active_tab,
  on_tab_change,
  on_sign_out,
  outbox_count,
}: {
  email: string | null;
  display_name: string | null;
  profile_picture: string | null;
  profile_color: string | null;
  bridge_running: boolean;
  active_tab: Tab;
  on_tab_change: (tab: Tab) => void;
  on_sign_out: () => void;
  outbox_count: number;
}) {
  const { t } = useTranslation();
  const [show_menu, set_show_menu] = useState(false);
  const [show_sign_out_modal, set_show_sign_out_modal] = useState(false);
  const menu_ref = useRef<HTMLDivElement>(null);
  const trigger_ref = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (!show_menu) return;
    const handle_click_outside = (e: MouseEvent) => {
      if (
        menu_ref.current && !menu_ref.current.contains(e.target as Node) &&
        trigger_ref.current && !trigger_ref.current.contains(e.target as Node)
      ) {
        set_show_menu(false);
      }
    };
    document.addEventListener("mousedown", handle_click_outside);
    return () => document.removeEventListener("mousedown", handle_click_outside);
  }, [show_menu]);

  return (
    <aside
      className="flex h-full flex-col flex-shrink-0 w-64 min-w-64 max-w-64"
      style={{ backgroundColor: "var(--sidebar-bg)" }}
    >
      <div className="px-3 pt-4 pb-2 relative">
        <button
          ref={trigger_ref}
          className="w-full flex items-center gap-3 group"
          onClick={() => set_show_menu(!show_menu)}
        >
          <div className="w-9 h-9 flex-shrink-0">
            <img alt="Aster Bridge" className="w-full h-full select-none rounded-lg" decoding="async" draggable={false} src="/mail_logo.webp" />
          </div>
          <div className="flex flex-col items-start min-w-0 flex-1">
            <span className="text-[15px] font-semibold text-txt-primary">Aster Bridge</span>
            <span className="text-[11px] truncate w-full text-left text-txt-muted">
              {display_name || email || t("not_connected")}
            </span>
          </div>
          <svg
            className={`h-4 w-4 flex-shrink-0 transition-transform duration-150 text-txt-muted ${show_menu ? "rotate-180" : ""}`}
            fill="none"
            stroke="currentColor"
            strokeWidth={2}
            viewBox="0 0 24 24"
          >
            <path d="M19.5 8.25l-7.5 7.5-7.5-7.5" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
        </button>

        {show_menu && (
          <div
            ref={menu_ref}
            className="absolute left-3 right-3 mt-2 rounded-2xl overflow-hidden z-50 animate-dropdown-in"
            style={{
              backgroundColor: "var(--dropdown-bg)",
              border: "1px solid var(--border-secondary)",
              boxShadow: "0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04)",
            }}
          >
            <div className="p-1.5 pb-0">
              <button
                className="w-full px-2.5 py-2 rounded-lg text-left flex items-center gap-2.5 transition-colors hover:bg-black/[0.04] dark:hover:bg-white/[0.06]"
                onClick={() => {
                  if (email) {
                    navigator.clipboard.writeText(email).catch(() => {});
                    show_toast(t("copied_to_clipboard"), "success");
                  }
                }}
              >
                <div className="relative">
                  <UserAvatar
                    email={email || ""}
                    profile_picture={profile_picture}
                    profile_color={profile_color}
                    display_name={display_name}
                    size={32}
                  />
                  {bridge_running && (
                    <div
                      className="absolute -bottom-0.5 -right-0.5 w-2.5 h-2.5 rounded-full border-2"
                      style={{
                        backgroundColor: "var(--color-success)",
                        borderColor: "var(--dropdown-bg)",
                      }}
                    />
                  )}
                </div>
                <div className="flex flex-col min-w-0 flex-1">
                  <span className="text-[12px] font-medium truncate" style={{ color: "var(--text-primary)" }}>
                    {display_name || email || ""}
                  </span>
                  <span className="text-[11px] truncate" style={{ color: "var(--text-muted)" }}>
                    {email}
                  </span>
                </div>
                <svg className="w-3.5 h-3.5 flex-shrink-0" fill="none" stroke="currentColor" strokeWidth={2} style={{ color: "var(--text-muted)" }} viewBox="0 0 24 24">
                  <rect height="13" rx="2" width="13" x="9" y="9" />
                  <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" strokeLinecap="round" strokeLinejoin="round" />
                </svg>
              </button>
            </div>

            <div className="h-px my-1.5 mx-1.5" style={{ backgroundColor: "var(--border-secondary)" }} />

            <div className="p-1.5 pt-0 space-y-1">
              <Button
                size="sm"
                variant="destructive"
                className="w-full text-[12px]"
                onClick={() => { set_show_menu(false); set_show_sign_out_modal(true); }}
              >
                <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" strokeWidth={1.5} viewBox="0 0 24 24">
                  <path d="M15.75 9V5.25A2.25 2.25 0 0 0 13.5 3h-6a2.25 2.25 0 0 0-2.25 2.25v13.5A2.25 2.25 0 0 0 7.5 21h6a2.25 2.25 0 0 0 2.25-2.25V15m3 0 3-3m0 0-3-3m3 3H9" strokeLinecap="round" strokeLinejoin="round" />
                </svg>
                {t("sign_out")}
              </Button>
            </div>
          </div>
        )}
      </div>

      <nav className="flex-1 px-2.5 pt-0.5 pb-2 relative">
        <div
          className="sidebar-indicator absolute left-2.5 right-2.5 rounded-[12px] pointer-events-none"
          style={{
            height: 32,
            backgroundColor: "var(--indicator-bg)",
            transform: `translateY(${active_tab === "status" ? 0 : active_tab === "passwords" ? 34 : 68}px)`,
            zIndex: 0,
          }}
        />
        <SidebarNavButton
          label={t("nav_configuration")}
          active={active_tab === "status"}
          on_click={() => { set_show_menu(false); on_tab_change("status"); }}
          icon={
            <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth={1.5} viewBox="0 0 24 24">
              <path d="M9.594 3.94c.09-.542.56-.94 1.11-.94h2.593c.55 0 1.02.398 1.11.94l.213 1.281c.063.374.313.686.645.87.074.04.147.083.22.127.325.196.72.257 1.075.124l1.217-.456a1.125 1.125 0 0 1 1.37.49l1.296 2.247a1.125 1.125 0 0 1-.26 1.431l-1.003.827c-.293.241-.438.613-.43.992a7.723 7.723 0 0 1 0 .255c-.008.378.137.75.43.991l1.004.827c.424.35.534.955.26 1.43l-1.298 2.247a1.125 1.125 0 0 1-1.369.491l-1.217-.456c-.355-.133-.75-.072-1.076.124a6.47 6.47 0 0 1-.22.128c-.331.183-.581.495-.644.869l-.213 1.281c-.09.543-.56.94-1.11.94h-2.594c-.55 0-1.019-.398-1.11-.94l-.213-1.281c-.062-.374-.312-.686-.644-.87a6.52 6.52 0 0 1-.22-.127c-.325-.196-.72-.257-1.076-.124l-1.217.456a1.125 1.125 0 0 1-1.369-.49l-1.297-2.247a1.125 1.125 0 0 1 .26-1.431l1.004-.827c.292-.24.437-.613.43-.991a6.932 6.932 0 0 1 0-.255c.007-.38-.138-.751-.43-.992l-1.004-.827a1.125 1.125 0 0 1-.26-1.43l1.297-2.247a1.125 1.125 0 0 1 1.37-.491l1.216.456c.356.133.751.072 1.076-.124.072-.044.146-.086.22-.128.332-.183.582-.495.644-.869l.214-1.28Z" strokeLinecap="round" strokeLinejoin="round" />
              <path d="M15 12a3 3 0 1 1-6 0 3 3 0 0 1 6 0Z" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
          }
        />
        <SidebarNavButton
          label={t("nav_app_passwords")}
          active={active_tab === "passwords"}
          on_click={() => { set_show_menu(false); on_tab_change("passwords"); }}
          icon={
            <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth={1.5} viewBox="0 0 24 24">
              <path d="M15.75 5.25a3 3 0 0 1 3 3m3 0a6 6 0 0 1-7.029 5.912c-.563-.097-1.159.026-1.563.43L10.5 17.25H8.25v2.25H6v2.25H2.25v-2.818c0-.597.237-1.17.659-1.591l6.499-6.499c.404-.404.527-1 .43-1.563A6 6 0 1 1 21.75 8.25Z" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
          }
        />
        <SidebarNavButton
          label={t("nav_settings")}
          active={active_tab === "settings"}
          on_click={() => { set_show_menu(false); on_tab_change("settings"); }}
          badge={outbox_count}
          icon={
            <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth={1.5} viewBox="0 0 24 24">
              <path d="M10.5 6h9.75M10.5 6a1.5 1.5 0 1 1-3 0m3 0a1.5 1.5 0 1 0-3 0M3.75 6H7.5m3 12h9.75m-9.75 0a1.5 1.5 0 0 1-3 0m3 0a1.5 1.5 0 0 0-3 0m-3.75 0H7.5m9-6h3.75m-3.75 0a1.5 1.5 0 0 1-3 0m3 0a1.5 1.5 0 0 0-3 0m-9.75 0h9.75" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
          }
        />
      </nav>

      <Modal open={show_sign_out_modal} on_close={() => set_show_sign_out_modal(false)}>
        <p className="text-base font-semibold text-txt-primary">{t("sign_out_title")}</p>
        <ModalBody>
          <span>{t("sign_out_body")}</span>
        </ModalBody>
        <ModalActions>
          <Button variant="ghost" size="md" onClick={() => set_show_sign_out_modal(false)}>{t("cancel")}</Button>
          <Button variant="destructive" size="md" onClick={() => { set_show_sign_out_modal(false); on_sign_out(); }}>{t("sign_out")}</Button>
        </ModalActions>
      </Modal>
    </aside>
  );
}

function ConfigPanel({
  email,
  display_name,
  profile_picture,
  profile_color,
  conn_info,
  bridge_running,
  on_toggle_bridge,
  connected_since,
  sync_progress,
}: {
  email: string | null;
  display_name: string | null;
  profile_picture: string | null;
  profile_color: string | null;
  conn_info: ConnectionInfo | null;
  bridge_running: boolean;
  on_toggle_bridge: () => void;
  connected_since: number | null;
  sync_progress: { folder: string; done: number; total: number } | null;
}) {
  const { t } = useTranslation();
  const imap_host = conn_info?.imap_host || "127.0.0.1";
  const imap_port = String(conn_info?.imap_port || 1143);
  const smtp_host = conn_info?.smtp_host || "127.0.0.1";
  const smtp_port = String(conn_info?.smtp_port || 1025);
  const jmap_host = conn_info?.jmap_host || "127.0.0.1";
  const jmap_port = String(conn_info?.jmap_port || 1080);
  const jmap_url = conn_info?.jmap_url || `http://${jmap_host}:${jmap_port}/jmap/session`;
  const jmap_enabled = conn_info?.jmap_enabled ?? true;
  const tls_enabled = conn_info?.tls_enabled ?? false;
  const imap_security = tls_enabled ? "STARTTLS" : t("field_none");
  const smtp_security = tls_enabled ? "STARTTLS" : t("field_none");
  const imap_implicit_tls_port = String(conn_info?.imap_implicit_tls_port || 1993);
  const smtp_implicit_tls_port = String(conn_info?.smtp_implicit_tls_port || 1465);
  const jmap_https_enabled = conn_info?.jmap_https_enabled ?? false;
  const pop3_host = imap_host;
  const pop3_port = String(conn_info?.pop3_port || 1110);
  const pop3s_port = String(conn_info?.pop3s_port || 1995);

  const email_value = email || "-";

  const avatar_letter = (display_name || email || "?")[0].toUpperCase();
  const avatar_bg = profile_color && HEX_COLOR.test(profile_color) ? profile_color : "#6366f1";

  return (
    <div className="p-5">
      <div className="flex items-center gap-3 mb-4">
        <div className="w-10 h-10 rounded-xl flex-shrink-0 overflow-hidden">
          {profile_picture ? (
            <img src={profile_picture} className="w-full h-full object-cover" alt="" draggable={false} />
          ) : (
            <div className="w-full h-full flex items-center justify-center text-white font-semibold text-sm" style={{ backgroundColor: avatar_bg }}>
              {avatar_letter}
            </div>
          )}
        </div>
        <div className="min-w-0 flex-1">
          <p className="text-sm font-semibold text-txt-primary truncate">{display_name || email?.split("@")[0] || "-"}</p>
          <p className="text-[11px] text-txt-muted truncate">{email_value}</p>
        </div>
      </div>

      <div
        className="rounded-xl border border-edge-secondary px-4 py-3.5 flex items-center justify-between gap-4 mb-4"
        style={{ backgroundColor: "color-mix(in srgb, var(--text-primary) 3%, var(--bg-primary))", boxShadow: "0 1px 2px rgba(0, 0, 0, 0.04)" }}
        title={bridge_running
          ? (connected_since
              ? `${t("connected_since_label")} ${new Date(connected_since).toLocaleString()}. ${t("connected_tooltip_servers")}`
              : t("connected_tooltip_servers"))
          : t("not_connected_tooltip")}
      >
        <div className="flex items-center gap-3 min-w-0">
          <span
            className="flex-shrink-0"
            style={{ color: bridge_running ? "var(--accent-color)" : "var(--color-danger)" }}
          >
            {bridge_running
              ? <SignalIcon className="w-6 h-6" />
              : <SignalSlashIcon className="w-6 h-6" />}
          </span>
          <div className="min-w-0">
            <p className="text-sm font-semibold text-txt-primary leading-tight truncate">
              {bridge_running ? t("connected") : t("not_connected")}
            </p>
            {bridge_running && connected_since && (
              <p className="text-[12px] text-txt-muted leading-tight mt-0.5 tabular-nums">
                <UptimeCounter since={connected_since} />
              </p>
            )}
          </div>
        </div>
        <Button variant={bridge_running ? "destructive" : "depth"} size="lg" className="flex-shrink-0" onClick={on_toggle_bridge}>
          {bridge_running ? t("disconnect") : t("connect")}
        </Button>
      </div>

      {bridge_running && sync_progress && (
        <div className="mb-4">
          <div className="flex items-end justify-between mb-1.5 gap-3">
            <span className="flex items-center gap-1.5 text-xs font-medium text-txt-primary truncate min-w-0">
              <svg className="w-3.5 h-3.5 text-brand animate-spin flex-shrink-0" fill="none" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="3" />
                <path className="opacity-90" fill="currentColor" d="M12 2a10 10 0 0 1 10 10h-3a7 7 0 0 0-7-7V2z" />
              </svg>
              <span className="truncate">{t("syncing_folder", { folder: sync_progress.folder })}</span>
            </span>
            <span className="text-xs font-normal text-txt-muted tabular-nums flex-shrink-0 leading-none">
              {sync_progress.done.toLocaleString()} / {sync_progress.total.toLocaleString()}
            </span>
          </div>
          <div className="h-1.5 rounded-full overflow-hidden" style={{ backgroundColor: "var(--border-secondary)" }}>
            <div
              className="h-full rounded-full bg-brand transition-all duration-500 ease-out"
              style={{ width: `${sync_progress.total > 0 ? (sync_progress.done / sync_progress.total) * 100 : 0}%` }}
            />
          </div>
        </div>
      )}

      <SettingsGroup title={t("section_incoming")}>
        <InfoRow label={t("field_protocol")} value="IMAP" copy={false} />
        <InfoRow label={t("field_hostname")} value={imap_host} />
        <InfoRow label={t("field_port")} value={imap_port} />
        <InfoRow label={t("field_connection_security")} value={imap_security} copy={false} mono={false} />
        {tls_enabled && <InfoRow label={t("field_implicit_tls_port")} value={imap_implicit_tls_port} />}
        <InfoRow label={t("field_auth_method")} value={t("field_normal_password")} copy={false} mono={false} />
        <InfoRow label={t("field_username")} value={email_value} />
      </SettingsGroup>

      <SettingsGroup title={t("section_outgoing")}>
        <InfoRow label={t("field_hostname")} value={smtp_host} />
        <InfoRow label={t("field_port")} value={smtp_port} />
        <InfoRow label={t("field_connection_security")} value={smtp_security} copy={false} mono={false} />
        {tls_enabled && <InfoRow label={t("field_implicit_tls_port")} value={smtp_implicit_tls_port} />}
      </SettingsGroup>

      <SettingsGroup title={jmap_enabled ? t("section_jmap") : t("section_jmap_disabled")} hint={t("jmap_hint")}>
        <InfoRow label={t("field_protocol")} value={t("field_jmap_protocol")} copy={false} mono={false} />
        <InfoRow label={t("field_session_url")} value={jmap_url} />
        <InfoRow label={t("field_hostname")} value={jmap_host} />
        <InfoRow label={t("field_port")} value={jmap_port} />
        <InfoRow label={t("field_authentication")} value={t("field_http_basic")} copy={false} mono={false} />
        <InfoRow label={t("field_username")} value={email_value} />
        <div className="flex items-center justify-between gap-3 px-3.5 min-h-[42px] py-1.5">
          <span className="text-[13px] text-txt-muted flex-shrink-0">{t("field_password")}</span>
          <span className="text-[13px] text-txt-tertiary text-right">{t("field_password_hint")}</span>
        </div>
      </SettingsGroup>

      <SettingsGroup title={t("section_pop3")}>
        <InfoRow label={t("field_hostname")} value={pop3_host} />
        <InfoRow label={t("field_port")} value={pop3_port} />
        <InfoRow label={t("field_connection_security")} value={t("field_none")} copy={false} mono={false} />
        {tls_enabled && <InfoRow label={t("field_implicit_tls_port")} value={pop3s_port} />}
        <InfoRow label={t("field_username")} value={email_value} />
      </SettingsGroup>

      {tls_enabled && <TlsInfoBlock jmap_https_enabled={jmap_https_enabled} />}
    </div>
  );
}

function TlsInfoBlock({
  jmap_https_enabled,
}: {
  jmap_https_enabled: boolean;
}) {
  const { t } = useTranslation();
  const [tls_info, set_tls_info] = useState<api.TlsInfo | null>(null);
  useEffect(() => {
    let cancelled = false;
    api.get_tls_info().then((info) => { if (!cancelled) set_tls_info(info); }).catch(() => {});
    return () => { cancelled = true; };
  }, []);
  const fingerprint = tls_info?.fingerprint_sha256 || "(unavailable)";
  const cert_path = tls_info?.cert_path || "(unavailable)";
  return (
    <SettingsGroup title={t("section_tls")} hint={t("tls_hint")}>
      <InfoRow label={t("tls_status")} value={t("tls_enabled")} copy={false} mono={false} />
      <InfoRow label={t("tls_cert_sha256")} value={fingerprint} />
      <div className="flex items-center justify-between gap-3 px-3.5 min-h-[42px] py-1.5">
        <span className="text-[13px] text-txt-muted flex-shrink-0">{t("tls_cert_path")}</span>
        <span className="inline-flex items-center justify-end gap-2 min-w-0">
          <span className="text-[13px] text-txt-primary font-mono truncate max-w-[140px]" title={cert_path}>{cert_path.split(/[/\\]/).pop() ?? cert_path}</span>
          <button
            type="button"
            className="text-[11px] text-txt-muted hover:text-txt-primary underline underline-offset-2 transition-colors flex-shrink-0"
            onClick={() => api.open_tls_cert().catch(() => {})}
          >
            {t("tls_open_cert_folder")}
          </button>
        </span>
      </div>
      <InfoRow label={t("tls_jmap_scheme")} value={jmap_https_enabled ? "https://" : "http://"} copy={false} />
    </SettingsGroup>
  );
}


function PasswordsPanel({
  passwords,
  on_generate_password,
  on_delete_password,
}: {
  passwords: { id: string; label: string; created_at: string; last_used_at: number | null; last_client: string | null; use_count: number }[];
  on_generate_password: (label: string) => Promise<string | null>;
  on_delete_password: (id: string) => Promise<void>;
}) {
  const { t } = useTranslation();
  const [new_password_label, set_new_password_label] = useState("");
  const [generated_password, set_generated_password] = useState<string | null>(null);
  const [generating, set_generating] = useState(false);
  const [banner_copied, set_banner_copied] = useState(false);
  const [delete_target, set_delete_target] = useState<{ id: string; label: string } | null>(null);
  const delete_display = use_frozen(delete_target);
  const [deleting, set_deleting] = useState(false);

  useEffect(() => {
    if (!generated_password) return;
    const timer = window.setTimeout(() => set_generated_password(null), 60_000);
    return () => window.clearTimeout(timer);
  }, [generated_password]);

  useEffect(() => {
    return () => set_generated_password(null);
  }, []);

  const handle_copy = async (value: string) => {
    try {
      await navigator.clipboard.writeText(value);
      show_toast(t("copied_to_clipboard"), "success");
      clear_clipboard_if_unchanged(value);
    } catch {
      show_toast(t("failed_to_copy"), "error");
    }
  };

  const handle_generate = async () => {
    set_generating(true);
    const label = new_password_label.trim() || "App Password";
    const password = await on_generate_password(label);
    if (password) { set_generated_password(password); set_new_password_label(""); }
    set_generating(false);
  };

  const handle_delete = async () => {
    if (!delete_target) return;
    set_deleting(true);
    await on_delete_password(delete_target.id);
    set_deleting(false);
    set_delete_target(null);
  };

  return (
    <div className="p-5">
      <h2 className="text-base font-semibold text-txt-primary mb-0.5">{t("passwords_title")}</h2>
      <p className="text-sm text-txt-tertiary mb-4">
        {t("passwords_subtitle")}
      </p>

      {generated_password && (
        <div className="mb-4 rounded-lg p-4" style={{ backgroundColor: "var(--accent-color)" }}>
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm font-medium text-white">{t("password_created_banner")}</span>
            <button className="p-1 rounded-lg transition-all duration-150 hover:opacity-70" onClick={() => set_generated_password(null)}>
              <svg className="w-4 h-4 text-white/70" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
                <path d="M6 18L18 6M6 6l12 12" strokeLinecap="round" strokeLinejoin="round" />
              </svg>
            </button>
          </div>
          <div className="flex items-center gap-2">
            <code className="flex-1 text-sm font-mono text-white px-3 py-2 rounded-md select-all" style={{ backgroundColor: "rgba(255, 255, 255, 0.15)" }}>
              {generated_password}
            </code>
            <button className="p-2 rounded-md transition-all duration-150 hover:opacity-70" style={{ backgroundColor: "rgba(255, 255, 255, 0.2)" }} onClick={async () => { await handle_copy(generated_password); set_banner_copied(true); setTimeout(() => set_banner_copied(false), 1500); }}>
              <CopyIcon copied={banner_copied} />
            </button>
          </div>
          <p className="mt-2 text-xs" style={{ color: "rgba(255, 255, 255, 0.7)" }}>{t("password_copy_hint")}</p>
        </div>
      )}

      <div className="flex gap-2 mb-2 items-stretch">
        <input
          className="flex-1 h-9 rounded-lg border px-3 text-sm text-txt-primary placeholder-txt-muted focus:outline-none transition-colors"
          style={{ backgroundColor: "var(--bg-tertiary)", borderColor: "var(--border-secondary)" }}
          placeholder={t("password_label_placeholder")}
          type="text"
          value={new_password_label}
          onChange={(e) => set_new_password_label(e.target.value)}
          onKeyDown={(e) => { if (e.key === "Enter") handle_generate(); }}
        />
        <Button disabled={generating} variant="depth" size="lg" onClick={handle_generate}>
          {generating ? t("generating") : t("generate")}
        </Button>
      </div>
      <div className="flex flex-wrap items-center gap-1.5 mb-4">
        <span className="text-[11px] text-txt-muted">{t("label_quick")}</span>
        {["Thunderbird", "Outlook", "Apple Mail", "iPhone", "iPad", "Android"].map(s => (
          <button
            key={s}
            type="button"
            className="text-[11px] px-2 py-0.5 rounded-full border transition-colors hover:bg-black/[0.04] dark:hover:bg-white/[0.06]"
            style={{ borderColor: "var(--border-secondary)", color: "var(--text-secondary)" }}
            onClick={() => set_new_password_label(s)}
          >
            {s}
          </button>
        ))}
      </div>

      {passwords.length === 0 && !generated_password && (
        <p className="text-sm text-txt-muted py-8 text-center">{t("no_passwords")}</p>
      )}

      {passwords.length > 0 && (
        <div className="space-y-2">
          {passwords.map((pw) => {
            const last_used_label = pw.last_used_at
              ? pw.last_client
                ? t("last_used_from", { time: format_relative_time(pw.last_used_at), client: pw.last_client })
                : t("last_used", { time: format_relative_time(pw.last_used_at) })
              : t("never_used");
            return (
              <div key={pw.id} className="flex items-center justify-between p-3 rounded-lg" style={{ backgroundColor: "var(--bg-tertiary)", border: "1px solid var(--border-secondary)" }}>
                <div className="min-w-0 pr-3">
                  <p className="text-sm font-medium text-txt-primary truncate">{pw.label}</p>
                  <p className="text-[11px] text-txt-muted mt-0.5">{t("created_date", { date: format_date(pw.created_at) })}</p>
                  <p className="text-[11px] text-txt-muted mt-0.5 truncate" title={last_used_label}>{last_used_label}</p>
                </div>
                <Button variant="outline" size="sm" onClick={() => set_delete_target(pw)}>{t("delete")}</Button>
              </div>
            );
          })}
        </div>
      )}

      <Modal open={!!delete_target} on_close={() => set_delete_target(null)}>
        <p className="text-base font-semibold text-txt-primary">{t("delete_password_title")}</p>
        <ModalBody>
          <span>{t("delete_password_confirm", { label: delete_display?.label ?? "" })}</span>
        </ModalBody>
        <ModalActions>
          <Button variant="ghost" size="md" onClick={() => set_delete_target(null)}>{t("cancel")}</Button>
          <Button disabled={deleting} variant="destructive" size="md" onClick={handle_delete}>{deleting ? t("deleting") : t("delete")}</Button>
        </ModalActions>
      </Modal>
    </div>
  );
}

function SettingsPanel({ on_reset, conn_info, email, bridge_running }: { on_reset: () => Promise<void>; conn_info: ConnectionInfo | null; email: string | null; bridge_running: boolean }) {
  const { t } = useTranslation();
  const [autostart, set_autostart] = useState(false);
  const [autostart_loading, set_autostart_loading] = useState(true);
  const [service_mode, set_service_mode] = useState(false);
  const [service_mode_loading, set_service_mode_loading] = useState(true);
  const [update_info, set_update_info] = useState<UpdateInfo | null>(null);
  const [update_checking, set_update_checking] = useState(false);
  const [update_installing, set_update_installing] = useState(false);
  const [app_version, set_app_version] = useState("");
  const [show_reset_modal, set_show_reset_modal] = useState(false);
  const [resetting, set_resetting] = useState(false);
  const [imap_port, set_imap_port] = useState(conn_info?.imap_port?.toString() ?? "1143");
  const [smtp_port, set_smtp_port] = useState(conn_info?.smtp_port?.toString() ?? "1025");
  const [ports_dirty, set_ports_dirty] = useState(false);
  const [saving_ports, set_saving_ports] = useState(false);
  const [data_dir, set_data_dir] = useState("");
  const [setup_client, set_setup_client] = useState<string | null>(null);
  const setup_display = use_frozen(setup_client);
  const [show_repair_modal, set_show_repair_modal] = useState(false);
  const [repairing, set_repairing] = useState(false);
  const [logs_open, set_logs_open] = useState(false);
  const [log_lines, set_log_lines] = useState<string[]>([]);
  const [logs_loading, set_logs_loading] = useState(false);
  const [copying_bundle, set_copying_bundle] = useState(false);
  const log_container_ref = useRef<HTMLDivElement>(null);
  const [outbox_items, set_outbox_items] = useState<api.OutboxItem[]>([]);
  const [outbox_retrying_id, set_outbox_retrying_id] = useState<number | null>(null);

  useEffect(() => {
    if (log_container_ref.current) {
      log_container_ref.current.scrollTop = log_container_ref.current.scrollHeight;
    }
  }, [log_lines]);

  const sanitize_error = (e: string): string => {
    const first_line = e.split('\n')[0].trim();
    return first_line.length > 120 ? first_line.slice(0, 117) + '...' : first_line;
  };

  const load_outbox = useCallback(async () => {
    try {
      const items = await api.outbox_list();
      set_outbox_items(items);
    } catch {
      set_outbox_items([]);
    }
  }, []);

  useEffect(() => {
    load_outbox();
    const timer = window.setInterval(load_outbox, 15000);
    return () => window.clearInterval(timer);
  }, [load_outbox]);

  const handle_outbox_retry = async (id: number) => {
    set_outbox_retrying_id(id);
    try {
      await api.outbox_retry_now(id);
      show_toast(t("toast_retry_queued"), "success");
      setTimeout(load_outbox, 1500);
    } catch (e) {
      show_toast(typeof e === "string" ? e : t("toast_retry_failed"), "error");
    }
    set_outbox_retrying_id(null);
  };

  const handle_repair = async () => {
    set_repairing(true);
    try {
      await api.repair_cache();
      show_toast(t("toast_cache_rebuilt"), "success");
      set_show_repair_modal(false);
    } catch (e) {
      show_toast(typeof e === "string" ? e : t("toast_repair_failed"), "error");
    }
    set_repairing(false);
  };

  const handle_toggle_logs = async () => {
    const next = !logs_open;
    set_logs_open(next);
    if (next) {
      set_logs_loading(true);
      try {
        const lines = await api.get_recent_logs();
        set_log_lines(lines);
      } catch {
        set_log_lines([]);
      }
      set_logs_loading(false);
    }
  };

  const handle_refresh_logs = async () => {
    set_logs_loading(true);
    try {
      const lines = await api.get_recent_logs();
      set_log_lines(lines);
    } catch {
      set_log_lines([]);
    }
    set_logs_loading(false);
  };

  const handle_copy_bundle = async () => {
    set_copying_bundle(true);
    try {
      const blob = await api.copy_diagnostic_bundle();
      try {
        await navigator.clipboard.writeText(blob);
        show_toast(t("toast_bundle_copied"), "success");
      } catch {
        show_toast(t("toast_bundle_clipboard_failed"), "error");
      }
    } catch {
      show_toast(t("toast_bundle_build_failed"), "error");
    }
    set_copying_bundle(false);
  };

  useEffect(() => {
    api.get_data_directory().then(set_data_dir).catch(() => {});
  }, []);

  useEffect(() => {
    if (conn_info) {
      set_imap_port(conn_info.imap_port.toString());
      set_smtp_port(conn_info.smtp_port.toString());
      set_ports_dirty(false);
    }
  }, [conn_info]);

  useEffect(() => {
    api.get_service_settings().then((s) => {
      set_autostart(s.autostart);
      set_service_mode(s.service_mode);
      set_autostart_loading(false);
      set_service_mode_loading(false);
    }).catch(() => {
      set_autostart_loading(false);
      set_service_mode_loading(false);
    });
  }, []);

  useEffect(() => {
    import("@tauri-apps/api/app").then(({ getVersion }) => getVersion()).then(set_app_version).catch(() => {});
  }, []);

  const handle_toggle_service_mode = async () => {
    const new_value = !service_mode;
    set_service_mode(new_value);
    try {
      await api.set_service_mode(new_value);
      show_toast(new_value ? t("toast_background_mode_on") : t("toast_background_mode_off"), "success");
    } catch {
      set_service_mode(!new_value);
      show_toast(t("toast_background_mode_failed"), "error");
    }
  };

  const handle_toggle_autostart = async () => {
    const new_value = !autostart;
    set_autostart(new_value);
    try {
      await api.set_autostart_enabled(new_value);
      show_toast(new_value ? t("toast_autolaunch_enabled") : t("toast_autolaunch_disabled"), "success");
    } catch {
      set_autostart(!new_value);
      show_toast(t("toast_autolaunch_failed"), "error");
    }
  };

  const handle_save_ports = async () => {
    const imap = parseInt(imap_port, 10);
    const smtp = parseInt(smtp_port, 10);
    if (isNaN(imap) || isNaN(smtp) || imap < 1024 || imap > 65535 || smtp < 1024 || smtp > 65535) {
      show_toast(t("toast_ports_invalid"), "error");
      return;
    }
    if (imap === smtp) {
      show_toast(t("toast_ports_same"), "error");
      return;
    }
    set_saving_ports(true);
    try {
      await api.update_connection_settings(imap, smtp);
      set_ports_dirty(false);
      show_toast(t("toast_ports_updated"), "success");
    } catch {
      show_toast(t("toast_ports_failed"), "error");
    }
    set_saving_ports(false);
  };

  const handle_check_updates = async () => {
    set_update_checking(true);
    const info = await check_for_update().catch(() => null);
    set_update_info(info);
    set_update_checking(false);
    if (!info) show_toast(t("toast_up_to_date"), "success");
  };

  const handle_install_update = async () => {
    set_update_installing(true);
    try {
      await download_and_install();
    } catch {
      show_toast(t("toast_update_failed"), "error");
      set_update_installing(false);
    }
  };

  const handle_reset = async () => {
    set_resetting(true);
    try {
      await on_reset();
      show_toast(t("toast_bridge_data_cleared"), "success");
      set_show_reset_modal(false);
    } catch {
      show_toast(t("toast_reset_failed"), "error");
    }
    set_resetting(false);
  };

  return (
    <div className="p-5">
      <h2 className="text-base font-semibold text-txt-primary mb-4">{t("settings_title")}</h2>

      <SettingsGroup title={t("section_general")}>
        <SettingRow label={t("launch_on_startup")} sublabel={t("launch_on_startup_hint")}>
          <Toggle checked={autostart} disabled={autostart_loading} on_click={handle_toggle_autostart} />
        </SettingRow>
        <SettingRow label={t("run_in_background")} sublabel={t("run_in_background_hint")}>
          <Toggle checked={service_mode} disabled={service_mode_loading} on_click={handle_toggle_service_mode} />
        </SettingRow>
      </SettingsGroup>

      <SettingsGroup title={t("section_email_client_setup")}>
        {["Thunderbird", "Outlook", "Apple Mail"].map((client) => (
          <ActionRow
            key={client}
            label={t("setup_with_client", { client })}
            on_click={() => set_setup_client(client)}
            icon={
              <svg className="w-[18px] h-[18px]" fill="none" stroke="currentColor" strokeWidth={1.5} viewBox="0 0 24 24">
                <rect x="2.25" y="5.25" width="19.5" height="13.5" rx="2" strokeLinecap="round" strokeLinejoin="round" />
                <path d="m3 6.75 9 6 9-6" strokeLinecap="round" strokeLinejoin="round" />
              </svg>
            }
          />
        ))}
      </SettingsGroup>

      <SettingsGroup title={t("section_support")}>
        <ActionRow
          label={t("help_center")}
          on_click={() => api.open_url("https://astermail.org/help")}
          icon={
            <svg className="w-[18px] h-[18px]" fill="none" stroke="currentColor" strokeWidth={1.5} viewBox="0 0 24 24">
              <path d="M9.879 7.519c1.171-1.025 3.071-1.025 4.242 0 1.172 1.025 1.172 2.687 0 3.712-.203.179-.43.326-.67.442-.745.361-1.45.999-1.45 1.827v.75M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Zm-9 5.25h.008v.008H12v-.008Z" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
          }
        />
        <ActionRow
          label={t("report_bug")}
          on_click={() => api.open_url("https://astermail.org/issue")}
          icon={
            <svg className="w-[18px] h-[18px]" fill="none" stroke="currentColor" strokeWidth={1.5} viewBox="0 0 24 24">
              <path d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126ZM12 15.75h.007v.008H12v-.008Z" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
          }
        />
      </SettingsGroup>

      <SettingsGroup title={t("section_port_config")} hint={t("port_config_hint")}>
        <SettingRow label={t("imap_port")}>
          <input
            type="text"
            inputMode="numeric"
            pattern="[0-9]*"
            value={imap_port}
            onChange={(e) => { const v = e.target.value.replace(/\D/g, ""); set_imap_port(v); set_ports_dirty(true); }}
            className="w-20 h-8 px-2.5 text-sm rounded-lg text-txt-primary text-center font-mono"
            style={{ backgroundColor: "var(--input-bg)", border: "1px solid var(--input-border)" }}
          />
        </SettingRow>
        <SettingRow label={t("smtp_port")}>
          <input
            type="text"
            inputMode="numeric"
            pattern="[0-9]*"
            value={smtp_port}
            onChange={(e) => { const v = e.target.value.replace(/\D/g, ""); set_smtp_port(v); set_ports_dirty(true); }}
            className="w-20 h-8 px-2.5 text-sm rounded-lg text-txt-primary text-center font-mono"
            style={{ backgroundColor: "var(--input-bg)", border: "1px solid var(--input-border)" }}
          />
        </SettingRow>
        {ports_dirty && (
          <div className="flex justify-end px-3.5 py-2.5">
            <Button variant="depth" size="sm" disabled={saving_ports} onClick={handle_save_ports}>
              {saving_ports ? t("saving") : t("save")}
            </Button>
          </div>
        )}
      </SettingsGroup>

      {outbox_items.length > 0 && (
        <SettingsGroup title={t("section_outbox")} hint={t("auto_sync_note")}>
          {outbox_items.map((item) => (
            <div key={item.id} className="flex items-start justify-between gap-3 px-3.5 py-3">
              <div className="min-w-0 flex-1">
                <div className="text-[14px] text-txt-primary truncate">
                  {item.subject && item.subject.trim().length > 0 ? item.subject : t("no_subject")}
                </div>
                <div className="text-[12px] text-txt-muted truncate mt-0.5">
                  {t("outbox_to", { to: item.envelope_to || "-" })}
                </div>
                <div className="text-[12px] text-txt-muted mt-0.5">
                  {t("outbox_status", { status: item.status, count: item.attempts })}
                </div>
                {item.last_error && (
                  <div className="text-[12px] text-aster-danger mt-1 break-words">
                    {sanitize_error(item.last_error)}
                  </div>
                )}
              </div>
              <Button
                variant="outline"
                size="sm"
                disabled={!bridge_running || outbox_retrying_id === item.id || item.status === "sending"}
                title={!bridge_running ? t("start_bridge_to_retry") : undefined}
                onClick={() => handle_outbox_retry(item.id)}
              >
                {outbox_retrying_id === item.id ? t("retrying") : t("retry_now")}
              </Button>
            </div>
          ))}
        </SettingsGroup>
      )}

      <SettingsGroup title={t("section_diagnostics")} hint={t("bundle_hint")}>
        <SettingRow label={t("diagnostics_logs_label")} sublabel={t("diagnostics_logs_hint")}>
          <Button variant="secondary" size="sm" onClick={handle_toggle_logs}>
            {logs_open ? t("hide") : t("show")}
          </Button>
        </SettingRow>
        <SettingRow label={t("diagnostics_bundle_label")} sublabel={t("diagnostics_bundle_sub")}>
          <Button variant="secondary" size="sm" disabled={copying_bundle} onClick={handle_copy_bundle}>
            <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
              <rect height="13" rx="2" width="13" x="9" y="9" />
              <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
            {copying_bundle ? t("building") : t("copy")}
          </Button>
        </SettingRow>
        {logs_open && (
          <div className="px-3.5 py-3">
            <div className="flex items-center justify-between mb-2">
              <span className="text-[11px] font-medium uppercase tracking-wider text-txt-muted">{t("show_recent_logs")}</span>
              <Button variant="ghost" size="sm" disabled={logs_loading} onClick={handle_refresh_logs}>
                {logs_loading ? t("loading") : t("refresh")}
              </Button>
            </div>
            <div
              ref={log_container_ref}
              className="rounded-lg p-3 text-[11px] font-mono whitespace-pre overflow-auto border border-edge-secondary"
              style={{ backgroundColor: "var(--bg-secondary)", maxHeight: "240px", color: "var(--text-secondary)" }}
            >
              {logs_loading && log_lines.length === 0 ? t("loading") : null}
              {!logs_loading && log_lines.length === 0 ? t("no_log_entries") : null}
              {log_lines.map((line, idx) => (
                <div key={idx}>{line}</div>
              ))}
            </div>
          </div>
        )}
      </SettingsGroup>

      <SettingsGroup title={t("section_updates")}>
        {update_info && (
          <div className="px-3.5 py-3">
            <p className="text-[14px] font-medium text-txt-primary mb-0.5">{t("update_available", { version: update_info.version })}</p>
            {update_info.notes && (
              <p className="text-[12px] text-txt-muted mb-2.5 line-clamp-3 leading-snug">{update_info.notes}</p>
            )}
            <Button variant="depth" size="sm" disabled={update_installing} onClick={handle_install_update}>
              {update_installing ? t("update_installing") : t("update_install")}
            </Button>
          </div>
        )}
        <SettingRow label={t("updates_app_row")} sublabel={app_version ? `${t("app_version")} ${app_version}` : undefined}>
          <Button variant="outline" size="sm" disabled={update_checking || update_installing} onClick={handle_check_updates}>
            {update_checking ? t("update_checking") : t("update_check_now")}
          </Button>
        </SettingRow>
      </SettingsGroup>

      <SettingsGroup title={t("section_advanced")}>
        {data_dir && (
          <ActionRow
            label={t("open_data_folder")}
            sublabel={data_dir}
            on_click={() => api.open_data_directory()}
            icon={
              <svg className="w-[18px] h-[18px]" fill="none" stroke="currentColor" strokeWidth={1.5} viewBox="0 0 24 24">
                <path d="M2.25 12.75V12A2.25 2.25 0 0 1 4.5 9.75h15A2.25 2.25 0 0 1 21.75 12v.75m-8.69-6.44-2.12-2.12a1.5 1.5 0 0 0-1.061-.44H4.5A2.25 2.25 0 0 0 2.25 6v12a2.25 2.25 0 0 0 2.25 2.25h15A2.25 2.25 0 0 0 21.75 18V9a2.25 2.25 0 0 0-2.25-2.25h-5.379a1.5 1.5 0 0 1-1.06-.44Z" strokeLinecap="round" strokeLinejoin="round" />
              </svg>
            }
          />
        )}
        <SettingRow
          label={t("repair_cache")}
          sublabel={t("repair_cache_sub")}
          icon={
            <svg className="w-[18px] h-[18px]" fill="none" stroke="currentColor" strokeWidth={1.5} viewBox="0 0 24 24">
              <path d="M16.023 9.348h4.992v-.001M2.985 19.644v-4.992m0 0h4.992m-4.993 0 3.181 3.183a8.25 8.25 0 0 0 13.803-3.7M4.031 9.865a8.25 8.25 0 0 1 13.803-3.7l3.181 3.182m0-4.991v4.99" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
          }
        >
          <Button variant="secondary" size="sm" disabled={repairing} onClick={() => set_show_repair_modal(true)}>
            {repairing ? t("rebuilding_cache") : t("repair")}
          </Button>
        </SettingRow>
        <SettingRow
          danger
          label={t("reset_bridge")}
          sublabel={t("reset_bridge_sub")}
          icon={
            <svg className="w-[18px] h-[18px]" fill="none" stroke="currentColor" strokeWidth={1.5} viewBox="0 0 24 24">
              <path d="M14.74 9l-.346 9m-4.788 0L9.26 9m9.968-3.21c.342.052.682.107 1.022.166m-1.022-.165L18.16 19.673a2.25 2.25 0 0 1-2.244 2.077H8.084a2.25 2.25 0 0 1-2.244-2.077L4.772 5.79m14.456 0a48.108 48.108 0 0 0-3.478-.397m-12 .562c.34-.059.68-.114 1.022-.165m0 0a48.11 48.11 0 0 1 3.478-.397m7.5 0v-.916c0-1.18-.91-2.164-2.09-2.201a51.964 51.964 0 0 0-3.32 0c-1.18.037-2.09 1.022-2.09 2.201v.916m7.5 0a48.667 48.667 0 0 0-7.5 0" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
          }
        >
          <Button variant="destructive" size="sm" onClick={() => set_show_reset_modal(true)}>
            {t("reset_bridge")}
          </Button>
        </SettingRow>
      </SettingsGroup>

      <Modal open={show_repair_modal} on_close={() => !repairing && set_show_repair_modal(false)}>
        <p className="text-base font-semibold text-txt-primary">{t("repair_cache_title")}</p>
        <ModalBody>
          <span>{t("repair_cache_body")}</span>
        </ModalBody>
        <ModalActions>
          <Button variant="ghost" size="md" disabled={repairing} onClick={() => set_show_repair_modal(false)}>{t("cancel")}</Button>
          <Button disabled={repairing} variant="destructive" size="md" onClick={handle_repair}>{repairing ? t("rebuilding") : t("repair")}</Button>
        </ModalActions>
      </Modal>


      <Modal open={show_reset_modal} on_close={() => set_show_reset_modal(false)}>
        <p className="text-base font-semibold text-txt-primary">{t("reset_bridge_title")}</p>
        <ModalBody>
          <span>{t("reset_bridge_body")}</span>
        </ModalBody>
        <ModalActions>
          <Button variant="ghost" size="md" onClick={() => set_show_reset_modal(false)}>{t("cancel")}</Button>
          <Button disabled={resetting} variant="destructive" size="md" onClick={handle_reset}>{resetting ? t("resetting") : t("reset")}</Button>
        </ModalActions>
      </Modal>

      <Modal open={!!setup_client} on_close={() => set_setup_client(null)} size="lg">
        <p className="text-base font-semibold text-txt-primary">{t("setup_with_client", { client: setup_display ?? "" })}</p>
        <ModalBody>
          <div className="space-y-5">
            {setup_display === "Thunderbird" && (
              <>
                <SetupStep n={1} title={t("tb_step1_title")}>
                  <SetupNote>{t("tb_step1_desc")}</SetupNote>
                  <SetupBox>
                    <SetupRow label={t("tb_field_full_name")} hint={t("tb_field_full_name_hint")} />
                    <SetupRow label={t("field_email_address")} value={email || "-"} />
                    <SetupRow label={t("tb_field_password")} hint={t("tb_field_password_hint")} />
                  </SetupBox>
                  <SetupNote>{t("tb_step1_note")}</SetupNote>
                </SetupStep>
                <SetupStep n={2} title={t("tb_step2_title")}>
                  <SetupBox>
                    <SetupRow label={t("field_protocol")} value="IMAP" />
                    <SetupRow label={t("field_hostname")} value="127.0.0.1" />
                    <SetupRow label={t("field_port")} value={String(conn_info?.imap_port || 1143)} />
                    <SetupRow label={t("field_connection_security")} value={t("field_none")} mono={false} />
                    <SetupRow label={t("field_auth_method")} value={t("field_normal_password")} mono={false} />
                    <SetupRow label={t("field_username")} value={email || "-"} />
                  </SetupBox>
                </SetupStep>
                <SetupStep n={3} title={t("tb_step3_title")}>
                  <SetupBox>
                    <SetupRow label={t("field_hostname")} value="127.0.0.1" />
                    <SetupRow label={t("field_port")} value={String(conn_info?.smtp_port || 1025)} />
                    <SetupRow label={t("field_connection_security")} value={t("field_none")} mono={false} />
                    <SetupRow label={t("field_auth_method")} value={t("field_normal_password")} mono={false} />
                    <SetupRow label={t("field_username")} value={email || "-"} />
                  </SetupBox>
                </SetupStep>
                <SetupStep n={4} title={t("tb_step4_title")}>
                  <SetupNote>{t("tb_step4_desc")}</SetupNote>
                </SetupStep>
              </>
            )}
            {setup_display === "Outlook" && (
              <>
                <SetupStep n={1} title={t("ol_step1_title")}>
                  <SetupNote>{t("ol_step1_desc")}</SetupNote>
                </SetupStep>
                <SetupStep n={2} title={t("ol_step2_title")}>
                  <SetupNote>{t("ol_step2_desc")}</SetupNote>
                </SetupStep>
                <SetupStep n={3} title={t("ol_step3_title")}>
                  <SetupBox>
                    <SetupGroupLabel>{t("ol_incoming_mail")}</SetupGroupLabel>
                    <SetupRow label={t("ol_field_server")} value="127.0.0.1" />
                    <SetupRow label={t("field_port")} value={String(conn_info?.imap_port || 1143)} />
                    <SetupRow label={t("ol_field_encryption")} value={t("field_none")} mono={false} />
                    <div className="h-px my-1" style={{ backgroundColor: "var(--border-secondary)" }} />
                    <SetupGroupLabel>{t("ol_outgoing_mail")}</SetupGroupLabel>
                    <SetupRow label={t("ol_field_server")} value="127.0.0.1" />
                    <SetupRow label={t("field_port")} value={String(conn_info?.smtp_port || 1025)} />
                    <SetupRow label={t("ol_field_encryption")} value={t("field_none")} mono={false} />
                  </SetupBox>
                </SetupStep>
                <SetupStep n={4} title={t("ol_step4_title")}>
                  <SetupNote>{t("ol_step4_desc")}</SetupNote>
                </SetupStep>
              </>
            )}
            {setup_display === "Apple Mail" && (
              <>
                <SetupStep n={1} title={t("am_step1_title")}>
                  <SetupNote>{t("am_step1_desc")}</SetupNote>
                </SetupStep>
                <SetupStep n={2} title={t("am_step2_title")}>
                  <SetupBox>
                    <SetupRow label={t("am_field_name")} hint={t("am_field_name_hint")} />
                    <SetupRow label={t("field_email_address")} value={email || "-"} />
                    <SetupRow label={t("field_password")} hint={t("am_field_password_hint")} />
                  </SetupBox>
                  <SetupNote>{t("am_step2_note")}</SetupNote>
                </SetupStep>
                <SetupStep n={3} title={t("am_step3_title")}>
                  <SetupNote>{t("am_step3_desc")}</SetupNote>
                  <SetupBox>
                    <SetupGroupLabel>{t("am_incoming_server")}</SetupGroupLabel>
                    <SetupRow label={t("am_field_mail_server")} value="127.0.0.1" />
                    <SetupRow label={t("field_port")} value={String(conn_info?.imap_port || 1143)} />
                    <div className="h-px my-1" style={{ backgroundColor: "var(--border-secondary)" }} />
                    <SetupGroupLabel>{t("am_outgoing_server")}</SetupGroupLabel>
                    <SetupRow label={t("am_field_mail_server")} value="127.0.0.1" />
                    <SetupRow label={t("field_port")} value={String(conn_info?.smtp_port || 1025)} />
                  </SetupBox>
                  <SetupNote>{t("am_step3_note")}</SetupNote>
                </SetupStep>
              </>
            )}
            <div className="flex gap-3 items-start rounded-xl border border-edge-secondary bg-surf-tertiary px-3.5 py-3">
              <svg className="w-[18px] h-[18px] text-txt-muted flex-shrink-0 mt-px" fill="none" stroke="currentColor" strokeWidth={1.6} viewBox="0 0 24 24">
                <path d="M9 12.75 11.25 15 15 9.75m-3-7.036A11.959 11.959 0 0 1 3.598 6 11.99 11.99 0 0 0 3 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.249-8.25-3.285Z" strokeLinecap="round" strokeLinejoin="round" />
              </svg>
              <p className="text-[13px] leading-relaxed text-txt-tertiary">{t("setup_guide_no_encryption_note")}</p>
            </div>
          </div>
        </ModalBody>
        <ModalActions>
          <Button variant="depth" size="md" onClick={() => set_setup_client(null)}>{t("done")}</Button>
        </ModalActions>
      </Modal>
    </div>
  );
}

function PlanGateFull({ on_retry }: { on_retry: () => void }) {
  const { t } = useTranslation();
  const [retrying, set_retrying] = useState(false);

  const handle_retry = async () => {
    set_retrying(true);
    try {
      await api.refresh_plan_info();
      try { await api.start_bridge(); } catch { /* ignore - load_state will show correct state */ }
    } catch {
      /* plan check failed - load_state will keep upgrade wall visible */
    } finally {
      set_retrying(false);
      on_retry();
    }
  };

  return (
    <div className="h-full flex flex-col items-center justify-center p-8 text-center gap-5">
      <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round" className="text-txt-muted">
        <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
        <path d="M7 11V7a5 5 0 0 1 10 0v4" />
      </svg>
      <div className="max-w-xs">
        <h2 className="text-base font-semibold text-txt-primary mb-2">{t("plan_gate_title")}</h2>
        <p className="text-sm text-txt-secondary leading-relaxed">{t("plan_gate_body")}</p>
      </div>
      <div className="flex flex-col gap-2 items-center">
        <UpgradeBtn size="md" onClick={() => api.open_url(UPGRADE_URL)}>
          {t("plan_gate_upgrade")}
        </UpgradeBtn>
        <button
          onClick={handle_retry}
          disabled={retrying}
          className="text-xs text-txt-muted hover:text-txt-secondary transition-colors disabled:opacity-50"
        >
          {retrying ? t("checking") : t("plan_gate_retry")}
        </button>
      </div>
    </div>
  );
}

function DashboardView({
  email, display_name, profile_picture, profile_color, bridge_running, conn_info, passwords,
  on_toggle_bridge, on_generate_password, on_delete_password, on_sign_out, on_reset, on_retry_plan,
  has_bridge_access, plan_info_loaded, outbox_count, connected_since, sync_progress, is_online,
}: {
  email: string | null; display_name: string | null; profile_picture: string | null;
  profile_color: string | null; bridge_running: boolean; conn_info: ConnectionInfo | null;
  passwords: { id: string; label: string; created_at: string; last_used_at: number | null; last_client: string | null; use_count: number }[];
  on_toggle_bridge: () => void;
  on_generate_password: (label: string) => Promise<string | null>;
  on_delete_password: (id: string) => Promise<void>;
  on_sign_out: () => void;
  on_reset: () => Promise<void>;
  on_retry_plan: () => void;
  has_bridge_access: boolean;
  plan_info_loaded: boolean;
  outbox_count: number;
  connected_since: number | null;
  sync_progress: { folder: string; done: number; total: number } | null;
  is_online: boolean;
}) {
  const { t } = useTranslation();
  const show_upgrade_banner = plan_info_loaded && !has_bridge_access;
  const [active_tab, set_active_tab] = useState<Tab>("status");

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (!(e.ctrlKey || e.metaKey)) return;
      if (e.key === "1") { e.preventDefault(); set_active_tab("status"); }
      else if (e.key === "2") { e.preventDefault(); set_active_tab("passwords"); }
      else if (e.key === "3") { e.preventDefault(); set_active_tab("settings"); }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, []);

  return (
    <div className="h-dvh w-screen flex overflow-hidden" style={{ backgroundColor: "var(--bg-secondary)" }}>
      <Sidebar
        email={email}
        display_name={display_name}
        profile_picture={profile_picture}
        profile_color={profile_color}
        bridge_running={bridge_running}
        active_tab={active_tab}
        on_tab_change={set_active_tab}
        on_sign_out={on_sign_out}
        outbox_count={outbox_count}
      />
      <div className="flex-1 p-2 min-h-0 min-w-0 flex flex-col overflow-hidden">
        {!is_online && (
          <div className="flex items-center gap-2 px-3 py-1.5 mb-1.5 rounded-lg text-[12px] font-medium" style={{ backgroundColor: "color-mix(in srgb, var(--color-warning, #f59e0b) 12%, transparent)", color: "var(--color-warning, #f59e0b)", border: "1px solid color-mix(in srgb, var(--color-warning, #f59e0b) 25%, transparent)" }}>
            <svg className="w-3.5 h-3.5 flex-shrink-0" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
              <path d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126ZM12 15.75h.007v.008H12v-.008Z" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
            {t("offline_banner")}
          </div>
        )}
        <div
          className="flex-1 w-full rounded-xl border overflow-hidden transition-colors duration-200"
          style={{ backgroundColor: "var(--bg-primary)", borderColor: "var(--border-primary)" }}
        >
          <div className="h-full overflow-y-auto">
            {show_upgrade_banner && active_tab !== "settings" ? (
              <PlanGateFull on_retry={on_retry_plan} />
            ) : (
              <>
                {active_tab === "status" && (
                  <ConfigPanel email={email} display_name={display_name} profile_picture={profile_picture} profile_color={profile_color} conn_info={conn_info} bridge_running={bridge_running} on_toggle_bridge={on_toggle_bridge} connected_since={connected_since} sync_progress={sync_progress} />
                )}
                {active_tab === "passwords" && !plan_info_loaded && (
                  <div className="p-5 text-sm text-txt-muted text-center">{t("loading")}</div>
                )}
                {active_tab === "passwords" && plan_info_loaded && (
                  <PasswordsPanel passwords={passwords} on_generate_password={on_generate_password} on_delete_password={on_delete_password} />
                )}
                {active_tab === "settings" && (
                  <SettingsPanel on_reset={on_reset} conn_info={conn_info} email={email} bridge_running={bridge_running} />
                )}
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

export function BridgeApp() {
  use_theme();

  const [view, set_view] = useState<View>("loading");
  const [email, set_email] = useState<string | null>(null);
  const [display_name, set_display_name] = useState<string | null>(null);
  const [profile_picture, set_profile_picture] = useState<string | null>(null);
  const [profile_color, set_profile_color] = useState<string | null>(null);
  const [bridge_running, set_bridge_running] = useState(false);
  const [conn_info, set_conn_info] = useState<ConnectionInfo | null>(null);
  const [passwords, set_passwords] = useState<{ id: string; label: string; created_at: string; last_used_at: number | null; last_client: string | null; use_count: number }[]>([]);
  const [was_enrolled, set_was_enrolled] = useState(false);
  const [has_bridge_access, set_has_bridge_access] = useState(false);
  const [plan_info_loaded, set_plan_info_loaded] = useState(false);
  const [provision_label, set_provision_label] = useState<string | null>(null);
  const provision_display = use_frozen(provision_label);
  const [outbox_count, set_outbox_count] = useState(0);
  const [connected_since, set_connected_since] = useState<number | null>(null);
  const [sync_progress, set_sync_progress] = useState<{ folder: string; done: number; total: number } | null>(null);
  const sync_show_timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const sync_hide_timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const sync_visible = useRef(false);
  const latest_sync = useRef<{ folder: string; done: number; total: number } | null>(null);
  const [is_online, set_is_online] = useState(() => typeof navigator !== "undefined" ? navigator.onLine : true);

  const load_state = useCallback(async () => {
    try {
      const [state, info] = await Promise.all([
        api.get_bridge_state(),
        api.get_connection_info(),
      ]);
      set_conn_info(info);
      if (state.enrolled) {
        set_view("dashboard");
        set_email(state.email);
        set_display_name(state.display_name);
        set_profile_picture(state.profile_picture);
        set_profile_color(state.profile_color);
        set_bridge_running(state.running);
        set_passwords(state.passwords);
        set_has_bridge_access(state.has_bridge_access);
        set_plan_info_loaded(state.plan_info_loaded);
        set_was_enrolled(true);
      } else {
        set_view("setup");
      }
    } catch {
      set_view("setup");
    }
  }, []);

  useEffect(() => {
    let cleanup: (() => void) | null = null;
    (async () => {
      const { listen } = await import("@tauri-apps/api/event");
      const unlisten_state = await listen("state_updated", () => { load_state(); });
      cleanup = () => { unlisten_state(); };
      await load_state();
    })();
    return () => { if (cleanup) cleanup(); };
  }, [load_state]);

  useEffect(() => {
    const timer = setInterval(() => { load_state(); }, 60_000);
    return () => clearInterval(timer);
  }, [load_state]);

  useEffect(() => {
    set_connected_since(bridge_running ? Date.now() : null);
  }, [bridge_running]);

  useEffect(() => {
    const on_online = () => set_is_online(true);
    const on_offline = () => set_is_online(false);
    window.addEventListener("online", on_online);
    window.addEventListener("offline", on_offline);
    return () => {
      window.removeEventListener("online", on_online);
      window.removeEventListener("offline", on_offline);
    };
  }, []);

  useEffect(() => {
    let cleanup: (() => void) | null = null;
    (async () => {
      const { listen } = await import("@tauri-apps/api/event");
      const unlisten_progress = await listen<{ folder: string; done: number; total: number }>("sync_progress", (e) => {
        latest_sync.current = e.payload;
        if (sync_hide_timer.current) { clearTimeout(sync_hide_timer.current); sync_hide_timer.current = null; }
        if (sync_visible.current) {
          set_sync_progress(e.payload);
        } else if (!sync_show_timer.current) {
          sync_show_timer.current = setTimeout(() => {
            sync_show_timer.current = null;
            if (latest_sync.current) {
              sync_visible.current = true;
              set_sync_progress(latest_sync.current);
            }
          }, 350);
        }
      });
      const unlisten_done = await listen<{ failed: boolean }>("sync_done", (e) => {
        latest_sync.current = null;
        if (sync_show_timer.current) { clearTimeout(sync_show_timer.current); sync_show_timer.current = null; }
        if (!sync_visible.current) return;
        set_sync_progress(prev => prev ? { ...prev, done: prev.total } : null);
        if (sync_hide_timer.current) clearTimeout(sync_hide_timer.current);
        sync_hide_timer.current = setTimeout(() => {
          sync_hide_timer.current = null;
          sync_visible.current = false;
          set_sync_progress(null);
        }, e.payload.failed ? 0 : 1200);
      });
      const unlisten_revoked = await listen("bridge_access_revoked", async () => {
        try { await api.stop_bridge(); } catch { /* ignore */ }
        show_toast(i18next.t("toast_bridge_upgrade_required"), "error");
        await load_state();
      });
      cleanup = () => { unlisten_progress(); unlisten_done(); unlisten_revoked(); };
    })();
    return () => { if (cleanup) cleanup(); };
  }, [load_state]);

  useEffect(() => {
    if (!bridge_running) { set_outbox_count(0); return; }
    const fetch_outbox = async () => {
      try { const items = await api.outbox_list(); set_outbox_count(items.length); } catch { set_outbox_count(0); }
    };
    fetch_outbox();
    const timer = setInterval(fetch_outbox, 30_000);
    return () => clearInterval(timer);
  }, [bridge_running]);

  useEffect(() => {
    if (!bridge_running) return;
    const timer = setInterval(async () => {
      try { await api.trigger_sync(); } catch { /* ignore */ }
    }, 5 * 60_000);
    return () => clearInterval(timer);
  }, [bridge_running]);

  const handle_enrolled = useCallback(async () => {
    try {
      await api.start_bridge();
      show_toast(i18next.t("toast_bridge_connected"), "success");
    } catch (e) {
      if (typeof e === "string" && e.includes("bridge_access_required")) {
        show_toast(i18next.t("toast_bridge_upgrade_required"), "error");
      }
    }
    await load_state();
  }, [load_state]);

  const handle_toggle_bridge = async () => {
    if (!has_bridge_access && !bridge_running) {
      show_toast(i18next.t("toast_bridge_upgrade_required"), "error");
      return;
    }
    try {
      if (bridge_running) {
        await api.stop_bridge();
        show_toast(i18next.t("toast_bridge_disconnected"), "success");
      } else {
        await api.start_bridge();
        show_toast(i18next.t("toast_bridge_connected"), "success");
      }
      await load_state();
    } catch (e) {
      if (typeof e === "string" && e.includes("bridge_access_required")) {
        show_toast(i18next.t("toast_bridge_upgrade_required"), "error");
      } else {
        show_toast(i18next.t("toast_bridge_status_failed"), "error");
      }
    }
  };

  const handle_generate_password = async (label: string): Promise<string | null> => {
    try {
      const password = await api.generate_app_password(label);
      show_toast(i18next.t("toast_password_created"), "success");
      await load_state();
      return password;
    } catch {
      show_toast(i18next.t("toast_password_create_failed"), "error");
      return null;
    }
  };

  const handle_delete_password = async (id: string): Promise<void> => {
    try {
      await api.delete_app_password(id);
      show_toast(i18next.t("toast_password_deleted"), "success");
      await load_state();
    } catch {
      show_toast(i18next.t("toast_password_delete_failed"), "error");
    }
  };

  const force_link_device = useCallback(() => {
    set_view("setup");
    set_email(null);
    set_display_name(null);
    set_profile_picture(null);
    set_profile_color(null);
    set_bridge_running(false);
    set_passwords([]);
    set_was_enrolled(false);
    set_has_bridge_access(false);
    set_plan_info_loaded(false);
  }, []);

  useEffect(() => {
    let cleanup: (() => void) | null = null;
    (async () => {
      const { listen } = await import("@tauri-apps/api/event");
      const unlisten = await listen("session_expired", async () => {
        const { getCurrentWindow } = await import("@tauri-apps/api/window");
        await getCurrentWindow().show();
        force_link_device();
      });
      cleanup = () => { unlisten(); };
    })();
    return () => { if (cleanup) cleanup(); };
  }, [force_link_device]);

  const handle_sign_out = async () => {
    try { await api.sign_out(); } catch { /* ignore */ }
    show_toast(i18next.t("toast_signed_out"), "success");
    force_link_device();
  };

  const handle_reset = async () => {
    await api.reset_bridge_data();
    try { await api.sign_out(); } catch { /* ignore */ }
    force_link_device();
  };


  useEffect(() => {
    let unlisten_fn: (() => void) | null = null;
    (async () => {
      const { listen } = await import("@tauri-apps/api/event");
      const unlisten = await listen<string>("deep_link", (event) => {
        try {
          const url = new URL(event.payload);
          if (url.protocol !== "aster-mail:") return;
          if (url.hostname !== "provision" && url.pathname !== "//provision" && url.pathname !== "/provision") return;
          const raw_label = url.searchParams.get("label") || "Auto-provisioned";
          // Deep links arrive from arbitrary local apps; the label is untrusted.
          // Strip control chars and cap length before it is shown in the confirm modal.
          const label = [...raw_label].filter((ch) => ch.charCodeAt(0) >= 0x20 && ch.charCodeAt(0) !== 0x7f).join("").slice(0, 64).trim() || "Auto-provisioned";
          set_provision_label(label);
        } catch {
          /* ignore malformed deep link */
        }
      });
      unlisten_fn = unlisten;
    })();
    return () => {
      if (unlisten_fn) unlisten_fn();
    };
  }, []);

  const handle_provision_confirm = async () => {
    if (!provision_label) return;
    const label = provision_label;
    set_provision_label(null);
    try {
      const bundle = await api.provision_bundle(label);
      const payload = JSON.stringify(bundle, null, 2);
      await navigator.clipboard.writeText(payload).catch(() => {});
      clear_clipboard_if_unchanged(payload);
      show_toast(i18next.t("toast_provisioned", { label: bundle.label }), "success");
    } catch {
      show_toast(i18next.t("toast_provision_failed"), "error");
    }
  };

  const handle_back_to_dashboard = () => { set_view("dashboard"); };

  if (view === "loading") {
    return (
      <>
        <div className="fixed inset-0 flex items-center justify-center" style={{ backgroundColor: "var(--bg-secondary)" }}>
          <Spinner class_name="w-6 h-6 text-txt-muted" />
        </div>
        <ToastContainer />
      </>
    );
  }

  if (view === "setup") {
    return (
      <>
        <SetupView on_enrolled={handle_enrolled} can_go_back={was_enrolled} on_back={handle_back_to_dashboard} />
        <ToastContainer />
      </>
    );
  }

  return (
    <>
      <DashboardView
        email={email} display_name={display_name} profile_picture={profile_picture}
        profile_color={profile_color} bridge_running={bridge_running} conn_info={conn_info}
        passwords={passwords} on_toggle_bridge={handle_toggle_bridge}
        on_generate_password={handle_generate_password} on_delete_password={handle_delete_password}
        on_sign_out={handle_sign_out} on_reset={handle_reset} on_retry_plan={load_state}
        has_bridge_access={has_bridge_access}
        plan_info_loaded={plan_info_loaded} outbox_count={outbox_count}
        connected_since={connected_since} sync_progress={sync_progress} is_online={is_online}
      />
      <Modal open={!!provision_label} on_close={() => set_provision_label(null)}>
        <p className="text-base font-semibold text-txt-primary">{i18next.t("provision_title")}</p>
        <ModalBody>
          <span>{i18next.t("provision_confirm", { label: provision_display ?? "" })}</span>
        </ModalBody>
        <ModalActions>
          <Button variant="ghost" size="md" onClick={() => set_provision_label(null)}>{i18next.t("cancel")}</Button>
          <Button variant="depth" size="md" onClick={handle_provision_confirm}>{i18next.t("provision_allow")}</Button>
        </ModalActions>
      </Modal>
      <UpdateBanner />
      <ToastContainer />
    </>
  );
}
