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

import { describe, expect, it, vi } from "vitest";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

vi.mock("@aster/ui", () => ({
  Button: ({ children, onClick }: { children: unknown; onClick?: () => void }) =>
    createElement("button", { onClick }, children as string),
  Popover: ({ children }: { children: unknown }) => createElement("div", { "data-popover": "" }, children as string),
  PopoverTrigger: ({ children }: { children: unknown }) => children,
  PopoverContent: ({ children }: { children: unknown }) =>
    createElement("div", { "data-popover-content": "" }, children as string),
}));

import "./i18n";
import { guard_pending_from_status, setup_confirmation_from } from "./api";
import { should_notify_activation } from "./notify";
import { format_countdown, GuardPendingPanel, seconds_until } from "./guard_pending_panel";

const activates_at = "2030-01-01T10:00:00+00:00";
const at_ms = Date.parse(activates_at);

describe("bridge status mapping", () => {
  it("reads the held activation time only while signed out", () => {
    expect(guard_pending_from_status({ connected: false, activates_at })).toEqual({ activates_at });
    expect(guard_pending_from_status({ connected: true, activates_at })).toBeNull();
  });

  it("keeps old status replies unchanged", () => {
    expect(guard_pending_from_status({ connected: false })).toBeNull();
    expect(guard_pending_from_status({ connected: false, activates_at: null })).toBeNull();
    expect(guard_pending_from_status({ connected: false, activation_pending: false })).toBeNull();
  });

  it("stays on the waiting screen when the activation time is missing", () => {
    expect(guard_pending_from_status({ connected: false, activation_pending: true })).toEqual({ activates_at: null });
    expect(guard_pending_from_status({ connected: false, activates_at: null, activation_pending: true })).toEqual({ activates_at: null });
    expect(guard_pending_from_status({ connected: true, activation_pending: true })).toBeNull();
  });
});

describe("setup status mapping", () => {
  it("maps every reply the app knows", () => {
    expect(setup_confirmation_from({ status: "confirmed", done: true })).toBe("confirmed");
    expect(setup_confirmation_from({ status: "activation_pending", done: true })).toBe("activation_pending");
    expect(setup_confirmation_from({ status: "denied", done: true })).toBe("denied");
    expect(setup_confirmation_from({ status: "expired", done: true })).toBe("expired");
  });

  it("keeps polling on anything else", () => {
    expect(setup_confirmation_from({ status: "confirmed", done: false })).toBe("pending");
    expect(setup_confirmation_from({ status: "pending", done: false })).toBe("pending");
    expect(setup_confirmation_from({ status: "something_new", done: false })).toBe("pending");
  });
});

describe("activation notice", () => {
  it("fires once when a held device becomes active", () => {
    expect(should_notify_activation(true, false, true)).toBe(true);
    expect(should_notify_activation(false, false, true)).toBe(false);
    expect(should_notify_activation(true, true, false)).toBe(false);
    expect(should_notify_activation(true, false, false)).toBe(false);
  });
});

describe("countdown", () => {
  it("counts down to the activation time", () => {
    expect(seconds_until(activates_at, at_ms - 3600_000)).toBe(3600);
    expect(seconds_until(activates_at, at_ms - 61_500)).toBe(62);
    expect(seconds_until(activates_at, at_ms + 5_000)).toBe(0);
    expect(seconds_until(null, at_ms)).toBeNull();
    expect(seconds_until("not a time", at_ms)).toBeNull();
  });

  it("formats hours, minutes, and seconds", () => {
    expect(format_countdown(3600)).toBe("1:00:00");
    expect(format_countdown(3599)).toBe("59:59");
    expect(format_countdown(65)).toBe("1:05");
    expect(format_countdown(0)).toBe("0:00");
  });
});

describe("waiting panel", () => {
  it("shows the wait, the activation time, and a way to cancel", () => {
    const html = renderToStaticMarkup(
      createElement(GuardPendingPanel, { activates_at, on_cancel: () => {}, initial_now_ms: at_ms - 30 * 60_000 }),
    );
    expect(html).toContain("Waiting for activation");
    expect(html).toContain("30:00");
    expect(html).toContain("Mail apps can connect in 30 minutes, at");
    expect(html).toContain('aria-live="polite"');
    expect(html).toContain("Cancel");
    expect(html.split("<button").length - 1).toBe(2);
  });

  it("uses the singular for the last minute", () => {
    const html = renderToStaticMarkup(
      createElement(GuardPendingPanel, { activates_at, on_cancel: () => {}, initial_now_ms: at_ms - 45_000 }),
    );
    expect(html).toContain("Mail apps can connect in 1 minute, at");
  });

  it("names the nearest whole minute to match the countdown", () => {
    const html = renderToStaticMarkup(
      createElement(GuardPendingPanel, { activates_at, on_cancel: () => {}, initial_now_ms: at_ms - (42 * 60 + 18) * 1000 }),
    );
    expect(html).toContain("42:18");
    expect(html).toContain("Mail apps can connect in 42 minutes, at");
  });

  it("explains the wait when the time is unknown", () => {
    const html = renderToStaticMarkup(
      createElement(GuardPendingPanel, { activates_at: null, on_cancel: () => {} }),
    );
    expect(html).toContain("checks again in a few moments");
    expect(html).not.toContain("Time remaining");
    expect(html).toContain("Protected by Aster Guard");
  });

  it("explains the timer with an info button after the time remaining label", () => {
    const html = renderToStaticMarkup(
      createElement(GuardPendingPanel, { activates_at, on_cancel: () => {}, initial_now_ms: at_ms - 30 * 60_000 }),
    );
    const label = html.indexOf("Time remaining");
    const info = html.indexOf('aria-label="About the activation wait"');
    expect(label).toBeGreaterThan(-1);
    expect(info).toBeGreaterThan(label);
    expect(info).toBeLessThan(html.indexOf("30:00"));
    expect(html).toContain('type="button"');
    expect(html).toContain("Aster Guard is on");
    expect(html).toContain(
      "Aster Guard protects your account, so new Aster Bridge sign-ins wait one hour before mail apps can connect. This gives you time to stop a sign-in you didn&#x27;t make.",
    );
    expect(html).toContain("Protected by Aster Guard");
    expect(html).not.toContain("<a ");
  });
});
