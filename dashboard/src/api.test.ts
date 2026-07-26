import { describe, expect, it, vi, afterEach } from "vitest";

import {
  clockTime,
  duration,
  isAlarm,
  isAttackerAuthored,
  relativeTime,
  summarize,
} from "./api";
import type { CollectorEvent } from "./api";

// The console had no tests at all, only a typecheck. Typecheck confirms the
// shapes line up; none of it says the feed renders the right sentence, that a
// canary is flagged as an alarm, or that a session lasting 90 seconds is not
// described as lasting 90 milliseconds.

function event(payload: Record<string, unknown>): CollectorEvent {
  return {
    node_id: "node-a",
    seq: 1,
    session_id: "S1",
    ts_node: "2026-07-26T12:00:00Z",
    ts_collector: "2026-07-26T12:00:00Z",
    payload,
  } as unknown as CollectorEvent;
}

describe("summarize", () => {
  // One case per payload kind. The collector emits eleven, and a kind with no
  // arm falls through to printing its own name -- which looks like a rendered
  // line rather than a gap, so it is the kind of miss that survives review.
  const cases: Array<[string, Record<string, unknown>, string]> = [
    [
      "session_start",
      { kind: "session_start", protocol: "ssh", peer: { src_ip: "203.0.113.9" } },
      "ssh session opened — 203.0.113.9",
    ],
    ["session_end", { kind: "session_end", reason: "client_closed" }, "session ended (client_closed)"],
    [
      "auth accepted",
      { kind: "auth", success: true, username: "root", password: "xc3511" },
      "accepted  root:xc3511",
    ],
    [
      "auth rejected",
      { kind: "auth", success: false, username: "admin", password: "hunter2" },
      "rejected  admin:hunter2",
    ],
    ["command", { kind: "command", raw: "uname -a" }, "$ uname -a"],
    [
      "artifact",
      { kind: "artifact", url: "http://198.51.100.9/x.sh" },
      "payload referenced — http://198.51.100.9/x.sh",
    ],
    [
      "upload",
      { kind: "upload", claimed_name: "x", size_bytes: 12, detected_type: "elf" },
      "upload x (12 bytes, elf)",
    ],
    [
      "http_request without attacks",
      { kind: "http_request", method: "GET", path: "/", response_status: 200, detected_attacks: [] },
      "GET / → 200",
    ],
    [
      "http_request with attacks",
      {
        kind: "http_request",
        method: "POST",
        path: "/x",
        response_status: 500,
        detected_attacks: ["sqli", "log4shell"],
      },
      "POST /x → 500  [sqli log4shell]",
    ],
    ["rdp_connect", { kind: "rdp_connect", cookie: "mstshash=admin" }, "rdp cookie mstshash=admin"],
    ["canary", { kind: "canary", planted_path: "/.env" }, "canary opened — /.env"],
    ["heartbeat", { kind: "heartbeat", spool_depth: 4 }, "heartbeat, spool 4"],
    ["anomaly", { kind: "anomaly", detail: "sftp declined" }, "anomaly: sftp declined"],
  ];

  it.each(cases)("renders %s", (_name, payload, expected) => {
    expect(summarize(event(payload))).toBe(expected);
  });

  // An RDP scan that sends no cookie is common; the line must not read
  // "rdp cookie undefined".
  it("names an absent RDP cookie explicitly", () => {
    expect(summarize(event({ kind: "rdp_connect", cookie: "" }))).toBe("rdp cookie (none)");
  });

  // A session_start whose peer never parsed must not render "undefined".
  it("tolerates a missing peer", () => {
    expect(summarize(event({ kind: "session_start", protocol: "telnet" }))).toBe(
      "telnet session opened — ?",
    );
  });

  it("falls back to the kind for an unrecognised payload", () => {
    expect(summarize(event({ kind: "future_kind" }))).toBe("future_kind");
  });
});

describe("isAttackerAuthored", () => {
  // Drives the styling that separates what the attacker did from what the
  // sensor said about it. Heartbeats appearing as attacker activity would make
  // an idle node look busy.
  it.each(["command", "auth", "artifact", "upload", "http_request", "rdp_connect"])(
    "treats %s as attacker-authored",
    (kind) => {
      expect(isAttackerAuthored(event({ kind }))).toBe(true);
    },
  );

  it.each(["session_start", "session_end", "heartbeat", "anomaly", "canary"])(
    "treats %s as sensor-authored",
    (kind) => {
      expect(isAttackerAuthored(event({ kind }))).toBe(false);
    },
  );
});

describe("isAlarm", () => {
  // A canary firing means bait left the sensor and was opened elsewhere. It is
  // the one event that should interrupt an operator.
  it("flags a canary", () => {
    expect(isAlarm(event({ kind: "canary", planted_path: "/.env" }))).toBe(true);
  });

  it.each(["command", "auth", "session_start", "heartbeat"])("does not flag %s", (kind) => {
    expect(isAlarm(event({ kind }))).toBe(false);
  });
});

describe("relativeTime", () => {
  afterEach(() => vi.useRealTimers());

  function at(iso: string, now: string) {
    vi.useFakeTimers();
    vi.setSystemTime(new Date(now));
    return relativeTime(iso);
  }

  it.each([
    ["2026-07-26T12:00:00Z", "2026-07-26T12:00:30Z", "30s ago"],
    ["2026-07-26T12:00:00Z", "2026-07-26T12:05:00Z", "5m ago"],
    ["2026-07-26T12:00:00Z", "2026-07-26T15:00:00Z", "3h ago"],
    ["2026-07-20T12:00:00Z", "2026-07-26T12:00:00Z", "6d ago"],
  ])("renders %s at %s as %s", (iso, now, expected) => {
    expect(at(iso, now)).toBe(expected);
  });

  // Sensor and collector clocks drift, so a timestamp slightly in the future
  // arrives routinely. It must not render as a negative age.
  it("clamps a future timestamp to zero rather than going negative", () => {
    expect(at("2026-07-26T12:00:10Z", "2026-07-26T12:00:00Z")).toBe("0s ago");
  });
});

describe("duration", () => {
  it.each([
    [0, "0ms"],
    [999, "999ms"],
    [1000, "1.0s"],
    [59_900, "59.9s"],
    [60_000, "1m 0s"],
    [90_000, "1m 30s"],
    [3_661_000, "61m 1s"],
  ])("renders %ims as %s", (ms, expected) => {
    expect(duration(ms)).toBe(expected);
  });
});

describe("clockTime", () => {
  it("renders a 24-hour time", () => {
    // Locale-dependent, so assert the shape rather than a literal.
    expect(clockTime("2026-07-26T13:45:07Z")).toMatch(/^\d{2}:\d{2}:\d{2}$/);
  });
});
