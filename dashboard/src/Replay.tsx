/**
 * Transcript replay.
 *
 * The sensor records the gap between every keystroke an attacker typed. This
 * component plays a session back at that original cadence, so you watch the
 * session happen rather than read a log of it.
 *
 * It earns its place because the cadence is the evidence. A person pauses
 * before `cat /etc/shadow`, backs up, mistypes. A loader emits the identical
 * line in a single frame, every time. Rendering that difference makes the
 * automation call self-evident, where a badge saying "automated (0.98)" asks
 * you to take the classifier's word for it.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { CollectorEvent, Peer, SessionView } from "./api";
import { duration } from "./api";

type Chunk =
  | { at: number; kind: "sys"; text: string }
  | { at: number; kind: "meta"; text: string }
  | { at: number; kind: "prompt"; text: string }
  | { at: number; kind: "typed"; text: string };

interface Timeline {
  chunks: Chunk[];
  totalMs: number;
  /** Inter-keystroke gaps across the whole session, for the cadence strip. */
  cadence: number[];
  typedCommands: number;
  pastedCommands: number;
}

/** Caps a gap so one long idle period does not make a replay unwatchable. */
const MAX_GAP_MS = 4000;

function buildTimeline(session: SessionView, events: CollectorEvent[]): Timeline {
  const chunks: Chunk[] = [];
  const cadence: number[] = [];
  let clock = 0;
  let typedCommands = 0;
  let pastedCommands = 0;

  const host = session.client_banner || session.protocol.toUpperCase();
  chunks.push({
    at: 0,
    kind: "meta",
    text: `── ${session.protocol.toUpperCase()} from ${session.src_ip}  ·  ${host}\n`,
  });
  clock += 300;

  for (const e of events) {
    const p = e.payload as Record<string, unknown> & { kind: string };

    switch (p.kind) {
      case "session_start": {
        const peer = p.peer as Peer | undefined;
        chunks.push({
          at: clock,
          kind: "sys",
          text: `Connection from ${peer?.src_ip ?? session.src_ip} port ${peer?.src_port ?? "?"}\n`,
        });
        clock += 200;
        break;
      }

      case "auth": {
        const gap = Math.min(Number(p.since_previous_ms) || 0, MAX_GAP_MS);
        clock += gap;
        const verdict = p.success ? "Accepted" : "Failed";
        chunks.push({
          at: clock,
          kind: p.success ? "meta" : "sys",
          text: `${verdict} password for ${p.username} (offered ${JSON.stringify(p.password)})\n`,
        });
        clock += 120;
        break;
      }

      case "command": {
        const gap = Math.min(Number(p.since_previous_ms) || 0, MAX_GAP_MS);
        clock += gap;

        const prompt = `${session.protocol === "telnet" ? "#" : "$"} `;
        chunks.push({ at: clock, kind: "prompt", text: prompt });
        clock += 40;

        const raw = String(p.raw ?? "");
        const deltas = (p.keystroke_deltas_ms as number[]) ?? [];
        const bulk = Boolean(p.bulk_input);

        if (bulk || deltas.length < 2) {
          // No per-key timing: the client did not type this. It arrives whole,
          // which is the visual signature of automation.
          pastedCommands++;
          chunks.push({ at: clock, kind: "typed", text: raw + "\n" });
          clock += 60;
        } else {
          typedCommands++;
          // The first delta is the pause before typing began -- thinking time,
          // not rhythm -- so it is excluded from the cadence strip.
          const keyGaps = deltas.slice(1);
          for (let i = 0; i < raw.length; i++) {
            const g = Math.min(keyGaps[i % keyGaps.length] ?? 90, 900);
            clock += g;
            if (i > 0) cadence.push(g);
            chunks.push({ at: clock, kind: "typed", text: raw[i] });
          }
          chunks.push({ at: clock + 60, kind: "typed", text: "\n" });
          clock += 120;
        }
        break;
      }

      case "http_request": {
        clock += 150;
        const attacks = (p.detected_attacks as string[]) ?? [];
        const tail = attacks.length ? `   ⟨${attacks.join(" ")}⟩` : "";
        chunks.push({
          at: clock,
          kind: "typed",
          text: `${p.method} ${p.path}${p.query ? "?" + p.query : ""} → ${p.response_status}${tail}\n`,
        });
        break;
      }

      case "artifact": {
        clock += 100;
        chunks.push({
          at: clock,
          kind: "meta",
          text: `   ↳ payload referenced: ${p.url}   (recorded, not fetched)\n`,
        });
        break;
      }

      case "upload": {
        clock += 100;
        chunks.push({
          at: clock,
          kind: "meta",
          text: `   ↳ wrote ${p.claimed_name} — ${p.size_bytes} bytes, ${p.detected_type}\n     sha256 ${p.sha256}\n`,
        });
        break;
      }

      case "canary": {
        clock += 100;
        chunks.push({
          at: clock,
          kind: "meta",
          text: `   ⚑ CANARY OPENED — ${p.planted_path}\n`,
        });
        break;
      }

      case "rdp_connect": {
        clock += 150;
        chunks.push({
          at: clock,
          kind: "typed",
          text: `mstshash=${p.cookie || "(none)"}   protocols=${((p.requested_protocols as string[]) ?? []).join(",")}\n`,
        });
        break;
      }

      case "session_end": {
        clock += 200;
        chunks.push({
          at: clock,
          kind: "sys",
          text: `\nConnection closed (${p.reason}) after ${duration(Number(p.duration_ms) || 0)}\n`,
        });
        break;
      }

      default:
        break;
    }
  }

  return { chunks, totalMs: clock, cadence, typedCommands, pastedCommands };
}

const SPEEDS = [
  { label: "1×", value: 1 },
  { label: "4×", value: 4 },
  { label: "16×", value: 16 },
];

interface Props {
  session: SessionView;
  events: CollectorEvent[];
}

export function TranscriptReplay({ session, events }: Props) {
  const timeline = useMemo(() => buildTimeline(session, events), [session, events]);

  const reduceMotion = useMemo(
    () => window.matchMedia?.("(prefers-reduced-motion: reduce)").matches ?? false,
    [],
  );

  // With reduced motion the replay is meaningless as animation, so the whole
  // transcript is present from the start and the controls stand down.
  const [cursor, setCursor] = useState(reduceMotion ? timeline.chunks.length : 0);
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = useState(4);
  const timer = useRef<number | null>(null);
  const termRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    setCursor(reduceMotion ? timeline.chunks.length : 0);
    setPlaying(false);
  }, [timeline, reduceMotion]);

  const stop = useCallback(() => {
    if (timer.current !== null) {
      window.clearTimeout(timer.current);
      timer.current = null;
    }
  }, []);

  useEffect(() => {
    if (!playing || cursor >= timeline.chunks.length) {
      stop();
      if (cursor >= timeline.chunks.length) setPlaying(false);
      return;
    }

    const current = timeline.chunks[cursor];
    const previous = cursor > 0 ? timeline.chunks[cursor - 1] : undefined;
    const waitMs = Math.max(0, current.at - (previous?.at ?? 0)) / speed;

    timer.current = window.setTimeout(() => setCursor((c) => c + 1), waitMs);
    return stop;
  }, [playing, cursor, speed, timeline, stop]);

  useEffect(() => stop, [stop]);

  // Follow the output as it arrives.
  useEffect(() => {
    const el = termRef.current;
    if (el && playing) el.scrollTop = el.scrollHeight;
  }, [cursor, playing]);

  const visible = timeline.chunks.slice(0, cursor);
  const done = cursor >= timeline.chunks.length;

  const restart = () => {
    stop();
    setCursor(0);
    setPlaying(true);
  };

  const skip = () => {
    stop();
    setCursor(timeline.chunks.length);
    setPlaying(false);
  };

  return (
    <div className="replay">
      <div className="replay-controls">
        <button
          className="replay-btn"
          onClick={() => (done ? restart() : setPlaying((p) => !p))}
          disabled={reduceMotion || timeline.chunks.length === 0}
        >
          {done ? "Replay" : playing ? "Pause" : "Play"}
        </button>
        <button className="replay-btn" onClick={skip} disabled={done}>
          Show all
        </button>

        <span className="term-meta">
          {timeline.typedCommands > 0 && `${timeline.typedCommands} typed`}
          {timeline.typedCommands > 0 && timeline.pastedCommands > 0 && " · "}
          {timeline.pastedCommands > 0 && `${timeline.pastedCommands} pasted`}
          {timeline.totalMs > 0 && ` · ${duration(timeline.totalMs)}`}
        </span>

        <div className="replay-speed" role="group" aria-label="Playback speed">
          {SPEEDS.map((s) => (
            <button
              key={s.value}
              aria-pressed={speed === s.value}
              onClick={() => setSpeed(s.value)}
              disabled={reduceMotion}
            >
              {s.label}
            </button>
          ))}
        </div>
      </div>

      <div className="term" ref={termRef} aria-live="off">
        {visible.map((c, i) => (
          <span
            key={i}
            className={
              c.kind === "sys" ? "term-sys" : c.kind === "meta" ? "term-meta" : c.kind === "prompt" ? "term-prompt" : undefined
            }
          >
            {c.text}
          </span>
        ))}
        {!done && <span className="term-cursor" aria-hidden="true" />}
      </div>

      {timeline.cadence.length > 2 && (
        <div
          className="cadence"
          title="Inter-keystroke gaps. Even ticks are a script; ragged ticks are a person."
          aria-label={`Keystroke cadence, ${timeline.cadence.length} intervals`}
        >
          {timeline.cadence.slice(0, 240).map((gap, i) => (
            <span
              key={i}
              className="cadence-tick"
              style={{ height: `${Math.min(100, 12 + (gap / 400) * 88)}%` }}
            />
          ))}
        </div>
      )}
    </div>
  );
}
