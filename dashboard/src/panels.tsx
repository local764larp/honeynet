import { useMemo } from "react";
import type { CollectorEvent, IocEntry, SessionView, Stats } from "./api";
import { clockTime, duration, isAlarm, isAttackerAuthored, relativeTime, summarize } from "./api";

/* ------------------------------------------------------------------ shell */

export function Panel({
  title,
  aside,
  children,
  bodyClass,
}: {
  title: string;
  aside?: React.ReactNode;
  children: React.ReactNode;
  bodyClass?: string;
}) {
  return (
    <section className="panel">
      <header className="panel-head">
        <h2>{title}</h2>
        {aside && <div className="aside">{aside}</div>}
      </header>
      <div className={`panel-body ${bodyClass ?? ""}`}>{children}</div>
    </section>
  );
}

export function Empty({ title, children }: { title: string; children?: React.ReactNode }) {
  return (
    <div className="empty">
      <strong>{title}</strong>
      {children && <p className="note" style={{ margin: 0, maxWidth: "42ch" }}>{children}</p>}
    </div>
  );
}

/* ------------------------------------------------------------- live feed */

export function LiveFeed({ events }: { events: CollectorEvent[] }) {
  if (events.length === 0) {
    return (
      <Empty title="No traffic yet">
        Events appear here the moment a sensor observes one. Run the end-to-end
        harness, or wait for the internet to find your traps.
      </Empty>
    );
  }

  return (
    <div className="feed">
      {events.map((e, i) => (
        <div
          key={`${e.node_id}-${e.seq}`}
          className={[
            "feed-row",
            isAttackerAuthored(e) ? "is-attacker" : "",
            isAlarm(e) ? "is-alarm" : "",
            i === 0 ? "is-new" : "",
          ]
            .filter(Boolean)
            .join(" ")}
        >
          <span className="feed-time">{clockTime(e.ts_collector)}</span>
          <span className="feed-kind">{e.payload.kind.replace(/_/g, " ")}</span>
          <span className="feed-text">{summarize(e)}</span>
        </div>
      ))}
    </div>
  );
}

/* ------------------------------------------------------------- origin map */

/**
 * Land as a dot matrix on an equirectangular grid.
 *
 * Deliberately coarse. A low-detail coastline outline reads as a bad map;
 * a dot matrix reads as an instrument's abstraction of one, which is the
 * honest thing to show when the underlying geolocation is itself approximate.
 *
 * Each entry is a row of 6° latitude, listing inclusive column ranges of 6°
 * longitude that contain land.
 */
const LAND: Record<number, [number, number][]> = {
  1: [[17, 24]],
  2: [[4, 12], [17, 25], [32, 58]],
  3: [[1, 24], [28, 58]],
  4: [[1, 22], [27, 58]],
  5: [[2, 20], [28, 58]],
  6: [[3, 19], [28, 56]],
  7: [[4, 19], [29, 54]],
  8: [[5, 18], [29, 33], [35, 38], [40, 52]],
  9: [[6, 17], [28, 40], [42, 50]],
  10: [[8, 16], [27, 38], [40, 47]],
  11: [[9, 15], [26, 38], [41, 46]],
  12: [[12, 16], [26, 38], [41, 45], [47, 52]],
  13: [[15, 19], [27, 38], [45, 52]],
  14: [[16, 21], [28, 37], [47, 53]],
  15: [[16, 22], [28, 36], [48, 53]],
  16: [[16, 22], [28, 35], [49, 54]],
  17: [[16, 22], [28, 35], [50, 56]],
  18: [[17, 22], [29, 35], [48, 57]],
  19: [[17, 22], [29, 34], [48, 57]],
  20: [[18, 22], [30, 33], [49, 56]],
  21: [[18, 21], [50, 55]],
  22: [[18, 20], [51, 53]],
  23: [[18, 20]],
  24: [[18, 19]],
  26: [[0, 59]],
  27: [[0, 59]],
  28: [[0, 59]],
  29: [[0, 59]],
};

interface MapPoint {
  ip: string;
  lat: number;
  lon: number;
  label: string;
  alarm: boolean;
  weight: number;
}

export function OriginMap({ sessions, provider }: { sessions: SessionView[]; provider: string }) {
  const { points, synthetic, located, unlocated } = useMemo(() => {
    const byIp = new Map<string, MapPoint>();
    let syn = false;
    let un = 0;

    for (const s of sessions) {
      const g = s.geo;
      if (!g || g.latitude === undefined || g.longitude === undefined) {
        un++;
        continue;
      }
      if (g.synthetic) syn = true;

      const existing = byIp.get(s.src_ip);
      if (existing) {
        existing.weight++;
        existing.alarm ||= s.detected_attacks.length > 0 || s.artifact_count > 0;
        continue;
      }
      byIp.set(s.src_ip, {
        ip: s.src_ip,
        lat: g.latitude,
        lon: g.longitude,
        label: [g.city, g.country].filter(Boolean).join(", ") || s.src_ip,
        alarm: s.detected_attacks.length > 0 || s.artifact_count > 0,
        weight: 1,
      });
    }

    return {
      points: [...byIp.values()],
      synthetic: syn,
      located: byIp.size,
      unlocated: un,
    };
  }, [sessions]);

  const dots: React.ReactNode[] = [];
  for (const [rowStr, ranges] of Object.entries(LAND)) {
    const row = Number(rowStr);
    for (const [from, to] of ranges) {
      for (let col = from; col <= to; col++) {
        dots.push(
          <circle key={`${row}-${col}`} className="map-land" cx={col * 6 + 3} cy={row * 6 + 3} r={1} />,
        );
      }
    }
  }

  return (
    <div className="map">
      {/* 1 unit == 1 degree, so projection is a straight offset. */}
      <svg viewBox="0 0 360 180" preserveAspectRatio="xMidYMid meet" role="img"
           aria-label={`Attack origins: ${located} located, ${unlocated} unlocated`}>
        <g className="map-grid">
          {[-120, -60, 0, 60, 120].map((lon) => (
            <line key={`v${lon}`} x1={lon + 180} y1={0} x2={lon + 180} y2={180} />
          ))}
          {[-60, -30, 0, 30, 60].map((lat) => (
            <line key={`h${lat}`} x1={0} y1={90 - lat} x2={360} y2={90 - lat} />
          ))}
        </g>

        <g opacity={0.55}>{dots}</g>

        {points.map((p) => {
          const x = p.lon + 180;
          const y = 90 - p.lat;
          const r = Math.min(3.4, 1.2 + Math.log2(p.weight + 1) * 0.7);
          return (
            <g key={p.ip}>
              <circle className="map-ping" cx={x} cy={y} r={1} />
              <circle className={`map-hit ${p.alarm ? "is-alarm" : ""}`} cx={x} cy={y} r={r}>
                <title>{`${p.ip} — ${p.label} — ${p.weight} session(s)`}</title>
              </circle>
            </g>
          );
        })}
      </svg>

      <div className={`map-caption ${synthetic ? "is-synthetic" : ""}`}>
        {synthetic
          ? `synthetic coordinates — development only`
          : provider === "disabled"
            ? `${unlocated} unlocated · no geo database configured`
            : `${located} located · ${unlocated} unlocated`}
      </div>
    </div>
  );
}

/* -------------------------------------------------------------- bar lists */

export function BarList({
  rows,
  attacker,
  emptyLabel,
}: {
  rows: [string, number][];
  attacker?: boolean;
  emptyLabel: string;
}) {
  if (rows.length === 0) {
    return <Empty title={emptyLabel} />;
  }
  const max = Math.max(...rows.map(([, n]) => n), 1);

  return (
    <div className="bars">
      {rows.map(([label, count]) => (
        <div key={label} className={`bar ${attacker ? "is-attacker" : ""}`}>
          <span className="bar-fill" style={{ width: `${(count / max) * 100}%` }} />
          <span className="bar-label" title={label}>
            {label}
          </span>
          <span className="bar-count">{count}</span>
        </div>
      ))}
    </div>
  );
}

/* ---------------------------------------------------------- session list */

export function SessionRow({
  session,
  selected,
  onSelect,
}: {
  session: SessionView;
  selected: boolean;
  onSelect: (s: SessionView) => void;
}) {
  const live = !session.ended_at;
  return (
    <button className="srow" aria-selected={selected} onClick={() => onSelect(session)}>
      <span className="srow-top">
        <span className="srow-ip">{session.src_ip || "unknown"}</span>
        <span className="srow-proto">{session.protocol}</span>
        {session.detected_attacks.length > 0 && (
          <span className="tag">{session.detected_attacks[0]}</span>
        )}
        {session.cluster_label && <span className="tag is-signal">{session.cluster_label}</span>}
        {session.automated === false && <span className="tag is-signal">interactive</span>}
        <span className="srow-when">
          {live ? "live" : relativeTime(session.started_at)}
        </span>
      </span>

      <span className="srow-meta">
        {session.command_count > 0 && <span>{session.command_count} cmd</span>}
        {session.http_request_count > 0 && <span>{session.http_request_count} req</span>}
        {session.auth_count > 0 && <span>{session.auth_count} auth</span>}
        {session.artifact_count > 0 && <span>{session.artifact_count} payload</span>}
        {session.duration_ms > 0 && <span>{duration(session.duration_ms)}</span>}
        {session.geo?.country && <span>{session.geo.country}</span>}
      </span>

      {session.client_banner && <span className="srow-banner">{session.client_banner}</span>}
      {session.credential_used && (
        <span className="srow-banner">accepted {session.credential_used}</span>
      )}
    </button>
  );
}

/* --------------------------------------------------------------- ioc feed */

export function IocList({ title, entries }: { title: string; entries: IocEntry[] }) {
  return (
    <Panel title={title} aside={`${entries.length}`}>
      {entries.length === 0 ? (
        <Empty title="Nothing yet" />
      ) : (
        entries.slice(0, 60).map((e) => (
          <div className="ioc-row" key={e.value}>
            <span className="ioc-value">{e.value}</span>
            <span className="ioc-count">{e.count}</span>
            {e.context && <span className="ioc-context">{e.context}</span>}
          </div>
        ))
      )}
    </Panel>
  );
}

/* ------------------------------------------------------------ status rail */

export function StatusRail({ stats, connected }: { stats: Stats | null; connected: boolean }) {
  return (
    <header className="rail">
      <div className="mark">
        honeynet <span>console</span>
      </div>

      <div className="pips" title={connected ? "Live feed connected" : "Live feed disconnected"}>
        {stats?.nodes.length ? (
          stats.nodes.map((n) => {
            const stale = Date.now() - new Date(n.last_seen).getTime() > 180_000;
            // A sensor that dropped events has holes in its corpus, and that is
            // more urgent than one that is merely quiet.
            const lossy = n.spool_dropped > 0;
            return (
              <span
                key={n.node_id}
                className={`pip ${lossy ? "is-lossy" : stale ? "is-stale" : ""}`}
                title={`${n.node_id} — ${n.events} events, spool ${n.spool_depth}${
                  lossy ? `, ${n.spool_dropped} DROPPED` : ""
                }`}
              />
            );
          })
        ) : (
          <span className="pip is-stale" title="No sensors reporting" />
        )}
        <span className="stat">
          <i>{stats?.nodes.length ?? 0} sensors</i>
        </span>
      </div>

      <div className="rail-stats">
        <span className="stat">
          <b>{stats?.sessions.toLocaleString() ?? "—"}</b>
          <i>sessions</i>
        </span>
        <span className="stat">
          <b>{stats?.events.toLocaleString() ?? "—"}</b>
          <i>events</i>
        </span>
        <span className="stat">
          <b>{stats?.credentials.toLocaleString() ?? "—"}</b>
          <i>credentials</i>
        </span>
        <span className="stat">
          <b>{stats?.artifacts.toLocaleString() ?? "—"}</b>
          <i>payloads</i>
        </span>
        <span className={`stat ${stats?.canary_hits ? "is-alarm" : ""}`}>
          <b>{stats?.canary_hits.toLocaleString() ?? "—"}</b>
          <i>canary hits</i>
        </span>
      </div>
    </header>
  );
}
