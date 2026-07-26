import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  api,
  subscribe,
  type AttackTechnique,
  type ClusterProfile,
  type CollectorEvent,
  type IocFeed,
  type ProfileReport,
  type SessionView,
  type Stats,
} from "./api";
import { TranscriptReplay } from "./Replay";
import {
  BarList,
  Empty,
  IocList,
  LiveFeed,
  OriginMap,
  Panel,
  SessionRow,
  StatusRail,
} from "./panels";

type View = "live" | "sessions" | "clusters" | "iocs";

const VIEWS: { id: View; label: string }[] = [
  { id: "live", label: "Live" },
  { id: "sessions", label: "Sessions" },
  { id: "clusters", label: "Attackers" },
  { id: "iocs", label: "Indicators" },
];

/** Newest events first; the live feed reads top-down. */
const FEED_LIMIT = 200;

export default function App() {
  const [view, setView] = useState<View>("live");
  const [stats, setStats] = useState<Stats | null>(null);
  const [sessions, setSessions] = useState<SessionView[]>([]);
  const [feed, setFeed] = useState<CollectorEvent[]>([]);
  const [connected, setConnected] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Poll for aggregates; stream for individual events. Polling everything
  // would waste a round trip per second, and streaming aggregates would mean
  // recomputing them per subscriber.
  const refresh = useCallback(async () => {
    try {
      const [s, list] = await Promise.all([api.stats(), api.sessions({ limit: 300 })]);
      setStats(s);
      setSessions(list);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "collector unreachable");
    }
  }, []);

  useEffect(() => {
    void refresh();
    const id = window.setInterval(() => void refresh(), 5000);
    return () => window.clearInterval(id);
  }, [refresh]);

  useEffect(() => {
    return subscribe(
      (e) => setFeed((prev) => [e, ...prev].slice(0, FEED_LIMIT)),
      setConnected,
    );
  }, []);

  return (
    <div className="console">
      <StatusRail stats={stats} connected={connected} />

      <nav className="views" aria-label="Views">
        {VIEWS.map((v) => (
          <button
            key={v.id}
            className="view-tab"
            aria-current={view === v.id}
            onClick={() => setView(v.id)}
          >
            {v.label}
            {v.id === "sessions" && sessions.length > 0 && (
              <span className="count">{sessions.length}</span>
            )}
          </button>
        ))}
      </nav>

      <main className="stage">
        {error && view === "live" ? (
          <Empty title="Collector unreachable">
            {error}. Start it with <code>--api-addr 127.0.0.1:8088</code>, or check that
            the address this page is served from proxies <code>/api</code>.
          </Empty>
        ) : view === "live" ? (
          <LiveView feed={feed} sessions={sessions} stats={stats} />
        ) : view === "sessions" ? (
          <SessionsView sessions={sessions} />
        ) : view === "clusters" ? (
          <ClustersView sessions={sessions} />
        ) : (
          <IocsView />
        )}
      </main>
    </div>
  );
}

/* -------------------------------------------------------------- live view */

function LiveView({
  feed,
  sessions,
  stats,
}: {
  feed: CollectorEvent[];
  sessions: SessionView[];
  stats: Stats | null;
}) {
  return (
    <div className="live">
      <Panel
        title="Event feed"
        aside={feed.length > 0 ? `${feed.length} recent` : "waiting"}
      >
        <LiveFeed events={feed} />
      </Panel>

      <div className="live-side">
        <Panel title="Origins" aside={stats?.geo_provider}>
          <OriginMap sessions={sessions} provider={stats?.geo_provider ?? "disabled"} />
        </Panel>

        <Panel title="Credentials offered" aside="most frequent">
          <BarList
            rows={stats?.top_credentials ?? []}
            attacker
            emptyLabel="No credentials yet"
          />
        </Panel>
      </div>
    </div>
  );
}

/* ---------------------------------------------------------- sessions view */

function SessionsView({ sessions }: { sessions: SessionView[] }) {
  const [selected, setSelected] = useState<SessionView | null>(null);
  const [events, setEvents] = useState<CollectorEvent[]>([]);
  const [loading, setLoading] = useState(false);
  const [filter, setFilter] = useState<"all" | "attacks" | "interactive" | "payloads">("all");
  const lastRequested = useRef<string | null>(null);

  const filtered = useMemo(() => {
    switch (filter) {
      case "attacks":
        return sessions.filter((s) => s.detected_attacks.length > 0);
      case "interactive":
        return sessions.filter((s) => s.automated === false);
      case "payloads":
        return sessions.filter((s) => s.artifact_count > 0);
      default:
        return sessions;
    }
  }, [sessions, filter]);

  const open = useCallback(async (s: SessionView) => {
    setSelected(s);
    setLoading(true);
    lastRequested.current = s.session_id;
    try {
      const evs = await api.sessionEvents(s.session_id);
      // A slower earlier request must not overwrite a newer selection.
      if (lastRequested.current === s.session_id) setEvents(evs);
    } catch {
      if (lastRequested.current === s.session_id) setEvents([]);
    } finally {
      if (lastRequested.current === s.session_id) setLoading(false);
    }
  }, []);

  return (
    <div className="sessions">
      <Panel title="Sessions" aside={`${filtered.length}`}>
        <div className="filters">
          {(
            [
              ["all", "All"],
              ["attacks", "Exploit attempts"],
              ["interactive", "Interactive"],
              ["payloads", "Dropped payloads"],
            ] as const
          ).map(([id, label]) => (
            <button
              key={id}
              className="chip"
              aria-pressed={filter === id}
              onClick={() => setFilter(id)}
            >
              {label}
            </button>
          ))}
        </div>

        {filtered.length === 0 ? (
          <Empty title="No sessions match">
            Sessions arrive as sensors observe them. Change the filter, or wait.
          </Empty>
        ) : (
          filtered.map((s) => (
            <SessionRow
              key={s.session_id}
              session={s}
              selected={selected?.session_id === s.session_id}
              onSelect={(sel) => void open(sel)}
            />
          ))
        )}
      </Panel>

      <Panel
        title="Transcript"
        aside={selected ? selected.session_id.slice(0, 12) : undefined}
      >
        {!selected ? (
          <Empty title="Select a session">
            Transcripts replay at the attacker's original keystroke timing. A person
            hesitates and mistypes; a loader emits the same line in one frame.
          </Empty>
        ) : loading ? (
          <Empty title="Loading transcript" />
        ) : (
          <TranscriptReplay session={selected} events={events} />
        )}
      </Panel>
    </div>
  );
}

/* ---------------------------------------------------------- clusters view */

function ClustersView({ sessions }: { sessions: SessionView[] }) {
  const [profile, setProfile] = useState<ProfileReport | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api
      .profile()
      .then(setProfile)
      .catch((e) => setError(e instanceof Error ? e.message : "no profile available"));
  }, []);

  const clusters = profile?.report.clustering?.clusters ?? [];
  const attack = profile?.report.attack ?? {};

  if (error || clusters.length === 0) {
    return (
      <Empty title="No attacker profile loaded">
        Clustering runs in the profiling pipeline, not the collector — one
        implementation of that decision, not two. Generate a report and point the
        collector at it:
        <br />
        <br />
        <code>honeynet-ml report .e2e/events.jsonl --out profile.json</code>
        <br />
        <code>honeynet-collector --profile-path profile.json</code>
      </Empty>
    );
  }

  return (
    <div className="clusters">
      {clusters.map((c) => (
        <ClusterCard
          key={c.cluster_id}
          cluster={c}
          techniques={attack[String(c.cluster_id)]?.techniques ?? []}
          sessions={sessions}
        />
      ))}
    </div>
  );
}

function ClusterCard({
  cluster,
  techniques,
}: {
  cluster: ClusterProfile;
  techniques: AttackTechnique[];
  sessions: SessionView[];
}) {
  const byTactic = useMemo(() => {
    const groups = new Map<string, AttackTechnique[]>();
    for (const t of techniques) {
      const list = groups.get(t.tactic) ?? [];
      list.push(t);
      groups.set(t.tactic, list);
    }
    return [...groups.entries()];
  }, [techniques]);

  return (
    <section className="panel">
      <div className="cluster-head">
        <span className="cluster-label">{cluster.label}</span>
        <span className="cluster-size">
          {cluster.size} session{cluster.size === 1 ? "" : "s"} ·{" "}
          {Math.round(cluster.automated_fraction * 100)}% automated
        </span>
      </div>

      <dl className="kv">
        <dt>Client</dt>
        <dd className="attacker">{cluster.banners.slice(0, 2).join(" · ") || "—"}</dd>

        <dt>Fingerprint</dt>
        <dd>{cluster.hasshes.map((h) => h.slice(0, 16)).join(" · ") || "—"}</dd>

        <dt>Shape</dt>
        <dd>
          {cluster.mean_command_count.toFixed(1)} commands over{" "}
          {cluster.mean_duration_s.toFixed(1)}s
        </dd>

        {cluster.top_tools.length > 0 && (
          <>
            <dt>Tools</dt>
            <dd className="attacker">
              {cluster.top_tools.slice(0, 8).map(([t, n]) => `${t}(${n})`).join(" ")}
            </dd>
          </>
        )}

        {cluster.artifact_hosts.length > 0 && (
          <>
            <dt>Payload hosts</dt>
            <dd className="attacker">{cluster.artifact_hosts.join(" · ")}</dd>
          </>
        )}

        {cluster.credentials.length > 0 && (
          <>
            <dt>Credentials</dt>
            <dd className="attacker">{cluster.credentials.slice(0, 6).join(" · ")}</dd>
          </>
        )}
      </dl>

      {byTactic.length > 0 && (
        <div className="attack">
          {byTactic.map(([tactic, list]) => (
            <div className="attack-tactic" key={tactic}>
              <span>{tactic.replace(/-/g, " ")}</span>
              <div className="attack-chips">
                {list.map((t) => (
                  <span
                    className="attack-chip"
                    key={t.technique_id}
                    // Prevalence drives opacity: a technique in every session
                    // characterises the group, one in a tenth is incidental.
                    style={{ opacity: 0.45 + t.prevalence * 0.55 }}
                    title={`${t.technique} — ${Math.round(t.prevalence * 100)}% of sessions\n${t.rationale}`}
                  >
                    {t.technique_id}
                  </span>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}

/* -------------------------------------------------------------- ioc view */

function IocsView() {
  const [feed, setFeed] = useState<IocFeed | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const load = () =>
      api
        .iocs()
        .then(setFeed)
        .catch((e) => setError(e instanceof Error ? e.message : "unavailable"));
    void load();
    const id = window.setInterval(load, 15000);
    return () => window.clearInterval(id);
  }, []);

  if (error) return <Empty title="Indicators unavailable">{error}</Empty>;
  if (!feed) return <Empty title="Loading indicators" />;

  return (
    <div className="iocs">
      <IocList title="Source addresses" entries={feed.source_ips} />
      <IocList title="Payload URLs" entries={feed.payload_urls} />
      <IocList title="Payload hosts" entries={feed.payload_hosts} />
      <IocList title="Client fingerprints" entries={feed.client_fingerprints} />

      <section className="panel">
        <header className="panel-head">
          <h2>Credential patterns</h2>
        </header>
        <div className="panel-body">
          {feed.credential_patterns.slice(0, 40).map((e) => (
            <div className="ioc-row" key={e.value}>
              <span className="ioc-value">{e.value}</span>
              <span className="ioc-count">{e.count}</span>
            </div>
          ))}
        </div>
        <p className="disclosure">
          Shapes, not passwords. <code>a</code> lowercase, <code>A</code> uppercase,{" "}
          <code>d</code> digit, <code>s</code> symbol. Harvested pairs stay in the
          database because real users occasionally type a real password into a fake
          prompt, and a published feed is not the place to find out.
        </p>
      </section>
    </div>
  );
}
