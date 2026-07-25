/** Types and fetchers for the collector's read API. */

export interface GeoInfo {
  country?: string;
  country_code?: string;
  city?: string;
  latitude?: number;
  longitude?: number;
  asn?: number;
  as_org?: string;
  /** Coordinates were fabricated for local development. Never hide this. */
  synthetic?: boolean;
}

export interface SessionView {
  session_id: string;
  node_id: string;
  protocol: string;
  src_ip: string;
  src_port: number;
  client_banner: string;
  hassh: string;
  started_at: string;
  ended_at?: string;
  end_reason?: string;
  duration_ms: number;
  command_count: number;
  auth_count: number;
  artifact_count: number;
  http_request_count: number;
  credential_used?: string;
  detected_attacks: string[];
  artifact_urls: string[];
  geo?: GeoInfo;
  cluster_id?: number;
  cluster_label?: string;
  automated?: boolean;
}

export interface NodeHealth {
  node_id: string;
  last_seen: string;
  uptime_ms: number;
  spool_depth: number;
  /** Non-zero means this sensor's corpus has holes for the period. */
  spool_dropped: number;
  build_version: string;
  events: number;
}

export interface Stats {
  sessions: number;
  events: number;
  commands: number;
  credentials: number;
  artifacts: number;
  canary_hits: number;
  nodes: NodeHealth[];
  top_credentials: [string, number][];
  top_sources: [string, number][];
  top_attacks: [string, number][];
  protocols: [string, number][];
  geo_provider: string;
}

export type Payload =
  | { kind: "session_start"; protocol: string; peer: Peer; client_banner: string; hassh: string }
  | { kind: "session_end"; reason: string; duration_ms: number; command_count: number }
  | { kind: "auth"; method: string; username: string; password: string; success: boolean; attempt_index: number; since_previous_ms: number }
  | { kind: "command"; raw: string; argv: string[]; cwd: string; since_session_start_ms: number; since_previous_ms: number; keystroke_deltas_ms: number[]; bulk_input: boolean; command_index: number }
  | { kind: "artifact"; url: string; host: string; via_tool: string; source_command: string }
  | { kind: "upload"; sha256: string; size_bytes: number; claimed_name: string; transport: string; detected_type: string }
  | { kind: "http_request"; method: string; path: string; query: string; decoy_profile: string; response_status: number; detected_attacks: string[]; form_username: string; form_password: string }
  | { kind: "rdp_connect"; cookie: string; username: string; requested_protocols: string[] }
  | { kind: "canary"; token_id: string; token_type: string; planted_path: string; user_agent: string }
  | { kind: "heartbeat"; uptime_ms: number; spool_depth: number; spool_dropped: number; build_version: string }
  | { kind: "anomaly"; kind_detail?: string; detail: string };

export interface Peer {
  src_ip: string;
  src_port: number;
  dst_ip: string;
  dst_port: number;
}

export interface CollectorEvent {
  node_id: string;
  seq: number;
  session_id: string;
  ts_node: string;
  ts_collector: string;
  payload: Payload & { kind: string; [k: string]: unknown };
}

export interface IocEntry {
  value: string;
  count: number;
  context?: string;
}

export interface IocFeed {
  source_ips: IocEntry[];
  payload_urls: IocEntry[];
  payload_hosts: IocEntry[];
  client_fingerprints: IocEntry[];
  credential_patterns: IocEntry[];
  note: string;
}

export interface ClusterProfile {
  cluster_id: number;
  label: string;
  size: number;
  sessions: string[];
  source_ips: string[];
  hasshes: string[];
  banners: string[];
  top_commands: [string, number][];
  top_tools: [string, number][];
  artifact_hosts: string[];
  credentials: string[];
  automated_fraction: number;
  mean_duration_s: number;
  mean_command_count: number;
}

export interface AttackTechnique {
  technique_id: string;
  technique: string;
  tactic: string;
  rationale: string;
  evidence: string[];
  sessions: number;
  prevalence: number;
}

export interface ProfileReport {
  applied: number;
  report: {
    corpus?: Record<string, unknown>;
    classification?: { automated: number; interactive: number };
    clustering?: { n_clusters: number; n_noise: number; reducer: string; clusters: ClusterProfile[] };
    attack?: Record<string, { techniques: AttackTechnique[]; tactics: string[] }>;
  };
}

const BASE = "/api";

async function get<T>(path: string): Promise<T> {
  const res = await fetch(`${BASE}${path}`, { headers: { accept: "application/json" } });
  if (!res.ok) {
    throw new Error(`${path} responded ${res.status}`);
  }
  return (await res.json()) as T;
}

export const api = {
  stats: () => get<Stats>("/stats"),
  sessions: (params: Record<string, string | number | boolean | undefined> = {}) => {
    const q = new URLSearchParams();
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== "" && v !== false) q.set(k, String(v));
    }
    const suffix = q.toString() ? `?${q}` : "";
    return get<SessionView[]>(`/sessions${suffix}`);
  },
  sessionEvents: (id: string) => get<CollectorEvent[]>(`/sessions/${encodeURIComponent(id)}/events`),
  iocs: () => get<IocFeed>("/iocs"),
  profile: () => get<ProfileReport>("/profile"),
};

/** Subscribes to the live event stream. Returns a teardown function. */
export function subscribe(
  onEvent: (e: CollectorEvent) => void,
  onState?: (connected: boolean) => void,
): () => void {
  const src = new EventSource(`${BASE}/stream`);

  const handle = (ev: MessageEvent) => {
    try {
      onEvent(JSON.parse(ev.data) as CollectorEvent);
    } catch {
      // A malformed frame is not worth tearing the feed down for.
    }
  };

  // The server names each frame after its payload kind, so every kind needs
  // its own listener; the default `message` handler never fires for named
  // events.
  const kinds = [
    "session_start", "session_end", "auth", "command", "artifact", "upload",
    "http_request", "rdp_connect", "canary", "heartbeat", "anomaly",
  ];
  for (const k of kinds) src.addEventListener(k, handle as EventListener);

  src.onopen = () => onState?.(true);
  src.onerror = () => onState?.(false);

  return () => {
    for (const k of kinds) src.removeEventListener(k, handle as EventListener);
    src.close();
  };
}

/** One-line description of an event, mirroring the collector's own summary. */
export function summarize(e: CollectorEvent): string {
  const p = e.payload as Record<string, unknown> & { kind: string };
  switch (p.kind) {
    case "session_start":
      return `${p.protocol} session opened — ${(p.peer as Peer)?.src_ip ?? "?"}`;
    case "session_end":
      return `session ended (${p.reason})`;
    case "auth": {
      const verdict = p.success ? "accepted" : "rejected";
      return `${verdict}  ${p.username}:${p.password}`;
    }
    case "command":
      return `$ ${p.raw}`;
    case "artifact":
      return `payload referenced — ${p.url}`;
    case "upload":
      return `upload ${p.claimed_name} (${p.size_bytes} bytes, ${p.detected_type})`;
    case "http_request": {
      const attacks = (p.detected_attacks as string[]) ?? [];
      const tail = attacks.length ? `  [${attacks.join(" ")}]` : "";
      return `${p.method} ${p.path} → ${p.response_status}${tail}`;
    }
    case "rdp_connect":
      return `rdp cookie ${p.cookie || "(none)"}`;
    case "canary":
      return `canary opened — ${p.planted_path}`;
    case "heartbeat":
      return `heartbeat, spool ${p.spool_depth}`;
    case "anomaly":
      return `anomaly: ${p.detail}`;
    default:
      return p.kind;
  }
}

/** True when the event carries something the attacker authored or saw. */
export function isAttackerAuthored(e: CollectorEvent): boolean {
  return ["command", "auth", "artifact", "upload", "http_request", "rdp_connect"].includes(
    e.payload.kind,
  );
}

export function isAlarm(e: CollectorEvent): boolean {
  return e.payload.kind === "canary";
}

export function relativeTime(iso: string): string {
  const then = new Date(iso).getTime();
  const secs = Math.max(0, (Date.now() - then) / 1000);
  if (secs < 60) return `${Math.floor(secs)}s ago`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m ago`;
  if (secs < 86400) return `${Math.floor(secs / 3600)}h ago`;
  return `${Math.floor(secs / 86400)}d ago`;
}

export function clockTime(iso: string): string {
  const d = new Date(iso);
  return d.toLocaleTimeString([], { hour12: false });
}

export function duration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  const s = ms / 1000;
  if (s < 60) return `${s.toFixed(1)}s`;
  const m = Math.floor(s / 60);
  return `${m}m ${Math.floor(s % 60)}s`;
}
