//! In-memory view of recent activity, for the operator dashboard.
//!
//! Postgres is the durable record; this is the working set. A dashboard wants
//! the last few thousand sessions, live, with sub-millisecond response — which
//! is a different access pattern from the archival one, and serving it from an
//! index that the ingest path already touches avoids a query round trip per
//! panel refresh.
//!
//! Bounded on purpose. An exposed sensor fleet produces events indefinitely,
//! and an unbounded cache is a memory leak with a nicer name. Oldest sessions
//! are evicted; the durable store keeps them.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::geo::{GeoInfo, GeoProvider};
use crate::model::{Event, Payload, Protocol};

/// Sessions retained in memory. Roughly a day of traffic for a small fleet.
const MAX_SESSIONS: usize = 5_000;

/// Events retained per session, so one abusive session cannot evict the rest.
const MAX_EVENTS_PER_SESSION: usize = 2_000;

/// Recent events kept for the live feed.
const MAX_RECENT: usize = 500;

#[derive(Debug, Clone, Serialize)]
pub struct SessionView {
    pub session_id: String,
    pub node_id: String,
    pub protocol: String,
    pub src_ip: String,
    pub src_port: u32,
    pub client_banner: String,
    pub hassh: String,

    pub started_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
    pub end_reason: Option<String>,
    pub duration_ms: i64,

    pub command_count: u32,
    pub auth_count: u32,
    pub artifact_count: u32,
    pub http_request_count: u32,

    /// Credential that the sensor accepted, if any.
    pub credential_used: Option<String>,
    /// Exploit classes seen across the session's HTTP requests.
    pub detected_attacks: Vec<String>,
    pub artifact_urls: Vec<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub geo: Option<GeoInfo>,

    /// Set by the profiling pipeline when a report is loaded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cluster_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cluster_label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub automated: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Stats {
    pub sessions: u64,
    pub events: u64,
    pub commands: u64,
    pub credentials: u64,
    pub artifacts: u64,
    pub canary_hits: u64,
    pub nodes: Vec<NodeHealth>,
    pub top_credentials: Vec<(String, u64)>,
    pub top_sources: Vec<(String, u64)>,
    pub top_attacks: Vec<(String, u64)>,
    pub protocols: Vec<(String, u64)>,
    pub geo_provider: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct NodeHealth {
    pub node_id: String,
    pub last_seen: DateTime<Utc>,
    pub uptime_ms: i64,
    pub spool_depth: u64,
    /// Non-zero means that sensor's corpus has holes for the period.
    pub spool_dropped: u64,
    pub build_version: String,
    pub events: u64,
}

/// LiveIndex holds the working set.
pub struct LiveIndex {
    inner: Mutex<Inner>,
    geo: GeoProvider,
}

struct Inner {
    sessions: HashMap<String, SessionView>,
    /// Insertion order, for bounded eviction.
    order: VecDeque<String>,
    events: HashMap<String, Vec<Event>>,
    recent: VecDeque<Event>,

    nodes: HashMap<String, NodeHealth>,

    total_events: u64,
    commands: u64,
    credentials: u64,
    artifacts: u64,
    canary_hits: u64,

    credential_counts: HashMap<String, u64>,
    source_counts: HashMap<String, u64>,
    attack_counts: HashMap<String, u64>,
    protocol_counts: HashMap<String, u64>,
}

impl LiveIndex {
    pub fn new(geo: GeoProvider) -> Self {
        Self {
            geo,
            inner: Mutex::new(Inner {
                sessions: HashMap::new(),
                order: VecDeque::new(),
                events: HashMap::new(),
                recent: VecDeque::new(),
                nodes: HashMap::new(),
                total_events: 0,
                commands: 0,
                credentials: 0,
                artifacts: 0,
                canary_hits: 0,
                credential_counts: HashMap::new(),
                source_counts: HashMap::new(),
                attack_counts: HashMap::new(),
                protocol_counts: HashMap::new(),
            }),
        }
    }

    /// Folds one event into the index.
    pub fn ingest(&self, event: &Event) {
        let mut inner = self.inner.lock().expect("index poisoned");
        inner.total_events += 1;

        // Node-level telemetry has no session and updates fleet health instead.
        if event.session_id.is_empty() {
            if let Payload::Heartbeat(h) = &event.payload {
                let entry =
                    inner
                        .nodes
                        .entry(event.node_id.clone())
                        .or_insert_with(|| NodeHealth {
                            node_id: event.node_id.clone(),
                            last_seen: event.ts_collector,
                            uptime_ms: 0,
                            spool_depth: 0,
                            spool_dropped: 0,
                            build_version: String::new(),
                            events: 0,
                        });
                entry.last_seen = event.ts_collector;
                entry.uptime_ms = h.uptime_ms;
                entry.spool_depth = h.spool_depth;
                entry.spool_dropped = h.spool_dropped;
                entry.build_version = h.build_version.clone();
            }
            return;
        }

        if let Some(node) = inner.nodes.get_mut(&event.node_id) {
            node.events += 1;
            node.last_seen = event.ts_collector;
        }

        let sid = event.session_id.clone();
        if !inner.sessions.contains_key(&sid) {
            let view = SessionView {
                session_id: sid.clone(),
                node_id: event.node_id.clone(),
                protocol: "unknown".into(),
                src_ip: String::new(),
                src_port: 0,
                client_banner: String::new(),
                hassh: String::new(),
                started_at: event.ts_collector,
                ended_at: None,
                end_reason: None,
                duration_ms: 0,
                command_count: 0,
                auth_count: 0,
                artifact_count: 0,
                http_request_count: 0,
                credential_used: None,
                detected_attacks: Vec::new(),
                artifact_urls: Vec::new(),
                geo: None,
                cluster_id: None,
                cluster_label: None,
                automated: None,
            };
            inner.sessions.insert(sid.clone(), view);
            inner.order.push_back(sid.clone());

            while inner.order.len() > MAX_SESSIONS {
                if let Some(old) = inner.order.pop_front() {
                    inner.sessions.remove(&old);
                    inner.events.remove(&old);
                }
            }
        }

        // Update the aggregate before pushing the raw event, so a session that
        // hits the per-session event cap still has accurate counters.
        let geo = match &event.payload {
            Payload::SessionStart(s) if !s.peer.src_ip.is_empty() => {
                self.geo.lookup(&s.peer.src_ip)
            }
            _ => None,
        };

        {
            let counts_key = match &event.payload {
                Payload::SessionStart(s) => Some(s.protocol),
                _ => None,
            };
            if let Some(p) = counts_key {
                *inner
                    .protocol_counts
                    .entry(protocol_name(p).to_string())
                    .or_insert(0) += 1;
            }
        }

        match &event.payload {
            Payload::SessionStart(s) => {
                let src = s.peer.src_ip.clone();
                if !src.is_empty() {
                    *inner.source_counts.entry(src.clone()).or_insert(0) += 1;
                }
                if let Some(v) = inner.sessions.get_mut(&sid) {
                    v.protocol = protocol_name(s.protocol).to_string();
                    v.src_ip = s.peer.src_ip.clone();
                    v.src_port = s.peer.src_port;
                    v.client_banner = s.client_banner.clone();
                    v.hassh = s.hassh.clone();
                    v.geo = geo;
                }
            }
            Payload::SessionEnd(e) => {
                if let Some(v) = inner.sessions.get_mut(&sid) {
                    v.ended_at = Some(event.ts_collector);
                    v.end_reason = Some(e.reason.clone());
                    v.duration_ms = e.duration_ms;
                }
            }
            Payload::Auth(a) => {
                inner.credentials += 1;
                let pair = format!("{}:{}", a.username, a.password);
                *inner.credential_counts.entry(pair.clone()).or_insert(0) += 1;
                if let Some(v) = inner.sessions.get_mut(&sid) {
                    v.auth_count += 1;
                    if a.success {
                        v.credential_used = Some(pair);
                    }
                }
            }
            Payload::Command(_) => {
                inner.commands += 1;
                if let Some(v) = inner.sessions.get_mut(&sid) {
                    v.command_count += 1;
                }
            }
            Payload::Artifact(a) => {
                inner.artifacts += 1;
                if let Some(v) = inner.sessions.get_mut(&sid) {
                    v.artifact_count += 1;
                    if !v.artifact_urls.contains(&a.url) {
                        v.artifact_urls.push(a.url.clone());
                    }
                }
            }
            Payload::HttpRequest(h) => {
                for a in &h.detected_attacks {
                    *inner.attack_counts.entry(a.clone()).or_insert(0) += 1;
                }
                let attacks = h.detected_attacks.clone();
                if let Some(v) = inner.sessions.get_mut(&sid) {
                    v.http_request_count += 1;
                    for a in attacks {
                        if !v.detected_attacks.contains(&a) {
                            v.detected_attacks.push(a);
                        }
                    }
                }
            }
            Payload::Canary(_) => {
                inner.canary_hits += 1;
            }
            _ => {}
        }

        let bucket = inner.events.entry(sid).or_default();
        if bucket.len() < MAX_EVENTS_PER_SESSION {
            bucket.push(event.clone());
        }

        inner.recent.push_back(event.clone());
        while inner.recent.len() > MAX_RECENT {
            inner.recent.pop_front();
        }
    }

    /// Returns sessions newest first, optionally filtered.
    pub fn sessions(
        &self,
        limit: usize,
        offset: usize,
        protocol: Option<&str>,
        src_ip: Option<&str>,
        with_attacks: bool,
    ) -> Vec<SessionView> {
        let inner = self.inner.lock().expect("index poisoned");
        let mut all: Vec<&SessionView> = inner
            .sessions
            .values()
            .filter(|s| protocol.map_or(true, |p| s.protocol == p))
            .filter(|s| src_ip.map_or(true, |ip| s.src_ip == ip))
            .filter(|s| !with_attacks || !s.detected_attacks.is_empty())
            .collect();

        // Newest first. sort_by_key with Reverse rather than a comparator so
        // the ordering cannot be silently inverted by an edit to the closure.
        all.sort_by_key(|s| std::cmp::Reverse(s.started_at));
        all.into_iter().skip(offset).take(limit).cloned().collect()
    }

    pub fn session(&self, id: &str) -> Option<SessionView> {
        self.inner
            .lock()
            .expect("index poisoned")
            .sessions
            .get(id)
            .cloned()
    }

    /// Full event stream for one session -- the transcript view.
    pub fn session_events(&self, id: &str) -> Vec<Event> {
        self.inner
            .lock()
            .expect("index poisoned")
            .events
            .get(id)
            .cloned()
            .unwrap_or_default()
    }

    /// Most recent events across all sessions.
    ///
    /// Not on the serving path: the live feed pushes events over /stream as
    /// they arrive rather than polling for them. Retained because it is the
    /// only way to read the ring buffer, which the eviction tests assert on.
    #[allow(dead_code)]
    pub fn recent(&self, limit: usize) -> Vec<Event> {
        let inner = self.inner.lock().expect("index poisoned");
        inner.recent.iter().rev().take(limit).cloned().collect()
    }

    pub fn stats(&self) -> Stats {
        let inner = self.inner.lock().expect("index poisoned");
        Stats {
            sessions: inner.sessions.len() as u64,
            events: inner.total_events,
            commands: inner.commands,
            credentials: inner.credentials,
            artifacts: inner.artifacts,
            canary_hits: inner.canary_hits,
            nodes: {
                let mut n: Vec<NodeHealth> = inner.nodes.values().cloned().collect();
                n.sort_by(|a, b| a.node_id.cmp(&b.node_id));
                n
            },
            top_credentials: top_n(&inner.credential_counts, 15),
            top_sources: top_n(&inner.source_counts, 15),
            top_attacks: top_n(&inner.attack_counts, 15),
            protocols: top_n(&inner.protocol_counts, 10),
            geo_provider: self.geo.describe().to_string(),
        }
    }

    /// Applies clustering results produced by the profiling pipeline.
    ///
    /// The collector deliberately does not cluster. Reimplementing HDBSCAN in
    /// Rust to avoid a file handoff would put two implementations of the same
    /// decision in the system, and they would diverge.
    pub fn apply_profile(&self, assignments: &HashMap<String, (i64, String, bool)>) {
        let mut inner = self.inner.lock().expect("index poisoned");
        for (sid, (cluster, label, automated)) in assignments {
            if let Some(v) = inner.sessions.get_mut(sid) {
                v.cluster_id = Some(*cluster);
                v.cluster_label = Some(label.clone());
                v.automated = Some(*automated);
            }
        }
    }
}

fn top_n(counts: &HashMap<String, u64>, n: usize) -> Vec<(String, u64)> {
    let mut v: Vec<(String, u64)> = counts.iter().map(|(k, c)| (k.clone(), *c)).collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    v.truncate(n);
    v
}

fn protocol_name(p: Protocol) -> &'static str {
    p.as_str()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::*;

    fn start(sid: &str, ip: &str) -> Event {
        Event {
            node_id: "n1".into(),
            seq: 1,
            session_id: sid.into(),
            ts_node: Utc::now(),
            ts_collector: Utc::now(),
            payload: Payload::SessionStart(SessionStart {
                protocol: Protocol::Ssh,
                peer: Peer {
                    src_ip: ip.into(),
                    src_port: 4444,
                    dst_ip: "10.0.0.1".into(),
                    dst_port: 22,
                },
                client_banner: "SSH-2.0-test".into(),
                hassh: "abc".into(),
                kex_algorithms: vec![],
                ciphers: vec![],
                macs: vec![],
                compression: vec![],
            }),
        }
    }

    fn auth(sid: &str, user: &str, pass: &str, ok: bool) -> Event {
        Event {
            node_id: "n1".into(),
            seq: 2,
            session_id: sid.into(),
            ts_node: Utc::now(),
            ts_collector: Utc::now(),
            payload: Payload::Auth(AuthAttempt {
                method: "password".into(),
                username: user.into(),
                password: pass.into(),
                public_key_sha256: None,
                public_key_type: None,
                success: ok,
                attempt_index: 0,
                since_previous_ms: 10,
            }),
        }
    }

    #[test]
    fn folds_events_into_a_session_view() {
        let idx = LiveIndex::new(GeoProvider::Disabled);
        idx.ingest(&start("S1", "203.0.113.5"));
        idx.ingest(&auth("S1", "root", "toor", false));
        idx.ingest(&auth("S1", "root", "123456", true));

        let s = idx.session("S1").expect("session should exist");
        assert_eq!(s.src_ip, "203.0.113.5");
        assert_eq!(s.protocol, "ssh");
        assert_eq!(s.auth_count, 2);
        assert_eq!(s.credential_used.as_deref(), Some("root:123456"));
    }

    #[test]
    fn heartbeats_do_not_create_sessions() {
        let idx = LiveIndex::new(GeoProvider::Disabled);
        idx.ingest(&Event {
            node_id: "n1".into(),
            seq: 1,
            session_id: String::new(),
            ts_node: Utc::now(),
            ts_collector: Utc::now(),
            payload: Payload::Heartbeat(Heartbeat {
                uptime_ms: 1000,
                spool_depth: 3,
                spool_dropped: 7,
                active_sessions: 0,
                build_version: "dev".into(),
            }),
        });

        let stats = idx.stats();
        assert_eq!(stats.sessions, 0);
        assert_eq!(stats.nodes.len(), 1);
        // A non-zero drop count means that sensor's corpus has holes, and the
        // dashboard has to be able to say so.
        assert_eq!(stats.nodes[0].spool_dropped, 7);
    }

    #[test]
    fn evicts_oldest_sessions_when_bounded() {
        let idx = LiveIndex::new(GeoProvider::Disabled);
        for i in 0..(MAX_SESSIONS + 50) {
            idx.ingest(&start(&format!("S{i}"), "203.0.113.5"));
        }
        let stats = idx.stats();
        assert_eq!(stats.sessions as usize, MAX_SESSIONS);
        assert!(
            idx.session("S0").is_none(),
            "oldest session should be evicted"
        );
        assert!(idx.session(&format!("S{}", MAX_SESSIONS + 49)).is_some());
    }

    #[test]
    fn caps_events_per_session() {
        // One abusive session must not evict every other session's transcript.
        let idx = LiveIndex::new(GeoProvider::Disabled);
        idx.ingest(&start("S1", "203.0.113.5"));
        for _ in 0..(MAX_EVENTS_PER_SESSION + 100) {
            idx.ingest(&auth("S1", "root", "x", false));
        }
        assert_eq!(idx.session_events("S1").len(), MAX_EVENTS_PER_SESSION);
        // Counters stay accurate even past the cap.
        assert!(idx.session("S1").unwrap().auth_count > MAX_EVENTS_PER_SESSION as u32);
    }

    #[test]
    fn filters_sessions() {
        let idx = LiveIndex::new(GeoProvider::Disabled);
        idx.ingest(&start("S1", "203.0.113.5"));
        idx.ingest(&start("S2", "198.51.100.9"));

        assert_eq!(idx.sessions(10, 0, None, None, false).len(), 2);
        assert_eq!(idx.sessions(10, 0, Some("ssh"), None, false).len(), 2);
        assert_eq!(idx.sessions(10, 0, Some("http"), None, false).len(), 0);
        assert_eq!(
            idx.sessions(10, 0, None, Some("203.0.113.5"), false).len(),
            1
        );
        assert_eq!(idx.sessions(10, 0, None, None, true).len(), 0);
    }

    #[test]
    fn synthetic_geo_is_flagged_in_the_view() {
        let idx = LiveIndex::new(GeoProvider::Synthetic);
        idx.ingest(&start("S1", "203.0.113.5"));
        let geo = idx
            .session("S1")
            .unwrap()
            .geo
            .expect("should have location");
        assert!(geo.synthetic, "dashboard must be able to mark demo data");
    }
}
