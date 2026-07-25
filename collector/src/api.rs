//! Read API for the operator dashboard.
//!
//! Read-only by design. The collector's write path is the NATS subscription and
//! nothing else; an HTTP surface that could mutate state would be a second way
//! into the system with a much larger attack surface than a subject-scoped
//! message bus.

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{sse::Event as SseEvent, IntoResponse, Sse},
    routing::get,
    Json, Router,
};
use futures::stream::Stream;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt as _;
use tower_http::cors::CorsLayer;
use tower_http::services::{ServeDir, ServeFile};
use tracing::{info, warn};

use crate::index::LiveIndex;
use crate::model::{Event, Payload};

#[derive(Clone)]
pub struct ApiState {
    pub index: Arc<LiveIndex>,
    pub events: broadcast::Sender<Event>,
    /// Path to the profiling pipeline's report, reloaded on request.
    pub profile_path: Option<PathBuf>,
}

/// Builds the router.
pub fn router(state: ApiState, dashboard_dir: Option<PathBuf>) -> Router {
    let api = Router::new()
        .route("/stats", get(stats))
        .route("/sessions", get(sessions))
        .route("/sessions/:id", get(session_detail))
        .route("/sessions/:id/events", get(session_events))
        .route("/iocs", get(iocs))
        .route("/profile", get(profile))
        .route("/stream", get(stream))
        .with_state(state);

    let mut app = Router::new()
        .nest("/api", api)
        // The dashboard is served from a different origin during development
        // (Vite on :5173), so permissive CORS is needed there. In deployment
        // the dashboard is served from this same origin and the header is
        // inert. Bind the API to loopback and reverse-proxy it -- it must not
        // be internet-facing.
        .layer(CorsLayer::permissive());

    if let Some(dir) = dashboard_dir {
        let index = dir.join("index.html");
        if index.exists() {
            info!(path = %dir.display(), "serving dashboard");
            app = app.fallback_service(
                ServeDir::new(&dir).not_found_service(ServeFile::new(index)),
            );
        } else {
            warn!(path = %dir.display(), "dashboard directory has no index.html; not serving it");
        }
    }

    app
}

/// Serves the API until the process exits.
pub async fn serve(addr: SocketAddr, app: Router) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind api on {addr}"))?;
    info!(%addr, "operator api listening");
    axum::serve(listener, app).await.context("api server")?;
    Ok(())
}

// ---- handlers ----

async fn stats(State(s): State<ApiState>) -> impl IntoResponse {
    Json(s.index.stats())
}

#[derive(Debug, Deserialize)]
struct SessionQuery {
    #[serde(default = "default_limit")]
    limit: usize,
    #[serde(default)]
    offset: usize,
    protocol: Option<String>,
    src_ip: Option<String>,
    #[serde(default)]
    attacks: bool,
}

fn default_limit() -> usize {
    100
}

async fn sessions(State(s): State<ApiState>, Query(q): Query<SessionQuery>) -> impl IntoResponse {
    // Bounded so a hand-written query cannot ask for the whole index at once.
    let limit = q.limit.clamp(1, 1000);
    Json(s.index.sessions(
        limit,
        q.offset,
        q.protocol.as_deref(),
        q.src_ip.as_deref(),
        q.attacks,
    ))
}

async fn session_detail(State(s): State<ApiState>, Path(id): Path<String>) -> impl IntoResponse {
    match s.index.session(&id) {
        Some(v) => Json(v).into_response(),
        None => (StatusCode::NOT_FOUND, Json(err("session not found"))).into_response(),
    }
}

async fn session_events(State(s): State<ApiState>, Path(id): Path<String>) -> impl IntoResponse {
    let events = s.index.session_events(&id);
    if events.is_empty() && s.index.session(&id).is_none() {
        return (StatusCode::NOT_FOUND, Json(err("session not found"))).into_response();
    }
    Json(events).into_response()
}

#[derive(Debug, Serialize)]
struct IocFeed {
    source_ips: Vec<IocEntry>,
    payload_urls: Vec<IocEntry>,
    payload_hosts: Vec<IocEntry>,
    client_fingerprints: Vec<IocEntry>,
    credential_patterns: Vec<IocEntry>,
    note: &'static str,
}

#[derive(Debug, Serialize)]
struct IocEntry {
    value: String,
    count: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    context: Option<String>,
}

async fn iocs(State(s): State<ApiState>) -> impl IntoResponse {
    let stats = s.index.stats();
    let sessions = s.index.sessions(1000, 0, None, None, false);

    let mut urls: HashMap<String, u64> = HashMap::new();
    let mut hosts: HashMap<String, u64> = HashMap::new();
    let mut hasshes: HashMap<String, u64> = HashMap::new();

    for sess in &sessions {
        for u in &sess.artifact_urls {
            *urls.entry(u.clone()).or_insert(0) += 1;
            if let Some(host) = host_of(u) {
                *hosts.entry(host).or_insert(0) += 1;
            }
        }
        if !sess.hassh.is_empty() {
            *hasshes.entry(sess.hassh.clone()).or_insert(0) += 1;
        }
    }

    // Only sources that did something beyond spraying are published. Spray-only
    // addresses are overwhelmingly shared infrastructure and compromised
    // third-party hosts, and publishing them generates false positives.
    let source_ips = sessions
        .iter()
        .filter(|s| s.command_count > 0 || s.artifact_count > 0 || !s.detected_attacks.is_empty())
        .fold(HashMap::<String, (u64, u32, u32)>::new(), |mut acc, s| {
            let e = acc.entry(s.src_ip.clone()).or_insert((0, 0, 0));
            e.0 += 1;
            e.1 += s.command_count;
            e.2 += s.artifact_count;
            acc
        })
        .into_iter()
        .map(|(ip, (n, cmds, arts))| IocEntry {
            value: ip,
            count: n,
            context: Some(format!("{n} session(s), {cmds} command(s), {arts} payload ref(s)")),
        })
        .collect();

    Json(IocFeed {
        source_ips,
        payload_urls: to_entries(urls),
        payload_hosts: to_entries(hosts),
        client_fingerprints: to_entries(hasshes),
        // Shapes, not pairs. Real users occasionally typo real passwords into a
        // fake prompt, so the feed never carries the harvested credential.
        credential_patterns: stats
            .top_credentials
            .iter()
            .map(|(pair, n)| IocEntry {
                value: credential_shape(pair),
                count: *n,
                context: None,
            })
            .fold(HashMap::<String, u64>::new(), |mut acc, e| {
                *acc.entry(e.value).or_insert(0) += e.count;
                acc
            })
            .into_iter()
            .map(|(value, count)| IocEntry { value, count, context: None })
            .collect(),
        note: "Credential patterns are character-class shapes, never harvested pairs.",
    })
}

/// Reloads the profiling pipeline's report and applies it to the index.
///
/// Pull rather than push: the pipeline runs on its own schedule and writing a
/// file is the simplest interface that does not couple the two processes'
/// lifetimes.
async fn profile(State(s): State<ApiState>) -> impl IntoResponse {
    let Some(path) = s.profile_path.clone() else {
        return (
            StatusCode::NOT_FOUND,
            Json(err("no profile path configured; run honeynet-ml report --out <path>")),
        )
            .into_response();
    };

    let raw = match tokio::fs::read_to_string(&path).await {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::NOT_FOUND,
                Json(err(&format!("could not read {}: {e}", path.display()))),
            )
                .into_response()
        }
    };

    let doc: serde_json::Value = match serde_json::from_str(&raw) {
        Ok(d) => d,
        Err(e) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(err(&format!("profile is not valid JSON: {e}"))),
            )
                .into_response()
        }
    };

    let mut assignments = HashMap::new();
    if let Some(clusters) = doc
        .get("clustering")
        .and_then(|c| c.get("clusters"))
        .and_then(|c| c.as_array())
    {
        for c in clusters {
            let id = c.get("cluster_id").and_then(|v| v.as_i64()).unwrap_or(-1);
            let label = c
                .get("label")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let automated = c
                .get("automated_fraction")
                .and_then(|v| v.as_f64())
                .map(|f| f >= 0.5)
                .unwrap_or(true);
            if let Some(members) = c.get("sessions").and_then(|v| v.as_array()) {
                for m in members {
                    if let Some(sid) = m.as_str() {
                        assignments.insert(sid.to_string(), (id, label.clone(), automated));
                    }
                }
            }
        }
    }

    let applied = assignments.len();
    s.index.apply_profile(&assignments);

    Json(serde_json::json!({
        "applied": applied,
        "report": doc,
    }))
    .into_response()
}

/// Server-sent events feed of live activity.
async fn stream(State(s): State<ApiState>) -> Sse<impl Stream<Item = Result<SseEvent, Infallible>>> {
    let rx = s.events.subscribe();

    let stream = BroadcastStream::new(rx).filter_map(|res| match res {
        Ok(event) => {
            let kind = event.payload.kind().to_string();
            serde_json::to_string(&event)
                .ok()
                .map(|json| Ok(SseEvent::default().event(kind).data(json)))
        }
        // A lagging client misses events rather than stalling the broadcast for
        // everyone else. The dashboard is a live view, not a record.
        Err(_) => None,
    });

    Sse::new(stream).keep_alive(
        axum::response::sse::KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keep-alive"),
    )
}

// ---- helpers ----

fn err(msg: &str) -> serde_json::Value {
    serde_json::json!({ "error": msg })
}

fn to_entries(counts: HashMap<String, u64>) -> Vec<IocEntry> {
    let mut v: Vec<IocEntry> = counts
        .into_iter()
        .map(|(value, count)| IocEntry { value, count, context: None })
        .collect();
    v.sort_by(|a, b| b.count.cmp(&a.count).then(a.value.cmp(&b.value)));
    v
}

fn host_of(url: &str) -> Option<String> {
    let rest = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .or_else(|| url.strip_prefix("ftp://"))
        .or_else(|| url.strip_prefix("tftp://"))
        .or_else(|| url.strip_prefix("ldap://"))?;
    let host = rest.split('/').next()?;
    let host = host.split(':').next()?;
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

/// credential_shape reduces a pair to its character-class skeleton, so the feed
/// publishes the structure of a wordlist without publishing the credential.
fn credential_shape(pair: &str) -> String {
    let (user, pass) = pair.split_once(':').unwrap_or((pair, ""));
    format!("{}:{}", user, shape(pass))
}

fn shape(s: &str) -> String {
    if s.is_empty() {
        return "(empty)".into();
    }
    s.chars()
        .take(24)
        .map(|c| {
            if c.is_ascii_digit() {
                'd'
            } else if c.is_ascii_lowercase() {
                'a'
            } else if c.is_ascii_uppercase() {
                'A'
            } else {
                's'
            }
        })
        .collect()
}

/// summarize_event renders a one-line description for the live feed, so the
/// dashboard does not have to duplicate payload knowledge.
pub fn summarize_event(e: &Event) -> String {
    match &e.payload {
        Payload::SessionStart(s) => format!("{} session from {}", s.protocol.as_str(), s.peer.src_ip),
        Payload::SessionEnd(s) => format!("session ended ({})", s.reason),
        Payload::Auth(a) => {
            let verdict = if a.success { "accepted" } else { "rejected" };
            format!("{} {}:{}", verdict, a.username, shape(&a.password))
        }
        Payload::Command(c) => format!("$ {}", c.raw),
        Payload::Artifact(a) => format!("payload referenced: {}", a.url),
        Payload::Upload(u) => format!("upload {} ({} bytes)", u.claimed_name, u.size_bytes),
        Payload::HttpRequest(h) => format!("{} {} -> {}", h.method, h.path, h.response_status),
        Payload::RdpConnect(r) => format!("rdp cookie {}", r.cookie),
        Payload::Canary(c) => format!("CANARY {} ({})", c.token_id, c.planted_path),
        Payload::Heartbeat(h) => format!("heartbeat, spool {}", h.spool_depth),
        Payload::Anomaly(a) => format!("anomaly: {}", a.kind),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_shapes_hide_the_password() {
        assert_eq!(credential_shape("root:xc3511"), "root:aadddd");
        assert_eq!(credential_shape("admin:"), "admin:(empty)");
        assert!(!credential_shape("root:hunter2").contains("hunter2"));
    }

    #[test]
    fn distinct_passwords_collapse_to_one_shape() {
        // This is what makes the published pattern non-identifying.
        assert_eq!(credential_shape("root:vizxv"), credential_shape("root:admin"));
    }

    #[test]
    fn extracts_hosts_from_payload_urls() {
        assert_eq!(host_of("http://1.2.3.4/bins.sh").as_deref(), Some("1.2.3.4"));
        assert_eq!(host_of("https://evil.test:8443/x").as_deref(), Some("evil.test"));
        assert_eq!(host_of("ldap://198.51.100.7:1389/a").as_deref(), Some("198.51.100.7"));
        assert_eq!(host_of("not a url"), None);
    }
}
