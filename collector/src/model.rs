//! Canonical event model.
//!
//! Everything downstream of the normalizer works with these types rather than
//! with protobuf messages. The separation matters because the wire schema is
//! shaped by what a sensor can cheaply emit, while these types are shaped by
//! what analysis needs -- and because protobuf's all-fields-optional semantics
//! would otherwise leak `Option` handling into every consumer.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A validated, normalized observation from a sensor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    /// Sensor identity, already verified against the authenticated connection.
    pub node_id: String,
    /// Per-node monotonic sequence number.
    pub seq: u64,
    /// Session grouping key (ULID). Empty for node-level events.
    pub session_id: String,
    /// Sensor-reported time. Advisory only -- node clocks are attacker-adjacent.
    pub ts_node: DateTime<Utc>,
    /// Collector receive time. Authoritative for cross-node ordering.
    pub ts_collector: DateTime<Utc>,
    pub payload: Payload,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Payload {
    SessionStart(SessionStart),
    SessionEnd(SessionEnd),
    Auth(AuthAttempt),
    Command(Command),
    Artifact(ArtifactRef),
    Upload(Upload),
    HttpRequest(HttpRequest),
    RdpConnect(RdpConnect),
    Canary(CanaryTrigger),
    Heartbeat(Heartbeat),
    Anomaly(Anomaly),
}

impl Payload {
    /// Short discriminator used for metrics and for the events table's type
    /// column.
    pub fn kind(&self) -> &'static str {
        match self {
            Payload::SessionStart(_) => "session_start",
            Payload::SessionEnd(_) => "session_end",
            Payload::Auth(_) => "auth",
            Payload::Command(_) => "command",
            Payload::Artifact(_) => "artifact",
            Payload::Upload(_) => "upload",
            Payload::HttpRequest(_) => "http_request",
            Payload::RdpConnect(_) => "rdp_connect",
            Payload::Canary(_) => "canary",
            Payload::Heartbeat(_) => "heartbeat",
            Payload::Anomaly(_) => "anomaly",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Ssh,
    Telnet,
    Http,
    Https,
    Rdp,
    Canary,
    Unknown,
}

impl Protocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            Protocol::Ssh => "ssh",
            Protocol::Telnet => "telnet",
            Protocol::Http => "http",
            Protocol::Https => "https",
            Protocol::Rdp => "rdp",
            Protocol::Canary => "canary",
            Protocol::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Peer {
    pub src_ip: String,
    pub src_port: u32,
    pub dst_ip: String,
    pub dst_port: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionStart {
    pub protocol: Protocol,
    pub peer: Peer,
    pub client_banner: String,
    /// Client SSH fingerprint. Survives banner spoofing, so it is the primary
    /// tool-family link between sessions.
    pub hassh: String,
    pub kex_algorithms: Vec<String>,
    pub ciphers: Vec<String>,
    pub macs: Vec<String>,
    pub compression: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionEnd {
    pub reason: String,
    pub duration_ms: i64,
    pub command_count: u32,
    pub auth_attempts: u32,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub pcap_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthAttempt {
    pub method: String,
    pub username: String,
    /// Stored verbatim. Redaction is a publish-boundary concern, not a storage
    /// one -- the exact bytes are what link a session to a specific wordlist.
    pub password: String,
    pub public_key_sha256: Option<String>,
    pub public_key_type: Option<String>,
    pub success: bool,
    pub attempt_index: u32,
    pub since_previous_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Command {
    pub raw: String,
    pub argv: Vec<String>,
    pub parse_failed: bool,
    pub cwd: String,
    pub since_session_start_ms: i64,
    pub since_previous_ms: i64,
    pub keystroke_deltas_ms: Vec<u32>,
    pub bulk_input: bool,
    pub command_index: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactRef {
    pub url: String,
    pub scheme: String,
    pub host: String,
    pub port: u32,
    pub path: String,
    pub via_tool: String,
    pub source_command: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Upload {
    pub sha256: String,
    pub size_bytes: u64,
    pub claimed_name: String,
    pub transport: String,
    pub detected_type: String,
    #[serde(with = "hex_bytes")]
    pub magic_prefix: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub query: String,
    pub version: String,
    pub headers: Vec<(String, String)>,
    pub body_sha256: String,
    pub body_size: u64,
    pub decoy_profile: String,
    pub response_status: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RdpConnect {
    pub cookie: String,
    pub domain: String,
    pub username: String,
    pub password: String,
    pub client_build: String,
    pub client_name: String,
    pub requested_protocols: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanaryTrigger {
    pub token_id: String,
    pub token_type: String,
    pub planted_path: String,
    pub callback_peer: Option<Peer>,
    pub user_agent: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Heartbeat {
    pub uptime_ms: i64,
    pub spool_depth: u64,
    /// Non-zero means the sensor's corpus has gaps. Surfaced prominently
    /// because an analyst reading a gap as a quiet period draws wrong
    /// conclusions about campaign timing.
    pub spool_dropped: u64,
    pub active_sessions: u32,
    pub build_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Anomaly {
    pub kind: String,
    pub detail: String,
    pub peer: Option<Peer>,
}

/// Hex encoding for byte fields, so JSON columns stay readable in psql.
mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        hex::decode(s).map_err(serde::de::Error::custom)
    }
}
