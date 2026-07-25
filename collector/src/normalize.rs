//! Converts untrusted wire envelopes into validated canonical events.
//!
//! This module is the trust boundary. Everything arriving here originated on an
//! internet-exposed sensor that the design assumes will eventually be
//! compromised, so nothing is taken on faith: identity is checked against the
//! authenticated connection, every string is length-bounded, and structurally
//! impossible values are rejected rather than clamped silently.

use chrono::{DateTime, TimeZone, Utc};
use thiserror::Error;

use crate::model::*;
use crate::pb;

/// Bounds on attacker-influenced strings.
///
/// A sensor under an attacker's control could otherwise emit a gigabyte
/// username and turn one forged event into a storage incident. The limits are
/// generous enough that no legitimate observation is truncated: real passwords
/// from credential sprays are tens of bytes, and the longest genuine command
/// lines seen in loader chains are a few kilobytes.
pub const MAX_SHORT: usize = 512;
pub const MAX_COMMAND: usize = 64 * 1024;
pub const MAX_LIST_ITEMS: usize = 128;
pub const MAX_KEYSTROKES: usize = 8192;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum NormalizeError {
    #[error("envelope has no node_id")]
    MissingNodeId,

    /// The self-reported node identity disagrees with the authenticated one.
    /// Treated as hostile rather than as a misconfiguration: a node may only
    /// speak for itself.
    #[error("node_id {claimed:?} does not match authenticated identity {authenticated:?}")]
    IdentityMismatch {
        claimed: String,
        authenticated: String,
    },

    #[error("envelope has no sequence number")]
    MissingSeq,

    #[error("envelope carries no event body")]
    EmptyEvent,

    #[error("unsupported schema version {0}")]
    UnsupportedSchema(u32),

    #[error("session_id {0:?} is not a valid ULID")]
    BadSessionId(String),
}

/// Highest schema version this collector understands.
pub const MAX_SCHEMA_VERSION: u32 = 1;

/// Normalizes one envelope.
///
/// `authenticated_node` is the identity the transport established (the client
/// certificate CN). The envelope's self-reported `node_id` must match it.
pub fn normalize(
    env: pb::Envelope,
    authenticated_node: &str,
    received_at: DateTime<Utc>,
) -> Result<Event, NormalizeError> {
    if env.node_id.is_empty() {
        return Err(NormalizeError::MissingNodeId);
    }
    if env.node_id != authenticated_node {
        return Err(NormalizeError::IdentityMismatch {
            claimed: env.node_id,
            authenticated: authenticated_node.to_string(),
        });
    }
    if env.seq == 0 {
        return Err(NormalizeError::MissingSeq);
    }
    if env.schema_version > MAX_SCHEMA_VERSION {
        return Err(NormalizeError::UnsupportedSchema(env.schema_version));
    }
    if !env.session_id.is_empty() && !is_ulid(&env.session_id) {
        return Err(NormalizeError::BadSessionId(truncate(
            &env.session_id,
            MAX_SHORT,
        )));
    }

    let body = env.event.ok_or(NormalizeError::EmptyEvent)?;
    let payload = normalize_payload(body);

    Ok(Event {
        node_id: env.node_id,
        seq: env.seq,
        session_id: env.session_id,
        ts_node: env.ts_node.map(timestamp).unwrap_or(received_at),
        ts_collector: received_at,
        payload,
    })
}

fn normalize_payload(body: pb::envelope::Event) -> Payload {
    use pb::envelope::Event as E;
    match body {
        E::SessionStart(v) => Payload::SessionStart(SessionStart {
            protocol: protocol(v.protocol),
            peer: peer(v.peer),
            client_banner: truncate(&v.client_banner, MAX_SHORT),
            hassh: truncate(&v.hassh, MAX_SHORT),
            kex_algorithms: string_list(v.kex_algorithms),
            ciphers: string_list(v.ciphers),
            macs: string_list(v.macs),
            compression: string_list(v.compression_algorithms),
        }),

        E::SessionEnd(v) => Payload::SessionEnd(SessionEnd {
            reason: end_reason(v.reason),
            duration_ms: duration_ms(v.duration),
            command_count: v.command_count,
            auth_attempts: v.auth_attempts,
            bytes_in: v.bytes_in,
            bytes_out: v.bytes_out,
            pcap_sha256: non_empty(truncate(&v.pcap_sha256, MAX_SHORT)),
        }),

        E::AuthAttempt(v) => Payload::Auth(AuthAttempt {
            method: auth_method(v.method),
            username: truncate(&v.username, MAX_SHORT),
            password: truncate(&v.password, MAX_SHORT),
            public_key_sha256: non_empty(truncate(&v.public_key_sha256, MAX_SHORT)),
            public_key_type: non_empty(truncate(&v.public_key_type, MAX_SHORT)),
            success: v.success,
            attempt_index: v.attempt_index,
            since_previous_ms: duration_ms(v.since_previous),
        }),

        E::CommandInput(v) => Payload::Command(Command {
            raw: truncate(&v.raw, MAX_COMMAND),
            argv: v
                .argv
                .into_iter()
                .take(MAX_LIST_ITEMS)
                .map(|s| truncate(&s, MAX_SHORT))
                .collect(),
            parse_failed: v.parse_failed,
            cwd: truncate(&v.cwd, MAX_SHORT),
            since_session_start_ms: duration_ms(v.since_session_start),
            since_previous_ms: duration_ms(v.since_previous),
            keystroke_deltas_ms: {
                let mut k = v.keystroke_deltas_ms;
                k.truncate(MAX_KEYSTROKES);
                k
            },
            bulk_input: v.bulk_input,
            command_index: v.command_index,
        }),

        E::ArtifactReference(v) => Payload::Artifact(ArtifactRef {
            url: truncate(&v.url, MAX_SHORT * 4),
            scheme: truncate(&v.scheme, 16),
            host: truncate(&v.host, MAX_SHORT),
            port: v.port,
            path: truncate(&v.path, MAX_SHORT * 2),
            via_tool: truncate(&v.via_tool, MAX_SHORT),
            source_command: truncate(&v.source_command, MAX_COMMAND),
        }),

        E::FileUpload(v) => Payload::Upload(Upload {
            sha256: truncate(&v.sha256, 64),
            size_bytes: v.size_bytes,
            claimed_name: truncate(&v.claimed_name, MAX_SHORT),
            transport: truncate(&v.transport, 32),
            detected_type: truncate(&v.detected_type, MAX_SHORT),
            magic_prefix: {
                let mut p = v.magic_prefix;
                p.truncate(64);
                p
            },
        }),

        E::HttpRequest(v) => Payload::HttpRequest(HttpRequest {
            method: truncate(&v.method, 16),
            path: truncate(&v.path, MAX_SHORT * 4),
            query: truncate(&v.query, MAX_SHORT * 4),
            version: truncate(&v.version, 16),
            headers: v
                .headers
                .into_iter()
                .take(MAX_LIST_ITEMS)
                .map(|(k, val)| (truncate(&k, MAX_SHORT), truncate(&val, MAX_SHORT * 2)))
                .collect(),
            body_sha256: truncate(&v.body_sha256, 64),
            body_size: v.body_size,
            decoy_profile: truncate(&v.decoy_profile, MAX_SHORT),
            response_status: v.response_status,
        }),

        E::RdpConnect(v) => Payload::RdpConnect(RdpConnect {
            cookie: truncate(&v.cookie, MAX_SHORT),
            domain: truncate(&v.domain, MAX_SHORT),
            username: truncate(&v.username, MAX_SHORT),
            password: truncate(&v.password, MAX_SHORT),
            client_build: truncate(&v.client_build, MAX_SHORT),
            client_name: truncate(&v.client_name, MAX_SHORT),
            requested_protocols: string_list(v.requested_protocols),
        }),

        E::CanaryTrigger(v) => Payload::Canary(CanaryTrigger {
            token_id: truncate(&v.token_id, MAX_SHORT),
            token_type: truncate(&v.token_type, MAX_SHORT),
            planted_path: truncate(&v.planted_path, MAX_SHORT * 2),
            callback_peer: v.callback_peer.map(|p| peer(Some(p))),
            user_agent: truncate(&v.user_agent, MAX_SHORT * 2),
        }),

        E::NodeHeartbeat(v) => Payload::Heartbeat(Heartbeat {
            uptime_ms: duration_ms(v.uptime),
            spool_depth: v.spool_depth,
            spool_dropped: v.spool_dropped,
            active_sessions: v.active_sessions,
            build_version: truncate(&v.build_version, MAX_SHORT),
        }),

        E::NodeAnomaly(v) => Payload::Anomaly(Anomaly {
            kind: truncate(&v.kind, MAX_SHORT),
            detail: truncate(&v.detail, MAX_SHORT * 4),
            peer: v.peer.map(|p| peer(Some(p))),
        }),
    }
}

// ---- field helpers ----

/// Truncates on a character boundary. Byte-slicing a multi-byte sequence would
/// panic, and a hostile node can trivially arrange for one to straddle the
/// limit.
fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

fn non_empty(s: String) -> Option<String> {
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

fn string_list(v: Vec<String>) -> Vec<String> {
    v.into_iter()
        .take(MAX_LIST_ITEMS)
        .map(|s| truncate(&s, MAX_SHORT))
        .collect()
}

fn peer(p: Option<pb::Peer>) -> Peer {
    let p = p.unwrap_or_default();
    Peer {
        src_ip: truncate(&p.src_ip, 45), // longest possible IPv6 textual form
        src_port: p.src_port.min(65535),
        dst_ip: truncate(&p.dst_ip, 45),
        dst_port: p.dst_port.min(65535),
    }
}

fn protocol(v: i32) -> Protocol {
    match pb::Protocol::try_from(v) {
        Ok(pb::Protocol::Ssh) => Protocol::Ssh,
        Ok(pb::Protocol::Telnet) => Protocol::Telnet,
        Ok(pb::Protocol::Http) => Protocol::Http,
        Ok(pb::Protocol::Https) => Protocol::Https,
        Ok(pb::Protocol::Rdp) => Protocol::Rdp,
        Ok(pb::Protocol::Canary) => Protocol::Canary,
        _ => Protocol::Unknown,
    }
}

fn auth_method(v: i32) -> String {
    match pb::AuthMethod::try_from(v) {
        Ok(pb::AuthMethod::Password) => "password",
        Ok(pb::AuthMethod::Publickey) => "publickey",
        Ok(pb::AuthMethod::Keyboard) => "keyboard-interactive",
        Ok(pb::AuthMethod::None) => "none",
        _ => "unspecified",
    }
    .to_string()
}

fn end_reason(v: i32) -> String {
    match pb::SessionEndReason::try_from(v) {
        Ok(pb::SessionEndReason::ClientClosed) => "client_closed",
        Ok(pb::SessionEndReason::Timeout) => "timeout",
        Ok(pb::SessionEndReason::LimitExceeded) => "limit_exceeded",
        Ok(pb::SessionEndReason::NodeShutdown) => "node_shutdown",
        Ok(pb::SessionEndReason::ProtocolError) => "protocol_error",
        _ => "unspecified",
    }
    .to_string()
}

fn duration_ms(d: Option<prost_types::Duration>) -> i64 {
    d.map(|d| d.seconds.saturating_mul(1000) + i64::from(d.nanos) / 1_000_000)
        .unwrap_or(0)
}

fn timestamp(ts: prost_types::Timestamp) -> DateTime<Utc> {
    Utc.timestamp_opt(ts.seconds, ts.nanos.clamp(0, 999_999_999) as u32)
        .single()
        .unwrap_or_else(Utc::now)
}

/// Validates the ULID shape: 26 characters of Crockford base32.
///
/// Checked rather than trusted because the session ID becomes a database key
/// and appears in dashboard URLs.
fn is_ulid(s: &str) -> bool {
    const ALPHABET: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    s.len() == 26
        && s.bytes()
            .all(|b| ALPHABET.contains(&b.to_ascii_uppercase()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope() -> pb::Envelope {
        pb::Envelope {
            node_id: "node-a".into(),
            seq: 1,
            session_id: "01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
            schema_version: 1,
            ts_node: None,
            event: Some(pb::envelope::Event::NodeAnomaly(pb::NodeAnomaly {
                kind: "test".into(),
                detail: "detail".into(),
                peer: None,
            })),
        }
    }

    #[test]
    fn accepts_a_well_formed_envelope() {
        let ev = normalize(envelope(), "node-a", Utc::now()).expect("should normalize");
        assert_eq!(ev.node_id, "node-a");
        assert_eq!(ev.seq, 1);
        assert_eq!(ev.payload.kind(), "anomaly");
    }

    #[test]
    fn rejects_identity_spoofing() {
        // A compromised sensor must not be able to attribute its output to a
        // different node in the fleet.
        let err = normalize(envelope(), "node-b", Utc::now()).unwrap_err();
        assert_eq!(
            err,
            NormalizeError::IdentityMismatch {
                claimed: "node-a".into(),
                authenticated: "node-b".into()
            }
        );
    }

    #[test]
    fn rejects_zero_sequence() {
        let mut e = envelope();
        e.seq = 0;
        assert_eq!(
            normalize(e, "node-a", Utc::now()).unwrap_err(),
            NormalizeError::MissingSeq
        );
    }

    #[test]
    fn rejects_malformed_session_id() {
        let mut e = envelope();
        e.session_id = "not-a-ulid".into();
        assert!(matches!(
            normalize(e, "node-a", Utc::now()).unwrap_err(),
            NormalizeError::BadSessionId(_)
        ));
    }

    #[test]
    fn rejects_future_schema_versions() {
        let mut e = envelope();
        e.schema_version = MAX_SCHEMA_VERSION + 1;
        assert!(matches!(
            normalize(e, "node-a", Utc::now()).unwrap_err(),
            NormalizeError::UnsupportedSchema(_)
        ));
    }

    #[test]
    fn rejects_empty_event_body() {
        let mut e = envelope();
        e.event = None;
        assert_eq!(
            normalize(e, "node-a", Utc::now()).unwrap_err(),
            NormalizeError::EmptyEvent
        );
    }

    #[test]
    fn bounds_hostile_field_lengths() {
        let mut e = envelope();
        e.event = Some(pb::envelope::Event::AuthAttempt(pb::AuthAttempt {
            method: pb::AuthMethod::Password as i32,
            username: "u".repeat(10_000),
            password: "p".repeat(10_000),
            success: false,
            ..Default::default()
        }));

        let ev = normalize(e, "node-a", Utc::now()).expect("should normalize");
        let Payload::Auth(a) = ev.payload else {
            panic!("expected auth payload")
        };
        assert_eq!(a.username.len(), MAX_SHORT);
        assert_eq!(a.password.len(), MAX_SHORT);
    }

    #[test]
    fn truncation_never_splits_a_utf8_sequence() {
        // A hostile node can place a multi-byte character exactly across the
        // limit; byte-slicing there would panic and take down the ingest task.
        let mut e = envelope();
        let mut name = "a".repeat(MAX_SHORT - 1);
        name.push('\u{1F600}'); // 4 bytes, straddles the boundary
        e.event = Some(pb::envelope::Event::AuthAttempt(pb::AuthAttempt {
            username: name,
            ..Default::default()
        }));

        let ev = normalize(e, "node-a", Utc::now()).expect("should normalize");
        let Payload::Auth(a) = ev.payload else {
            panic!("expected auth payload")
        };
        assert_eq!(a.username.len(), MAX_SHORT - 1);
    }

    #[test]
    fn caps_keystroke_timing_arrays() {
        let mut e = envelope();
        e.event = Some(pb::envelope::Event::CommandInput(pb::CommandInput {
            raw: "id".into(),
            keystroke_deltas_ms: vec![5; MAX_KEYSTROKES * 4],
            ..Default::default()
        }));

        let ev = normalize(e, "node-a", Utc::now()).expect("should normalize");
        let Payload::Command(c) = ev.payload else {
            panic!("expected command payload")
        };
        assert_eq!(c.keystroke_deltas_ms.len(), MAX_KEYSTROKES);
    }

    #[test]
    fn ulid_validation() {
        assert!(is_ulid("01ARZ3NDEKTSV4RRFFQ69G5FAV"));
        assert!(!is_ulid(""));
        assert!(!is_ulid("01ARZ3NDEKTSV4RRFFQ69G5FA")); // 25 chars
        assert!(!is_ulid("01ARZ3NDEKTSV4RRFFQ69G5FA!")); // bad char
    }
}
