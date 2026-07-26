//! NATS ingest: subscribe, authenticate, decode, normalize, persist.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Context, Result};
use chrono::Utc;
use futures::StreamExt;
use prost::Message;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

use crate::model::Event;
use crate::normalize::{normalize, NormalizeError};
use crate::pb;
use crate::store::Store;

/// Subject prefix every sensor publishes beneath.
pub const SUBJECT_PREFIX: &str = "honeynet.events";

/// Wildcard the collector subscribes to.
pub fn subscribe_subject() -> String {
    format!("{SUBJECT_PREFIX}.>")
}

/// Extracts the sensor identity from a subject of the form
/// `honeynet.events.<node_id>[.…]`.
///
/// The subject is a trustworthy identity source in production because NATS
/// account permissions restrict each sensor to publishing beneath its own
/// `honeynet.events.<node_id>` prefix, and that restriction is enforced by the
/// server against the client certificate -- not by anything the sensor says
/// about itself. The normalizer then cross-checks the envelope's self-reported
/// `node_id` against this value, so a compromised sensor cannot attribute its
/// output to a peer.
pub fn node_from_subject(subject: &str) -> Option<&str> {
    let rest = subject.strip_prefix(SUBJECT_PREFIX)?.strip_prefix('.')?;
    let node = rest.split('.').next()?;
    if node.is_empty() {
        None
    } else {
        Some(node)
    }
}

/// Per-node sequence bookkeeping.
///
/// Sensors number their events monotonically from a counter persisted in the
/// local spool. Gaps mean events were lost; repeats mean a replay. Neither is
/// fatal -- the event is still stored -- but both are recorded, because an
/// analyst who mistakes a gap for a quiet period will misread campaign timing.
#[derive(Default)]
pub struct SeqTracker {
    last: HashMap<String, u64>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SeqStatus {
    /// Exactly the expected next value.
    InOrder,
    /// First event seen from this node in this collector's lifetime.
    FirstSeen,
    /// Events are missing.
    Gap {
        expected: u64,
        got: u64,
        missing: u64,
    },
    /// A sequence number we have already processed.
    Replay { last: u64, got: u64 },
}

impl SeqTracker {
    pub fn observe(&mut self, node_id: &str, seq: u64) -> SeqStatus {
        match self.last.get(node_id).copied() {
            None => {
                self.last.insert(node_id.to_string(), seq);
                SeqStatus::FirstSeen
            }
            Some(last) if seq == last + 1 => {
                self.last.insert(node_id.to_string(), seq);
                SeqStatus::InOrder
            }
            Some(last) if seq > last + 1 => {
                self.last.insert(node_id.to_string(), seq);
                SeqStatus::Gap {
                    expected: last + 1,
                    got: seq,
                    missing: seq - last - 1,
                }
            }
            Some(last) => SeqStatus::Replay { last, got: seq },
        }
    }
}

/// Counters exposed for operational visibility.
#[derive(Debug, Default, Clone)]
pub struct IngestStats {
    pub received: u64,
    pub stored: u64,
    pub rejected_identity: u64,
    pub rejected_decode: u64,
    pub rejected_other: u64,
    pub gaps: u64,
    pub replays: u64,
    pub missing_events: u64,
}

/// Observer notified of every successfully stored event.
///
/// Used to feed the live index and the dashboard's event stream. It runs after
/// the durable write, so a slow or panicking observer can never cost us the
/// record of an attack.
pub type Observer = Box<dyn Fn(&Event) + Send + Sync>;

pub struct Ingestor<S: Store> {
    store: Arc<S>,
    seq: Mutex<SeqTracker>,
    stats: Mutex<IngestStats>,
    observer: Option<Observer>,
}

impl<S: Store> Ingestor<S> {
    pub fn new(store: Arc<S>) -> Self {
        Self {
            store,
            seq: Mutex::new(SeqTracker::default()),
            stats: Mutex::new(IngestStats::default()),
            observer: None,
        }
    }

    /// Attaches an observer for stored events.
    pub fn with_observer(mut self, observer: Observer) -> Self {
        self.observer = Some(observer);
        self
    }

    pub async fn stats(&self) -> IngestStats {
        self.stats.lock().await.clone()
    }

    /// Processes one raw message. Returns the stored event, or `None` when the
    /// message was rejected.
    ///
    /// Rejection never propagates as an error: one malformed or hostile message
    /// must not stop the ingest loop, because stopping the loop is precisely
    /// what an attacker who has compromised a sensor would want.
    pub async fn handle(&self, subject: &str, payload: &[u8]) -> Option<Event> {
        {
            let mut s = self.stats.lock().await;
            s.received += 1;
        }

        let Some(authenticated) = node_from_subject(subject) else {
            warn!(subject, "message on unrecognised subject");
            self.stats.lock().await.rejected_other += 1;
            return None;
        };

        let envelope = match pb::Envelope::decode(payload) {
            Ok(e) => e,
            Err(e) => {
                warn!(subject, error = %e, "undecodable envelope");
                self.stats.lock().await.rejected_decode += 1;
                return None;
            }
        };

        let event = match normalize(envelope, authenticated, Utc::now()) {
            Ok(e) => e,
            Err(err) => {
                match &err {
                    NormalizeError::IdentityMismatch { claimed, .. } => {
                        // A sensor speaking for another node is a compromise
                        // indicator, not a bug. Log loudly.
                        error!(
                            subject,
                            authenticated, claimed, "sensor attempted identity spoofing"
                        );
                        self.stats.lock().await.rejected_identity += 1;
                    }
                    _ => {
                        warn!(subject, error = %err, "envelope rejected");
                        self.stats.lock().await.rejected_other += 1;
                    }
                }
                return None;
            }
        };

        match self.seq.lock().await.observe(&event.node_id, event.seq) {
            SeqStatus::InOrder | SeqStatus::FirstSeen => {}
            SeqStatus::Gap {
                expected,
                got,
                missing,
            } => {
                warn!(
                    node = %event.node_id,
                    expected, got, missing,
                    "sequence gap: sensor lost events"
                );
                let mut s = self.stats.lock().await;
                s.gaps += 1;
                s.missing_events += missing;
            }
            SeqStatus::Replay { last, got } => {
                warn!(node = %event.node_id, last, got, "replayed sequence number");
                self.stats.lock().await.replays += 1;
            }
        }

        if let Err(e) = self.store.put_event(&event).await {
            error!(node = %event.node_id, error = %e, "store write failed");
            self.stats.lock().await.rejected_other += 1;
            return None;
        }

        self.stats.lock().await.stored += 1;
        debug!(
            node = %event.node_id,
            seq = event.seq,
            kind = event.payload.kind(),
            "event stored"
        );

        if let Some(observe) = &self.observer {
            observe(&event);
        }
        Some(event)
    }

    /// Runs the subscription loop until cancelled.
    pub async fn run(&self, client: async_nats::Client) -> Result<()> {
        let subject = subscribe_subject();
        let mut sub = client
            .subscribe(subject.clone())
            .await
            .with_context(|| format!("subscribe to {subject}"))?;

        info!(subject = %subject, "ingest subscribed");

        while let Some(msg) = sub.next().await {
            self.handle(&msg.subject, &msg.payload).await;
        }

        info!("ingest subscription closed");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_node_from_subject() {
        assert_eq!(
            node_from_subject("honeynet.events.sensor-fra-01"),
            Some("sensor-fra-01")
        );
        assert_eq!(
            node_from_subject("honeynet.events.sensor-fra-01.ssh"),
            Some("sensor-fra-01")
        );
        assert_eq!(node_from_subject("honeynet.events."), None);
        assert_eq!(node_from_subject("honeynet.events"), None);
        assert_eq!(node_from_subject("something.else.node"), None);
    }

    #[test]
    fn tracks_sequence_continuity() {
        let mut t = SeqTracker::default();
        assert_eq!(t.observe("a", 1), SeqStatus::FirstSeen);
        assert_eq!(t.observe("a", 2), SeqStatus::InOrder);
        assert_eq!(
            t.observe("a", 7),
            SeqStatus::Gap {
                expected: 3,
                got: 7,
                missing: 4
            }
        );
        assert_eq!(t.observe("a", 8), SeqStatus::InOrder);
        assert_eq!(t.observe("a", 4), SeqStatus::Replay { last: 8, got: 4 });
    }

    #[test]
    fn tracks_nodes_independently() {
        let mut t = SeqTracker::default();
        assert_eq!(t.observe("a", 1), SeqStatus::FirstSeen);
        assert_eq!(t.observe("b", 1), SeqStatus::FirstSeen);
        assert_eq!(t.observe("a", 2), SeqStatus::InOrder);
        assert_eq!(t.observe("b", 2), SeqStatus::InOrder);
    }
}
