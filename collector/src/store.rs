//! Persistence.
//!
//! Two implementations behind one trait: Postgres for deployment, in-memory for
//! tests. The trait exists so the ingest path can be exercised without a
//! database -- a collector whose only test requires live Postgres is a
//! collector whose ingest logic never gets tested.

use anyhow::Result;
use async_trait::async_trait;
use std::sync::Mutex;
use tracing::info;

use crate::model::{Event, Payload};

#[async_trait]
pub trait Store: Send + Sync + 'static {
    /// Persists one normalized event.
    async fn put_event(&self, event: &Event) -> Result<()>;

    /// Number of events held. Used by tests and the health endpoint.
    async fn count(&self) -> Result<u64>;
}

// ---- in-memory ----

#[derive(Default)]
pub struct MemoryStore {
    events: Mutex<Vec<Event>>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn events(&self) -> Vec<Event> {
        self.events.lock().expect("memory store poisoned").clone()
    }

    /// Returns every event belonging to one session, in arrival order.
    pub fn session(&self, session_id: &str) -> Vec<Event> {
        self.events
            .lock()
            .expect("memory store poisoned")
            .iter()
            .filter(|e| e.session_id == session_id)
            .cloned()
            .collect()
    }
}

#[async_trait]
impl Store for MemoryStore {
    async fn put_event(&self, event: &Event) -> Result<()> {
        self.events
            .lock()
            .expect("memory store poisoned")
            .push(event.clone());
        Ok(())
    }

    async fn count(&self) -> Result<u64> {
        Ok(self.events.lock().expect("memory store poisoned").len() as u64)
    }
}

// ---- jsonl ----

/// Append-only JSON-lines sink.
///
/// Exists for two reasons: it makes an end-to-end run verifiable without
/// standing up Postgres, and it is the corpus format the Python profiling
/// pipeline reads during development. One JSON object per line, so it streams
/// and survives truncation.
pub struct JsonlStore {
    file: Mutex<std::fs::File>,
    written: std::sync::atomic::AtomicU64,
}

impl JsonlStore {
    pub fn create(path: &std::path::Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        info!(path = %path.display(), "writing events as JSON lines");
        Ok(Self {
            file: Mutex::new(file),
            written: std::sync::atomic::AtomicU64::new(0),
        })
    }
}

#[async_trait]
impl Store for JsonlStore {
    async fn put_event(&self, event: &Event) -> Result<()> {
        use std::io::Write;
        let line = serde_json::to_string(event)?;
        let mut f = self.file.lock().expect("jsonl store poisoned");
        writeln!(f, "{line}")?;
        // Flushed per event on purpose: an E2E run that inspects the file
        // immediately after the last session must not race the buffer.
        f.flush()?;
        self.written
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    async fn count(&self) -> Result<u64> {
        Ok(self.written.load(std::sync::atomic::Ordering::Relaxed))
    }
}

// ---- tee ----

/// Writes to a primary store and a secondary one.
///
/// A secondary failure is logged and swallowed: losing the JSONL export must
/// never cost us the durable Postgres write, since the export is a development
/// convenience and the database is the record.
pub struct TeeStore<A: Store, B: Store> {
    primary: A,
    secondary: B,
}

impl<A: Store, B: Store> TeeStore<A, B> {
    pub fn new(primary: A, secondary: B) -> Self {
        Self { primary, secondary }
    }
}

#[async_trait]
impl<A: Store, B: Store> Store for TeeStore<A, B> {
    async fn put_event(&self, event: &Event) -> Result<()> {
        self.primary.put_event(event).await?;
        if let Err(e) = self.secondary.put_event(event).await {
            tracing::warn!(error = %e, "secondary store write failed");
        }
        Ok(())
    }

    async fn count(&self) -> Result<u64> {
        self.primary.count().await
    }
}

// ---- postgres ----

pub struct PostgresStore {
    pool: sqlx::PgPool,
}

impl PostgresStore {
    pub async fn connect(url: &str, max_connections: u32) -> Result<Self> {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(max_connections)
            .connect(url)
            .await?;
        Ok(Self { pool })
    }

    /// Applies the schema. Runs at startup so a fresh deployment needs no
    /// separate migration step.
    pub async fn migrate(&self) -> Result<()> {
        sqlx::raw_sql(include_str!("../migrations/0001_init.sql"))
            .execute(&self.pool)
            .await?;
        info!("schema applied");
        Ok(())
    }

    pub fn pool(&self) -> &sqlx::PgPool {
        &self.pool
    }
}

#[async_trait]
impl Store for PostgresStore {
    async fn put_event(&self, event: &Event) -> Result<()> {
        let body = serde_json::to_value(&event.payload)?;

        // Session-scoped rows get an upsert into `sessions` so the session
        // aggregate exists before any child row references it, regardless of
        // which event arrives first. Sensors publish in order, but a replay or
        // a gap can still deliver a command before its session start.
        if !event.session_id.is_empty() {
            upsert_session(&self.pool, event).await?;
        }

        sqlx::query(
            r#"
            INSERT INTO events (
                node_id, seq, session_id, event_type,
                ts_node, ts_collector, body
            ) VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (node_id, seq) DO NOTHING
            "#,
        )
        .bind(&event.node_id)
        .bind(event.seq as i64)
        .bind(nullable(&event.session_id))
        .bind(event.payload.kind())
        .bind(event.ts_node)
        .bind(event.ts_collector)
        .bind(&body)
        .execute(&self.pool)
        .await?;

        // Credentials are denormalized into their own table because the
        // credential corpus is queried on its own -- wordlist correlation,
        // reuse across actors -- and digging them out of JSONB for every
        // analysis would be needlessly slow.
        if let Payload::Auth(a) = &event.payload {
            sqlx::query(
                r#"
                INSERT INTO credentials (
                    node_id, session_id, ts_collector, method,
                    username, password, public_key_sha256, success, attempt_index
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                "#,
            )
            .bind(&event.node_id)
            .bind(nullable(&event.session_id))
            .bind(event.ts_collector)
            .bind(&a.method)
            .bind(&a.username)
            .bind(&a.password)
            .bind(&a.public_key_sha256)
            .bind(a.success)
            .bind(a.attempt_index as i32)
            .execute(&self.pool)
            .await?;
        }

        // Likewise for artifact references: these are the IOC feed's raw
        // material and get queried by host and hash constantly.
        if let Payload::Artifact(a) = &event.payload {
            sqlx::query(
                r#"
                INSERT INTO artifacts (
                    node_id, session_id, ts_collector,
                    url, scheme, host, port, path, via_tool, source_command
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                "#,
            )
            .bind(&event.node_id)
            .bind(nullable(&event.session_id))
            .bind(event.ts_collector)
            .bind(&a.url)
            .bind(&a.scheme)
            .bind(&a.host)
            .bind(a.port as i32)
            .bind(&a.path)
            .bind(&a.via_tool)
            .bind(&a.source_command)
            .execute(&self.pool)
            .await?;
        }

        Ok(())
    }

    async fn count(&self) -> Result<u64> {
        let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM events")
            .fetch_one(&self.pool)
            .await?;
        Ok(row.0 as u64)
    }
}

/// Creates or updates the session aggregate from whichever event arrived.
async fn upsert_session(pool: &sqlx::PgPool, event: &Event) -> Result<()> {
    match &event.payload {
        Payload::SessionStart(s) => {
            sqlx::query(
                r#"
                INSERT INTO sessions (
                    session_id, node_id, protocol, src_ip, src_port, dst_ip, dst_port,
                    client_banner, hassh, started_at
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                ON CONFLICT (session_id) DO UPDATE SET
                    protocol      = EXCLUDED.protocol,
                    src_ip        = EXCLUDED.src_ip,
                    src_port      = EXCLUDED.src_port,
                    dst_ip        = EXCLUDED.dst_ip,
                    dst_port      = EXCLUDED.dst_port,
                    client_banner = EXCLUDED.client_banner,
                    hassh         = EXCLUDED.hassh,
                    started_at    = EXCLUDED.started_at
                "#,
            )
            .bind(&event.session_id)
            .bind(&event.node_id)
            .bind(s.protocol.as_str())
            .bind(&s.peer.src_ip)
            .bind(s.peer.src_port as i32)
            .bind(&s.peer.dst_ip)
            .bind(s.peer.dst_port as i32)
            .bind(&s.client_banner)
            .bind(&s.hassh)
            .bind(event.ts_collector)
            .execute(pool)
            .await?;
        }
        Payload::SessionEnd(e) => {
            sqlx::query(
                r#"
                INSERT INTO sessions (
                    session_id, node_id, started_at, ended_at, end_reason,
                    duration_ms, command_count, auth_attempts, bytes_in, bytes_out
                ) VALUES ($1, $2, $3, $3, $4, $5, $6, $7, $8, $9)
                ON CONFLICT (session_id) DO UPDATE SET
                    ended_at      = EXCLUDED.ended_at,
                    end_reason    = EXCLUDED.end_reason,
                    duration_ms   = EXCLUDED.duration_ms,
                    command_count = EXCLUDED.command_count,
                    auth_attempts = EXCLUDED.auth_attempts,
                    bytes_in      = EXCLUDED.bytes_in,
                    bytes_out     = EXCLUDED.bytes_out
                "#,
            )
            .bind(&event.session_id)
            .bind(&event.node_id)
            .bind(event.ts_collector)
            .bind(&e.reason)
            .bind(e.duration_ms)
            .bind(e.command_count as i32)
            .bind(e.auth_attempts as i32)
            .bind(e.bytes_in as i64)
            .bind(e.bytes_out as i64)
            .execute(pool)
            .await?;
        }
        _ => {
            // Any other session-scoped event still guarantees the aggregate
            // row exists, so foreign keys hold when events arrive out of order.
            sqlx::query(
                r#"
                INSERT INTO sessions (session_id, node_id, started_at)
                VALUES ($1, $2, $3)
                ON CONFLICT (session_id) DO NOTHING
                "#,
            )
            .bind(&event.session_id)
            .bind(&event.node_id)
            .bind(event.ts_collector)
            .execute(pool)
            .await?;
        }
    }
    Ok(())
}

fn nullable(s: &str) -> Option<&str> {
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Anomaly, Payload};
    use chrono::Utc;

    fn event(node: &str, seq: u64, session: &str) -> Event {
        Event {
            node_id: node.into(),
            seq,
            session_id: session.into(),
            ts_node: Utc::now(),
            ts_collector: Utc::now(),
            payload: Payload::Anomaly(Anomaly {
                kind: "t".into(),
                detail: "d".into(),
                peer: None,
            }),
        }
    }

    #[tokio::test]
    async fn memory_store_round_trips() {
        let s = MemoryStore::new();
        s.put_event(&event("a", 1, "S1")).await.unwrap();
        s.put_event(&event("a", 2, "S1")).await.unwrap();
        s.put_event(&event("a", 3, "S2")).await.unwrap();

        assert_eq!(s.count().await.unwrap(), 3);
        assert_eq!(s.session("S1").len(), 2);
        assert_eq!(s.session("S2").len(), 1);
        assert_eq!(s.session("nope").len(), 0);
    }
}
