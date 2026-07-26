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

    /// Rows currently persisted.
    ///
    /// Not on the serving path -- /stats reads the in-memory index, because
    /// that is what the dashboard needs and it costs no query. This exists to
    /// verify durability: it is the only way to ask a sink what it actually
    /// wrote, which is what the Postgres tests below assert on.
    #[allow(dead_code)]
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

    /// Everything written, in arrival order. Inspection for tests; production
    /// reads go through the index.
    #[allow(dead_code)]
    pub fn events(&self) -> Vec<Event> {
        self.events.lock().expect("memory store poisoned").clone()
    }

    /// Returns every event belonging to one session, in arrival order.
    #[allow(dead_code)]
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
    ///
    /// Serialized with an advisory lock because CREATE TABLE IF NOT EXISTS is
    /// not concurrency-safe in Postgres. Two collectors starting against the
    /// same fresh database both see the table missing, both proceed, and the
    /// loser fails on the unique index over the composite type the table
    /// implicitly creates -- reported as a duplicate key on
    /// pg_type_typname_nsp_index, which reads like corruption rather than a
    /// race. Running two collectors is the normal way to deploy for
    /// availability, so this is reachable on any first rollout.
    pub async fn migrate(&self) -> Result<()> {
        // Arbitrary constant; only has to be the same in every collector.
        const MIGRATION_LOCK: i64 = 0x686F_6E65_796E_6574;

        let mut conn = self.pool.acquire().await?;

        sqlx::query("SELECT pg_advisory_lock($1)")
            .bind(MIGRATION_LOCK)
            .execute(&mut *conn)
            .await?;

        let applied = sqlx::raw_sql(include_str!("../migrations/0001_init.sql"))
            .execute(&mut *conn)
            .await;

        // Released even when the schema failed, or the next start would block
        // forever behind a lock nobody holds a reason for.
        let unlocked = sqlx::query("SELECT pg_advisory_unlock($1)")
            .bind(MIGRATION_LOCK)
            .execute(&mut *conn)
            .await;

        applied?;
        unlocked?;

        info!("schema applied");
        Ok(())
    }

    /// The underlying connection pool, for queries the Store trait does not
    /// express. Used by the integration tests to assert on schema-level
    /// behaviour such as session upserts and the replay conflict clause.
    #[allow(dead_code)]
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

    // ---- Postgres ----
    //
    // The archival sink was wired into main.rs and never executed: every
    // end-to-end run used the JSONL sink, so the only thing known about this
    // path was that it compiled. These tests run the real migration against a
    // real server and put events through it.
    //
    // Skipped when DATABASE_URL is unset so a local `cargo test` still works
    // without a database. CI always sets it, so the path cannot silently go
    // unexercised there -- which is exactly how it stayed unverified before.

    // These tests share one database and each starts by truncating it, so they
    // cannot run concurrently -- the default test harness runs them in
    // parallel and they wiped each other's rows, which showed up as counts
    // that were short rather than as an obvious collision. The guard is held
    // for the duration of each test.
    static PG_SERIAL: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();

    async fn pg() -> Option<(PostgresStore, tokio::sync::MutexGuard<'static, ()>)> {
        let url = std::env::var("DATABASE_URL").ok()?;

        let guard = PG_SERIAL
            .get_or_init(|| tokio::sync::Mutex::new(()))
            .lock()
            .await;

        let store = PostgresStore::connect(&url, 4)
            .await
            .expect("connect to DATABASE_URL");
        store.migrate().await.expect("apply migration");

        // Each test starts from a clean slate; the migration is idempotent but
        // rows from a previous test are not.
        sqlx::query("TRUNCATE events, sessions CASCADE")
            .execute(store.pool())
            .await
            .expect("truncate");
        Some((store, guard))
    }

    macro_rules! require_pg {
        () => {
            match pg().await {
                Some((s, guard)) => {
                    // Bound to the test body so the next test cannot truncate
                    // this one's rows mid-assertion.
                    let _serial = guard;
                    s
                }
                None => {
                    eprintln!("skipping: DATABASE_URL is not set");
                    return;
                }
            }
        };
    }

    #[tokio::test]
    async fn postgres_migration_is_idempotent() {
        let store = require_pg!();
        // Startup applies the schema every time, so a restart against an
        // existing database must not fail.
        store.migrate().await.expect("second migration");
        store.migrate().await.expect("third migration");
    }

    #[tokio::test]
    async fn postgres_round_trips_events() {
        let store = require_pg!();

        store.put_event(&event("node-a", 1, "S1")).await.unwrap();
        store.put_event(&event("node-a", 2, "S1")).await.unwrap();
        store.put_event(&event("node-a", 3, "S2")).await.unwrap();

        assert_eq!(store.count().await.unwrap(), 3);

        // The session aggregate must exist for every session referenced by an
        // event, which is what upsert_session is for.
        let sessions: i64 = sqlx::query_scalar("SELECT count(*) FROM sessions")
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(sessions, 2, "one session row per distinct session_id");
    }

    // Sensors replay their spool after a collector outage, so the same event
    // arrives more than once. The ON CONFLICT clause is what stops that from
    // double-counting, and nothing tested it.
    #[tokio::test]
    async fn postgres_replay_does_not_duplicate() {
        let store = require_pg!();

        let e = event("node-b", 7, "S9");
        for _ in 0..5 {
            store.put_event(&e).await.unwrap();
        }

        assert_eq!(
            store.count().await.unwrap(),
            1,
            "replaying one event five times must leave a single row"
        );
    }

    // Two sensors number their events independently, so seq collides across
    // nodes constantly. The primary key is (node_id, seq) for that reason.
    #[tokio::test]
    async fn postgres_separates_nodes_sharing_a_sequence_number() {
        let store = require_pg!();

        store.put_event(&event("node-x", 1, "SX")).await.unwrap();
        store.put_event(&event("node-y", 1, "SY")).await.unwrap();

        assert_eq!(
            store.count().await.unwrap(),
            2,
            "same seq from two nodes must be two rows, not an overwrite"
        );
    }

    // A child event can arrive before the session-start that describes it,
    // after a replay or a gap. The session row still has to exist.
    #[tokio::test]
    async fn postgres_tolerates_out_of_order_arrival() {
        let store = require_pg!();

        store
            .put_event(&event("node-c", 2, "S-late"))
            .await
            .unwrap();
        store
            .put_event(&event("node-c", 1, "S-late"))
            .await
            .unwrap();

        assert_eq!(store.count().await.unwrap(), 2);

        let sessions: i64 = sqlx::query_scalar("SELECT count(*) FROM sessions WHERE id = 'S-late'")
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(sessions, 1);
    }

    // Events with no session -- heartbeats and node-level anomalies -- must
    // persist without inventing a session row for them.
    #[tokio::test]
    async fn postgres_accepts_events_without_a_session() {
        let store = require_pg!();

        store.put_event(&event("node-d", 1, "")).await.unwrap();

        assert_eq!(store.count().await.unwrap(), 1);
        let sessions: i64 = sqlx::query_scalar("SELECT count(*) FROM sessions")
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(
            sessions, 0,
            "a session-less event must not create a session"
        );
    }

    // The tee is how production writes both sinks at once; if it dropped one
    // side the archive would silently diverge from the live feed.
    #[tokio::test]
    async fn postgres_tee_writes_both_sinks() {
        let store = require_pg!();

        let mem = MemoryStore::new();
        let tee = TeeStore::new(store, mem);

        tee.put_event(&event("node-t", 1, "ST")).await.unwrap();
        tee.put_event(&event("node-t", 2, "ST")).await.unwrap();

        assert_eq!(tee.count().await.unwrap(), 2);
    }
}
