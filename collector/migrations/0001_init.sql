-- Honeynet collector schema.
--
-- Idempotent: applied on every collector start so a fresh deployment needs no
-- separate migration step.

CREATE TABLE IF NOT EXISTS sessions (
    session_id    TEXT PRIMARY KEY,
    node_id       TEXT NOT NULL,
    protocol      TEXT,
    src_ip        TEXT,
    src_port      INTEGER,
    dst_ip        TEXT,
    dst_port      INTEGER,
    client_banner TEXT,
    -- Client SSH fingerprint. Indexed because clustering joins on it
    -- constantly: it links sessions from one tool across rotating source IPs.
    hassh         TEXT,
    started_at    TIMESTAMPTZ NOT NULL,
    ended_at      TIMESTAMPTZ,
    end_reason    TEXT,
    duration_ms   BIGINT,
    command_count INTEGER,
    auth_attempts INTEGER,
    bytes_in      BIGINT,
    bytes_out     BIGINT,

    -- Enrichment, filled in by the enrichment stage after ingest.
    geo_country   TEXT,
    geo_city      TEXT,
    asn           INTEGER,
    as_org        TEXT,

    -- Populated by the ML pipeline. NULL until a clustering run has seen
    -- this session.
    cluster_id    INTEGER,
    is_human      BOOLEAN
);

CREATE INDEX IF NOT EXISTS sessions_node_started_idx ON sessions (node_id, started_at DESC);
CREATE INDEX IF NOT EXISTS sessions_src_ip_idx       ON sessions (src_ip);
CREATE INDEX IF NOT EXISTS sessions_hassh_idx        ON sessions (hassh) WHERE hassh IS NOT NULL;
CREATE INDEX IF NOT EXISTS sessions_cluster_idx      ON sessions (cluster_id) WHERE cluster_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS events (
    node_id      TEXT        NOT NULL,
    -- Per-node monotonic counter. The (node_id, seq) pair is the natural key
    -- and makes ingest idempotent under replay.
    seq          BIGINT      NOT NULL,
    session_id   TEXT,
    event_type   TEXT        NOT NULL,
    ts_node      TIMESTAMPTZ NOT NULL,
    ts_collector TIMESTAMPTZ NOT NULL,
    body         JSONB       NOT NULL,
    PRIMARY KEY (node_id, seq)
);

CREATE INDEX IF NOT EXISTS events_session_idx   ON events (session_id) WHERE session_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS events_collector_idx ON events (ts_collector DESC);
CREATE INDEX IF NOT EXISTS events_type_idx      ON events (event_type, ts_collector DESC);

CREATE TABLE IF NOT EXISTS credentials (
    id                BIGSERIAL PRIMARY KEY,
    node_id           TEXT        NOT NULL,
    session_id        TEXT,
    ts_collector      TIMESTAMPTZ NOT NULL,
    method            TEXT        NOT NULL,
    username          TEXT        NOT NULL,
    -- Stored verbatim on purpose: the exact bytes, typos included, are what
    -- link a session to a specific published wordlist. Redaction happens at
    -- the publish boundary, never at rest. Access to this table is restricted
    -- separately -- see design doc section 9.
    password          TEXT        NOT NULL,
    public_key_sha256 TEXT,
    success           BOOLEAN     NOT NULL,
    attempt_index     INTEGER     NOT NULL
);

CREATE INDEX IF NOT EXISTS credentials_pair_idx    ON credentials (username, password);
CREATE INDEX IF NOT EXISTS credentials_session_idx ON credentials (session_id) WHERE session_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS credentials_time_idx    ON credentials (ts_collector DESC);

CREATE TABLE IF NOT EXISTS artifacts (
    id             BIGSERIAL PRIMARY KEY,
    node_id        TEXT        NOT NULL,
    session_id     TEXT,
    ts_collector   TIMESTAMPTZ NOT NULL,
    url            TEXT        NOT NULL,
    scheme         TEXT,
    host           TEXT,
    port           INTEGER,
    path           TEXT,
    via_tool       TEXT,
    source_command TEXT,

    -- Set only after a sandboxed fetcher on separate infrastructure retrieves
    -- the sample. The sensor never fetches -- design doc section 4.2 -- so
    -- these stay NULL until an operator acts.
    fetched_at     TIMESTAMPTZ,
    sample_sha256  TEXT
);

CREATE INDEX IF NOT EXISTS artifacts_host_idx    ON artifacts (host);
CREATE INDEX IF NOT EXISTS artifacts_url_idx     ON artifacts (url);
CREATE INDEX IF NOT EXISTS artifacts_session_idx ON artifacts (session_id) WHERE session_id IS NOT NULL;

-- Node liveness and spool health. A non-zero spool_dropped means that sensor's
-- corpus has holes for that window.
CREATE TABLE IF NOT EXISTS node_health (
    node_id         TEXT        NOT NULL,
    ts_collector    TIMESTAMPTZ NOT NULL,
    uptime_ms       BIGINT,
    spool_depth     BIGINT,
    spool_dropped   BIGINT,
    active_sessions INTEGER,
    build_version   TEXT,
    PRIMARY KEY (node_id, ts_collector)
);
