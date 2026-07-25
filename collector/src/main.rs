//! Honeynet collector.
//!
//! Subscribes to the sensor fleet's NATS subjects, validates and normalizes
//! every envelope, and persists the result.
//!
//! Trust posture: sensors are internet-exposed and assumed compromisable, so
//! nothing they send is trusted. Identity is checked against the authenticated
//! subject, fields are length-bounded, and a rejected message never interrupts
//! the ingest loop.

use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

mod api;
mod geo;
mod index;
mod ingest;
mod model;
mod normalize;
mod pb;
mod store;

use geo::GeoProvider;
use index::LiveIndex;
use ingest::Ingestor;
use store::{JsonlStore, MemoryStore, PostgresStore, Store, TeeStore};

#[derive(Parser, Debug)]
#[command(name = "honeynet-collector", version, about)]
struct Args {
    /// NATS server URL.
    #[arg(long, env = "COLLECTOR_NATS_URL", default_value = "nats://127.0.0.1:4222")]
    nats_url: String,

    /// Postgres connection string. Omit to run with an in-memory store, which
    /// is useful for smoke-testing a sensor without standing up a database.
    #[arg(long, env = "COLLECTOR_DATABASE_URL")]
    database_url: Option<String>,

    #[arg(long, env = "COLLECTOR_DB_MAX_CONNECTIONS", default_value_t = 16)]
    db_max_connections: u32,

    /// Client certificate for mutual TLS to NATS.
    #[arg(long, env = "COLLECTOR_TLS_CERT")]
    tls_cert: Option<String>,

    #[arg(long, env = "COLLECTOR_TLS_KEY")]
    tls_key: Option<String>,

    #[arg(long, env = "COLLECTOR_TLS_CA")]
    tls_ca: Option<String>,

    /// Write every normalized event to this file as JSON lines. Usable with or
    /// without Postgres; this is the corpus format the profiling pipeline reads.
    #[arg(long, env = "COLLECTOR_EVENTS_JSONL")]
    events_jsonl: Option<std::path::PathBuf>,

    /// Seconds between ingest statistics reports.
    #[arg(long, env = "COLLECTOR_STATS_INTERVAL", default_value_t = 60)]
    stats_interval: u64,

    /// Address for the operator API. Bind to loopback and reverse-proxy it;
    /// the API is read-only but it is not an internet-facing surface.
    #[arg(long, env = "COLLECTOR_API_ADDR")]
    api_addr: Option<std::net::SocketAddr>,

    /// Directory of built dashboard assets to serve alongside the API.
    #[arg(long, env = "COLLECTOR_DASHBOARD_DIR")]
    dashboard_dir: Option<std::path::PathBuf>,

    /// Report written by `honeynet-ml report --out`, polled by GET /api/profile
    /// to attach cluster assignments to sessions.
    #[arg(long, env = "COLLECTOR_PROFILE_PATH")]
    profile_path: Option<std::path::PathBuf>,

    /// MaxMind GeoLite2 City database. Operator-supplied; none is bundled.
    #[arg(long, env = "COLLECTOR_GEOIP_CITY")]
    geoip_city: Option<std::path::PathBuf>,

    #[arg(long, env = "COLLECTOR_GEOIP_ASN")]
    geoip_asn: Option<std::path::PathBuf>,

    /// Fabricate coordinates for local development.
    ///
    /// The end-to-end harness drives every session from 127.0.0.1, which leaves
    /// the attack map empty and untestable. Results are flagged `synthetic` all
    /// the way through the API so they cannot be mistaken for attribution.
    #[arg(long, env = "COLLECTOR_GEOIP_SYNTHETIC", default_value_t = false)]
    geoip_synthetic: bool,

    #[arg(long, env = "COLLECTOR_LOG_FORMAT", default_value = "text")]
    log_format: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    init_tracing(&args.log_format);

    info!(
        nats = %args.nats_url,
        storage = if args.database_url.is_some() { "postgres" } else { "memory" },
        "collector starting"
    );

    match (args.database_url.clone(), args.events_jsonl.clone()) {
        (Some(url), jsonl) => {
            let pg = PostgresStore::connect(&url, args.db_max_connections)
                .await
                .context("connect to postgres")?;
            pg.migrate().await.context("apply schema")?;
            match jsonl {
                Some(path) => {
                    let j = JsonlStore::create(&path).context("open jsonl sink")?;
                    run(args, Arc::new(TeeStore::new(pg, j))).await
                }
                None => run(args, Arc::new(pg)).await,
            }
        }
        (None, Some(path)) => {
            let store = JsonlStore::create(&path).context("open jsonl sink")?;
            run(args, Arc::new(store)).await
        }
        (None, None) => {
            warn!("no database_url or events_jsonl set; events will be held in memory and lost on exit");
            run(args, Arc::new(MemoryStore::new())).await
        }
    }
}

async fn run<S: Store>(args: Args, store: Arc<S>) -> Result<()> {
    let client = connect_nats(&args).await?;

    let geo = if args.geoip_synthetic {
        warn!("synthetic geo-IP enabled: map coordinates are fabricated and flagged as such");
        GeoProvider::Synthetic
    } else {
        GeoProvider::maxmind(args.geoip_city.as_deref(), args.geoip_asn.as_deref())
    };
    info!(provider = geo.describe(), "geo enrichment");

    let live = Arc::new(LiveIndex::new(geo));
    // Capacity bounds how far a slow dashboard may lag before it starts
    // missing events. Missing events on a live view is the right trade; the
    // durable store is the record.
    let (tx, _) = tokio::sync::broadcast::channel(1024);

    let ingestor = {
        let live = Arc::clone(&live);
        let tx = tx.clone();
        Arc::new(Ingestor::new(store).with_observer(Box::new(move |event| {
            live.ingest(event);
            let _ = tx.send(event.clone());
        })))
    };

    let api_task = match args.api_addr {
        Some(addr) => {
            let app = api::router(
                api::ApiState {
                    index: Arc::clone(&live),
                    events: tx.clone(),
                    profile_path: args.profile_path.clone(),
                },
                args.dashboard_dir.clone(),
            );
            Some(tokio::spawn(async move {
                if let Err(e) = api::serve(addr, app).await {
                    error!(error = %e, "operator api stopped");
                }
            }))
        }
        None => None,
    };

    let stats_task = {
        let ingestor = Arc::clone(&ingestor);
        let interval = args.stats_interval.max(1);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(interval));
            tick.tick().await; // the first tick fires immediately
            loop {
                tick.tick().await;
                let s = ingestor.stats().await;
                info!(
                    received = s.received,
                    stored = s.stored,
                    gaps = s.gaps,
                    missing_events = s.missing_events,
                    replays = s.replays,
                    rejected_identity = s.rejected_identity,
                    rejected_decode = s.rejected_decode,
                    rejected_other = s.rejected_other,
                    "ingest stats"
                );
                if s.rejected_identity > 0 {
                    warn!(
                        count = s.rejected_identity,
                        "sensors attempted identity spoofing; investigate the fleet"
                    );
                }
            }
        })
    };

    let ingest_task = {
        let ingestor = Arc::clone(&ingestor);
        let client = client.clone();
        tokio::spawn(async move {
            if let Err(e) = ingestor.run(client).await {
                error!(error = %e, "ingest loop failed");
            }
        })
    };

    tokio::select! {
        _ = tokio::signal::ctrl_c() => info!("shutdown signal received"),
        _ = ingest_task => warn!("ingest task exited"),
    }

    stats_task.abort();
    if let Some(t) = api_task {
        t.abort();
    }

    let s = ingestor.stats().await;
    info!(received = s.received, stored = s.stored, "collector stopped");
    Ok(())
}

async fn connect_nats(args: &Args) -> Result<async_nats::Client> {
    let mut opts = async_nats::ConnectOptions::new().name("honeynet-collector");

    // Mutual TLS is how the collector learns which sensor it is talking to.
    // It is optional only so the local harness can run against a plain
    // nats-server; a production deployment must set all three.
    if let (Some(cert), Some(key)) = (&args.tls_cert, &args.tls_key) {
        opts = opts.add_client_certificate(cert.into(), key.into());
    }
    if let Some(ca) = &args.tls_ca {
        opts = opts.add_root_certificates(ca.into());
    }

    let client = opts
        .connect(&args.nats_url)
        .await
        .with_context(|| format!("connect to {}", args.nats_url))?;

    info!(url = %args.nats_url, "connected to message bus");
    Ok(client)
}

fn init_tracing(format: &str) {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,sqlx=warn"));

    if format == "json" {
        tracing_subscriber::fmt()
            .json()
            .with_env_filter(filter)
            .init();
    } else {
        tracing_subscriber::fmt().with_env_filter(filter).init();
    }
}
