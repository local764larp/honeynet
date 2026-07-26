# honeynet

A distributed honeypot network with ML attacker profiling.

Internet-exposed sensors record unauthorised access attempts, stream them to a
central collector, and a profiling pipeline groups the resulting sessions into
attacker campaigns, maps their behaviour to MITRE ATT&CK, and publishes the
result as STIX 2.1 threat intelligence.

Design: [`docs/superpowers/specs/2026-07-25-honeynet-design.md`](docs/superpowers/specs/2026-07-25-honeynet-design.md)

## Layout

| Path | Language | What it is |
|---|---|---|
| `proto/` | Protobuf | The event schema. Single source of truth for all four languages. |
| `node/` | Go | The sensor: SSH, Telnet, HTTP and RDP honeypots, emulated shell, canary tokens, WAL spool, NATS publisher. |
| `collector/` | Rust | Ingest, validation, normalization, geo enrichment, read API, Postgres and JSONL sinks. |
| `ml/` | Python | Feature extraction, bot/human classification, HDBSCAN clustering, ATT&CK mapping, STIX output. |
| `dashboard/` | React | Operator console: live feed, origin map, session replay, attacker profiles, IOC feed. |
| `deploy/` | — | nftables egress containment, systemd unit, NATS per-node permissions, cert issuance. |
| `scripts/` | PowerShell | Build, end-to-end acceptance run, and a local demo. |

## Build

```bash
powershell -ExecutionPolicy Bypass -File scripts/build.ps1
```

Needs Go, Rust, Python 3.11+ with `uv`, and `buf`. No Docker.

## Run the acceptance test

```bash
powershell -ExecutionPolicy Bypass -File scripts/e2e.ps1 -KeepArtifacts
```

Stands up nats-server, the collector, and a sensor; drives them with six
simulated attacker families; then asserts the observations arrive as validated
structured events. Writes a corpus to `.e2e/events.jsonl`.

## Profile the corpus

```bash
ml/.venv/Scripts/python -m honeynet_ml.cli clusters .e2e/events.jsonl
```

Other subcommands: `sessions` (bot/human classification), `attack` (ATT&CK
mapping), `intel` (STIX 2.1 bundle), `report` (everything as JSON).

## Run the console

```bash
powershell -ExecutionPolicy Bypass -File scripts/demo.ps1
```

Brings the whole platform up with every protocol enabled, replays attacker
traffic, runs the profiling pipeline, and serves the operator console at
`http://127.0.0.1:8088`.

The console's signature view is **transcript replay**: sessions play back at the
attacker's original keystroke timing, because the sensor records the gap between
every key. A person hesitates, backspaces, pauses before `cat /etc/shadow`; a
loader emits the identical line in one frame. Watching that difference settles
the automation question in a way a confidence score does not.

Map coordinates in a local run are synthetic — every session originates from
127.0.0.1, which has no location — and are flagged as such through the API and
labelled in the UI. Supply a MaxMind GeoLite2 database via `--geoip-city` for
real locations; none is bundled, because the licence forbids redistribution and
a stale copy is worse than none.

## Containment

The sensor is designed on the assumption that it will eventually be
compromised. Four invariants, all enforced rather than documented:

**No execution path.** The shell is an emulator over an in-memory filesystem.
`os/exec` and the process-spawning syscalls are absent from the sensor tree,
and `go test ./internal/containment` fails the build if one appears.

**No fetching of attacker URLs.** A `wget http://…` is recorded as an artifact
reference and answered with a plausible transcript. Retrieval is a separate,
operator-initiated action on different infrastructure. Fetching on the sensor
is how honeypot operators become malware distributors.

**Default-deny egress.** `deploy/provision/nftables.conf`. A sensor reaches its
collector and a pinned resolver. The forward chain drops everything, so the
box cannot be used as a relay.

**Per-node isolation.** NATS account permissions restrict each sensor to
publish-only on its own subject with no subscribe rights, and the collector
rejects any envelope whose self-reported `node_id` disagrees with the
authenticated certificate CN.

## Publish boundary

Harvested credentials are stored verbatim — their exact bytes are what link a
session to a specific wordlist. The generated intelligence feed carries
credential *shapes* and salted-free hashes instead, because real users
occasionally typo real passwords into a fake prompt. `--include-credentials`
overrides this for internal use and marks the bundle unsuitable for
distribution.

## Scope

This platform observes attacks against infrastructure you own. It does not
scan, attack, retaliate, or relay. Before exposing sensors, check your
provider's acceptable use policy and your obligations around storing
third-party credentials and source addresses.
