"""Threat intelligence generation: IOCs and STIX 2.1 bundles.

Publish boundary (design doc section 9): the generated feed carries credential
*patterns and statistics*, never raw harvested pairs. Real users occasionally
typo a real password into a fake SSH prompt, and republishing the corpus
verbatim would leak it. Raw pairs stay in the database, behind access control,
and are emitted only when an operator explicitly asks.
"""

from __future__ import annotations

import hashlib
import re
import uuid
from collections import Counter
from datetime import datetime, timezone
from typing import Sequence

from .attack import map_cluster
from .cluster import ClusteringResult
from .corpus import Session

STIX_VERSION = "2.1"

#: Deterministic namespace for STIX identifiers, so re-running the pipeline
#: over the same corpus produces the same IDs rather than a fresh set of
#: duplicates in the consumer's TAXII store.
NAMESPACE = uuid.UUID("6ba7b812-9dad-11d1-80b4-00c04fd430c8")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _id(kind: str, seed: str) -> str:
    return f"{kind}--{uuid.uuid5(NAMESPACE, f'{kind}:{seed}')}"


def _is_ip(value: str) -> bool:
    parts = value.split(".")
    if len(parts) != 4:
        return False
    return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


# ---------------------------------------------------------------- IOCs ----


def extract_iocs(sessions: Sequence[Session]) -> dict:
    """Pulls indicators out of a session corpus.

    Source addresses are reported with the behaviour that justified them.
    An IP that only ever sprayed credentials is a weaker indicator than one
    that dropped a payload, and a consumer needs that distinction to set
    their own thresholds.
    """
    src_behaviour: dict[str, Counter] = {}
    payload_urls: Counter[str] = Counter()
    payload_hosts: Counter[str] = Counter()
    file_hashes: Counter[str] = Counter()
    hasshes: Counter[str] = Counter()
    banners: Counter[str] = Counter()
    usernames: Counter[str] = Counter()
    password_shapes: Counter[str] = Counter()
    password_hashes: Counter[str] = Counter()

    for s in sessions:
        if s.src_ip:
            b = src_behaviour.setdefault(s.src_ip, Counter())
            b["sessions"] += 1
            b["commands"] += s.command_count
            b["credentials"] += len(s.credentials)
            b["payloads"] += len(s.artifacts)

        for a in s.artifacts:
            if a.url:
                payload_urls[a.url] += 1
            if a.host:
                payload_hosts[a.host] += 1

        for u in s.uploads:
            if h := u.get("sha256"):
                file_hashes[h] += 1

        if s.hassh:
            hasshes[s.hassh] += 1
        if s.client_banner:
            banners[s.client_banner] += 1

        for c in s.credentials:
            if c.username:
                usernames[c.username] += 1
            if c.password:
                password_shapes[_password_shape(c.password)] += 1
                # A salted-free SHA-256 of the password lets a consumer test
                # whether a credential they hold appears in the corpus without
                # the feed disclosing the corpus itself.
                password_hashes[hashlib.sha256(c.password.encode()).hexdigest()] += 1

    return {
        "source_ips": [
            {
                "value": ip,
                "sessions": b["sessions"],
                "commands": b["commands"],
                "credential_attempts": b["credentials"],
                "payload_drops": b["payloads"],
                "confidence": _ip_confidence(b),
            }
            for ip, b in sorted(src_behaviour.items(), key=lambda kv: -kv[1]["sessions"])
        ],
        "payload_urls": [{"value": u, "count": n} for u, n in payload_urls.most_common()],
        "payload_hosts": [
            {"value": h, "count": n, "type": "ipv4-addr" if _is_ip(h) else "domain-name"}
            for h, n in payload_hosts.most_common()
        ],
        "file_hashes": [{"sha256": h, "count": n} for h, n in file_hashes.most_common()],
        "client_fingerprints": [
            {"hassh": h, "count": n} for h, n in hasshes.most_common()
        ],
        "client_banners": [{"value": b, "count": n} for b, n in banners.most_common()],
        "credential_patterns": {
            "usernames": [{"value": u, "count": n} for u, n in usernames.most_common(50)],
            "password_shapes": [
                {"pattern": p, "count": n} for p, n in password_shapes.most_common(20)
            ],
            "password_sha256": [
                {"sha256": h, "count": n} for h, n in password_hashes.most_common(200)
            ],
        },
    }


def _password_shape(password: str) -> str:
    """Reduces a password to a character-class skeleton.

    ``xc3511`` becomes ``aaddd``. This publishes the structural signature of a
    wordlist -- enough for a defender to recognise the same list arriving at
    their own sensors -- without publishing the credential.
    """
    shape = []
    for ch in password[:24]:
        if ch.isdigit():
            shape.append("d")
        elif ch.isalpha():
            shape.append("a" if ch.islower() else "A")
        else:
            shape.append("s")
    return "".join(shape) or "(empty)"


def _ip_confidence(behaviour: Counter) -> str:
    """Grades an address by what it actually did.

    Dropping a payload is unambiguous. Executing commands after authenticating
    is strong. Credential spraying alone is common enough -- and spoofable
    enough via shared NAT and compromised hosts -- to warrant caution.
    """
    if behaviour["payloads"] > 0:
        return "high"
    if behaviour["commands"] > 3:
        return "medium"
    return "low"


# ---------------------------------------------------------------- STIX ----


def build_intel(
    sessions: Sequence[Session],
    clustering: ClusteringResult,
    redact_credentials: bool = True,
) -> dict:
    """Builds a STIX 2.1 bundle from a clustered corpus."""
    iocs = extract_iocs(sessions)
    now = _now()
    objects: list[dict] = []

    identity_id = _id("identity", "honeynet-sensor-fleet")
    objects.append(
        {
            "type": "identity",
            "spec_version": STIX_VERSION,
            "id": identity_id,
            "created": now,
            "modified": now,
            "name": "Honeynet Sensor Fleet",
            "identity_class": "system",
            "description": "Automated deception platform. Observations are of "
            "unauthorised access attempts against sensor infrastructure.",
        }
    )

    # --- indicators ---

    for entry in iocs["source_ips"]:
        if entry["confidence"] == "low":
            # Spray-only addresses are excluded from the published feed. They
            # are overwhelmingly shared infrastructure and compromised hosts,
            # and publishing them produces false positives for consumers.
            continue
        objects.append(
            _indicator(
                seed=f"ip:{entry['value']}",
                name=f"Honeypot interaction from {entry['value']}",
                pattern=f"[ipv4-addr:value = '{entry['value']}']",
                created=now,
                labels=["malicious-activity"],
                confidence=85 if entry["confidence"] == "high" else 60,
                description=(
                    f"Observed in {entry['sessions']} honeypot session(s): "
                    f"{entry['commands']} commands, {entry['payload_drops']} payload reference(s)."
                ),
            )
        )

    for entry in iocs["payload_urls"]:
        objects.append(
            _indicator(
                seed=f"url:{entry['value']}",
                name="Malware distribution URL",
                pattern=f"[url:value = '{_escape(entry['value'])}']",
                created=now,
                labels=["malicious-activity"],
                confidence=90,
                description=(
                    f"Requested by {entry['count']} honeypot session(s). "
                    "The sensor recorded the URL and did not retrieve it."
                ),
            )
        )

    for entry in iocs["payload_hosts"]:
        prop = "ipv4-addr:value" if entry["type"] == "ipv4-addr" else "domain-name:value"
        objects.append(
            _indicator(
                seed=f"host:{entry['value']}",
                name=f"Payload host {entry['value']}",
                pattern=f"[{prop} = '{_escape(entry['value'])}']",
                created=now,
                labels=["malicious-activity"],
                confidence=90,
                description=f"Hosts payloads referenced in {entry['count']} session(s).",
            )
        )

    for entry in iocs["file_hashes"]:
        objects.append(
            _indicator(
                seed=f"hash:{entry['sha256']}",
                name="Uploaded artifact",
                pattern=f"[file:hashes.'SHA-256' = '{entry['sha256']}']",
                created=now,
                labels=["malicious-activity"],
                confidence=75,
                description=f"Written to a sensor in {entry['count']} session(s).",
            )
        )

    # --- intrusion sets, one per cluster ---

    for profile in clustering.profiles:
        members = [
            s for s, l in zip(sessions, clustering.labels) if l == profile.cluster_id
        ]
        attack = map_cluster(members)

        set_id = _id("intrusion-set", f"cluster-{profile.cluster_id}-{profile.label}")
        objects.append(
            {
                "type": "intrusion-set",
                "spec_version": STIX_VERSION,
                "id": set_id,
                "created": now,
                "modified": now,
                "created_by_ref": identity_id,
                "name": f"honeynet-cluster-{profile.cluster_id} ({profile.label})",
                "description": (
                    f"Behavioural cluster of {profile.size} honeypot session(s). "
                    f"{profile.automated_fraction:.0%} automated, "
                    f"mean {profile.mean_command_count:.1f} commands over "
                    f"{profile.mean_duration_s:.1f}s. "
                    "Grouped by observed behaviour; this is not an attribution claim."
                ),
                "goals": [profile.label],
                "resource_level": "individual",
                "primary_motivation": "unknown",
            }
        )

        for technique in attack["techniques"]:
            ap_id = _id("attack-pattern", technique["technique_id"])
            objects.append(
                {
                    "type": "attack-pattern",
                    "spec_version": STIX_VERSION,
                    "id": ap_id,
                    "created": now,
                    "modified": now,
                    "name": technique["technique"],
                    "description": technique["rationale"],
                    "external_references": [
                        {
                            "source_name": "mitre-attack",
                            "external_id": technique["technique_id"],
                            "url": "https://attack.mitre.org/techniques/"
                            + technique["technique_id"].replace(".", "/"),
                        }
                    ],
                    "kill_chain_phases": [
                        {
                            "kill_chain_name": "mitre-attack",
                            "phase_name": technique["tactic"],
                        }
                    ],
                }
            )
            objects.append(
                {
                    "type": "relationship",
                    "spec_version": STIX_VERSION,
                    "id": _id(
                        "relationship",
                        f"{set_id}-uses-{technique['technique_id']}",
                    ),
                    "created": now,
                    "modified": now,
                    "relationship_type": "uses",
                    "source_ref": set_id,
                    "target_ref": ap_id,
                    "description": f"Observed in {technique['prevalence']:.0%} of cluster sessions.",
                }
            )

    # --- credential intelligence ---
    #
    # Shapes and hashes only. A consumer can test their own credentials against
    # the hashes and recognise the wordlist from the shapes, and neither
    # discloses what was harvested.
    creds = iocs["credential_patterns"]
    note_content = [
        "Credential observations from honeypot sensors.",
        "",
        f"Distinct usernames: {len(creds['usernames'])}",
        f"Distinct password shapes: {len(creds['password_shapes'])}",
        "",
        "Top usernames: "
        + ", ".join(f"{u['value']} ({u['count']})" for u in creds["usernames"][:15]),
        "",
        "Top password shapes (a=lower, A=upper, d=digit, s=symbol): "
        + ", ".join(f"{p['pattern']} ({p['count']})" for p in creds["password_shapes"][:15]),
    ]
    if not redact_credentials:
        note_content.append("")
        note_content.append(
            "NOTE: this bundle was generated with --include-credentials. "
            "It is unsuitable for external distribution."
        )

    objects.append(
        {
            "type": "note",
            "spec_version": STIX_VERSION,
            "id": _id("note", "credential-patterns"),
            "created": now,
            "modified": now,
            "created_by_ref": identity_id,
            "abstract": "Harvested credential patterns",
            "content": "\n".join(note_content),
            "object_refs": [identity_id],
        }
    )

    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects,
    }


def _indicator(
    seed: str,
    name: str,
    pattern: str,
    created: str,
    labels: list[str],
    confidence: int,
    description: str,
) -> dict:
    return {
        "type": "indicator",
        "spec_version": STIX_VERSION,
        "id": _id("indicator", seed),
        "created": created,
        "modified": created,
        "name": name,
        "description": description,
        "indicator_types": labels,
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": created,
        "confidence": confidence,
    }


def _escape(value: str) -> str:
    """Escapes a value for embedding in a STIX pattern string literal."""
    return value.replace("\\", "\\\\").replace("'", "\\'")
