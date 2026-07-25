"""MITRE ATT&CK technique mapping.

Deterministic rules, not a classifier.

A learned ATT&CK mapper is a research project: the label space is large, the
training data does not exist in any quantity, and the failure mode is confident
wrongness that an analyst cannot audit. Curated regex rules are transparent,
correctable in one line, and wrong in ways that are visible. Where a rule does
not fire, nothing is claimed -- silence is preferable to a fabricated technique
in a threat intelligence product.

Technique IDs follow ATT&CK for Enterprise.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from typing import Iterable, Sequence

from .corpus import Session


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    tactic: str


@dataclass(frozen=True)
class Rule:
    technique: Technique
    pattern: re.Pattern[str]
    #: Why this pattern implies the technique. Surfaced in the dashboard so an
    #: analyst can judge the inference rather than take it on trust.
    rationale: str


def _t(tid: str, name: str, tactic: str) -> Technique:
    return Technique(id=tid, name=name, tactic=tactic)


RULES: list[Rule] = [
    Rule(
        _t("T1110.001", "Brute Force: Password Guessing", "credential-access"),
        re.compile(r"^\x00$"),  # matched structurally, not textually
        "Multiple failed credential attempts before a successful login.",
    ),
    Rule(
        _t("T1059.004", "Command and Scripting Interpreter: Unix Shell", "execution"),
        re.compile(r"\b(sh|bash|dash|/bin/sh|/bin/bash)\b\s+(-c|\S+\.sh)"),
        "Shell invoked with an explicit command string or script argument.",
    ),
    Rule(
        _t("T1105", "Ingress Tool Transfer", "command-and-control"),
        re.compile(r"\b(wget|curl|tftp|ftpget|scp)\b.*\b(https?|ftp|tftp)://|\b(wget|tftp)\b\s+\S+"),
        "Remote payload retrieval requested from attacker-controlled infrastructure.",
    ),
    Rule(
        _t("T1222.002", "File and Directory Permissions Modification: Linux", "defense-evasion"),
        re.compile(r"\bchmod\s+(\+x|[0-7]{3,4})\b"),
        "Execute permission granted to a file, typically a freshly dropped payload.",
    ),
    Rule(
        _t("T1082", "System Information Discovery", "discovery"),
        re.compile(r"\b(uname|lscpu|nproc|cat\s+/proc/(cpuinfo|meminfo|version)|"
                   r"free\b|df\b|hostnamectl|lsb_release|cat\s+/etc/os-release)"),
        "Host hardware and operating system enumerated.",
    ),
    Rule(
        _t("T1033", "System Owner/User Discovery", "discovery"),
        re.compile(r"\b(whoami|id\b|groups\b|w\b|who\b|users\b|logname)"),
        "Current user identity and privilege level checked.",
    ),
    Rule(
        _t("T1087.001", "Account Discovery: Local Account", "discovery"),
        re.compile(r"cat\s+/etc/passwd|getent\s+passwd|\bcut\s+-d:\s*-f1"),
        "Local account list enumerated.",
    ),
    Rule(
        _t("T1057", "Process Discovery", "discovery"),
        re.compile(r"\b(ps\s+(aux|-ef|ax)|pgrep|top\b|htop\b)"),
        "Running process list enumerated.",
    ),
    Rule(
        _t("T1049", "System Network Connections Discovery", "discovery"),
        re.compile(r"\b(netstat|ss\s+-|lsof\s+-i)\b"),
        "Active network connections and listening services enumerated.",
    ),
    Rule(
        _t("T1016", "System Network Configuration Discovery", "discovery"),
        re.compile(r"\b(ifconfig|ip\s+a(ddr)?\b|ip\s+r(oute)?\b|route\s+-n|arp\s+-a)"),
        "Network interface and routing configuration read.",
    ),
    Rule(
        _t("T1003.008", "OS Credential Dumping: /etc/passwd and /etc/shadow", "credential-access"),
        re.compile(r"cat\s+/etc/shadow|cp\s+/etc/shadow|unshadow"),
        "Shadow password file accessed.",
    ),
    Rule(
        _t("T1552.004", "Unsecured Credentials: Private Keys", "credential-access"),
        re.compile(r"(id_rsa|id_ed25519|id_dsa|\.ssh/[^\s]*key|\.pem\b)"),
        "SSH private key material read from disk.",
    ),
    Rule(
        _t("T1098.004", "Account Manipulation: SSH Authorized Keys", "persistence"),
        re.compile(r"authorized_keys"),
        "Attacker key appended to an account's authorized_keys.",
    ),
    Rule(
        _t("T1053.003", "Scheduled Task/Job: Cron", "persistence"),
        re.compile(r"\bcrontab\b|/etc/cron|/var/spool/cron"),
        "Cron used to schedule recurring execution.",
    ),
    Rule(
        _t("T1543.002", "Create or Modify System Process: Systemd Service", "persistence"),
        re.compile(r"systemctl\s+(enable|start)|/etc/systemd/system|\.service\b"),
        "Systemd unit created or enabled for persistence.",
    ),
    Rule(
        _t("T1070.003", "Indicator Removal: Clear Command History", "defense-evasion"),
        re.compile(r"history\s+-c|unset\s+HISTFILE|export\s+HISTFILE=|rm\s+.*\.bash_history"),
        "Shell history cleared or disabled to frustrate investigation.",
    ),
    Rule(
        _t("T1070.004", "Indicator Removal: File Deletion", "defense-evasion"),
        re.compile(r"\brm\s+-[rf]{1,2}\b|\bshred\b|\bwipe\b"),
        "Files deleted, commonly the dropped payload after execution.",
    ),
    Rule(
        _t("T1496", "Resource Hijacking", "impact"),
        re.compile(r"\b(xmrig|minerd|cpuminer|stratum\+tcp|cryptonight|nicehash|"
                   r"pool\.min|monero)\b"),
        "Cryptocurrency mining software or pool endpoint referenced.",
    ),
    Rule(
        _t("T1027", "Obfuscated Files or Information", "defense-evasion"),
        re.compile(r"echo\s+-n?e?\s*['\"]?(\\x[0-9a-fA-F]{2}){4,}|base64\s+-d|"
                   r"\bxxd\s+-r\b|openssl\s+enc\s+-d"),
        "Payload delivered encoded or hex-escaped rather than as plain bytes.",
    ),
    Rule(
        _t("T1562.004", "Impair Defenses: Disable or Modify System Firewall", "defense-evasion"),
        re.compile(r"iptables\s+-F|ufw\s+disable|systemctl\s+stop\s+(firewalld|ufw)|"
                   r"setenforce\s+0"),
        "Host firewall or mandatory access control disabled.",
    ),
    Rule(
        _t("T1489", "Service Stop", "impact"),
        re.compile(r"\b(killall|pkill)\b|systemctl\s+stop\b|service\s+\S+\s+stop"),
        "Running services terminated, often to displace competing malware.",
    ),
    Rule(
        _t("T1036.005", "Masquerading: Match Legitimate Name or Location", "defense-evasion"),
        re.compile(r"-O\s+/tmp/\.\w|/tmp/\.[a-z]{1,3}\b|mv\s+\S+\s+/usr/(s)?bin/"),
        "Payload written to a hidden or system-looking path to blend in.",
    ),
    Rule(
        _t("T1018", "Remote System Discovery", "discovery"),
        re.compile(r"cat\s+.*known_hosts|\barp\s+-a\b|\bping\s+-c\b.*\d+\.\d+\.\d+\.\d+"),
        "Other reachable hosts enumerated, typically for lateral movement.",
    ),
]

#: Rules matched from session structure rather than command text.
STRUCTURAL_TECHNIQUES = {
    "brute_force": _t("T1110.001", "Brute Force: Password Guessing", "credential-access"),
    "valid_accounts": _t("T1078", "Valid Accounts", "initial-access"),
}


@dataclass
class TechniqueHit:
    technique: Technique
    evidence: list[str]
    rationale: str

    def as_dict(self) -> dict:
        return {
            "technique_id": self.technique.id,
            "technique": self.technique.name,
            "tactic": self.technique.tactic,
            "rationale": self.rationale,
            # Capped: a loader that runs the same command forty times should
            # not produce forty identical evidence lines in the report.
            "evidence": self.evidence[:5],
        }


def map_session(session: Session) -> list[TechniqueHit]:
    """Maps one session's observed behaviour to ATT&CK techniques."""
    hits: dict[str, TechniqueHit] = {}

    for cmd in session.commands:
        for rule in RULES:
            if rule.pattern.pattern == r"^\x00$":
                continue  # structural rule, handled below
            if rule.pattern.search(cmd.raw):
                hit = hits.get(rule.technique.id)
                if hit is None:
                    hits[rule.technique.id] = TechniqueHit(
                        technique=rule.technique,
                        evidence=[cmd.raw],
                        rationale=rule.rationale,
                    )
                elif cmd.raw not in hit.evidence:
                    hit.evidence.append(cmd.raw)

    # An artifact reference is ingress tool transfer whether or not the command
    # text matched -- the URL extraction is the stronger evidence.
    if session.artifacts:
        tech = _t("T1105", "Ingress Tool Transfer", "command-and-control")
        hits[tech.id] = TechniqueHit(
            technique=tech,
            evidence=[a.url for a in session.artifacts],
            rationale="Remote payload retrieval requested from attacker-controlled infrastructure.",
        )

    # Structural: repeated failures followed by success is a password guess.
    failures = [c for c in session.credentials if not c.success]
    if len(failures) >= 2:
        tech = STRUCTURAL_TECHNIQUES["brute_force"]
        hits[tech.id] = TechniqueHit(
            technique=tech,
            evidence=[f"{c.username}:{c.password}" for c in failures[:5]],
            rationale=f"{len(failures)} failed credential attempts against this host.",
        )

    if (used := session.successful_credential) is not None:
        tech = STRUCTURAL_TECHNIQUES["valid_accounts"]
        hits[tech.id] = TechniqueHit(
            technique=tech,
            evidence=[f"{used.username}:{used.password}"],
            rationale="Session authenticated with a credential the host accepted.",
        )

    return sorted(hits.values(), key=lambda h: (h.technique.tactic, h.technique.id))


def map_cluster(sessions: Sequence[Session]) -> dict:
    """Aggregates technique coverage across a cluster's member sessions.

    ``prevalence`` is the fraction of members exhibiting the technique. A
    technique present in every session characterises the group; one present in
    a tenth of them is incidental, and the distinction matters when the profile
    is published as intelligence.
    """
    if not sessions:
        return {"techniques": [], "tactics": []}

    counter: Counter[str] = Counter()
    detail: dict[str, TechniqueHit] = {}

    for s in sessions:
        for hit in map_session(s):
            counter[hit.technique.id] += 1
            detail.setdefault(hit.technique.id, hit)

    total = len(sessions)
    techniques = [
        {
            **detail[tid].as_dict(),
            "sessions": count,
            "prevalence": round(count / total, 3),
        }
        for tid, count in counter.most_common()
    ]

    tactics = sorted({t["tactic"] for t in techniques})
    return {"techniques": techniques, "tactics": tactics}


def kill_chain_order(techniques: Iterable[dict]) -> list[dict]:
    """Sorts techniques into rough kill-chain order for display."""
    order = {
        "initial-access": 0,
        "execution": 1,
        "persistence": 2,
        "privilege-escalation": 3,
        "defense-evasion": 4,
        "credential-access": 5,
        "discovery": 6,
        "lateral-movement": 7,
        "collection": 8,
        "command-and-control": 9,
        "exfiltration": 10,
        "impact": 11,
    }
    return sorted(techniques, key=lambda t: (order.get(t.get("tactic", ""), 99), t.get("technique_id", "")))
