"""Feature extraction.

Three families, deliberately kept separable so that a weak one can be dropped
without rebuilding the pipeline:

* **Behavioural scalars** -- timing, volume, and shape of the session.
* **Lexical** -- TF-IDF over command text, which captures the actual payload
  and tooling vocabulary.
* **Fingerprint** -- HASSH and banner, which identify the client library.

The scalars are the load-bearing ones for separating automation from humans;
the lexical features are what separate one malware family from another.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, asdict
from typing import Sequence

import numpy as np

from .corpus import Session

#: Tools whose presence is characteristic of a family or stage. Counted
#: individually rather than left to TF-IDF because the signal is strong and
#: a sparse n-gram representation dilutes it.
TOOL_VOCABULARY = [
    "wget", "curl", "tftp", "ftpget", "busybox", "chmod", "rm", "cat",
    "echo", "nc", "python", "perl", "sh", "bash", "crontab", "systemctl",
    "uname", "whoami", "id", "ps", "netstat", "ifconfig", "free", "nproc",
    "history", "passwd", "useradd", "ssh", "scp", "iptables", "kill",
]

#: Well-known credential lists. Jaccard overlap against these identifies which
#: published wordlist an actor is spraying, which is a strong campaign link.
KNOWN_WORDLISTS: dict[str, set[str]] = {
    "mirai_default": {
        "xc3511", "vizxv", "admin", "888888", "juantech", "123456", "54321",
        "anko", "zlxx.", "system", "ikwb", "dreambox", "user", "realtek",
        "root", "1234", "12345", "pass", "meinsm", "7ujMko0admin",
    },
    "top10_common": {
        "123456", "password", "12345678", "qwerty", "123456789", "12345",
        "1234", "111111", "1234567", "dragon",
    },
    "vendor_default": {
        "admin", "root", "toor", "ubnt", "supervisor", "service", "support",
        "guest", "default", "changeme", "smcadmin",
    },
}


@dataclass
class BehaviouralFeatures:
    """Scalar features describing how a session behaved.

    Field names are stable: they become column headers in the profile export
    and are referenced by the dashboard.
    """

    # --- volume ---
    command_count: float
    auth_attempt_count: float
    artifact_count: float
    upload_count: float
    duration_s: float
    unique_tools: float

    # --- inter-command timing ---
    # A scripted loader issues commands at a near-constant rate; a human does
    # not. The coefficient of variation captures that better than the mean,
    # because it is invariant to how fast the operator happens to be.
    gap_mean_ms: float
    gap_std_ms: float
    gap_cv: float
    gap_min_ms: float
    gap_max_ms: float

    # --- keystroke timing ---
    # Only populated for PTY sessions. Empty for exec-mode automation, which is
    # itself the signal, captured by keystroke_coverage.
    keystroke_mean_ms: float
    keystroke_std_ms: float
    keystroke_cv: float
    keystroke_coverage: float

    # --- input shape ---
    bulk_ratio: float
    mean_command_length: float
    max_command_length: float
    parse_failure_ratio: float

    # --- credential behaviour ---
    auth_gap_mean_ms: float
    auth_gap_cv: float
    distinct_usernames: float
    distinct_passwords: float
    auth_success_index: float

    # --- reconnaissance vs action ---
    recon_ratio: float
    destructive_ratio: float
    persistence_ratio: float

    def to_array(self) -> np.ndarray:
        return np.array(list(asdict(self).values()), dtype=np.float64)

    @staticmethod
    def names() -> list[str]:
        return list(BehaviouralFeatures.__dataclass_fields__.keys())


#: Commands that gather information without changing anything.
RECON_PATTERNS = re.compile(
    r"\b(uname|whoami|id|cat\s+/proc|cat\s+/etc/(passwd|shadow|os-release)|"
    r"nproc|lscpu|free|df|ps\b|netstat|ss\b|ifconfig|ip\s+a|w\b|who\b|last\b|"
    r"lsb_release|hostname|env\b|history)\b"
)

#: Commands that destroy data or cover tracks.
DESTRUCTIVE_PATTERNS = re.compile(
    r"\b(rm\s+-[rf]|rm\s+-rf|shred|wipe|>\s*/var/log|history\s+-c|"
    r"unset\s+HISTFILE|kill(all)?\b|pkill)\b"
)

#: Commands that establish a foothold that survives reboot.
PERSISTENCE_PATTERNS = re.compile(
    r"(crontab|/etc/cron|systemctl\s+enable|authorized_keys|/etc/rc\.local|"
    r"\.bashrc|/etc/init\.d|nohup|systemd)"
)


def _stats(values: Sequence[float]) -> tuple[float, float, float, float, float]:
    """Returns (mean, std, coefficient of variation, min, max).

    The coefficient of variation is the discriminating quantity: it measures
    regularity independently of speed, so a fast human and a slow script are
    still told apart.
    """
    if not values:
        return 0.0, 0.0, 0.0, 0.0, 0.0
    arr = np.asarray(values, dtype=np.float64)
    mean = float(arr.mean())
    std = float(arr.std())
    cv = std / mean if mean > 0 else 0.0
    return mean, std, cv, float(arr.min()), float(arr.max())


def extract_behavioural(session: Session) -> BehaviouralFeatures:
    """Computes the scalar feature vector for one session."""
    cmds = session.commands

    # Inter-command gaps, skipping the first command whose "since previous"
    # is really "since session start" and reflects handshake latency rather
    # than operator behaviour.
    gaps = [c.since_previous_ms for c in cmds[1:]] if len(cmds) > 1 else []
    g_mean, g_std, g_cv, g_min, g_max = _stats(gaps)

    # Keystroke deltas, excluding the first of each command: that gap measures
    # thinking time before typing started, not typing rhythm.
    keystrokes: list[int] = []
    typed_commands = 0
    for c in cmds:
        if len(c.keystroke_deltas_ms) > 1:
            keystrokes.extend(c.keystroke_deltas_ms[1:])
            typed_commands += 1
    k_mean, k_std, k_cv, _, _ = _stats(keystrokes)

    auth_gaps = [c.since_previous_ms for c in session.credentials[1:]]
    a_mean, _, a_cv, _, _ = _stats(auth_gaps)

    text = session.command_text().lower()
    n_cmds = max(len(cmds), 1)

    lengths = [len(c.raw) for c in cmds] or [0]

    success_index = -1.0
    for c in session.credentials:
        if c.success:
            success_index = float(c.attempt_index)
            break

    return BehaviouralFeatures(
        command_count=float(len(cmds)),
        auth_attempt_count=float(len(session.credentials)),
        artifact_count=float(len(session.artifacts)),
        upload_count=float(len(session.uploads)),
        duration_s=session.duration_ms / 1000.0,
        unique_tools=float(len(set(session.tools))),
        gap_mean_ms=g_mean,
        gap_std_ms=g_std,
        gap_cv=g_cv,
        gap_min_ms=g_min,
        gap_max_ms=g_max,
        keystroke_mean_ms=k_mean,
        keystroke_std_ms=k_std,
        keystroke_cv=k_cv,
        keystroke_coverage=typed_commands / n_cmds,
        bulk_ratio=sum(1 for c in cmds if c.bulk_input) / n_cmds,
        mean_command_length=float(np.mean(lengths)),
        max_command_length=float(max(lengths)),
        parse_failure_ratio=sum(1 for c in cmds if not c.argv) / n_cmds,
        auth_gap_mean_ms=a_mean,
        auth_gap_cv=a_cv,
        distinct_usernames=float(len({c.username for c in session.credentials})),
        distinct_passwords=float(len({c.password for c in session.credentials})),
        auth_success_index=success_index,
        recon_ratio=len(RECON_PATTERNS.findall(text)) / n_cmds,
        destructive_ratio=len(DESTRUCTIVE_PATTERNS.findall(text)) / n_cmds,
        persistence_ratio=len(PERSISTENCE_PATTERNS.findall(text)) / n_cmds,
    )


def extract_tool_vector(session: Session) -> np.ndarray:
    """Binary presence vector over TOOL_VOCABULARY."""
    used = set(session.tools)
    # Tools also appear inside compound command lines the tokenizer attributes
    # to a wrapper such as `sh -c`, so scan the raw text as well.
    text = session.command_text().lower()
    return np.array(
        [1.0 if (t in used or re.search(rf"\b{re.escape(t)}\b", text)) else 0.0
         for t in TOOL_VOCABULARY],
        dtype=np.float64,
    )


def wordlist_affinity(session: Session) -> dict[str, float]:
    """Jaccard overlap between the session's passwords and known wordlists.

    Identifies which published list an actor is working from, which links
    campaigns that share no source address.
    """
    offered = {c.password for c in session.credentials if c.password}
    if not offered:
        return {name: 0.0 for name in KNOWN_WORDLISTS}
    return {
        name: len(offered & words) / len(offered | words)
        for name, words in KNOWN_WORDLISTS.items()
    }


def is_automated(features: BehaviouralFeatures) -> tuple[bool, float]:
    """Classifies a session as automated or interactive.

    A rule-based classifier rather than a learned one, for two reasons. There
    is no labelled ground truth to train against without hand-labelling a
    corpus, and the decision boundary here is close to linear anyway --
    automation is separable on input shape alone in the overwhelming majority
    of cases.

    Returns (is_automated, confidence in [0, 1]).

    Evidence is only weighted when it is actually available. A session that ran
    no commands offers no input-shape evidence at all, and counting that
    absence as evidence *against* automation would misclassify every
    credential scanner -- the most purely automated behaviour there is.

    Command-bearing sessions are judged on, strongest first:

    * ``bulk_ratio`` -- a client that delivers whole lines in one read did not
      type them. This alone is near-conclusive.
    * ``keystroke_coverage`` -- automation allocates no PTY, so there is no
      per-keystroke timing to record.
    * ``keystroke_cv`` -- when timing does exist, human rhythm is irregular;
      a replay harness is not.
    * ``gap_mean_ms`` -- humans pause between commands on a scale scripts
      rarely do.

    Command-free sessions are judged on credential cadence instead: a person
    typing passwords takes seconds per attempt and is erratic about it, while
    a spray is sub-second and near-metronomic.
    """
    score = 0.0
    weight = 0.0

    if features.command_count > 0:
        # Bulk input: the dominant signal.
        score += 3.0 * features.bulk_ratio
        weight += 3.0

        # No keystroke timing at all means no interactive terminal.
        score += 2.0 * (1.0 - min(features.keystroke_coverage, 1.0))
        weight += 2.0

        # Regular keystroke rhythm. Human typing lands around cv 0.4-1.2; a
        # machine replaying at fixed intervals sits far below that.
        if features.keystroke_coverage > 0:
            regularity = 1.0 if features.keystroke_cv < 0.25 else 0.0
            score += 1.5 * regularity
            weight += 1.5

        # Command cadence. Sub-second gaps across a whole session are not human.
        if features.command_count > 1:
            fast = 1.0 if features.gap_mean_ms < 800 else 0.0
            score += 1.5 * fast
            weight += 1.5

    if features.auth_attempt_count > 1:
        # Spray rate. A person types a password in a couple of seconds at best.
        score += 2.0 * (1.0 if features.auth_gap_mean_ms < 1500 else 0.0)
        weight += 2.0

        # Spray regularity. Machine-paced attempts cluster tightly around
        # their mean; a person retyping credentials does not.
        score += 1.0 * (1.0 if features.auth_gap_cv < 0.6 else 0.0)
        weight += 1.0

    if features.command_count == 0 and features.auth_attempt_count > 1:
        # Authenticating and then doing nothing at all is harvesting
        # behaviour: the actor wanted to know which credential worked, not
        # what the host contained.
        score += 1.5
        weight += 1.5

    if weight == 0:
        # A bare connection that offered nothing. Genuinely unknown.
        return False, 0.5

    confidence = score / weight
    return confidence >= 0.5, confidence


def session_summary(session: Session) -> dict:
    """Human-readable summary used by the dashboard and the CLI report."""
    feats = extract_behavioural(session)
    automated, confidence = is_automated(feats)
    affinity = wordlist_affinity(session)
    best_list = max(affinity.items(), key=lambda kv: kv[1]) if affinity else ("", 0.0)

    return {
        "session_id": session.session_id,
        "node_id": session.node_id,
        "src_ip": session.src_ip,
        "protocol": session.protocol,
        "client_banner": session.client_banner,
        "hassh": session.hassh,
        "commands": session.command_count,
        "duration_s": round(feats.duration_s, 2),
        "automated": automated,
        "automation_confidence": round(confidence, 3),
        "wordlist": best_list[0] if best_list[1] > 0.05 else None,
        "wordlist_affinity": round(best_list[1], 3),
        "artifacts": [a.url for a in session.artifacts],
        "credential_used": (
            f"{c.username}:{c.password}"
            if (c := session.successful_credential)
            else None
        ),
    }


def _safe_log(x: float) -> float:
    return math.log1p(max(x, 0.0))
