"""Attacker grouping.

Builds a joint feature space from behavioural scalars, tool usage, and command
lexicon, reduces it, and clusters with HDBSCAN.

HDBSCAN rather than DBSCAN because cluster density varies by orders of
magnitude. A handful of human operators and a swarm of identical loader
sessions occupy the same feature space, and DBSCAN's single ``eps`` cannot
serve both: tuned for the swarm it merges the operators into noise, tuned for
the operators it shatters the swarm. HDBSCAN varies density per cluster and
labels genuine outliers ``-1`` rather than forcing them into a group.
"""

from __future__ import annotations

import re
import warnings
from dataclasses import dataclass, field
from typing import Sequence

import numpy as np
from sklearn.cluster import HDBSCAN
from sklearn.decomposition import TruncatedSVD
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler

from .corpus import Session
from .features import (
    BehaviouralFeatures,
    extract_behavioural,
    extract_tool_vector,
    is_automated,
)

#: Label HDBSCAN assigns to points it will not place in any cluster.
NOISE = -1


@dataclass
class ClusterProfile:
    """Aggregate description of one attacker group."""

    cluster_id: int
    size: int
    sessions: list[str] = field(default_factory=list)
    source_ips: list[str] = field(default_factory=list)
    hasshes: list[str] = field(default_factory=list)
    banners: list[str] = field(default_factory=list)
    protocols: list[str] = field(default_factory=list)
    detected_attacks: list[str] = field(default_factory=list)
    top_commands: list[tuple[str, int]] = field(default_factory=list)
    top_tools: list[tuple[str, int]] = field(default_factory=list)
    artifact_hosts: list[str] = field(default_factory=list)
    credentials: list[str] = field(default_factory=list)
    automated_fraction: float = 0.0
    mean_duration_s: float = 0.0
    mean_command_count: float = 0.0
    label: str = ""

    def as_dict(self) -> dict:
        return {
            "cluster_id": self.cluster_id,
            "label": self.label,
            "size": self.size,
            "sessions": self.sessions,
            "source_ips": self.source_ips,
            "hasshes": self.hasshes,
            "banners": self.banners,
            "protocols": self.protocols,
            "detected_attacks": self.detected_attacks,
            "top_commands": self.top_commands,
            "top_tools": self.top_tools,
            "artifact_hosts": self.artifact_hosts,
            "credentials": self.credentials,
            "automated_fraction": round(self.automated_fraction, 3),
            "mean_duration_s": round(self.mean_duration_s, 2),
            "mean_command_count": round(self.mean_command_count, 2),
        }


@dataclass
class ClusteringResult:
    labels: np.ndarray
    profiles: list[ClusterProfile]
    embedding: np.ndarray
    n_clusters: int
    n_noise: int
    reducer: str

    def label_for(self, index: int) -> int:
        return int(self.labels[index])


def build_matrix(sessions: Sequence[Session], svd_components: int = 12) -> np.ndarray:
    """Assembles the joint feature matrix.

    Three blocks, standardized so no block dominates purely through scale:
    behavioural scalars, binary tool usage, and an SVD projection of command
    text TF-IDF.
    """
    if not sessions:
        return np.zeros((0, 0))

    scalars = np.vstack([extract_behavioural(s).to_array() for s in sessions])
    scalars = np.nan_to_num(scalars, nan=0.0, posinf=0.0, neginf=0.0)
    scalars = StandardScaler().fit_transform(scalars)

    tools = np.vstack([extract_tool_vector(s) for s in sessions])

    corpus_text = [s.command_text() for s in sessions]
    if any(t.strip() for t in corpus_text):
        # Character n-grams rather than words: attacker command lines are full
        # of paths, flags and concatenations that word tokenisation shreds,
        # and character grams survive the obfuscation loaders apply.
        tfidf = TfidfVectorizer(
            analyzer="char_wb",
            ngram_range=(3, 5),
            min_df=1,
            max_features=4000,
            sublinear_tf=True,
        )
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            lexical = tfidf.fit_transform(corpus_text)

        k = min(svd_components, max(1, min(lexical.shape) - 1))
        if k >= 1 and lexical.shape[1] > 1:
            lexical = TruncatedSVD(n_components=k, random_state=0).fit_transform(lexical)
            lexical = StandardScaler().fit_transform(lexical)
        else:
            lexical = np.zeros((len(sessions), 1))
    else:
        lexical = np.zeros((len(sessions), 1))

    return np.hstack([scalars, tools, lexical])


def reduce_dimensions(matrix: np.ndarray, n_components: int = 8) -> tuple[np.ndarray, str]:
    """Projects the feature matrix into a low-dimensional space.

    Prefers UMAP when installed -- it preserves local structure better and
    yields cleaner HDBSCAN results -- and falls back to TruncatedSVD, which is
    always available and adequate for corpora up to a few thousand sessions.
    """
    if matrix.shape[0] < 3 or matrix.shape[1] < 2:
        return matrix, "none"

    n_components = min(n_components, matrix.shape[0] - 1, matrix.shape[1])
    if n_components < 2:
        return matrix, "none"

    try:
        import umap  # type: ignore

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            reducer = umap.UMAP(
                n_components=n_components,
                n_neighbors=min(15, max(2, matrix.shape[0] - 1)),
                min_dist=0.0,
                metric="euclidean",
                random_state=42,
            )
            return reducer.fit_transform(matrix), "umap"
    except ImportError:
        pass

    return TruncatedSVD(n_components=n_components, random_state=42).fit_transform(matrix), "svd"


def cluster_sessions(
    sessions: Sequence[Session],
    min_cluster_size: int = 2,
    min_samples: int | None = None,
) -> ClusteringResult:
    """Groups sessions into attacker clusters."""
    if len(sessions) < 2:
        return ClusteringResult(
            labels=np.full(len(sessions), NOISE),
            profiles=[],
            embedding=np.zeros((len(sessions), 0)),
            n_clusters=0,
            n_noise=len(sessions),
            reducer="none",
        )

    matrix = build_matrix(sessions)
    embedding, reducer = reduce_dimensions(matrix)

    clusterer = HDBSCAN(
        min_cluster_size=max(2, min_cluster_size),
        min_samples=min_samples,
        # Excess-of-mass tends to swallow small dense groups into one large
        # cluster; leaf selection keeps distinct loader families apart, which
        # is the resolution this analysis needs.
        cluster_selection_method="leaf",
        metric="euclidean",
        # Set explicitly: the default flips in scikit-learn 1.10 and the
        # warning is noise in CLI output.
        copy=True,
    )
    labels = clusterer.fit_predict(embedding)

    profiles = [
        summarize_cluster(int(cid), [s for s, l in zip(sessions, labels) if l == cid])
        for cid in sorted({int(l) for l in labels if l != NOISE})
    ]

    return ClusteringResult(
        labels=labels,
        profiles=profiles,
        embedding=embedding,
        n_clusters=len(profiles),
        n_noise=int(np.sum(labels == NOISE)),
        reducer=reducer,
    )


def summarize_cluster(cluster_id: int, members: Sequence[Session]) -> ClusterProfile:
    """Builds the aggregate description of a cluster."""
    from collections import Counter

    cmd_counter: Counter[str] = Counter()
    tool_counter: Counter[str] = Counter()
    for s in members:
        cmd_counter.update(c.raw for c in s.commands)
        tool_counter.update(s.tools)

    automated = sum(1 for s in members if is_automated(extract_behavioural(s))[0])

    profile = ClusterProfile(
        cluster_id=cluster_id,
        size=len(members),
        sessions=[s.session_id for s in members],
        source_ips=sorted({s.src_ip for s in members if s.src_ip}),
        hasshes=sorted({s.hassh for s in members if s.hassh}),
        banners=sorted({s.client_banner for s in members if s.client_banner}),
        protocols=sorted({s.protocol for s in members if s.protocol}),
        detected_attacks=sorted({a for s in members for a in s.detected_attacks}),
        top_commands=cmd_counter.most_common(8),
        top_tools=tool_counter.most_common(8),
        artifact_hosts=sorted({a.host for s in members for a in s.artifacts if a.host}),
        credentials=sorted(
            {f"{c.username}:{c.password}" for s in members for c in s.credentials}
        )[:20],
        automated_fraction=automated / len(members) if members else 0.0,
        mean_duration_s=float(np.mean([s.duration_ms / 1000.0 for s in members])) if members else 0.0,
        mean_command_count=float(np.mean([s.command_count for s in members])) if members else 0.0,
    )
    profile.label = derive_label(profile)
    return profile


def derive_label(profile: ClusterProfile) -> str:
    """Names a cluster from its dominant behaviour.

    Descriptive rather than attributive. Calling a cluster "Mirai" asserts
    family attribution the evidence does not support; calling it
    "iot-loader" describes what it actually did.

    Tool detection scans the raw command text rather than trusting the parsed
    argv. Sensors record argv for the leading stage of a command line only, so
    a chain like ``cd /tmp; wget …; chmod +x …`` reports its tool as ``cd`` and
    the fetch is invisible to an argv-based check -- while the raw line, which
    is recorded in full, still has it.
    """
    commands = " ".join(c for c, _ in profile.top_commands).lower()
    tools = {t for t, _ in profile.top_tools}
    tools |= {
        t for t in ("wget", "curl", "tftp", "busybox", "chmod", "crontab", "nc")
        if re.search(rf"\b{re.escape(t)}\b", commands)
    }

    # A group with no observed behaviour at all is not an operator. Canary
    # callbacks and bare connections land here, and calling them
    # "interactive-operator" -- which the automation branch below would do,
    # since a no-evidence session cannot be shown to be automated -- reads as a
    # human being at a keyboard when nothing of the sort was seen.
    if not profile.top_commands and profile.mean_command_count == 0:
        if profile.protocols and set(profile.protocols) == {"canary"}:
            return "canary-callback"
        if profile.credentials:
            return "credential-scanner"
        return "connection-probe"

    # Recognised exploit attempts name the group regardless of cadence: a web
    # scanner throwing Log4Shell is characterised by what it threw, not by how
    # fast it threw it.
    if profile.detected_attacks:
        return "web-exploit-scanner"

    if profile.automated_fraction < 0.5:
        return "interactive-operator"
    if not profile.top_commands:
        return "credential-scanner"
    if "busybox" in commands and ("wget" in tools or "tftp" in tools):
        return "iot-loader"
    if "crontab" in commands or "systemctl" in commands:
        return "persistence-installer"
    if "authorized_keys" in commands or "id_rsa" in commands:
        return "credential-harvester"
    if {"wget", "curl", "tftp"} & tools:
        return "payload-dropper"
    if profile.mean_command_count <= 3:
        return "reconnaissance-probe"
    return "unclassified-automation"


def cluster_stability(
    sessions: Sequence[Session],
    windows: int = 3,
    min_cluster_size: int = 2,
) -> dict:
    """Measures whether clusters persist across time slices.

    A group that appears in one window and never again is far more likely to be
    a sampling artifact than a campaign. Splitting the corpus chronologically
    and re-clustering each slice separates the two: real campaigns produce
    recognisably similar groups in consecutive windows.

    Similarity is Jaccard overlap on cluster command vocabulary, which is
    stable under the source-IP rotation that campaigns routinely perform.
    """
    if len(sessions) < windows * 2:
        return {"windows": 0, "stable_clusters": 0, "detail": []}

    ordered = sorted(sessions, key=lambda s: s.started_at or 0)
    size = len(ordered) // windows
    slices = [ordered[i * size : (i + 1) * size] for i in range(windows)]

    vocabularies: list[list[set[str]]] = []
    for sl in slices:
        result = cluster_sessions(sl, min_cluster_size=min_cluster_size)
        vocabularies.append(
            [{c for c, _ in p.top_commands} for p in result.profiles]
        )

    detail = []
    stable = 0
    for i in range(len(vocabularies) - 1):
        for a_idx, a in enumerate(vocabularies[i]):
            best, best_score = -1, 0.0
            for b_idx, b in enumerate(vocabularies[i + 1]):
                if not (a | b):
                    continue
                score = len(a & b) / len(a | b)
                if score > best_score:
                    best, best_score = b_idx, score
            if best_score >= 0.5:
                stable += 1
            detail.append(
                {
                    "window": i,
                    "cluster": a_idx,
                    "matched_next_window": best,
                    "jaccard": round(best_score, 3),
                }
            )

    return {"windows": windows, "stable_clusters": stable, "detail": detail}
