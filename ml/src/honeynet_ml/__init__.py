"""Attacker profiling pipeline for the honeynet deception platform."""

from .corpus import Session, load_corpus, fold_sessions, load_events
from .features import classify, extract_behavioural, is_automated, session_summary
from .cluster import cluster_sessions, cluster_stability, ClusteringResult
from .attack import map_session, map_cluster

__version__ = "0.1.0"

__all__ = [
    "Session",
    "load_corpus",
    "fold_sessions",
    "load_events",
    "extract_behavioural",
    "is_automated",
    "classify",
    "session_summary",
    "cluster_sessions",
    "cluster_stability",
    "ClusteringResult",
    "map_session",
    "map_cluster",
]
