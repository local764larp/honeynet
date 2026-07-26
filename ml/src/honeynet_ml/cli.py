"""Command-line interface for the profiling pipeline."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

from .attack import kill_chain_order, map_cluster, map_session
from .cluster import NOISE, cluster_sessions, cluster_stability
from .corpus import load_corpus
from .features import classify, extract_behavioural, is_automated, session_summary
from .intel import build_intel


def _load(path: str):
    sessions = load_corpus(Path(path))
    if not sessions:
        print(f"no sessions found in {path}", file=sys.stderr)
        sys.exit(1)
    return sessions


def cmd_sessions(args: argparse.Namespace) -> int:
    sessions = _load(args.events)

    if args.json:
        print(json.dumps([session_summary(s) for s in sessions], indent=2))
        return 0

    print(f"{len(sessions)} sessions\n")
    header = f"{'session':<28} {'src':<16} {'banner':<28} {'cmds':>5} {'dur':>8}  class"
    print(header)
    print("-" * len(header))
    for s in sessions:
        feats = extract_behavioural(s)
        automated, conf = is_automated(feats)
        kind = "automated" if automated else "INTERACTIVE"
        print(
            f"{s.session_id:<28} {s.src_ip:<16} {s.client_banner[:28]:<28} "
            f"{s.command_count:>5} {feats.duration_s:>7.1f}s  {kind} ({conf:.2f})"
        )
    return 0


def cmd_clusters(args: argparse.Namespace) -> int:
    sessions = _load(args.events)
    result = cluster_sessions(sessions, min_cluster_size=args.min_cluster_size)

    if args.json:
        payload = {
            "n_clusters": result.n_clusters,
            "n_noise": result.n_noise,
            "reducer": result.reducer,
            "clusters": [p.as_dict() for p in result.profiles],
        }
        print(json.dumps(payload, indent=2))
        return 0

    print(
        f"{result.n_clusters} clusters from {len(sessions)} sessions "
        f"({result.n_noise} unclustered, reducer={result.reducer})\n"
    )

    for p in result.profiles:
        print(f"cluster {p.cluster_id}  [{p.label}]  {p.size} sessions")
        print(f"  automated       {p.automated_fraction:.0%}")
        print(f"  mean commands   {p.mean_command_count:.1f}")
        print(f"  mean duration   {p.mean_duration_s:.1f}s")
        if p.banners:
            print(f"  banners         {', '.join(p.banners[:3])}")
        if p.hasshes:
            print(f"  hassh           {', '.join(h[:16] for h in p.hasshes[:3])}")
        if p.artifact_hosts:
            print(f"  payload hosts   {', '.join(p.artifact_hosts)}")
        if p.top_tools:
            print(f"  tools           {', '.join(f'{t}({n})' for t, n in p.top_tools[:6])}")
        if p.credentials:
            print(f"  credentials     {', '.join(p.credentials[:5])}")

        members = [s for s, l in zip(sessions, result.labels) if l == p.cluster_id]
        attack = map_cluster(members)
        if attack["techniques"]:
            print("  ATT&CK:")
            for t in kill_chain_order(attack["techniques"])[:10]:
                print(
                    f"    {t['technique_id']:<12} {t['technique'][:46]:<46} "
                    f"{t['prevalence']:.0%}"
                )
        print()

    if result.n_noise:
        print(f"{result.n_noise} sessions did not fit any cluster (label {NOISE}).")
    return 0


def cmd_attack(args: argparse.Namespace) -> int:
    sessions = _load(args.events)

    if args.session:
        matches = [s for s in sessions if s.session_id == args.session]
        if not matches:
            print(f"session {args.session} not found", file=sys.stderr)
            return 1
        sessions = matches

    if args.json:
        print(
            json.dumps(
                {
                    s.session_id: [h.as_dict() for h in map_session(s)]
                    for s in sessions
                },
                indent=2,
            )
        )
        return 0

    for s in sessions:
        hits = map_session(s)
        if not hits:
            continue
        print(f"{s.session_id}  ({s.src_ip}, {s.command_count} commands)")
        for h in kill_chain_order([x.as_dict() for x in hits]):
            print(f"  {h['tactic']:<20} {h['technique_id']:<12} {h['technique']}")
            print(f"    {h['rationale']}")
            for e in h["evidence"][:2]:
                print(f"    > {e[:100]}")
        print()
    return 0


def cmd_intel(args: argparse.Namespace) -> int:
    sessions = _load(args.events)
    result = cluster_sessions(sessions, min_cluster_size=args.min_cluster_size)
    bundle = build_intel(sessions, result, redact_credentials=not args.include_credentials)

    out = json.dumps(bundle, indent=2)
    if args.out:
        Path(args.out).write_text(out, encoding="utf-8")
        print(f"wrote STIX bundle to {args.out} ({len(bundle['objects'])} objects)")
    else:
        print(out)
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    sessions = _load(args.events)
    result = cluster_sessions(sessions, min_cluster_size=args.min_cluster_size)
    stability = cluster_stability(sessions, windows=args.windows)

    verdicts = Counter(classify(extract_behavioural(s)) for s in sessions)

    report = {
        "corpus": {
            "sessions": len(sessions),
            "nodes": sorted({s.node_id for s in sessions}),
            "source_ips": len({s.src_ip for s in sessions if s.src_ip}),
            "total_commands": sum(s.command_count for s in sessions),
            "total_credentials": sum(len(s.credentials) for s in sessions),
            "total_artifacts": sum(len(s.artifacts) for s in sessions),
            "distinct_hassh": len({s.hassh for s in sessions if s.hassh}),
        },
        "classification": {
            "automated": verdicts["automated"],
            "interactive": verdicts["interactive"],
            # Sessions that offered nothing to judge. Counting these as
            # interactive would overstate how many humans were observed.
            "undetermined": verdicts["undetermined"],
        },
        "clustering": {
            "n_clusters": result.n_clusters,
            "n_noise": result.n_noise,
            "reducer": result.reducer,
            "clusters": [p.as_dict() for p in result.profiles],
        },
        "stability": stability,
        "attack": {
            str(p.cluster_id): map_cluster(
                [s for s, l in zip(sessions, result.labels) if l == p.cluster_id]
            )
            for p in result.profiles
        },
    }

    out = json.dumps(report, indent=2)
    if args.out:
        Path(args.out).write_text(out, encoding="utf-8")
        print(f"wrote report to {args.out}")
    else:
        print(out)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="honeynet-ml",
        description="Attacker profiling over collector output.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    def add_common(p: argparse.ArgumentParser) -> None:
        p.add_argument("events", help="path to collector events JSONL")
        p.add_argument("--json", action="store_true", help="emit JSON")

    p_sessions = sub.add_parser("sessions", help="list sessions with bot/human classification")
    add_common(p_sessions)
    p_sessions.set_defaults(func=cmd_sessions)

    p_clusters = sub.add_parser("clusters", help="group sessions into attacker profiles")
    add_common(p_clusters)
    p_clusters.add_argument("--min-cluster-size", type=int, default=2)
    p_clusters.set_defaults(func=cmd_clusters)

    p_attack = sub.add_parser("attack", help="map sessions to MITRE ATT&CK techniques")
    add_common(p_attack)
    p_attack.add_argument("--session", help="restrict to one session ID")
    p_attack.set_defaults(func=cmd_attack)

    p_intel = sub.add_parser("intel", help="generate a STIX 2.1 bundle")
    p_intel.add_argument("events")
    p_intel.add_argument("--out", help="write to this path instead of stdout")
    p_intel.add_argument("--min-cluster-size", type=int, default=2)
    p_intel.add_argument(
        "--include-credentials",
        action="store_true",
        help="include raw credential pairs (off by default; see design doc section 9)",
    )
    p_intel.set_defaults(func=cmd_intel)

    p_report = sub.add_parser("report", help="full profiling report as JSON")
    p_report.add_argument("events")
    p_report.add_argument("--out", help="write to this path instead of stdout")
    p_report.add_argument("--min-cluster-size", type=int, default=2)
    p_report.add_argument("--windows", type=int, default=3)
    p_report.set_defaults(func=cmd_report)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
