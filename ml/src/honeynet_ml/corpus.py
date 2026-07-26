"""Loads collector output into session aggregates.

The collector emits one JSON object per event. Profiling works on sessions, so
this module performs the fold: group by ``session_id``, order by sequence, and
attach the metadata that later stages key on.

Events arriving out of order or with gaps are tolerated. A sensor whose spool
overflowed produces incomplete sessions, and dropping those would silently bias
the corpus toward quiet periods.
"""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Iterator


@dataclass
class Command:
    """One line of attacker input."""

    raw: str
    argv: list[str]
    cwd: str
    since_session_start_ms: int
    since_previous_ms: int
    keystroke_deltas_ms: list[int]
    bulk_input: bool
    index: int

    @property
    def tool(self) -> str:
        """First token, normalized to a bare command name."""
        if not self.argv:
            return ""
        return self.argv[0].rsplit("/", 1)[-1]


@dataclass
class Credential:
    username: str
    password: str
    method: str
    success: bool
    attempt_index: int
    since_previous_ms: int


@dataclass
class Artifact:
    url: str
    scheme: str
    host: str
    port: int
    path: str
    via_tool: str


@dataclass
class Session:
    """One attacker interaction, folded from its event stream."""

    session_id: str
    node_id: str

    protocol: str = "unknown"
    src_ip: str = ""
    src_port: int = 0
    client_banner: str = ""
    hassh: str = ""
    kex_algorithms: list[str] = field(default_factory=list)
    ciphers: list[str] = field(default_factory=list)
    macs: list[str] = field(default_factory=list)

    commands: list[Command] = field(default_factory=list)
    credentials: list[Credential] = field(default_factory=list)
    artifacts: list[Artifact] = field(default_factory=list)
    uploads: list[dict[str, Any]] = field(default_factory=list)

    #: Exploit classes the sensor recognised across this session's requests.
    detected_attacks: list[str] = field(default_factory=list)
    #: Web decoys the session touched, e.g. "phpmyadmin", "dotenv".
    decoy_profiles: list[str] = field(default_factory=list)
    #: Canary tokens opened. A non-empty list is the loudest signal the
    #: platform produces: a planted file left the network it was planted on.
    canary_tokens: list[str] = field(default_factory=list)

    started_at: datetime | None = None
    ended_at: datetime | None = None
    end_reason: str = ""
    duration_ms: int = 0

    #: True when the session's terminal event was seen. False means the sensor
    #: lost events or the collector was restarted mid-session; such sessions
    #: are still usable but their duration is unreliable.
    complete: bool = False

    @property
    def command_count(self) -> int:
        return len(self.commands)

    @property
    def successful_credential(self) -> Credential | None:
        for c in self.credentials:
            if c.success:
                return c
        return None

    @property
    def tools(self) -> list[str]:
        return [c.tool for c in self.commands if c.tool]

    def command_text(self) -> str:
        """Whitespace-joined raw commands, the input to n-gram features."""
        return " \n ".join(c.raw for c in self.commands)


def _parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    # Collector timestamps are RFC 3339 with a Z suffix; fromisoformat handles
    # the offset form on 3.11+ but not the literal Z on older patch levels.
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def load_events(path: Path | str) -> Iterator[dict[str, Any]]:
    """Streams events from a JSON-lines file, skipping malformed lines.

    Skipping rather than raising is deliberate: a truncated final line is
    normal when the file is read while a collector is still writing, and one
    bad line should not cost the whole corpus.
    """
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def fold_sessions(events: Iterable[dict[str, Any]]) -> list[Session]:
    """Groups events into sessions.

    Node-level events (heartbeats) carry no session ID and are dropped here;
    they are operational telemetry, not attacker behaviour.
    """
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for ev in events:
        sid = ev.get("session_id")
        if sid:
            grouped[sid].append(ev)

    sessions = []
    for sid, evs in grouped.items():
        evs.sort(key=lambda e: e.get("seq", 0))
        sessions.append(_fold_one(sid, evs))
    sessions.sort(key=lambda s: (s.started_at or datetime.min.replace(tzinfo=None)).isoformat())
    return sessions


def _fold_one(session_id: str, events: list[dict[str, Any]]) -> Session:
    s = Session(session_id=session_id, node_id=events[0].get("node_id", ""))

    for ev in events:
        p = ev.get("payload") or {}
        kind = p.get("kind")

        if kind == "session_start":
            peer = p.get("peer") or {}
            s.protocol = p.get("protocol", "unknown")
            s.src_ip = peer.get("src_ip", "")
            s.src_port = peer.get("src_port", 0)
            s.client_banner = p.get("client_banner", "")
            s.hassh = p.get("hassh", "")
            s.kex_algorithms = p.get("kex_algorithms") or []
            s.ciphers = p.get("ciphers") or []
            s.macs = p.get("macs") or []
            s.started_at = _parse_ts(ev.get("ts_collector"))

        elif kind == "session_end":
            s.ended_at = _parse_ts(ev.get("ts_collector"))
            s.end_reason = p.get("reason", "")
            s.duration_ms = p.get("duration_ms", 0)
            s.complete = True

        elif kind == "auth":
            s.credentials.append(
                Credential(
                    username=p.get("username", ""),
                    password=p.get("password", ""),
                    method=p.get("method", ""),
                    success=bool(p.get("success")),
                    attempt_index=p.get("attempt_index", 0),
                    since_previous_ms=p.get("since_previous_ms", 0),
                )
            )

        elif kind == "command":
            s.commands.append(
                Command(
                    raw=p.get("raw", ""),
                    argv=p.get("argv") or [],
                    cwd=p.get("cwd", ""),
                    since_session_start_ms=p.get("since_session_start_ms", 0),
                    since_previous_ms=p.get("since_previous_ms", 0),
                    keystroke_deltas_ms=p.get("keystroke_deltas_ms") or [],
                    bulk_input=bool(p.get("bulk_input")),
                    index=p.get("command_index", 0),
                )
            )

        elif kind == "http_request":
            # Folded into commands rather than kept in a parallel list.
            #
            # Every downstream stage -- n-gram features, volume counts, timing,
            # clustering -- already works on commands, and a web request is the
            # same kind of evidence: a thing the actor chose to send. Keeping
            # them separate meant HTTP sessions arrived at the classifier with
            # no evidence at all and fell through to "interactive", which is
            # exactly backwards for a scanner.
            request = f"{p.get('method', 'GET')} {p.get('path', '/')}"
            if q := p.get("query"):
                request += f"?{q}"
            s.commands.append(
                Command(
                    raw=request,
                    argv=[p.get("method", "GET"), p.get("path", "/")],
                    cwd="",
                    since_session_start_ms=0,
                    since_previous_ms=0,
                    # HTTP has no interactive terminal, so there is no
                    # per-keystroke timing and the input is by definition bulk.
                    keystroke_deltas_ms=[],
                    bulk_input=True,
                    index=len(s.commands),
                )
            )
            for a in p.get("detected_attacks") or []:
                if a not in s.detected_attacks:
                    s.detected_attacks.append(a)
            if (decoy := p.get("decoy_profile")) and decoy not in s.decoy_profiles:
                s.decoy_profiles.append(decoy)

            # Credentials submitted to a decoy login belong in the same corpus
            # as SSH ones.
            if p.get("form_username") or p.get("form_password"):
                s.credentials.append(
                    Credential(
                        username=p.get("form_username", ""),
                        password=p.get("form_password", ""),
                        method="http-form",
                        success=False,
                        attempt_index=len(s.credentials),
                        since_previous_ms=0,
                    )
                )

        elif kind == "canary":
            s.canary_tokens.append(p.get("token_id", ""))

        elif kind == "artifact":
            s.artifacts.append(
                Artifact(
                    url=p.get("url", ""),
                    scheme=p.get("scheme", ""),
                    host=p.get("host", ""),
                    port=p.get("port", 0),
                    path=p.get("path", ""),
                    via_tool=p.get("via_tool", ""),
                )
            )

        elif kind == "upload":
            s.uploads.append(p)

    # Sessions with no terminal event still need a duration for the feature
    # vector; derive it from the last command rather than leaving it zero,
    # which would make an incomplete session look instantaneous.
    if not s.complete and s.commands:
        s.duration_ms = max(c.since_session_start_ms for c in s.commands)

    return s


def load_corpus(path: Path | str) -> list[Session]:
    """Convenience: read a JSONL file and fold it into sessions."""
    return fold_sessions(load_events(path))
