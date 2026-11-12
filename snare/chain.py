"""Per-session ledger of what the agent read, and assembly of the attack chain when a trap fires."""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Optional

_MAX_EVENTS_PER_SESSION = 60


@dataclass
class Ingest:
    ts: float
    session: str
    tool: str
    source: str
    suspicious: bool = False
    score: int = 0
    labels: list[str] = field(default_factory=list)
    snippet: str = ""


@dataclass
class Exposure:
    ts: float
    session: str
    tool: str
    action: str
    canary: str


class Ledger:
    """Thread-safe, in-memory, bounded. Nothing here is written to disk until an incident.

    Every lookup is by the keys of one session. There is no cross-session view: in the messaging
    gateway many users share one process, and an incident must never name or quote another
    user's reads."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._ingests: dict[str, deque] = {}
        self._exposures: dict[str, deque] = {}

    def add_ingest(self, ev: Ingest, session: Optional[str] = None) -> None:
        """File ``ev`` under ``session`` (default: its own session). One read can be filed under
        both ids of the same session; lookups count it once."""
        with self._lock:
            key = session or ev.session
            self._ingests.setdefault(key, deque(maxlen=_MAX_EVENTS_PER_SESSION)).append(ev)

    def add_exposure(self, ev: Exposure) -> None:
        with self._lock:
            self._exposures.setdefault(ev.session, deque(maxlen=_MAX_EVENTS_PER_SESSION)).append(ev)

    def _session_ingests(self, keys: list[str]) -> list[Ingest]:
        # The same read can be filed under a session's session_id and its task_id: count it once.
        found = {id(e): e for k in keys for e in self._ingests.get(k, ())}
        return sorted(found.values(), key=lambda e: e.ts)

    def culprit(self, keys: list[str]) -> tuple[Optional[Ingest], bool]:
        """The most likely injection source: newest suspicious read, else the newest read at all.
        Returns ``(event, confident)``."""
        with self._lock:
            events = self._session_ingests(keys)
        for ev in reversed(events):
            if ev.suspicious:
                return ev, True
        external = [e for e in events if e.source.startswith("http")]
        if external:
            return external[-1], False
        return (events[-1], False) if events else (None, False)

    def exposure(self, keys: list[str], canary: Optional[str] = None) -> Optional[Exposure]:
        with self._lock:
            found: list[Exposure] = []
            for k in keys:
                found.extend(self._exposures.get(k, ()))
        found.sort(key=lambda e: e.ts)
        for ev in reversed(found):
            if canary is None or ev.canary == canary:
                return ev
        return found[-1] if found else None

    def reads(self, keys: list[str], limit: int = 8) -> list[Ingest]:
        with self._lock:
            return self._session_ingests(keys)[-limit:]


def build_chain(ledger: Ledger, keys: list[str], *, tool: str, action: str, leaked: str,
                encoding: str, destinations: list[str], kind: str) -> dict[str, Any]:
    """The attack chain as plain data: source -> instruction -> exposure -> attempted action."""
    src, confident = ledger.culprit(keys)
    exp = ledger.exposure(keys, None if leaked.startswith("the whole") else leaked)
    return {
        "source": None if src is None else {
            "tool": src.tool, "source": src.source, "at": src.ts, "confident": confident,
            "instruction": src.snippet, "labels": src.labels, "score": src.score,
        },
        "exposure": None if exp is None else {
            "tool": exp.tool, "action": exp.action, "canary": exp.canary, "at": exp.ts,
        },
        "attempt": {
            "tool": tool, "action": action, "leaked": leaked, "encoding": encoding,
            "destinations": destinations, "kind": kind, "at": time.time(),
        },
        "recent_reads": [
            {"tool": e.tool, "source": e.source, "suspicious": e.suspicious, "at": e.ts}
            for e in ledger.reads(keys)
        ],
    }
