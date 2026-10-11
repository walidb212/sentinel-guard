"""Where decisions get recorded: a local JSONL audit trail in the state dir."""
from __future__ import annotations

import json
import logging
import threading
from pathlib import Path
from typing import Protocol

from sentinel_guard.models import safe_json

log = logging.getLogger("sentinel_guard.sinks")


class DecisionSink(Protocol):
    def record(self, verdict: dict) -> None: ...


class JsonlSink:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._lock = threading.Lock()

    def record(self, verdict: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock, self.path.open("a", encoding="utf-8") as f:
            f.write(safe_json(verdict) + "\n")

    def read_all(self) -> list[dict]:
        if not self.path.exists():
            return []
        return [json.loads(l) for l in self.path.read_text(encoding="utf-8").splitlines() if l.strip()]


class CompositeSink:
    def __init__(self, *sinks: DecisionSink):
        self.sinks = sinks

    def record(self, verdict: dict) -> None:
        for s in self.sinks:
            try:
                s.record(verdict)
            except Exception as e:
                log.error("sink %s failed: %s", type(s).__name__, e)
                verdict.setdefault("sink_errors", []).append(f"{type(s).__name__}: {e}")
