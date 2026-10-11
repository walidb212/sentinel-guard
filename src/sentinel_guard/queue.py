"""Human-in-the-loop queue for needs_approval verdicts: one JSON file in the state dir."""
from __future__ import annotations

import json
import threading
from pathlib import Path

from sentinel_guard.config import write_atomic
from sentinel_guard.models import safe_json


class PendingQueue:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._lock = threading.Lock()

    def _load(self) -> dict:
        return json.loads(self.path.read_text(encoding="utf-8")) if self.path.exists() else {}

    def _save(self, d: dict) -> None:
        write_atomic(self.path, safe_json(d, indent=1))

    def add(self, verdict: dict) -> None:
        with self._lock:
            d = self._load()
            d[verdict["instruction_id"]] = verdict
            self._save(d)

    def list(self) -> list[dict]:
        return list(self._load().values())

    def get(self, instruction_id: str) -> dict | None:
        return self._load().get(instruction_id)

    def pop(self, instruction_id: str) -> dict | None:
        with self._lock:
            d = self._load()
            v = d.pop(instruction_id, None)
            if v is not None:
                self._save(d)
            return v
