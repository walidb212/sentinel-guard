"""Where authority and threat facts come from: the operator's local config, plus the guard's own local incident registry.

Local mode: an issuer present in mandates.json is an active authority (role and cap taken from its mandate);
authorities.json only revokes (`active: false`) or caps. Threats and nonces are state, written to the state dir.
The read-only shared registry of the hosted API lives in sentinel_guard.hosted.
"""
from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from sentinel_guard.config import read_json, write_atomic
from sentinel_guard.models import norm_addr, safe_json


@dataclass
class Authority:
    active: bool
    max_amount: float
    role: str
    flagged: bool = False
    flag_severity: int = 0
    flag_reason: str = ""


class AuthoritySource(Protocol):
    def get_authority(self, issuer: str) -> Authority | None: ...
    def is_flagged(self, key: str) -> tuple[bool, int, str]: ...
    def mark_threat(self, key: str, severity: int, reason: str) -> None: ...
    def nonce_seen(self, nonce: str) -> bool: ...
    def nonce_used(self, nonce: str) -> bool: ...
    def clear_threat(self, key: str) -> bool: ...


def _key(s: str) -> str:
    """threats are keyed by address, domain or instruction id, all lowercased."""
    return (s or "").strip().lower()


def _cap(*values) -> float:
    """The tightest cap among the positive ones; 0 means no cap."""
    caps = [float(v) for v in values if isinstance(v, (int, float)) and not isinstance(v, bool) and v > 0]
    return min(caps) if caps else 0.0


class LocalSource:
    """Authorities from the config dir (read only); threats.json + nonces.json in the state dir (read and written)."""

    def __init__(self, config_dir, state_dir: str | Path, mandates: dict | None = None):
        self.config_dir = config_dir
        self.dir = Path(state_dir)
        self._lock = threading.RLock()
        self.mandates = mandates if mandates is not None else {norm_addr(k): v for k, v in read_json(config_dir, "mandates.json", {}).items()}
        self.authorities = {norm_addr(k): v for k, v in read_json(config_dir, "authorities.json", {}).items() if isinstance(v, dict)}
        self._sigs: dict[str, tuple | None] = {}
        self.threats: dict = {}
        self.nonces: set[str] = set()
        with self._lock:
            self._sync()

    def _sig(self, name: str) -> tuple | None:
        try:
            st = (self.dir / name).stat()
            return st.st_mtime_ns, st.st_size
        except OSError:
            return None

    def _sync(self) -> None:
        """Reload a state file another process changed (the human's CLI next to a running server). Called under the lock."""
        sig = self._sig("threats.json")
        if sig != self._sigs.get("threats.json", False):
            self.threats = self._load("threats.json", {})
            self._sigs["threats.json"] = sig
        sig = self._sig("nonces.json")
        if sig != self._sigs.get("nonces.json", False):
            self.nonces = set(self._load("nonces.json", {}).get("seen", []))
            self._sigs["nonces.json"] = sig

    def _load(self, name: str, default):
        p = self.dir / name
        try:
            return json.loads(p.read_text(encoding="utf-8")) if p.is_file() else default
        except (OSError, ValueError):
            current = self.threats if name == "threats.json" else {"seen": sorted(self.nonces)} if name == "nonces.json" else default
            return current  # unreadable for a moment: keep what is known rather than forget a flag

    def _save(self, name: str, obj) -> None:
        # the state dir is created when the guard first has something to keep
        write_atomic(self.dir / name, safe_json(obj, indent=1, sort_keys=True))
        self._sigs[name] = self._sig(name)

    def registered(self, issuer: str) -> bool:
        """Does the operator's config know this issuer at all (a mandate, or an authority entry, revoked ones included)?"""
        i = norm_addr(issuer)
        return i in self.mandates or i in self.authorities

    def get_authority(self, issuer: str) -> Authority | None:
        i = norm_addr(issuer)
        m, a = self.mandates.get(i), self.authorities.get(i)
        if a is not None and not a.get("active", True):
            active, cap, role = False, float(a.get("max_amount") or 0), str(a.get("role") or (m or {}).get("role") or "")
        elif isinstance(m, dict):
            active, cap, role = True, _cap(m.get("max_amount"), (a or {}).get("max_amount")), str(m.get("role") or (a or {}).get("role") or "agent")
        elif a is not None:
            active, cap, role = True, float(a.get("max_amount") or 0), str(a.get("role") or "")
        else:
            return None
        fl, sev, reason = self.is_flagged(issuer)
        return Authority(active, cap, role, fl, sev, reason)

    def is_flagged_detail(self, key: str) -> tuple[bool, int, str, str | None]:
        """(flagged, severity, reason, origin): origin is "local" when the guard's own registry holds the flag."""
        with self._lock:
            self._sync()
            t = self.threats.get(_key(key))
        if t and t.get("flagged"):
            return True, int(t.get("severity") or 0), str(t.get("reason") or ""), "local"
        return False, 0, "", None

    def is_flagged(self, key: str) -> tuple[bool, int, str]:
        return self.is_flagged_detail(key)[:3]

    def mark_threat(self, key: str, severity: int, reason: str) -> None:
        with self._lock:
            self._sync()
            self.threats[_key(key)] = {"flagged": True, "severity": severity, "reason": reason}
            self._save("threats.json", self.threats)

    def clear_threat(self, key: str) -> bool:
        """A human lifts a flag. True if there was one."""
        with self._lock:
            self._sync()
            had = self.threats.pop(_key(key), None) is not None
            if had:
                self._save("threats.json", self.threats)
            return had

    def nonce_used(self, nonce: str) -> bool:
        """Read only: has this nonce already paid for something?"""
        with self._lock:
            self._sync()
            return nonce in self.nonces

    def nonce_seen(self, nonce: str) -> bool:
        """Spend the nonce. True if it was already spent."""
        with self._lock:
            self._sync()
            seen = nonce in self.nonces
            self.nonces.add(nonce)
            self._save("nonces.json", {"seen": sorted(self.nonces)})
            return seen

    def consume_notes(self) -> list[str]:
        return []
