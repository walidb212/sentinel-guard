"""Connected mode: the HTTP client of the hosted Sentinel API. Nothing here ever runs in local-only mode.

- HostedRegistrySource reads the shared incident registry (GET /flagged/{address}) on top of the local one.
- AuthorizeClient asks the hosted API to record a decision on-chain (POST /authorize): a visa, a flag, or a pending mark.
Both never raise: the network is an enrichment, a local verdict always stands on its own.
"""
from __future__ import annotations

import json
import logging
import re
import threading
import time
import urllib.error
import urllib.request
from decimal import Decimal, InvalidOperation
from typing import Any

from sentinel_guard import __version__
from sentinel_guard.sources import Authority, LocalSource

log = logging.getLogger("sentinel_guard.hosted")
ADDRESS = re.compile(r"0x[0-9a-fA-F]{40}")
API_VERDICT = {"allow": "allow", "needs_approval": "needs_human", "block": "block"}  # the hosted API and the chain say needs_human
SCHEMA_VERDICT = {"allow": "allow", "needs_human": "needs_approval", "needs_approval": "needs_approval", "block": "block"}
RANK = {"allow": 0, "needs_approval": 1, "block": 2}
UNREACHABLE = "shared registry unreachable, local registry only"


def _headers(api_key: str | None, json_body: bool = False) -> dict[str, str]:
    h = {"Accept": "application/json", "User-Agent": f"sentinel-guard/{__version__}"}
    if json_body:
        h["Content-Type"] = "application/json"
    if api_key:  # only a real key: an unresolved ${...} placeholder never reaches this point (config.env)
        h["Authorization"] = f"Bearer {api_key}"
    return h


class HostedRegistrySource:
    """The local registry first; for an EVM address it does not flag, the shared registry of the hosted API.

    The API answers {address, flagged, severity} without a reason. Answers are cached 30 s; after a network error the
    shared registry is skipped for the same 30 s and the verdict carries a note (an optional enrichment, never a floor)."""

    def __init__(self, local: LocalSource, api: str, api_key: str | None = None, timeout: float = 3.0, ttl: float = 30.0):
        self.local, self.api, self.api_key, self.timeout, self.ttl = local, api.rstrip("/"), api_key, timeout, ttl
        self._cache: dict[str, tuple[float, tuple[bool, int]]] = {}
        self._down_until = 0.0
        self._lock = threading.Lock()
        self._notes = threading.local()

    # ----- the local registry stays the one the guard writes -----
    def registered(self, issuer: str) -> bool:
        return self.local.registered(issuer)

    def mark_threat(self, key: str, severity: int, reason: str) -> None:
        self.local.mark_threat(key, severity, reason)

    def clear_threat(self, key: str) -> bool:
        return self.local.clear_threat(key)

    def nonce_seen(self, nonce: str) -> bool:
        return self.local.nonce_seen(nonce)

    def nonce_used(self, nonce: str) -> bool:
        return self.local.nonce_used(nonce)

    def _note(self, text: str) -> None:
        notes = getattr(self._notes, "items", None)
        if notes is None:
            notes = self._notes.items = []
        if text not in notes:
            notes.append(text)

    def consume_notes(self) -> list[str]:
        """Notes gathered on this thread since the last call (one verification runs on one thread)."""
        notes = getattr(self._notes, "items", None) or []
        self._notes.items = []
        return notes

    def _shared(self, address: str) -> tuple[bool, int] | None:
        key = address.lower()
        now = time.monotonic()
        with self._lock:
            hit = self._cache.get(key)
            if hit and now - hit[0] < self.ttl:
                return hit[1]
            if now < self._down_until:
                self._note(UNREACHABLE)
                return None
        try:
            req = urllib.request.Request(f"{self.api}/flagged/{key}", headers=_headers(self.api_key))
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                body = json.loads(r.read().decode("utf-8") or "{}")
            flagged = body.get("flagged") is True
            sev = body.get("severity")
            sev = int(sev) if isinstance(sev, (int, float)) and not isinstance(sev, bool) else (3 if flagged else 0)
            res = (flagged, max(0, min(sev, 3)) if flagged else 0)
        except Exception as e:  # network down, HTTP error, junk body: local registry only, the verdict says so
            log.warning("shared registry lookup failed: %s", type(e).__name__)
            with self._lock:
                self._down_until = time.monotonic() + self.ttl
            self._note(UNREACHABLE)
            return None
        with self._lock:
            self._cache[key] = (time.monotonic(), res)
        return res

    def is_flagged_detail(self, key: str) -> tuple[bool, int, str, str | None]:
        local = self.local.is_flagged_detail(key)
        if local[0] or not ADDRESS.fullmatch((key or "").strip()):
            return local  # domains and instruction ids are local only: the API knows addresses
        shared = self._shared(key.strip())
        if shared and shared[0]:
            return True, shared[1], f"flagged in the Sentinel shared registry (severity {shared[1]})", "shared"
        return False, 0, "", None

    def is_flagged(self, key: str) -> tuple[bool, int, str]:
        return self.is_flagged_detail(key)[:3]

    def get_authority(self, issuer: str) -> Authority | None:
        a = self.local.get_authority(issuer)
        if a is not None and not a.flagged:
            fl, sev, reason, _ = self.is_flagged_detail(issuer)
            if fl:
                a.flagged, a.flag_severity, a.flag_reason = True, sev, reason
        return a


def to_wei(amount: Any, decimals: int) -> int:
    """Token units to integer base units without float error: 229.99 -> 229990000000000000000 at 18 decimals."""
    try:
        return int(Decimal(str(amount)) * (Decimal(10) ** decimals))
    except (InvalidOperation, ValueError) as e:
        raise ValueError(f"amount {amount!r} cannot be converted to base units") from e


def short_reason(out: dict) -> str:
    """trust=<n>/100; the first reasons without their layer tag and cost, at most 200 chars (the chain stores it)."""
    parts = []
    for r in out.get("reasons", [])[:4]:
        r = re.sub(r"^\[[a-z]+\]\s*", "", str(r))
        r = re.sub(r"\s*\(-[\d.]+\)", "", r)
        parts.append(r)
    return "; ".join([f"trust={out.get('trust_score')}/100", *parts])[:200]  # a clean allow reads "trust=100/100", no dangling "; "


def onchain_record(status: str, **kw: Any) -> dict:
    base = {"status": status, "verdict": None, "payment_id": None, "nonce": None, "visa_tx": None, "flag_tx": None,
            "decision_tx": None, "rescreened": False, "server_verdict": None, "error": None, "reason": None}
    base.update(kw)
    return base


class AuthorizeClient:
    """POST {api}/authorize. Sends the order, the local verdict and the screening inputs (the server re-screens and may only
    tighten). Never sends the full verdict: the API republishes what it receives on a public event stream."""

    def __init__(self, api: str, api_key: str | None, amount_decimals: int = 18, timeout: float = 45.0):
        self.api, self.api_key, self.decimals, self.timeout = api.rstrip("/"), api_key, amount_decimals, timeout

    def body(self, out: dict, screen: dict, ttl: int, labels: dict | None = None) -> dict:
        order = screen["order"]
        return {
            "payment": {"issuer": order["issuer"], "recipient": order["recipient"], "amount": to_wei(order["amount"], self.decimals),
                        "nonce": time.time_ns() // 1000},  # microseconds: two payments in the same second keep distinct ids
            "verdict": API_VERDICT[out["verdict"]],
            "reason": short_reason(out),
            "ttl": int(ttl),
            "screen": screen,
            "context": {"issuer_label": (labels or {}).get("issuer_label") or order["issuer"],
                        "recipient_label": (labels or {}).get("recipient_label") or order["recipient"], "source": "sentinel-guard"},
        }

    def authorize(self, out: dict, screen: dict, ttl: int = 300, labels: dict | None = None) -> dict:
        try:
            body = self.body(out, screen, ttl, labels)
        except (KeyError, ValueError) as e:
            return onchain_record("skipped", reason=f"cannot build the on-chain request: {e}")
        nonce = body["payment"]["nonce"]
        try:
            req = urllib.request.Request(f"{self.api}/authorize", data=json.dumps(body).encode("utf-8"),
                                         headers=_headers(self.api_key, json_body=True), method="POST")
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                resp = json.loads(r.read().decode("utf-8") or "{}")
        except urllib.error.HTTPError as e:
            detail = ""
            try:
                detail = str(json.loads(e.read().decode("utf-8") or "{}").get("detail", ""))[:200]
            except Exception:
                pass
            return onchain_record("error", nonce=nonce, error=f"HTTP {e.code}" + (f": {detail}" if detail else ""))
        except Exception as e:  # unreachable, timeout, TLS, junk body: the local verdict stands
            return onchain_record("error", nonce=nonce, error=f"{type(e).__name__}: {str(e)[:160]}")
        if not isinstance(resp, dict):
            return onchain_record("error", nonce=nonce, error="unexpected response from the hosted API")
        return onchain_record(
            "recorded", verdict=resp.get("verdict") or body["verdict"], payment_id=resp.get("payment_id"),
            nonce=resp.get("nonce", nonce), visa_tx=resp.get("visa_tx"), flag_tx=resp.get("flag_tx"), decision_tx=resp.get("decision_tx"),
            rescreened=bool(resp.get("rescreened", False)), server_verdict=resp.get("server_verdict"),
        )


def strictest(local: str, *server: str | None) -> str:
    """The client may only tighten: the effective verdict is the strictest of the local and the server's (schema naming)."""
    found = [SCHEMA_VERDICT[s] for s in server if s in SCHEMA_VERDICT]
    return max([local, *found], key=RANK.get)
