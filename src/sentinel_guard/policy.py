"""The caller's mandate can only tighten the operator's (OWASP ASI03).

The authority mandate comes from the operator's config (a file and the MCP process env, set by a human), never from the
model. A tool caller may declare a mandate of its own: it is intersected with the operator's, a widening is ignored and
reported, and the caller's role and description never replace the operator's (they never reach the LLM either).
"""
from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from typing import Any

from sentinel_guard.models import ACTIONS, Mandate, Signal, norm_addr

LAYER = "mandate"
OPERATOR, OPERATOR_CALLER, UNREGISTERED = "operator", "operator+caller", "caller (unregistered)"


def _cap(*values: float) -> float:
    caps = [v for v in values if v and v > 0]
    return min(caps) if caps else 0.0


def _amount(raw: Any, name: str) -> float:
    if raw is None:
        return 0.0
    if isinstance(raw, bool) or not isinstance(raw, (int, float, str)):
        raise ValueError(f"mandate.{name} must be a number")
    try:
        v = float(raw)
    except (TypeError, ValueError, OverflowError) as e:
        raise ValueError(f"mandate.{name} is not a number: {raw!r}") from e
    if math.isnan(v) or math.isinf(v) or v < 0:
        raise ValueError(f"mandate.{name} must be a finite number >= 0")
    return v


def _strings(raw: Any, name: str, limit: int, item_len: int) -> list[str] | None:
    if raw is None:
        return None
    if isinstance(raw, str):
        raw = [x for x in re.split(r"[,|]", raw)]
    if not isinstance(raw, (list, tuple)) or not all(isinstance(x, str) for x in raw):
        raise ValueError(f"mandate.{name} must be a list of strings")
    if len(raw) > limit or any(len(x) > item_len for x in raw):
        raise ValueError(f"mandate.{name} is too long")
    return [x.strip() for x in raw if x.strip()]


@dataclass
class CallerMandate:
    """What the tool caller declares. Every field optional; an absent field constrains nothing."""
    allowed_actions: list[str] | None = None
    max_amount: float = 0.0
    max_daily: float = 0.0
    allowed_recipients: list[str] | None = None
    currency: set[str] | None = None

    @property
    def constrains(self) -> bool:
        return bool(self.allowed_actions is not None or self.max_amount or self.max_daily or self.allowed_recipients or self.currency)

    @classmethod
    def parse(cls, raw: Any) -> "CallerMandate | None":
        """A dict (or its JSON text). Raises ValueError on a malformed mandate: the caller's mistake, never a verdict."""
        if raw is None or isinstance(raw, CallerMandate):
            return raw
        if isinstance(raw, str):
            if not raw.strip():
                return None
            try:
                raw = json.loads(raw)
            except ValueError as e:
                raise ValueError("mandate must be an object") from e
        if not isinstance(raw, dict):
            raise ValueError("mandate must be an object")
        actions = _strings(raw.get("allowed_actions", raw.get("actions")), "allowed_actions", 16, 32)
        recipients = _strings(raw.get("allowed_recipients", raw.get("recipients")), "allowed_recipients", 200, 256)
        cur = _strings(raw.get("currency", raw.get("currencies")), "currency", 16, 16)
        return cls(
            allowed_actions=[a.lower() for a in actions] if actions is not None else None,
            max_amount=_amount(raw.get("max_amount"), "max_amount"), max_daily=_amount(raw.get("max_daily"), "max_daily"),
            allowed_recipients=[norm_addr(r) for r in recipients] if recipients else None,
            currency={c.upper() for c in cur} if cur else None,
        )


def _currencies(s: str | None) -> list[str]:
    return [c.strip().upper() for c in (s or "").split("|") if c.strip()]


def tighten(op: Mandate, caller: CallerMandate) -> tuple[Mandate, list[Signal]]:
    """effective = operator ∩ caller. Role and description stay the operator's."""
    eff = Mandate(issuer=op.issuer, role=op.role, allowed_actions=list(op.allowed_actions), max_amount=op.max_amount,
                  max_daily=op.max_daily, currency=op.currency, allowed_recipients=list(op.allowed_recipients), description=op.description)
    sig: list[Signal] = []
    widened: list[str] = []
    if caller.allowed_actions is not None:
        extra = [a for a in caller.allowed_actions if a not in op.allowed_actions]
        if extra:
            widened.append(f"actions {extra} beyond {op.allowed_actions}")
        eff.allowed_actions = [a for a in op.allowed_actions if a in caller.allowed_actions]
    for f in ("max_amount", "max_daily"):
        c, o = getattr(caller, f), getattr(op, f)
        if c > 0 and o > 0 and c > o:
            widened.append(f"{f} {c:g} above {o:g}")
        setattr(eff, f, _cap(o, c))  # 0 means no cap: a caller's 0 never lifts the operator's cap
    if caller.allowed_recipients:
        if not op.allowed_recipients:
            eff.allowed_recipients = list(dict.fromkeys(caller.allowed_recipients))
        else:
            mine = set(caller.allowed_recipients)
            inter = [r for r in op.allowed_recipients if r in mine]
            extra = [r for r in caller.allowed_recipients if r not in op.allowed_recipients]
            if extra:
                widened.append(f"{len(extra)} recipient(s) outside the operator's list")
            if inter:
                eff.allowed_recipients = inter
            else:
                # an empty list means "anyone" in a mandate: an empty intersection must never widen to that
                sig.append(Signal("recipient_outside_declared_mandate", LAYER, 1.0,
                                  "the caller's declared recipients share none with the operator's mandate: no recipient satisfies both",
                                  hard=True, owasp=["ASI03"]))
    if caller.currency:
        ops = _currencies(op.currency)
        if not ops:
            eff.currency = "|".join(sorted(caller.currency))
        else:
            inter = [c for c in ops if c in caller.currency]
            extra = sorted(caller.currency - set(ops))
            if extra:
                widened.append(f"currencies {extra} beyond {ops}")
            if inter:
                eff.currency = "|".join(inter)
            else:
                sig.append(Signal("currency_mismatch", LAYER, 0.30,
                                  f"the caller's declared currencies {sorted(caller.currency)} share none with the mandate currency {op.currency}"))
    if widened:
        sig.append(Signal("caller_mandate_widening_ignored", LAYER, 0.05,
                          "the caller declared more than the operator's mandate allows (" + "; ".join(widened) + "): ignored, the operator's limits apply",
                          owasp=["ASI03"]))
    return eff, sig


def self_declared(issuer: str, caller: CallerMandate | None) -> tuple[Mandate, list[Signal]]:
    """SENTINEL_UNREGISTERED=review: an issuer the operator does not know. Its own mandate is a ceiling, never a grant:
    the floor signal keeps every order away from allow, and scams still block on their own signals."""
    c = caller or CallerMandate()
    m = Mandate(issuer=issuer, role="unregistered",
                allowed_actions=list(c.allowed_actions) if c.allowed_actions is not None else list(ACTIONS),
                max_amount=c.max_amount, max_daily=c.max_daily, currency="|".join(sorted(c.currency)) if c.currency else "",
                allowed_recipients=list(c.allowed_recipients or []), description="")
    said = "its limits are its own declaration" if c.constrains else "it declared no limits"
    return m, [Signal("mandate_self_declared", LAYER, 0.0,
                      f"issuer {norm_addr(issuer)} is not registered with this guard's operator ({said}): a human confirms every payment",
                      owasp=["ASI03"])]
