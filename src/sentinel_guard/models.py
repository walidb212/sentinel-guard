"""Typed data shared by the guard engine. The public projection is schema/verdict.schema.json."""
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any

from Crypto.Hash import keccak

ACTIONS = ("pay", "approve", "transfer", "swap")
VERDICTS = ("allow", "needs_approval", "block")
ORIGINS = ("user", "document", "tool_output", "agent", "email", "webpage", "memory")


def safe_json(obj, **kw) -> str:
    """json.dumps that never raises on lone surrogates (garbage bytes decoded as text)."""
    kw.setdefault("ensure_ascii", False)
    return json.dumps(obj, **kw).encode("utf-8", "replace").decode("utf-8")


def norm_addr(a: str | None) -> str:
    return (a or "").strip().lower()


@dataclass
class PaymentOrder:
    issuer: str
    action: str
    amount: float
    recipient: str = ""
    currency: str = "USDC"
    calldata: str | None = None
    nonce: str | None = None
    memo: str = ""

    def __post_init__(self):
        for f in ("issuer", "recipient", "action", "currency", "calldata", "nonce", "memo"):
            v = getattr(self, f)
            if v is None:
                if f in ("calldata", "nonce"):
                    continue
                if f in ("memo", "recipient"):
                    setattr(self, f, "")
                    continue
                if f == "currency":
                    self.currency = "USDC"
                    continue
                raise ValueError(f"{f} is required")
            if isinstance(v, bool) or not isinstance(v, (str, int)):
                raise ValueError(f"{f} must be a string, got {type(v).__name__}")
            if isinstance(v, int):
                if f not in ("nonce",):
                    raise ValueError(f"{f} must be a string, got int")
                setattr(self, f, str(v))
        self.issuer = norm_addr(self.issuer)
        self.recipient = norm_addr(self.recipient)
        self.action = (self.action or "").strip().lower()
        self.currency = (self.currency or "USDC").strip()
        if self.action not in ACTIONS:
            raise ValueError(f"action must be one of {ACTIONS}, got {self.action!r}")
        if isinstance(self.amount, bool) or not isinstance(self.amount, (int, float, str)):
            raise ValueError(f"amount must be a number, got {type(self.amount).__name__}")
        try:
            amount = float(self.amount)
        except (TypeError, ValueError, OverflowError) as e:
            raise ValueError(f"amount is not a number: {self.amount!r}") from e
        if amount != amount or amount in (float("inf"), float("-inf")):
            raise ValueError("amount must be finite")
        if amount <= 0:
            raise ValueError("amount must be > 0")
        self.amount = amount
        if not self.issuer:
            raise ValueError("issuer is required")
        if len(self.issuer) > 4096 or len(self.recipient) > 4096:
            raise ValueError("address too long")

    def canonical(self) -> str:
        return json.dumps(
            {"issuer": self.issuer, "action": self.action, "amount": self.amount,
             "currency": self.currency, "recipient": self.recipient,
             "calldata": self.calldata, "nonce": self.nonce},
            sort_keys=True, separators=(",", ":"),
        )

    def instruction_id(self) -> str:
        h = keccak.new(digest_bits=256)
        h.update(self.canonical().encode("utf-8", "replace"))
        return "0x" + h.hexdigest()


@dataclass
class Mandate:
    issuer: str
    role: str = "agent"
    allowed_actions: list[str] = field(default_factory=lambda: ["pay"])
    max_amount: float = 0.0  # 0 = no cap
    max_daily: float = 0.0  # 0 = no cumulative cap over 24 h
    currency: str = "USDC"
    allowed_recipients: list[str] = field(default_factory=list)
    description: str = ""

    def __post_init__(self):
        self.issuer = norm_addr(self.issuer)
        self.allowed_recipients = [norm_addr(r) for r in self.allowed_recipients]
        self.allowed_actions = [a.lower() for a in self.allowed_actions]


@dataclass
class VerifyRequest:
    order: PaymentOrder
    source_context: str = ""
    context_type: str = "text"  # text | html | tool_output | email
    task: str = ""
    context: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "VerifyRequest":
        if not isinstance(d, dict):
            raise ValueError("request must be an object")
        order = d.get("order")
        if not isinstance(order, dict):
            raise ValueError("order is required and must be an object")
        for k in ("issuer", "action", "amount"):
            if k not in order:
                raise ValueError(f"order.{k} is required")
        ctx = d.get("context")
        if ctx is None:
            ctx = {}
        if not isinstance(ctx, dict):
            raise ValueError("context must be an object")
        src = d.get("source_context")
        task = d.get("task")
        return cls(
            order=PaymentOrder(**{k: order[k] for k in order if k in PaymentOrder.__dataclass_fields__}),
            source_context=src if isinstance(src, str) else ("" if src is None else safe_json(src)),
            context_type=str(d.get("context_type") or "text").lower(),
            task=task if isinstance(task, str) else ("" if task is None else safe_json(task)),
            context=dict(ctx),
        )

    @property
    def origin(self) -> str:
        o = str(self.context.get("origin") or "").lower()
        if o in ORIGINS:
            return o
        return {"html": "webpage", "email": "email", "tool_output": "tool_output"}.get(self.context_type, "user")


@dataclass
class Signal:
    id: str
    layer: str
    weight: float
    evidence: str
    hard: bool = False
    owasp: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Verdict:
    instruction_id: str
    issuer: str
    action: str
    amount: float
    currency: str
    recipient: str
    verdict: str
    risk_score: float
    trust_score: int
    reasons: list[str]
    owasp: list[str]
    authority_check: dict[str, Any]
    poison_check: dict[str, Any]
    onchain_flagged: bool
    severity: int
    signals: list[dict[str, Any]]
    deductions: list[dict[str, Any]]
    risk_heuristic: float
    risk_llm: float | None
    llm_available: bool
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    latency_ms: float = 0.0
    approved_by: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
