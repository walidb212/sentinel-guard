"""The public verdict: a strict projection of the engine's detailed record onto schema/verdict.schema.json."""
from __future__ import annotations

import json
from importlib import resources

OWASP = ("ASI03", "ASI07")
VERDICTS = ("allow", "needs_approval", "block")


def load_schema() -> dict:
    return json.loads((resources.files("sentinel_guard") / "schema" / "verdict.schema.json").read_text(encoding="utf-8"))


def _unit(x) -> float:
    try:
        v = float(x)
    except (TypeError, ValueError):
        return 0.0
    return min(max(v, 0.0), 1.0) if v == v else 0.0


def to_schema(out: dict) -> dict:
    """Only the schema's keys, in the schema's types (additionalProperties is false). The details stay in the audit trail."""
    ac = out.get("authority_check") or {}
    pc = out.get("poison_check") or {}
    return {
        "instruction_id": str(out["instruction_id"]),
        "issuer": str(out["issuer"]),
        "action": str(out["action"]),
        "amount": float(out["amount"]),
        "currency": str(out.get("currency") or "USDC"),
        "recipient": str(out.get("recipient") or ""),
        "verdict": out["verdict"] if out.get("verdict") in VERDICTS else "needs_approval",
        "risk_score": _unit(out.get("risk_score")),
        "reasons": [str(r) for r in out.get("reasons") or []],
        "owasp": sorted({o for o in out.get("owasp") or [] if o in OWASP}),
        "authority_check": {"authorized": ac.get("authorized") is True, "within_limit": ac.get("within_limit") is True,
                            "source": str(ac.get("source") or "local")},
        "poison_check": {"is_poisoned": pc.get("is_poisoned") is True, "confidence": _unit(pc.get("confidence")),
                         "evidence": [str(e) for e in pc.get("evidence") or []]},
        "onchain_flagged": out.get("onchain_flagged") is True,
        "timestamp": str(out.get("timestamp") or ""),
    }
