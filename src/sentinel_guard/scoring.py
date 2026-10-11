"""Combine signals + Claude's judgement into risk, verdict, severity. Pure."""
from __future__ import annotations

from dataclasses import dataclass

from sentinel_guard.models import Signal

DEFAULT_THRESHOLDS = {"allow_below": 0.30, "block_at_or_above": 0.70,
                      "high_amount_adjustment": {"ratio": 0.5, "allow_below": 0.20, "block_at_or_above": 0.60}}

# cannot verify, so never allow alone. mandate_self_declared: the issuer is not registered with the operator, its limits are its own word
FLOOR_NEEDS_APPROVAL = {"calldata_undecodable", "authority_source_unavailable", "order_from_memory_not_current_turn", "mandate_self_declared"}
# mandate rules: the order is beyond what the issuer may do alone. No trust is taken, but it never passes without a human.
RULE_NEEDS_APPROVAL = {"amount_within_mandate", "amount_over_onchain_cap", "daily_cap_exceeded"}
# context, not evidence: they raise the score but never justify an escalation by themselves
INFORMATIONAL = {"order_origin", "hidden_text_ratio", "recipient_prior_incident_info", "invisible_unicode_trace", "payment_details_mention", "amount_just_under_threshold", "tld_risk", "source_is_ad", "tls_missing", "legal_pages_missing", "geo_mismatch",
                 "caller_mandate_widening_ignored"}


def noisy_or(weights: list[float]) -> float:
    p = 1.0
    for w in weights:
        p *= (1.0 - min(max(w, 0.0), 1.0))
    return round(1.0 - p, 4)


def trust_from_risk(risk: float) -> int:
    """Degressive trust score: every order starts at 100, each finding takes a share of what is left."""
    return int(round(100 * (1.0 - min(max(risk, 0.0), 1.0))))


def deductions(signals: list[Signal]) -> list[dict]:
    """Walk the signals strongest first, starting at 100 trust: each one costs weight x remaining trust.
    A hard signal takes everything. Sum of deductions == 100 - final trust (up to rounding)."""
    out, trust = [], 100.0
    for s in sorted(signals, key=lambda s: (-s.hard, -s.weight)):
        cost = trust if s.hard else trust * min(max(s.weight, 0.0), 1.0)
        trust -= cost
        out.append({"id": s.id, "layer": s.layer, "hard": s.hard, "cost": round(cost, 1), "trust_after": round(trust, 1)})
    return out


@dataclass
class ScoreResult:
    risk_heuristic: float
    risk_llm: float | None
    risk: float
    trust: int
    verdict: str
    severity: int
    hard_block: bool
    thresholds: tuple[float, float]
    notes: list[str]


def combine(signals: list[Signal], llm: dict | None, amount: float, max_amount: float,
            thresholds: dict | None = None, repeat_offender: bool = False) -> ScoreResult:
    th = thresholds or DEFAULT_THRESHOLDS
    notes: list[str] = []
    hard = [s for s in signals if s.hard]
    risk_h = 1.0 if hard else noisy_or([s.weight for s in signals])

    risk_llm = None
    if llm is not None:
        try:
            r = float(llm.get("risk_score"))
            has_evidence = bool(llm.get("reasons")) or bool((llm.get("poison_check") or {}).get("evidence"))
            if has_evidence:
                risk_llm = round(min(max(r, 0.0), 1.0), 4)
            else:
                notes.append("llm score ignored: no cited evidence")
        except (TypeError, ValueError):
            notes.append("llm returned no usable risk_score")

    if hard:
        risk = 1.0
    elif risk_llm is not None:
        risk = max(risk_h, risk_llm)
    else:
        risk = risk_h

    ratio = min(amount / max_amount, 1e6) if max_amount else 0.0  # an absurd amount must not overflow the report below
    if ratio >= th["high_amount_adjustment"].get("ratio", 0.5):
        lo, hi = th["high_amount_adjustment"]["allow_below"], th["high_amount_adjustment"]["block_at_or_above"]
        notes.append(f"amount is {round(100 * ratio)}% of the cap: thresholds tightened to {lo}/{hi}")
    else:
        lo, hi = th["allow_below"], th["block_at_or_above"]

    if hard or risk >= hi:
        verdict = "block"
    elif risk >= lo:
        verdict = "needs_approval"
    else:
        verdict = "allow"

    substantive = [s for s in signals if s.id not in INFORMATIONAL]
    if verdict == "needs_approval" and not hard and not substantive and (risk_llm is None or risk_llm < lo):
        verdict = "allow"
        notes.append("only contextual signals, no evidence: allow")
    if verdict == "allow" and llm is None and substantive:
        verdict = "needs_approval"
        notes.append("llm unavailable and signals present: never guess allow")
    if verdict == "allow" and any(s.id in FLOOR_NEEDS_APPROVAL or s.id.startswith("layer_error_") for s in signals):
        verdict = "needs_approval"
        notes.append("floored to needs_approval (cannot verify)")

    if verdict == "allow" and any(s.id in RULE_NEEDS_APPROVAL and not s.hard for s in signals):
        verdict = "needs_approval"
        notes.append("over the mandate cap: a human decides, whatever the score")

    severity = {"block": 3, "needs_approval": 2}.get(verdict, 1)
    if repeat_offender and severity < 3:
        severity += 1
        notes.append("repeat offender: severity raised")

    return ScoreResult(round(risk_h, 4), risk_llm, round(risk, 4), trust_from_risk(risk), verdict, severity, bool(hard), (lo, hi), notes)
