"""Layer 2: does the order fit what this issuer is allowed to do."""
from __future__ import annotations

from sentinel_guard.models import Mandate, Signal, VerifyRequest

LAYER = "mandate"


def extract(req: VerifyRequest, mandate: Mandate | None) -> list[Signal]:
    sig: list[Signal] = []
    o = req.order
    if o.amount > 1e18:
        sig.append(Signal("amount_implausible", LAYER, 1.0, f"amount {o.amount:g} is above any plausible value: an unlimited transfer in disguise", hard=True, owasp=["ASI03"]))
    if o.action in ("pay", "transfer") and not o.recipient:
        sig.append(Signal("recipient_missing", LAYER, 1.0, f"a {o.action} order names no recipient: nothing can be checked about who gets the money", hard=True, owasp=["ASI03"]))
    if mandate is None:
        sig.append(Signal("issuer_in_registry", LAYER, 1.0, f"no mandate registered for issuer {o.issuer}", hard=True, owasp=["ASI03"]))
        return sig

    if o.action not in mandate.allowed_actions:
        sig.append(Signal("action_not_in_mandate", LAYER, 0.50, f"action {o.action!r} not in mandate {mandate.allowed_actions}", owasp=["ASI03"]))

    if mandate.max_amount and o.amount > mandate.max_amount:
        # over the cap, by any margin, is a mandate rule, not a suspicion: it costs no trust and never blocks by itself,
        # a human decides (scoring.RULE_NEEDS_APPROVAL)
        sig.append(Signal("amount_within_mandate", LAYER, 0.0, f"amount {o.amount} exceeds mandate cap {mandate.max_amount}", owasp=["ASI03"]))
    elif mandate.max_amount and o.amount >= 0.95 * mandate.max_amount:
        sig.append(Signal("amount_just_under_threshold", LAYER, 0.15, f"amount {o.amount} sits just under the cap {mandate.max_amount} (structuring pattern)"))

    if mandate.currency and o.currency and o.currency.upper() not in {c.strip().upper() for c in mandate.currency.split("|")}:
        sig.append(Signal("currency_mismatch", LAYER, 0.30, f"order currency {o.currency} differs from mandate currency {mandate.currency}"))

    if mandate.allowed_recipients and o.recipient and o.recipient not in mandate.allowed_recipients:
        merchant = req.context.get("merchant") if isinstance(req.context.get("merchant"), dict) else {}
        dom = merchant.get("domain")
        if not (isinstance(dom, str) and dom.lower() in mandate.allowed_recipients):
            sig.append(Signal("recipient_whitelisted", LAYER, 0.35, f"recipient {o.recipient} not in the issuer's allowlist", owasp=["ASI03"]))

    if req.origin != "user":
        sig.append(Signal("order_origin", LAYER, 0.10, f"order originates from {req.origin}, not from the principal", owasp=["ASI07"]))

    return sig
