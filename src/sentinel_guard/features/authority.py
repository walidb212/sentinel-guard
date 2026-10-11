"""Layer 3: who gave the order, read from the authority registry (the operator's local config)."""
from __future__ import annotations

from sentinel_guard.models import Signal, VerifyRequest, norm_addr
from sentinel_guard.sources import Authority, AuthoritySource

LAYER = "authority"
LOW_PRIV_ROLES = ("reader", "document-reader", "doc-reader", "viewer", "low-priv", "low-privilege", "summarizer", "researcher", "scraper")
PAY_ACTIONS = ("pay", "transfer", "approve", "swap")


def _chain(req: VerifyRequest) -> list[str]:
    """Every agent the order went through before the issuer, as declared: context.relayed_by (one address or a list)."""
    raw = req.context.get("relayed_by")
    links = raw if isinstance(raw, (list, tuple)) else [raw]
    return [norm_addr(x) for x in links if isinstance(x, str) and x.strip()][:8]


def extract(req: VerifyRequest, auth: Authority | None, source_ok: bool, source: AuthoritySource | None = None,
            mandates: dict | None = None) -> list[Signal]:
    sig: list[Signal] = []
    o = req.order

    if not source_ok:
        sig.append(Signal("authority_source_unavailable", LAYER, 0.30, "authority registry unreachable: authority could not be verified"))

    if auth is None or not auth.active:
        sig.append(Signal("issuer_in_registry", LAYER, 1.0, f"issuer {o.issuer} not active in the authority registry", hard=True, owasp=["ASI03"]))
    else:
        if auth.role.lower() in LOW_PRIV_ROLES and o.action in PAY_ACTIONS:
            sig.append(Signal("issuer_role_mismatch", LAYER, 0.60, f"role {auth.role!r} is not allowed to order {o.action!r}", owasp=["ASI03"]))
        if auth.max_amount and o.amount > auth.max_amount:
            sig.append(Signal("amount_over_onchain_cap", LAYER, 0.0, f"amount {o.amount} > on-chain cap {auth.max_amount}", owasp=["ASI03"]))

    if auth is not None and auth.flagged:
        sig.append(Signal("issuer_flagged_onchain", LAYER, 1.0, f"issuer flagged in incident registry (severity {auth.flag_severity}): {auth.flag_reason}", hard=True))

    # the authority chain: an order is worth no more than the weakest agent it went through
    for link in _chain(req):
        if source is None:
            break
        try:
            la = source.get_authority(link)
        except Exception:
            la = None
        allowed = ((mandates or {}).get(link) or {}).get("allowed_actions")
        if la is None or not la.active:
            why = f"relayed by {link}, which is not an active agent in the registry"
        elif la.role.lower() in LOW_PRIV_ROLES or (allowed is not None and o.action not in [str(a).lower() for a in allowed]):
            why = f"relayed by {link} (role {la.role!r}), which may not order {o.action!r}"
        else:
            continue
        sig.append(Signal("authority_chain_broken", LAYER, 1.0, why + ": the order inherits the rights of the weakest agent in its chain", hard=True, owasp=["ASI03", "ASI07"]))
        break

    relayed = req.origin == "agent" or bool(_chain(req))
    if relayed and req.context.get("signed") is False:
        sig.append(Signal("inter_agent_message_signed", LAYER, 1.0, "order relayed by another agent without a verifiable signature", hard=True, owasp=["ASI07"]))
    elif relayed and req.context.get("signed") is not True:
        # nothing said about the signature is not good news: a relayed order with no proof of who sent it goes to a human
        sig.append(Signal("inter_agent_message_signed", LAYER, 0.50, "order relayed by another agent, and nothing establishes that the message was signed", owasp=["ASI07"]))
    if req.context.get("signature_valid") is False:
        sig.append(Signal("issuer_signature_invalid", LAYER, 1.0, "issuer signature missing or invalid", hard=True, owasp=["ASI07"]))

    return sig
