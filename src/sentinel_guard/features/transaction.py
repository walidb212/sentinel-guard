"""Layer 5: the transaction itself (calldata, velocity, x402 facts)."""
from __future__ import annotations

from sentinel_guard.models import Mandate, Signal, VerifyRequest
from sentinel_guard.sources import AuthoritySource

LAYER = "transaction"
MAX_UINT = (1 << 256) - 1


def _num(x):
    """float or None: context facts come from agents and may be mistyped."""
    if isinstance(x, bool) or x is None:
        return None
    try:
        v = float(x)
    except (TypeError, ValueError, OverflowError):
        return None
    return v if v == v and v not in (float("inf"), float("-inf")) else None


def _dict(x) -> dict:
    return x if isinstance(x, dict) else {}


def _str(x) -> str:
    return x if isinstance(x, str) else ("" if x is None else str(x))


SELECTORS = {
    "095ea7b3": "approve(address,uint256)",
    "a22cb465": "setApprovalForAll(address,bool)",
    "d505accf": "permit(...)",
    "a9059cbb": "transfer(address,uint256)",
    "23b872dd": "transferFrom(address,address,uint256)",
    "39509351": "increaseAllowance(address,uint256)",
}


def nonce_key(issuer: str, nonce: str) -> str:
    """Nonces are counted per issuer: one agent cannot burn another agent's nonce."""
    return f"{(issuer or '').strip().lower()}:{nonce}"


def decode_calldata(calldata: str) -> dict | None:
    cd = (calldata or "").lower().removeprefix("0x")
    if len(cd) < 8 or any(c not in "0123456789abcdef" for c in cd):
        return None
    sel = cd[:8]
    if sel not in SELECTORS:
        return None
    words = [cd[8 + i * 64: 8 + (i + 1) * 64] for i in range((len(cd) - 8) // 64)]
    out = {"selector": sel, "fn": SELECTORS[sel], "args": words}
    if sel in ("095ea7b3", "39509351", "d505accf") and len(words) >= 2:
        out["spender"] = "0x" + words[0][-40:]
        out["value"] = int(words[1], 16)
    if sel == "a22cb465" and len(words) >= 2:
        out["spender"] = "0x" + words[0][-40:]
        out["approved"] = int(words[1], 16) == 1
    return out


def extract(req: VerifyRequest, mandate: Mandate | None, source: AuthoritySource, data: dict) -> list[Signal]:
    sig: list[Signal] = []
    o = req.order

    if o.calldata:
        dec = decode_calldata(o.calldata)
        if dec is None:
            sig.append(Signal("calldata_undecodable", LAYER, 0.50, "calldata cannot be decoded: refusing blind signing"))
        else:
            if dec.get("fn", "").startswith("approve") and dec.get("value", 0) >= (1 << 255):
                sig.append(Signal("approve_unlimited", LAYER, 0.45, f"unlimited ERC-20 approval to {dec.get('spender')}", owasp=["ASI07"]))
            if dec.get("fn", "").startswith("setApprovalForAll") and dec.get("approved"):
                sig.append(Signal("approve_unlimited", LAYER, 0.45, f"setApprovalForAll(true) to {dec.get('spender')}", owasp=["ASI07"]))
            if dec.get("fn", "").startswith("permit"):
                sig.append(Signal("permit_signature", LAYER, 0.30, "permit() signature grants an allowance off-chain"))
            if o.action in ("pay", "transfer") and dec["fn"].startswith(("approve", "setApprovalForAll", "permit", "increaseAllowance")):
                sig.append(Signal("signature_contains_arbitrary_call", LAYER, 1.0, f"a {o.action} order carries an allowance call {dec['fn']}", hard=True, owasp=["ASI07"]))

    if o.nonce:
        # read only: a nonce is spent when its payment goes through (engine), not when an order is merely examined
        if source.nonce_used(nonce_key(o.issuer, o.nonce)):
            sig.append(Signal("nonce_replay", LAYER, 1.0, f"nonce {o.nonce} already used (replay)", hard=True))

    x = _dict(req.context.get("x402"))
    if x:
        q = _num(x.get("quote_amount"))
        if q is not None and o.amount > q * 1.01:
            sig.append(Signal("amount_matches_402_quote", LAYER, 1.0, f"order amount {o.amount} exceeds the 402 quote {q}", hard=True))
        fac = _str(x.get("facilitator")).lower()
        endorsed = [f.lower() for f in data.get("facilitators", [])]
        if fac and endorsed and fac not in endorsed:
            sig.append(Signal("facilitator_endorsed", LAYER, 1.0, f"settlement submitted by non-endorsed facilitator {fac}", hard=True))
        elif fac and source.is_flagged(fac)[0]:
            sig.append(Signal("facilitator_endorsed", LAYER, 1.0, f"facilitator {fac} is flagged in the incident registry", hard=True))
        if (_num(x.get("sybil_score")) or 0) > 0.5:
            sig.append(Signal("server_metadata_sybil_score", LAYER, 0.30, f"service metadata duplicated across endpoints (sybil score {x['sybil_score']})"))
        if x.get("confirmations_met") is False:
            sig.append(Signal("confirmations_required_met", LAYER, 0.20, "settlement delivered before the required block confirmations"))

    h = _dict(req.context.get("history"))
    if h:
        avg = _num(h.get("avg_amount"))
        if avg and o.amount > 3 * avg:
            sig.append(Signal("amount_vs_history_zscore", LAYER, 0.35, f"amount {o.amount} is {o.amount / avg:.1f}x this agent's average {avg}"))
        plh = _num(h.get("payments_last_hour"))
        if plh is not None and plh > 3:
            sig.append(Signal("velocity_1h", LAYER, 0.30, f"{int(plh)} payments in the last hour"))
        bal = _num(h.get("balance"))
        if bal and o.amount > 0.5 * bal:
            sig.append(Signal("amount_vs_balance_ratio", LAYER, 0.30, f"amount is {round(100 * o.amount / float(bal))}% of the balance"))
        if h.get("bank_detail_change_recent") is True:
            sig.append(Signal("bank_detail_change_recent", LAYER, 0.35, "beneficiary details changed recently (call-back verification needed)"))
        if h.get("geo_mismatch") is True:
            sig.append(Signal("geo_mismatch", LAYER, 0.15, "IP / billing / card countries disagree"))

    return sig
