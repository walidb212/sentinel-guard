"""Layer 1: what the agent read. Pure function over the sanitized text."""
from __future__ import annotations

import re

from sentinel_guard import lexicon as L
from sentinel_guard.models import Signal, VerifyRequest
from sentinel_guard.sanitize import Cleaned

LAYER = "content"
PII_FIELDS = re.compile(
    r"""name=["']?(?:ssn|social_?security|dob|date_?of_?birth|birth_?date|maiden|mother|passport|national_?id|tax_?id|id_?number)\b"""
    r"|social security (?:number|no)|date of birth|mother'?s maiden name|passport (?:number|no)|national id\b|num[ée]ro de s[ée]curit[ée] sociale|date de naissance|nom de jeune fille",
    re.I,
)
DEST_ID = re.compile(r"0x[0-9a-fA-F]{40}|\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]{4}){3,7}\b")
PAYMENT_CONTEXT = re.compile(r"\b(?:checkout|card number|cc-number|cvv|cvc|payment|pay now|place order|paiement|commander)\b", re.I)


def _snip(text: str, m, width: int = 70) -> str:
    s, e = max(0, m.start() - 25), min(len(text), m.end() + 25)
    return text[s:e].replace("\n", " ")[:width]


AMOUNT = re.compile(r"\b\d[\d,.]*\s?(?:usdc|usdt|usd|eur|€|\$|eth|btc|dai|avax)\b|[$€]\s?\d", re.I)
DESTINATION = re.compile(r"\bto\s+(?:the\s+)?(?:new\s+)?(?:0x[0-9a-f]{6,}|treasury|vault|wallet|address|account|recipient|beneficiary)\b|\b0x[0-9a-f]{20,}\b", re.I)


def _imperative_hits(text: str, hidden: bool = False) -> list[str]:
    """An instruction aimed at the agent: a control phrase, or a direct address to the agent followed by a
    payment verb or an override. In hidden text a bare routed order (verb + amount + destination) is enough:
    no human can read it, so it is for the agent."""
    hits = []
    for m in L.IMPERATIVE_CONTROL.finditer(text):
        hits.append(_snip(text, m))
    for m in L.AGENT_VOCATIVE.finditer(text):
        window = text[m.start(): m.end() + 200]
        if L.IMPERATIVE_PAY.search(window) or L.OVERRIDE.search(window) or L.MANDATE_OVERRIDE.search(window):
            hits.append(_snip(text, m, 90))
    if hidden:
        for m in L.IMPERATIVE_PAY.finditer(text):
            w = text[m.start(): m.end() + 120]
            if AMOUNT.search(w) and DESTINATION.search(w):
                hits.append(_snip(text, m, 90))
    return hits[:5]


def extract(req: VerifyRequest, cleaned: Cleaned) -> list[Signal]:
    sig: list[Signal] = []
    text = cleaned.all_text
    task = req.task or ""

    # Canary leaving in the order itself = exfiltration of our planted secret.
    outbound = " ".join([req.order.recipient, req.order.memo, req.order.calldata or "", task,
                         str(req.context.get("outbound", ""))])
    if L.CANARY.search(outbound):
        sig.append(Signal("canary_in_outbound", LAYER, 1.0, "canary token present in outbound payload (exfiltration)", hard=True, owasp=["ASI07"]))

    hidden_imp = _imperative_hits(cleaned.hidden, hidden=True) if cleaned.hidden else []
    visible_imp = (_imperative_hits(cleaned.visible) if cleaned.visible else []) + (_imperative_hits(cleaned.attrs) if cleaned.attrs else [])
    blob_imp = [h for b in cleaned.decoded_blobs for h in _imperative_hits(b)]

    if hidden_imp:
        sig.append(Signal("imperative_to_agent", LAYER, 1.0, f"instruction to the agent in HIDDEN content: {hidden_imp[0]!r}", hard=True, owasp=["ASI03", "ASI07"]))
    elif visible_imp:
        # the principal is allowed to instruct its own agent: only process-bending phrases count then, softly
        if req.origin == "user":
            ctrl = [h for h in visible_imp if L.IMPERATIVE_CONTROL.search(h)]
            if ctrl:
                sig.append(Signal("imperative_to_agent", LAYER, 0.35, f"process-bending instruction in the principal's request: {ctrl[0]!r}", owasp=["ASI07"]))
        else:
            sig.append(Signal("imperative_to_agent", LAYER, 0.55, f"instruction aimed at the agent in data: {visible_imp[0]!r}", owasp=["ASI03", "ASI07"]))

    # page code (CSS rules, scripts) is not prose hidden from a reader: the lexicon above still scans it, the ratio does not count it
    truly_hidden = [src for src in cleaned.hidden_sources
                    if (src.startswith("hidden:") and src not in ("hidden:style", "hidden:script")) or src in ("html_comment", "unicode_tags_decoded")]
    if cleaned.hidden and len(cleaned.hidden) > 20 and truly_hidden:
        sig.append(Signal("hidden_text_ratio", LAYER, 0.20, f"{len(cleaned.hidden)} chars hidden from humans ({', '.join(sorted(set(truly_hidden))[:4])}), ratio {cleaned.hidden_ratio:.2f}"))

    m = L.OVERRIDE.search(text)
    if m:
        sig.append(Signal("override_lexicon", LAYER, 0.40, f"override phrase: {_snip(text, m)!r}", owasp=["ASI03"]))

    m = L.MANDATE_OVERRIDE.search(text)
    if m:
        sig.append(Signal("mandate_override_attempt", LAYER, 1.0, f"content tries to change the mandate (limit / recipient / approval): {_snip(text, m)!r}", hard=True, owasp=["ASI03"]))

    m = L.CHAT_DELIMITERS.search(text)
    if m:
        sig.append(Signal("chat_template_delimiters", LAYER, 0.35, f"chat template token inside data: {m.group(0)!r}"))

    if blob_imp:
        sig.append(Signal("encoded_blob_instruction", LAYER, 0.30, f"encoded blob decodes to an instruction: {blob_imp[0]!r}"))
    elif cleaned.decoded_blobs and (L.OVERRIDE.search("\n".join(cleaned.decoded_blobs)) or L.IMPERATIVE_PAY.search("\n".join(cleaned.decoded_blobs))):
        sig.append(Signal("encoded_blob_instruction", LAYER, 0.30, f"encoded blob decodes to: {cleaned.decoded_blobs[0][:60]!r}"))

    uf = cleaned.unicode_findings
    if uf:
        total = sum(uf.values())
        if uf.get("tag_chars") or uf.get("bidi") or total >= 3:
            sig.append(Signal("invisible_unicode_count", LAYER, 0.35, f"{total} invisible/bidi characters: {uf}"))
        else:  # one or two zero-width chars: copy-paste residue, a trace only
            sig.append(Signal("invisible_unicode_trace", LAYER, 0.05, f"{total} zero-width character(s), likely copy-paste residue: {uf}"))
    if cleaned.homoglyph_words:
        sig.append(Signal("homoglyph_script_mix", LAYER, 0.25, f"mixed-script words (homoglyphs): {cleaned.homoglyph_words[:3]}"))

    pressure_text = L.DISCLAIMER.sub(" ", text)
    urg = sorted({m.group(0).lower() for m in L.URGENCY.finditer(pressure_text)})
    if len(urg) >= 3:
        sig.append(Signal("urgency_secrecy_markers", LAYER, 0.30, f"{len(urg)} distinct pressure markers: {urg[:4]}"))
    elif len(urg) == 2:
        sig.append(Signal("urgency_secrecy_markers", LAYER, 0.15, f"2 pressure markers: {urg}"))

    m = L.BANK_DETAIL_CHANGE.search(text)
    if m:
        dests = {d.lower() for d in DEST_ID.findall(text)}
        new_dest = any(d != req.order.recipient for d in dests)
        if new_dest:
            sig.append(Signal("bank_detail_change_notice", LAYER, 0.40, f"content announces new payment details with a destination that is not the current recipient (call-back verification): {_snip(text, m)!r}", owasp=["ASI03"]))
        else:
            sig.append(Signal("payment_details_mention", LAYER, 0.15, f"content mentions a change of payment details but gives no new destination: {_snip(text, m)!r}", owasp=["ASI03"]))

    if L.DISABLE_CONTROLS.search(text):
        sig.append(Signal("disable_logs_or_confirmation_attempt", LAYER, 1.0, f"content asks to disable controls: {L.DISABLE_CONTROLS.search(text).group(0)!r}", hard=True, owasp=["ASI07"]))
    elif req.origin != "user" and L.APPROVAL_CLAIM.search(text):
        sig.append(Signal("approval_claimed_in_data", LAYER, 0.35, f"data claims approval already granted: {L.APPROVAL_CLAIM.search(text).group(0)!r}", owasp=["ASI03"]))

    m = L.AGENT_TARGETED.search(text)
    if m:
        sig.append(Signal("agent_targeted_claims", LAYER, 0.30, f"content courts AI agents without proof: {m.group(0)!r}"))

    history = req.context.get("history") if isinstance(req.context.get("history"), dict) else {}
    if history.get("prior_purchase") is True and L.FOLLOWUP_FEE.search(text) and req.origin in ("email", "webpage", "document", "tool_output"):
        sig.append(Signal("second_payment_after_first", LAYER, 1.0, f"follow-up fee after a purchase: {L.FOLLOWUP_FEE.search(text).group(0)!r}", hard=True))

    raw = req.source_context or ""
    if PII_FIELDS.search(raw) and PAYMENT_CONTEXT.search(raw):
        sig.append(Signal("checkout_overcollects_pii", LAYER, 0.20, f"checkout asks for identity data a purchase never needs: {PII_FIELDS.search(raw).group(0)!r}"))

    # the agent was given a reading job and comes back with a payment: the order was born in what it read (Track 01, problem 2).
    # A paid API call (x402) is the one case where a task without money in it legitimately ends in a payment.
    if task.strip() and L.READ_ONLY_TASK.search(task) and not L.PAYMENT_INTENT.search(task) and not req.context.get("x402"):
        sig.append(Signal("task_order_mismatch", LAYER, 0.50, f"the agent's task is a reading job ({task.strip()[:60]!r}), yet it orders a {req.order.action}: the order comes from what it read",
                          owasp=["ASI03", "ASI07"]))

    if req.origin == "memory":
        sig.append(Signal("order_from_memory_not_current_turn", LAYER, 0.30, "order has no source in the current turn (replayed from memory)"))

    return sig
