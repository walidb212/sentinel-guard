"""Layer 4: who gets the money (address or merchant domain)."""
from __future__ import annotations

import re

from sentinel_guard.models import Mandate, Signal, VerifyRequest
from sentinel_guard.sources import AuthoritySource

LAYER = "counterparty"
RISKY_TLDS = (".shop", ".store", ".online", ".xyz", ".top", ".icu", ".click", ".buzz", ".live", ".site")
FREE_HOSTS = ("lovable.app", "vercel.app", "netlify.app", "pages.dev", "github.io", "weebly.com", "wixsite.com", "glitch.me", "repl.co", "web.app", "firebaseapp.com", "webflow.io")
RISKY_PAYMENT = {"crypto", "wire", "bank_transfer", "gift_card", "zelle", "western_union", "moneygram", "cash_app", "usdc", "usdt", "eth", "btc", "bitcoin", "ethereum", "stablecoin", "sol"}
SAFE_PAYMENT = {"card", "credit_card", "paypal", "apple_pay", "google_pay", "stripe", "klarna"}
GENERIC_TOKENS = {"deals", "shop", "store", "official", "outlet", "sale", "discount", "login", "secure", "verify", "account", "support", "online", "pay", "www", "com", "net", "app", "us", "fr", "eu"}


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


FREE_MAIL = ("gmail.com", "protonmail.com", "proton.me", "outlook.com", "hotmail.com", "yahoo.com", "mail.com", "gmx.com", "icloud.com")


def _lev(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _registrable(domain: str) -> tuple[str, str, str]:
    """Return (host, registrable label, tld). Crude, enough for the demo."""
    host = domain.lower().strip().split("/")[0].split(":")[0]
    parts = host.split(".")
    if len(parts) >= 2:
        return host, parts[-2], "." + parts[-1]
    return host, host, ""


def brand_lookalike(domain: str, brands: list[str]) -> str | None:
    host, label, _ = _registrable(domain)
    tokens = [t for t in re.split(r"[-._]", host) if t]
    for brand in brands:
        b = brand.lower()
        if label == b and host.count(".") <= 1 and not any(host.endswith(f) for f in FREE_HOSTS):
            return None  # exact brand domain
        if label != b and _lev(label, b) <= 2 and len(b) >= 5:
            return f"label {label!r} within edit distance 2 of brand {b!r}"
        for t in tokens:
            if t == b or (_lev(t, b) <= 1 and len(b) >= 5):
                if host != b and not host.endswith("." + b + ".com"):
                    return f"brand {b!r} used as a token in {host!r} with extra tokens {sorted(set(tokens) - {t})[:3]}"
    return None


def address_similarity(recipient: str, known: list[str]) -> str | None:
    r = recipient.lower()
    if not r.startswith("0x") or len(r) < 12:
        return None
    for k in known:
        k = k.lower()
        if k != r and k.startswith("0x") and len(k) == len(r) and k[:6] == r[:6] and k[-4:] == r[-4:]:
            return f"recipient {r[:8]}…{r[-4:]} mimics allowlisted {k[:8]}…{k[-4:]} (same prefix/suffix, different body)"
    return None


def _wallets(known: dict) -> list[str]:
    w = known.get("wallet")
    return [str(x).strip().lower() for x in (w if isinstance(w, (list, tuple)) else [w]) if x]


def established(recipient: str, data: dict) -> bool:
    """A counterparty the guard itself knows as long-standing: in the global allowlist, an old active address of its registry,
    or the registered wallet of a domain older than a month. Nothing a caller declares enters here."""
    r = (recipient or "").strip().lower()
    if not r:
        return False
    if r in data.get("allowlist", []):
        return True
    a = _dict((data.get("addresses") or {}).get(r))
    if (_num(a.get("age_days")) or 0) >= 30 and (_num(a.get("tx_count")) or 0) > 0:
        return True
    return any(r in _wallets(d) and (_num(d.get("age_days")) or 0) >= 30 for d in (data.get("domains") or {}).values() if isinstance(d, dict))


def extract(req: VerifyRequest, mandate: Mandate | None, source: AuthoritySource, data: dict, prior: bool | None = None) -> list[Signal]:
    """`prior`: has the guard itself already let this issuer pay this recipient (its own journal)? None = not asked (direct callers)."""
    sig: list[Signal] = []
    o = req.order

    if o.recipient:
        flagged, sev, reason = source.is_flagged(o.recipient)
        if flagged and sev >= 3:
            sig.append(Signal("recipient_flagged_onchain", LAYER, 1.0, f"recipient already flagged in incident registry (severity {sev}): {reason}", hard=True))
        elif flagged and sev == 2:
            sig.append(Signal("recipient_flagged_onchain", LAYER, 0.50, f"recipient has a prior incident (severity {sev}): {reason}"))
        elif flagged:
            sig.append(Signal("recipient_prior_incident_info", LAYER, 0.15, f"recipient appears in a prior protocol-level incident (severity 1): {reason}"))

        known = list((mandate.allowed_recipients if mandate else []) + list(data.get("allowlist", [])))
        sim = address_similarity(o.recipient, known)
        if sim:
            sig.append(Signal("address_poisoning_similarity", LAYER, 0.50, sim))

        info = dict(_dict((data.get("addresses") or {}).get(o.recipient)))
        info.update(_dict(req.context.get("recipient_info")))
        if info:
            age_d, txc = _num(info.get("age_days")), _num(info.get("tx_count"))
            if age_d is not None and age_d < 1 and (txc == 0):
                sig.append(Signal("recipient_age_tx_count", LAYER, 0.20, "recipient address is < 24h old with no transactions"))
            if o.action in ("approve", "swap") and info.get("verified_contract") is False:
                sig.append(Signal("contract_verified", LAYER, 0.20, "target contract source is not verified"))
            if info.get("honeypot") is True or _num(info.get("liquidity")) == 0:
                sig.append(Signal("token_honeypot_or_unverified", LAYER, 0.30, "token flagged honeypot / zero liquidity"))

    merchant = _dict(req.context.get("merchant"))
    domain = _str(merchant.get("domain")).lower().strip()
    known = _dict((data.get("domains") or {}).get(domain)) if domain else {}
    wallets = _wallets(known)

    if o.recipient and prior is not None:
        # who vouches for this recipient, among what the guard knows by itself? What the caller declares does not count.
        listed = o.recipient in (mandate.allowed_recipients if mandate else []) or o.recipient in data.get("allowlist", []) \
            or bool(mandate and domain and domain in mandate.allowed_recipients)
        in_registry = o.recipient in (data.get("addresses") or {}) or bool(known and (not wallets or o.recipient in wallets))
        if not (listed or in_registry or prior):
            sig.append(Signal("counterparty_unverified", LAYER, 0.30,
                              "the guard knows nothing about this recipient: not in a list, no entry for its address or its merchant domain, never paid before"
                              + (f" (declared domain {domain!r} is unknown to the guard)" if domain else " (no merchant declared)"), owasp=["ASI03"]))
    if o.recipient and wallets and o.recipient not in wallets:
        sig.append(Signal("recipient_not_merchant_wallet", LAYER, 0.50,
                          f"{domain} is paid at {wallets[0][:8]}…{wallets[0][-4:]}, not at this recipient: the money leaves for someone else", owasp=["ASI03"]))

    if domain:
        info = {k: v for k, v in merchant.items() if v is not None}
        declared_age = _num(info.get("age_days", info.get("domain_age_days")))
        info.update(known)  # what the guard knows by itself wins over what the caller declares
        if declared_age is not None and (_num(known.get("age_days")) is None or declared_age < _num(known.get("age_days"))):
            info["age_days"] = declared_age  # a caller may bring bad news (a younger domain), never good news
        host, label, tld = _registrable(domain)

        flagged, sev, reason = source.is_flagged(domain)
        if flagged and sev >= 3:
            sig.append(Signal("recipient_flagged_onchain", LAYER, 1.0, f"merchant domain already flagged: {reason}", hard=True))
        if info.get("safe_browsing_flag"):
            sig.append(Signal("safe_browsing_flag", LAYER, 1.0, "domain listed by Safe Browsing", hard=True))

        age = _num(info.get("age_days", info.get("domain_age_days")))
        if age is not None:
            if age < 7:
                sig.append(Signal("domain_age_days", LAYER, 0.50, f"domain registered {age} days ago"))
            elif age < 30:
                sig.append(Signal("domain_age_days", LAYER, 0.30, f"domain registered {age} days ago"))
            # a shop that did not exist last month, and the user is known never to have bought there: the Scamlexity pattern
            declared = _dict(req.context.get("history")).get("prior_purchase")
            if 0 <= age < 30 and (declared is False or (declared is True and prior is False)):
                sig.append(Signal("new_merchant_first_payment", LAYER, 0.50,
                                  f"first payment to a merchant whose domain is {age:g} days old"
                                  + ("" if declared is False else " (an earlier purchase is claimed, the guard has no record of one)"), owasp=["ASI07"]))
        if tld in RISKY_TLDS:
            sig.append(Signal("tld_risk", LAYER, 0.15, f"high-abuse TLD {tld}"))
        if any(host.endswith(f) for f in FREE_HOSTS):
            sig.append(Signal("free_hosting_subdomain", LAYER, 0.40, f"merchant served from free hosting {host}"))
        look = brand_lookalike(domain, data.get("brands", []))
        if look:
            sig.append(Signal("brand_lookalike_score", LAYER, 0.40, look))
        if info.get("tls") is False:
            sig.append(Signal("tls_missing", LAYER, 0.10, "no TLS on checkout domain"))
        if info.get("legal_pages") is False:
            sig.append(Signal("legal_pages_missing", LAYER, 0.15, "no terms / privacy / imprint pages"))
        final = _str(info.get("redirect_final_domain") or info.get("redirects_to")).lower()
        if final and _registrable(final)[1] != label:
            sig.append(Signal("redirect_chain_cross_domain", LAYER, 0.25, f"link to {host} lands on {final}"))
        checkout = _str(info.get("checkout_domain")).lower()
        if checkout and _registrable(checkout)[1] != label and not any(checkout.endswith(p) for p in ("stripe.com", "paypal.com", "shopify.com", "checkout.com", "adyen.com", "mollie.com")):
            sig.append(Signal("checkout_cross_domain", LAYER, 0.15, f"checkout on unrelated domain {checkout}"))
        pm = info.get("payment_methods")
        methods = {str(m).lower() for m in pm} if isinstance(pm, (list, tuple, set)) else set()
        if methods and methods <= RISKY_PAYMENT:
            sig.append(Signal("payment_methods_offered", LAYER, 0.30, f"only irreversible payment methods: {sorted(methods)}"))
        price, market = _num(info.get("price")), _num(info.get("market_price"))
        if price and market and price < 0.5 * market:
            sig.append(Signal("price_deviation", LAYER, 0.20, f"price {price} is {100 - round(100 * price / market)}% below market {market}"))
        if info.get("is_ad"):
            sig.append(Signal("source_is_ad", LAYER, 0.10, "merchant reached through an ad, not organic search"))
        if info.get("overcollects_pii"):
            sig.append(Signal("checkout_overcollects_pii", LAYER, 0.20, "checkout asks for DOB / ID / SSN"))
        rev = _dict(info.get("reviews"))
        burst = _num(rev.get("burst_days"))
        if burst is not None and burst < 14:
            sig.append(Signal("review_profile", LAYER, 0.15, f"all reviews posted within {rev['burst_days']} days"))

    email = _dict(req.context.get("email"))
    if email:
        frm = _str(email.get("from_address")).lower()
        display = _str(email.get("from_display")).lower()
        reply = _str(email.get("reply_to")).lower()
        dom = frm.split("@")[-1]
        reasons = []
        if reply and reply.split("@")[-1] != dom:
            reasons.append(f"reply-to domain {reply.split('@')[-1]} differs from sender {dom}")
        if dom in FREE_MAIL and any(b in display for b in [x.lower() for x in data.get("brands", [])]):
            reasons.append(f"brand {display!r} writing from free mailbox {dom}")
        look = brand_lookalike(dom, data.get("brands", [])) if dom else None
        if look:
            reasons.append(look)
        if reasons:
            sig.append(Signal("sender_identity_mismatch", LAYER, 0.25, "; ".join(reasons)))

    return sig
