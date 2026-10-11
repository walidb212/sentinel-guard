from sentinel_guard.models import Signal
from sentinel_guard.scoring import combine, noisy_or


def sig(i, w, hard=False):
    return Signal(i, "x", w, "ev", hard)


def test_noisy_or():
    assert noisy_or([]) == 0.0
    assert abs(noisy_or([0.4, 0.2]) - 0.52) < 1e-6
    assert noisy_or([1.0, 0.1]) == 1.0


def test_hard_block_wins_and_skips_llm():
    r = combine([sig("a", 0.1, hard=True)], {"risk_score": 0.0, "reasons": ["fine"]}, 10, 100)
    assert r.verdict == "block" and r.risk == 1.0 and r.severity == 3


def test_thresholds_and_amount_adjustment():
    assert combine([sig("a", 0.25)], {"risk_score": 0.1, "reasons": ["x"]}, 10, 100).verdict == "allow"
    assert combine([sig("a", 0.35)], {"risk_score": 0.1, "reasons": ["x"]}, 10, 100).verdict == "needs_approval"
    assert combine([sig("a", 0.25)], {"risk_score": 0.1, "reasons": ["x"]}, 80, 100).verdict == "needs_approval"  # tightened
    assert combine([sig("a", 0.4), sig("b", 0.4), sig("c", 0.4)], None, 10, 100).verdict == "block"


def test_llm_without_evidence_is_ignored_and_max_is_used():
    r = combine([sig("a", 0.1)], {"risk_score": 0.9, "reasons": []}, 10, 100)
    assert r.risk_llm is None and r.verdict == "allow"
    r = combine([sig("a", 0.1)], {"risk_score": 0.9, "reasons": ["injected directive"]}, 10, 100)
    assert r.risk == 0.9 and r.verdict == "block"


def test_llm_unavailable_never_guesses_allow_on_substantive_signal():
    assert combine([sig("recipient_whitelisted", 0.1)], None, 10, 100).verdict == "needs_approval"
    assert combine([sig("order_origin", 0.2)], None, 80, 100).verdict == "allow"  # informational only
    assert combine([], None, 10, 100).verdict == "allow"


def test_floor_for_undecodable_calldata():
    assert combine([sig("calldata_undecodable", 0.1)], {"risk_score": 0.0, "reasons": ["x"]}, 1, 100).verdict == "needs_approval"


def test_trust_is_degressive_and_deductions_add_up():
    from sentinel_guard.scoring import deductions, trust_from_risk
    assert trust_from_risk(0.0) == 100 and trust_from_risk(1.0) == 0 and trust_from_risk(0.3) == 70
    sigs = [sig("a", 0.4), sig("b", 0.2)]
    d = deductions(sigs)
    assert [x["id"] for x in d] == ["a", "b"]
    assert d[0]["cost"] == 40.0 and d[0]["trust_after"] == 60.0
    assert d[1]["cost"] == 12.0 and d[1]["trust_after"] == 48.0
    assert abs(sum(x["cost"] for x in d) - (100 - trust_from_risk(noisy_or([0.4, 0.2])))) < 0.6
    hard = deductions([sig("x", 0.1), sig("h", 0.1, hard=True)])
    assert hard[0]["id"] == "h" and hard[0]["cost"] == 100.0 and hard[1]["cost"] == 0.0


def test_combine_exposes_trust():
    r = combine([sig("a", 0.4), sig("b", 0.2)], None, 10, 100)
    assert r.trust == 48 and r.verdict == "needs_approval"
