from sentinel_guard.features.counterparty import address_similarity, brand_lookalike
from sentinel_guard.features.transaction import decode_calldata


def test_brand_lookalike():
    brands = ["walmart", "amazon", "wellsfargo"]
    assert brand_lookalike("walmart.com", brands) is None
    assert brand_lookalike("www.amazon.com", brands) is None
    assert brand_lookalike("walmart-deals.lovable.example", brands)
    assert brand_lookalike("wa1mart.example", brands)
    assert brand_lookalike("secure-wellsfargo-login.example", brands)
    assert brand_lookalike("acme-saas.example", brands) is None


def test_address_poisoning():
    known = ["0x5e11e40000000000000000000000000000000001"]
    assert address_similarity("0x5e11e4deadbeefdeadbeefdeadbeefdeadbe0001", known)
    assert address_similarity("0x5e11e40000000000000000000000000000000001", known) is None
    assert address_similarity("0xbad0000000000000000000000000000000000bad", known) is None


def test_calldata_decoding():
    approve_max = "0x095ea7b3" + "dead00000000000000000000000000000000beef".rjust(64, "0") + "f" * 64
    d = decode_calldata(approve_max)
    assert d["fn"].startswith("approve") and d["value"] == (1 << 256) - 1 and d["spender"].endswith("beef")
    assert decode_calldata("0xdeadbeef00") is None
    assert decode_calldata("not hex") is None
