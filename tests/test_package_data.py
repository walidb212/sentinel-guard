"""What the package ships: the synthetic example config (never state), the verdict schema, the eval corpus."""
from __future__ import annotations

import hashlib
import json
import re
from importlib import resources

from sentinel_guard.config import CONFIG_FILES, STATE_FILES, sample_config_dir
from sentinel_guard.features import counterparty
from sentinel_guard.models import PaymentOrder, VerifyRequest

PKG = resources.files("sentinel_guard")
# real businesses that appear only as legitimate merchants or a public mail provider; everything else is a reserved .example name
KNOWN_REAL = {"amazon.com", "www.amazon.com", "m.media-amazon.com", "walmart.com", "fnac.com", "zalando.fr", "elcorteingles.es",
              "schema.org", "protonmail.com"}
HOST = re.compile(r"\b[a-z0-9][a-z0-9.-]*\.(?:com|app|io|fr|es|net|org|shop|store|xyz|co|me|online|dev|ai|top|site|live|click)\b", re.I)


def test_example_config_is_exactly_the_documented_files_and_no_state():
    names = {e.name for e in sample_config_dir().iterdir()}
    assert names == set(CONFIG_FILES)
    assert not names & set(STATE_FILES) and not any("threat" in n or "nonce" in n for n in names)


def test_example_config_is_synthetic():
    mandates = json.loads((sample_config_dir() / "mandates.json").read_text())
    assert all(k.lower().startswith("0xa11ce") for k in mandates)
    for e in sample_config_dir().iterdir():
        for host in HOST.findall(e.read_text()):
            assert host.lower() in KNOWN_REAL, (e.name, host)


def test_pinned_tool_hash_is_a_real_sha256_of_its_description():
    inv = json.loads((sample_config_dir() / "tools_inventory.json").read_text())
    assert inv["convert_currency"]["hash"] == hashlib.sha256(b"Converts amounts between currencies.").hexdigest()


def test_eval_corpus_is_shipped_with_reserved_names_only():
    files = [e for e in (PKG / "evals").iterdir() if e.name.endswith(".json")]
    assert len(files) == 75
    for e in files:
        c = json.loads(e.read_text())
        assert "request" in c and "expected" in c
        for host in HOST.findall(e.read_text()):
            assert host.lower() in KNOWN_REAL, (e.name, host)


def test_verdict_schema_is_shipped():
    s = json.loads((PKG / "schema" / "verdict.schema.json").read_text())
    assert s["title"] == "AgenticPaymentVerdict"


# ----- detectors the renamed corpus no longer exercises: covered here explicitly ---------------------------
class _NoFlags:
    def is_flagged(self, key):
        return False, 0, ""


def _signals(domain: str) -> set[str]:
    req = VerifyRequest(PaymentOrder("0xa11ce00000000000000000000000000000000002", "pay", 20, "0x" + "4" * 40), "", "text", "",
                        {"merchant": {"domain": domain}})
    return {s.id for s in counterparty.extract(req, None, _NoFlags(), {"domains": {}, "brands": ["walmart"]})}


def test_high_abuse_tld_and_free_hosting_are_detected():
    assert "tld_risk" in _signals("fictional-shop-for-tests.online")
    assert "free_hosting_subdomain" in _signals("fictional-shop-for-tests.lovable.app")
    plain = _signals("fictional-shop-for-tests.example")
    assert "tld_risk" not in plain and "free_hosting_subdomain" not in plain
