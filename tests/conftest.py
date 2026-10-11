import os

# the user's own environment must not leak into the suite (a canary regex, a config dir, an API key...)
for _k in list(os.environ):
    if _k.startswith("SENTINEL_"):
        del os.environ[_k]

from pathlib import Path  # noqa: E402

import pytest  # noqa: E402

from sentinel_guard.config import sample_config_dir  # noqa: E402
from sentinel_guard.engine import Engine  # noqa: E402
from sentinel_guard.llm import ClaudeScorer  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent

T = "0xa11ce00000000000000000000000000000000001"
S = "0xa11ce00000000000000000000000000000000002"
R = "0xa11ce00000000000000000000000000000000003"
VENDOR = "0x5e11e40000000000000000000000000000000001"
BAD = "0xbad0000000000000000000000000000000000bad"


@pytest.fixture(autouse=True)
def _isolated_home(monkeypatch, tmp_path):
    """No test may read or write the real ~/.sentinel-guard."""
    for k in list(os.environ):
        if k.startswith("SENTINEL_"):
            monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))


@pytest.fixture
def data_dir(tmp_path):
    """The guard's state dir for one test, empty at start. The config is the shipped example, only ever read."""
    d = tmp_path / "state"
    d.mkdir()
    return d


def make_engine(data_dir, llm_fn=None, enabled=False, unregistered="block", **kw):
    """The ported suite pins SENTINEL_UNREGISTERED=block, the strict policy (an issuer unknown to the operator is a hard block).
    Review mode, the server default, has its own tests in test_mandate_policy.py."""
    return Engine.build(config_dir=sample_config_dir(), state_dir=data_dir, llm=ClaudeScorer(score_fn=llm_fn, enabled=enabled),
                        unregistered=unregistered, **kw)


@pytest.fixture
def engine(data_dir):
    return make_engine(data_dir)
