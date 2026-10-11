"""The CLI: init, screen, pending / approve / lift (a human at the terminal, next to a running server), eval."""
from __future__ import annotations

import io
import json
import os
import subprocess
import sys

from sentinel_guard import __version__
from sentinel_guard.cli import main
from sentinel_guard.config import Settings
from sentinel_guard.service import Guard
from tests.conftest import S, T, VENDOR

ME = "0x1234567890abcdef1234567890abcdef12345678"
SHOP = "0x9999999999999999999999999999999999999999"
VENDOR2 = "0x5e11e40000000000000000000000000000000002"


def cli(capsys, *argv) -> tuple[int, str, str]:
    code = main(list(argv))
    out, err = capsys.readouterr()
    return code, out, err


def test_version(capsys):
    try:
        main(["--version"])
    except SystemExit as e:
        assert e.code == 0
    assert capsys.readouterr().out.strip() == f"sentinel-guard {__version__}"


def test_init_registers_an_issuer_and_screen_uses_it(capsys, tmp_path):
    req = tmp_path / "req.json"
    req.write_text(json.dumps({"issuer": ME, "recipient": SHOP, "amount": 40, "source_context": "Order #12: 40 USDC", "context": {"origin": "user"}}))
    code, out, _ = cli(capsys, "screen", str(req))
    before = json.loads(out)
    assert code == 0 and before["verdict"] == "needs_approval"  # unregistered: review mode, never allow

    code, out, _ = cli(capsys, "init", "--issuer", ME, "--max-amount", "100", "--actions", "pay,approve", "--recipients", SHOP)
    written = json.loads(out)
    cfg = tmp_path / "home" / ".sentinel-guard" / "config"
    assert code == 0 and written["config_dir"] == str(cfg)
    mandates = json.loads((cfg / "mandates.json").read_text())
    assert mandates[ME] == {"role": "agent", "allowed_actions": ["pay", "approve"], "max_amount": 100.0, "currency": "USDC",
                            "allowed_recipients": [SHOP], "description": ""}
    assert (cfg / "brands.json").is_file()

    code, out, _ = cli(capsys, "screen", str(req), "--full")
    after = json.loads(out)
    assert code == 0 and after["verdict"] == "allow" and after["mandate"]["source"] == "operator"
    code, out, _ = cli(capsys, "screen", str(req), "--mandate", json.dumps({"max_amount": 10}))
    assert json.loads(out)["verdict"] == "needs_approval"  # a caller mandate tightens


def test_init_rejects_unknown_actions(capsys):
    code, _, err = cli(capsys, "init", "--issuer", ME, "--max-amount", "10", "--actions", "pay,steal")
    assert code == 2 and "steal" in err


def test_screen_reads_stdin_in_engine_format_and_rejects_garbage(capsys, monkeypatch):
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps({"order": {"issuer": T, "action": "pay", "amount": 80, "recipient": VENDOR},
                                                              "source_context": "Invoice", "context": {"origin": "user"}})))
    code, out, _ = cli(capsys, "screen", "-")
    assert code == 0 and json.loads(out)["verdict"] == "allow"
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps({"order": {"issuer": T, "action": "steal", "amount": 1}})))
    code, out, err = cli(capsys, "screen", "-")
    assert code == 2 and out == "" and "action" in err


def test_a_human_at_the_cli_settles_what_a_running_server_holds(tmp_path):
    """The CLI runs in its own process; the server's engine sees the visa and the flag without a restart."""
    g = Guard(Settings.from_env())
    held = dict(issuer=S, recipient=VENDOR2, amount=280, source_context="headphones 280 USDC", context={"origin": "user", "history": {"avg_amount": 28}})
    v = g.screen_payment(**held)
    assert v["verdict"] == "needs_approval"
    env = {"HOME": os.environ["HOME"], "PATH": os.environ.get("PATH", "")}
    run = lambda *a: subprocess.run([sys.executable, "-m", "sentinel_guard", *a], capture_output=True, text=True, env=env, timeout=60)  # noqa: E731
    pending = json.loads(run("pending").stdout)
    assert [p["instruction_id"] for p in pending] == [v["instruction_id"]]
    ok = run("approve", v["instruction_id"], "allow", "--approver", "alice", "--note", "called the user")
    assert ok.returncode == 0 and json.loads(ok.stdout)["approved_by"] == "alice"
    assert run("approve", v["instruction_id"], "allow", "--approver", "alice").returncode == 2  # settled already
    assert g.screen_payment(**held)["verdict"] == "allow"  # the visa reached the running engine: passes once
    assert g.screen_payment(**held)["verdict"] == "needs_approval"  # and only once

    v2 = g.screen_payment(**{**held, "amount": 281})
    assert run("approve", v2["instruction_id"], "block", "--approver", "alice").returncode == 0
    blocked = g.screen_payment(issuer=T, recipient=VENDOR2, amount=10, source_context="Invoice 10 USDC", context={"origin": "user"})
    assert blocked["verdict"] == "block"  # the human's flag reached the running engine
    lifted = run("lift", VENDOR2, "--approver", "alice", "--note", "mistake")
    assert json.loads(lifted.stdout)["lifted"] is True
    assert g.screen_payment(issuer=T, recipient=VENDOR2, amount=10, source_context="Invoice 10 USDC", context={"origin": "user"})["verdict"] == "allow"


def test_eval_reports_full_detection_and_no_false_positive(capsys):
    code, out, _ = cli(capsys, "eval")
    assert code == 0 and "detection rate      100.0 %" in out and "false positive rate 0.0 %" in out and "MISS" not in out
    code, out, _ = cli(capsys, "eval", "--json")
    rep = json.loads(out)
    assert code == 0 and rep["detection_rate"] == 1.0 and rep["false_positive_rate"] == 0.0
    assert rep["attacks"] + rep["controls"] == len(rep["cases"]) == 75


def test_eval_writes_nothing_and_leaks_no_temp_dir(tmp_path, monkeypatch, capsys):
    tmp = tmp_path / "tmp"
    tmp.mkdir()
    monkeypatch.setenv("TMPDIR", str(tmp))
    import tempfile
    monkeypatch.setattr(tempfile, "tempdir", None)
    assert cli(capsys, "eval")[0] == 0
    assert list(tmp.iterdir()) == []
    assert not (tmp_path / "home" / ".sentinel-guard").exists()
