"""The shipped evaluation corpus: attacks and benign controls, run against the shipped example config.

Each case runs on a fresh engine with its own temporary state dir, removed afterwards: nothing tracked is written.
Meta keys: `_after` (verify another case first, on the same engine: the second agent meets the first one's flag) and
`_replay` (verify the same request N times: replay protection). Detection = attacks whose verdict is in the expected list;
false positive = a control whose verdict is not.
"""
from __future__ import annotations

import copy
import json
import tempfile
import time
from importlib import resources
from typing import Any

from sentinel_guard.config import sample_config_dir
from sentinel_guard.engine import Engine
from sentinel_guard.llm import ClaudeScorer


def load_cases() -> dict[str, dict]:
    root = resources.files("sentinel_guard") / "evals"
    cases: dict[str, dict] = {}
    for entry in sorted((e for e in root.iterdir() if e.name.endswith(".json")), key=lambda e: e.name):
        c = json.loads(entry.read_text(encoding="utf-8"))
        if "request" not in c or "expected" not in c:
            continue
        name = entry.name[:-5]
        exp = c["expected"]
        if isinstance(exp, dict):  # demo fixtures: {"verdict": ..., "signals": [...]}
            exp = [exp["verdict"]]
            family = "control" if exp == ["allow"] else c.get("family", "demo")
        else:
            exp = [exp] if isinstance(exp, str) else list(exp)
            family = c.get("family", "?")
        cases[name] = {"name": name, "family": family, "expected": exp, "request": c["request"], "description": c.get("description", "")}
    return cases


def _strip(request: dict) -> tuple[dict, int, str | None]:
    req = copy.deepcopy(request)
    ctx = req.get("context") or {}
    replay = int(ctx.pop("_replay", 1) or 1)
    after = ctx.pop("_after", None)
    return req, max(1, replay), after


def run(llm: ClaudeScorer | None = None, cases: dict[str, dict] | None = None) -> dict[str, Any]:
    cases = cases if cases is not None else load_cases()
    rows = []
    for name, c in cases.items():
        with tempfile.TemporaryDirectory(prefix="sentinel-eval-") as td:
            engine = Engine.build(config_dir=sample_config_dir(), state_dir=td, llm=llm or ClaudeScorer(enabled=False))
            req, replay, after = _strip(c["request"])
            if after:
                engine.verify(_strip(cases[after]["request"])[0])
            t0 = time.perf_counter()
            for _ in range(replay):
                out = engine.verify(req)
            ms = (time.perf_counter() - t0) * 1000 / replay
        rows.append({"name": name, "family": c["family"], "expected": c["expected"], "verdict": out["verdict"], "trust": out["trust_score"],
                     "risk": out["risk_score"], "ok": out["verdict"] in c["expected"], "latency_ms": round(ms, 2),
                     "signals": sorted(s["id"] for s in out["signals"])})
    attacks = [r for r in rows if r["family"] != "control"]
    controls = [r for r in rows if r["family"] == "control"]
    det = sum(r["ok"] for r in attacks) / len(attacks) if attacks else 0.0
    fp = sum(not r["ok"] for r in controls) / len(controls) if controls else 0.0
    return {"detection_rate": round(det, 4), "false_positive_rate": round(fp, 4), "attacks": len(attacks), "controls": len(controls),
            "mean_latency_ms": round(sum(r["latency_ms"] for r in rows) / len(rows), 2) if rows else 0.0,
            "llm": bool(llm and llm.enabled), "misses": [r for r in rows if not r["ok"]], "cases": rows}
