"""sentinel-guard [serve] | init | screen | pending | approve | lift | eval

`serve` (the default) speaks MCP on stdio: nothing but protocol goes to stdout there, logs go to stderr.
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from sentinel_guard import __version__
from sentinel_guard.config import Settings, env, read_json, sample_config_dir, user_config_dir
from sentinel_guard.models import ACTIONS, norm_addr


def _logging() -> None:
    level = (env("SENTINEL_LOG_LEVEL") or "WARNING").upper()
    logging.basicConfig(stream=sys.stderr, level=getattr(logging, level, logging.WARNING), format="%(asctime)s %(levelname)s %(name)s: %(message)s")


def _csv(raw: str | None) -> list[str]:
    return [x.strip() for x in (raw or "").split(",") if x.strip()]


def _serve_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--transport", choices=["stdio", "streamable-http"], default=env("SENTINEL_TRANSPORT", "stdio"))
    p.add_argument("--host", default=env("SENTINEL_HOST", "127.0.0.1"))
    p.add_argument("--port", type=int, default=int(env("SENTINEL_PORT", "8000") or 8000))
    p.add_argument("--path", default=env("SENTINEL_HTTP_PATH", "/mcp"))
    p.add_argument("--allowed-host", action="append", default=None, help="Host header value accepted off localhost (repeatable)")
    p.add_argument("--allowed-origin", action="append", default=None, help="Origin header value accepted off localhost (repeatable)")


def _print(obj) -> None:
    sys.stdout.write(json.dumps(obj, indent=2, ensure_ascii=False, default=str) + "\n")


def cmd_serve(a: argparse.Namespace) -> int:
    from sentinel_guard.server import build_server, http_app
    settings = Settings.from_env()
    mcp = build_server(settings)
    log = logging.getLogger("sentinel_guard.cli")
    log.info("sentinel-guard %s: mode=%s llm=%s state=%s", __version__, settings.mode, settings.llm, settings.state_dir)
    if a.transport == "stdio":
        mcp.run()
        return 0
    import uvicorn
    hosts = a.allowed_host or _csv(env("SENTINEL_ALLOWED_HOSTS"))
    origins = a.allowed_origin or _csv(env("SENTINEL_ALLOWED_ORIGINS"))
    if a.host not in ("127.0.0.1", "localhost", "::1") and not settings.http_token:
        log.warning("serving MCP over HTTP off localhost without SENTINEL_HTTP_TOKEN: anyone who reaches %s:%s can call the tools", a.host, a.port)
    try:
        app = http_app(mcp, a.host, a.port, a.path, settings.http_token, hosts, origins)
    except ValueError as e:
        sys.stderr.write(f"sentinel-guard: {e}\n")
        return 2
    uvicorn.run(app, host=a.host, port=a.port, log_level="warning")
    return 0


def cmd_init(a: argparse.Namespace) -> int:
    target = Path(a.config_dir or env("SENTINEL_CONFIG_DIR") or user_config_dir()).expanduser()
    actions = [x.lower() for x in _csv(a.actions)]
    bad = [x for x in actions if x not in ACTIONS]
    if not norm_addr(a.issuer) or bad or a.max_amount < 0 or (a.max_daily or 0) < 0:
        sys.stderr.write(f"sentinel-guard init: need --issuer, --max-amount >= 0 and --actions among {list(ACTIONS)} (got {bad or actions})\n")
        return 2
    target.mkdir(parents=True, exist_ok=True)
    mandates = {k: v for k, v in read_json(target, "mandates.json", {}).items() if norm_addr(k) != norm_addr(a.issuer)}
    entry = {"role": a.role, "allowed_actions": actions, "max_amount": a.max_amount, "currency": a.currency,
             "allowed_recipients": [norm_addr(r) for r in _csv(a.recipients)], "description": a.description}
    if a.max_daily:
        entry["max_daily"] = a.max_daily
    mandates[a.issuer.strip()] = entry
    (target / "mandates.json").write_text(json.dumps(mandates, indent=2) + "\n", encoding="utf-8")
    if not (target / "brands.json").is_file():  # brand names for lookalike detection: generic, worth keeping
        (target / "brands.json").write_text((sample_config_dir() / "brands.json").read_text(encoding="utf-8"), encoding="utf-8")
    _print({"config_dir": str(target), "issuer": a.issuer.strip(), "mandate": entry,
            "note": "other config files are optional (a missing file is empty); restart the MCP server to load the change"})
    return 0


def _guard():
    from sentinel_guard.service import Guard
    return Guard(Settings.from_env())


def cmd_screen(a: argparse.Namespace) -> int:
    from sentinel_guard.schema import to_schema
    from sentinel_guard.service import build_request
    try:
        raw = sys.stdin.read() if a.request == "-" else Path(a.request).read_text(encoding="utf-8")
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise ValueError("the request must be a JSON object")
        mandate = data.pop("mandate", None)
        if a.mandate:
            mandate = json.loads(a.mandate)
        if "order" in data:
            request = data
        else:
            known = ("issuer", "recipient", "amount", "currency", "source_context", "action", "task", "context_type", "context")
            missing = [k for k in ("issuer", "recipient", "amount") if k not in data]
            if missing:
                raise ValueError(f"missing {missing}")
            request = build_request(**{k: v for k, v in data.items() if k in known})
        full = _guard().screen(request, mandate)
    except (OSError, ValueError) as e:
        sys.stderr.write(f"sentinel-guard screen: invalid request: {e}\n")
        return 2
    _print(full if a.full else to_schema(full))
    return 0


def cmd_pending(a: argparse.Namespace) -> int:
    items = _guard().pending()
    if not a.full:
        items = [{"instruction_id": p["instruction_id"], "issuer": p["issuer"], "recipient": p["recipient"], "amount": p["amount"],
                  "currency": p["currency"], "trust_score": p.get("trust_score"), "timestamp": p.get("timestamp"),
                  "reasons": p.get("reasons", [])[:3]} for p in items]
    _print(items)
    return 0


def cmd_approve(a: argparse.Namespace) -> int:
    try:
        _print(_guard().approve(a.instruction_id, a.decision, a.approver, a.note))
    except (KeyError, ValueError) as e:
        sys.stderr.write(f"sentinel-guard approve: {e}\n")
        return 2
    return 0


def cmd_lift(a: argparse.Namespace) -> int:
    _print(_guard().lift_flag(a.subject, a.approver, a.note))
    return 0


def cmd_eval(a: argparse.Namespace) -> int:
    from sentinel_guard import evals
    from sentinel_guard.llm import ClaudeScorer
    llm = ClaudeScorer(provider=env("SENTINEL_LLM") or "off") if a.llm else ClaudeScorer(enabled=False)
    report = evals.run(llm=llm)
    if a.json:
        _print(report)
    else:
        w = sys.stdout.write
        w(f"sentinel-guard eval: {len(report['cases'])} cases ({report['attacks']} attacks, {report['controls']} controls), llm={'on' if report['llm'] else 'off'}\n")
        w(f"detection rate      {report['detection_rate'] * 100:.1f} %\n")
        w(f"false positive rate {report['false_positive_rate'] * 100:.1f} %\n")
        w(f"mean latency        {report['mean_latency_ms']} ms\n")
        for m in report["misses"]:
            w(f"  MISS {m['name']} ({m['family']}): expected {m['expected']}, got {m['verdict']} (trust {m['trust']}) signals={m['signals']}\n")
    return 0 if report["detection_rate"] >= 0.9 and report["false_positive_rate"] == 0 else 1


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="sentinel-guard", description="A verification guard in front of AI agent payments, served over MCP.")
    p.add_argument("--version", action="version", version=f"sentinel-guard {__version__}")
    _serve_args(p)
    sub = p.add_subparsers(dest="cmd")
    _serve_args(sub.add_parser("serve", help="run the MCP server (default: stdio)"))

    i = sub.add_parser("init", help="write an issuer's mandate into the user config dir")
    i.add_argument("--issuer", required=True)
    i.add_argument("--max-amount", type=float, required=True, help="per-order cap in currency units (0 = no cap)")
    i.add_argument("--actions", default="pay", help="comma separated, among pay,approve,transfer,swap")
    i.add_argument("--recipients", default="", help="comma separated addresses or merchant domains (empty = any)")
    i.add_argument("--max-daily", type=float, default=0.0)
    i.add_argument("--currency", default="USDC", help='one currency, or several as "USDC|EUR"')
    i.add_argument("--role", default="agent")
    i.add_argument("--description", default="")
    i.add_argument("--config-dir", default=None)

    s = sub.add_parser("screen", help="screen one request (a JSON file, or - for stdin) and print the verdict")
    s.add_argument("request")
    s.add_argument("--full", action="store_true", help="print the detailed audit record instead of the schema verdict")
    s.add_argument("--mandate", default=None, help="caller mandate as JSON (can only tighten the operator's)")

    pe = sub.add_parser("pending", help="list the decisions waiting for a human")
    pe.add_argument("--full", action="store_true")

    ap = sub.add_parser("approve", help="settle a pending decision")
    ap.add_argument("instruction_id")
    ap.add_argument("decision", choices=["allow", "decline", "block"])
    ap.add_argument("--approver", required=True)
    ap.add_argument("--note", default="")

    li = sub.add_parser("lift", help="take an address or a domain out of the local incident registry")
    li.add_argument("subject")
    li.add_argument("--approver", required=True)
    li.add_argument("--note", default="")

    ev = sub.add_parser("eval", help="run the shipped evaluation corpus (detection rate, false positives)")
    ev.add_argument("--json", action="store_true")
    ev.add_argument("--llm", action="store_true", help="use the LLM configured by SENTINEL_LLM (default: off)")

    a = p.parse_args(argv)
    _logging()
    handlers = {None: cmd_serve, "serve": cmd_serve, "init": cmd_init, "screen": cmd_screen, "pending": cmd_pending,
                "approve": cmd_approve, "lift": cmd_lift, "eval": cmd_eval}
    return handlers[a.cmd](a)


if __name__ == "__main__":
    raise SystemExit(main())
