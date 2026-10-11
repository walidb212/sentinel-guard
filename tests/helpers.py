"""A local stand-in for the hosted Sentinel API (GET /flagged/{address}, POST /authorize). Records every request."""
from __future__ import annotations

import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable

from sentinel_guard.config import Settings, sample_config_dir


class MockAPI:
    def __init__(self, flagged: dict[str, int] | None = None, authorize: Callable[[dict], tuple[int, Any]] | None = None):
        self.flagged = {k.lower(): v for k, v in (flagged or {}).items()}
        self.authorize = authorize or self.default_authorize
        self.requests: list[dict] = []
        self._server: ThreadingHTTPServer | None = None

    @staticmethod
    def default_authorize(body: dict) -> tuple[int, Any]:
        v = body["verdict"]
        out = {"status": "ok", "verdict": v, "payment_id": "0x" + "ab" * 32, "nonce": body["payment"].get("nonce"), "decision_tx": "0x" + "dd" * 32}
        out["visa_tx" if v == "allow" else "flag_tx" if v == "block" else "noop"] = "0x" + ("11" if v == "allow" else "22") * 32
        out.pop("noop", None)
        return 200, out

    @property
    def url(self) -> str:
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}"

    def __enter__(self) -> "MockAPI":
        api = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):  # quiet
                pass

            def _send(self, status: int, payload: Any) -> None:
                data = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                api.requests.append({"method": "GET", "path": self.path, "headers": dict(self.headers), "body": None})
                if self.path.startswith("/flagged/"):
                    addr = self.path.split("/")[-1].lower()
                    sev = api.flagged.get(addr, 0)
                    return self._send(200, {"address": addr, "flagged": bool(sev), "severity": sev})
                self._send(404, {"detail": "not found"})

            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(n) or b"{}")
                api.requests.append({"method": "POST", "path": self.path, "headers": dict(self.headers), "body": body})
                if self.path == "/authorize":
                    status, payload = api.authorize(body)
                    return self._send(status, payload)
                self._send(404, {"detail": "not found"})

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self._server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
        return self

    def __exit__(self, *exc) -> None:
        self._server.shutdown()
        self._server.server_close()

    def calls(self, method: str, prefix: str) -> list[dict]:
        return [r for r in self.requests if r["method"] == method and r["path"].startswith(prefix)]


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def settings(state_dir, **kw) -> Settings:
    """Explicit settings for one test: the shipped example config, a private state dir, LLM off, local mode unless told."""
    base = dict(config_dir=sample_config_dir(), state_dir=state_dir, mode="local", llm="off", unregistered="review")
    base.update(kw)
    return Settings(**base)
