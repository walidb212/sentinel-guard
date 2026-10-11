"""stdio carries nothing but JSON-RPC on stdout (logs go to stderr); streamable HTTP enforces the optional bearer token."""
from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

import pytest

from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.shared._httpx_utils import create_mcp_http_client

from tests.conftest import T, VENDOR
from tests.helpers import free_port

ARGS = {"issuer": T, "recipient": VENDOR, "amount": 80, "source_context": "Monthly SaaS invoice, 80 USDC.", "context": {"origin": "user"}}


def _env(tmp_path, **kw):
    e = {"HOME": str(tmp_path / "home"), "SENTINEL_STATE_DIR": str(tmp_path / "state"), "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
         "PYTHONUNBUFFERED": "1"}
    e.update(kw)
    return e


def test_stdout_carries_only_json_rpc_even_with_debug_logs(tmp_path):
    p = subprocess.Popen([sys.executable, "-m", "sentinel_guard"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         env=_env(tmp_path, SENTINEL_LOG_LEVEL="DEBUG"), text=True)
    msgs = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                                                                     "clientInfo": {"name": "raw-test", "version": "1"}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "screen_payment", "arguments": ARGS}},
    ]
    lines: list[str] = []

    def read():
        for line in p.stdout:
            lines.append(line)
            try:
                if json.loads(line).get("id") == 3:
                    return
            except ValueError:
                return

    reader = threading.Thread(target=read, daemon=True)
    reader.start()
    for m in msgs:
        p.stdin.write(json.dumps(m) + "\n")
        p.stdin.flush()
    reader.join(30)
    p.stdin.close()
    try:
        p.wait(10)
    except subprocess.TimeoutExpired:
        p.kill()
    stderr = p.stderr.read()
    assert lines, stderr
    decoded = [json.loads(l) for l in lines if l.strip()]  # any stray print would fail here
    assert all(d.get("jsonrpc") == "2.0" for d in decoded)
    result = next(d for d in decoded if d.get("id") == 3)["result"]
    assert result.get("isError") is False and result["structuredContent"]["verdict"] == "allow"
    assert {t["name"] for t in next(d for d in decoded if d.get("id") == 2)["result"]["tools"]} == {"screen_payment", "authorize_payment", "explain_decision"}


@pytest.fixture
def http_server(tmp_path):
    port = free_port()
    p = subprocess.Popen([sys.executable, "-m", "sentinel_guard", "serve", "--transport", "streamable-http", "--port", str(port)],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=_env(tmp_path, SENTINEL_HTTP_TOKEN="http-token-123"))
    url = f"http://127.0.0.1:{port}/mcp"
    deadline = time.time() + 30
    while time.time() < deadline:
        try:
            urllib.request.urlopen(urllib.request.Request(url, method="GET"), timeout=1)
            break
        except urllib.error.HTTPError:
            break  # the server answers (401 without the token)
        except OSError:
            time.sleep(0.2)
    yield url
    p.terminate()
    try:
        p.wait(10)
    except subprocess.TimeoutExpired:
        p.kill()


def test_http_requires_the_bearer_token(http_server):
    with pytest.raises(urllib.error.HTTPError) as e:
        urllib.request.urlopen(urllib.request.Request(http_server, data=b"{}", method="POST", headers={"Content-Type": "application/json"}), timeout=5)
    assert e.value.code == 401 and e.value.headers.get("WWW-Authenticate") == "Bearer"
    with pytest.raises(urllib.error.HTTPError) as e:
        urllib.request.urlopen(urllib.request.Request(http_server, data=b"{}", method="POST", headers={"Authorization": "Bearer wrong"}), timeout=5)
    assert e.value.code == 401


def test_http_with_the_token_screens_a_payment(http_server):
    async def go():
        async with create_mcp_http_client(headers={"Authorization": "Bearer http-token-123"}) as client:
            async with streamable_http_client(http_server, http_client=client) as streams:
                async with ClientSession(streams[0], streams[1]) as s:
                    await s.initialize()
                    return await s.call_tool("screen_payment", ARGS)
    res = asyncio.run(asyncio.wait_for(go(), 60))
    assert res.is_error is False and res.structured_content["verdict"] == "allow"


def test_binding_every_interface_needs_allowed_hosts(tmp_path):
    out = subprocess.run([sys.executable, "-m", "sentinel_guard", "serve", "--transport", "streamable-http", "--host", "0.0.0.0", "--port", str(free_port())],
                         capture_output=True, text=True, env=_env(tmp_path), timeout=30)
    assert out.returncode == 2 and "--allowed-host" in out.stderr and out.stdout == ""
