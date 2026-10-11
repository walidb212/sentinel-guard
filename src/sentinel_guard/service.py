"""The guard as the MCP tools and the CLI see it: screen, authorize (connected mode), explain, and the human's commands."""
from __future__ import annotations

from typing import Any

from sentinel_guard.config import Settings
from sentinel_guard.engine import Engine
from sentinel_guard.hosted import ADDRESS, AuthorizeClient, onchain_record, strictest
from sentinel_guard.schema import to_schema

MAX_TTL = 86400


def build_request(issuer: str, recipient: str, amount: Any, currency: str = "USDC", source_context: str = "", action: str = "pay",
                  task: str = "", context_type: str = "text", context: dict | None = None) -> dict:
    return {"order": {"issuer": issuer, "action": action, "amount": amount, "currency": currency, "recipient": recipient},
            "source_context": source_context, "context_type": context_type, "task": task, "context": context or {}}


class Guard:
    def __init__(self, settings: Settings | None = None, engine: Engine | None = None):
        self.settings = settings or Settings.from_env()
        self.engine = engine or Engine.from_settings(self.settings)
        s = self.settings
        self.client = AuthorizeClient(s.api, s.api_key, s.amount_decimals, s.api_timeout) if s.connected else None

    # ----- the agent's tools -----
    def screen(self, request: dict, mandate: Any = None) -> dict:
        """The detailed engine record (audit). Raises ValueError for a malformed request."""
        return self.engine.verify(request, caller_mandate=mandate)

    def screen_payment(self, mandate: Any = None, **order: Any) -> dict:
        return to_schema(self.screen(build_request(**order), mandate))

    def authorize_payment(self, mandate: Any = None, ttl: int = 300, **order: Any) -> dict:
        """Screen locally, then (connected mode) ask the hosted API to record the decision on-chain. A network failure keeps
        the local verdict and says so in `onchain`; the server may only tighten the verdict, never loosen it."""
        request = build_request(**order)
        full = self.screen(request, mandate)
        flat = to_schema(full)
        if self.client is None:
            onchain = onchain_record("skipped", reason="local-only mode (no SENTINEL_API_KEY, or SENTINEL_MODE=local): nothing recorded on-chain")
        elif not (ADDRESS.fullmatch(full["issuer"]) and ADDRESS.fullmatch(full["recipient"] or "")):
            onchain = onchain_record("skipped", reason="on-chain records need EVM addresses (0x + 40 hex) for issuer and recipient")
        else:
            screen = {"order": {"issuer": full["issuer"], "action": full["action"], "amount": full["amount"], "currency": full["currency"],
                                "recipient": full["recipient"]},
                      "source_context": request["source_context"], "context_type": request["context_type"], "task": request["task"],
                      "context": request["context"]}
            onchain = self.client.authorize(full, screen, ttl=max(1, min(int(ttl), MAX_TTL)))
        recorded = onchain["status"] == "recorded"
        effective = strictest(flat["verdict"], *((onchain["verdict"], onchain["server_verdict"]) if recorded else ()))
        if effective != flat["verdict"]:
            flat["reasons"].append(f"[server] the hosted re-screen tightened the verdict from {flat['verdict']} to {effective}")
            flat["verdict"] = effective
        tx = onchain.get("visa_tx") or onchain.get("flag_tx") or onchain.get("decision_tx")
        flat["tx_hash"] = tx
        flat["explorer_url"] = f"{self.settings.explorer}/tx/{tx}" if tx else None
        flat["onchain"] = onchain
        return flat

    def explain(self, instruction_id: str) -> dict:
        found = self.engine.decision(instruction_id)
        if found is None:
            return {"found": False, "instruction_id": instruction_id, "message": "no decision recorded for this id in the local audit trail"}
        return {"found": True, **found}

    # ----- the human's commands -----
    def pending(self) -> list[dict]:
        return self.engine.pending()

    def approve(self, instruction_id: str, decision: str, approver: str, note: str = "") -> dict:
        return self.engine.approve(instruction_id, decision, approver, note)

    def lift_flag(self, subject: str, approver: str, note: str = "") -> dict:
        return self.engine.lift_flag(subject, approver, note)
