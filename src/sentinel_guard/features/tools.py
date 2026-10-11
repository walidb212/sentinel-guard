"""Layer 6 + 7: the tools the agent uses, and the agent's own behaviour."""
from __future__ import annotations

import hashlib

from sentinel_guard import lexicon as L
from sentinel_guard.models import Signal, VerifyRequest

LAYER = "tools"


def extract(req: VerifyRequest, data: dict) -> list[Signal]:
    sig: list[Signal] = []
    inventory = data.get("tools_inventory") or {}

    tools = req.context.get("tools")
    for t in (tools if isinstance(tools, list) else []):
        if not isinstance(t, dict):
            continue
        name = str(t.get("name", "?"))
        desc = t.get("description") if isinstance(t.get("description"), str) else ""
        if desc:
            addressed = L.IMPERATIVE_CONTROL.search(desc) or (L.AGENT_VOCATIVE.search(desc) and L.IMPERATIVE_PAY.search(desc)) or L.OVERRIDE.search(desc)
            if addressed or (L.IMPERATIVE_PAY.search(desc) and ("recipient" in desc.lower() or "0x" in desc)):
                sig.append(Signal("tool_description_has_directives", LAYER, 1.0, f"tool {name!r} description carries an instruction to the agent: {desc[:80]!r}", hard=True, owasp=["ASI07"]))
            elif L.MANDATE_OVERRIDE.search(desc):
                sig.append(Signal("tool_description_has_directives", LAYER, 0.40, f"tool {name!r} description mentions limits/recipients: {desc[:80]!r}", owasp=["ASI07"]))
        inv = inventory.get(name) if isinstance(inventory, dict) else None
        pinned = t.get("pinned_hash") or (inv.get("hash") if isinstance(inv, dict) else None)
        if isinstance(pinned, str) and pinned and desc:
            if hashlib.sha256(desc.encode()).hexdigest() != pinned:
                sig.append(Signal("tool_description_changed", LAYER, 0.50, f"tool {name!r} description differs from the pinned version (rug pull)", owasp=["ASI07"]))
        if inventory and name not in inventory:
            sig.append(Signal("tool_not_pinned", LAYER, 0.30, f"tool {name!r} not in the approved inventory"))

    agent = req.context.get("agent") if isinstance(req.context.get("agent"), dict) else {}
    called = agent.get("tool_called")
    allowed = agent.get("allowed_tools")
    if isinstance(called, str) and isinstance(allowed, (list, tuple, set)) and called not in allowed:
        sig.append(Signal("unexpected_tool_call", LAYER, 0.40, f"agent called {called!r}, outside its allowed tools {list(allowed)}", owasp=["ASI07"]))
    plan = agent.get("planned_actions")
    if isinstance(plan, (list, tuple)) and plan and req.order.action not in [str(p).lower() for p in plan]:
        sig.append(Signal("plan_action_deviation", LAYER, 0.35, f"action {req.order.action!r} was not in the announced plan {plan}"))

    return sig
