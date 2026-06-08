from __future__ import annotations

import uuid
from typing import Any

from invart.core.models import ActionEvent, utc_now


def normalize_native_event(agent: str, payload: dict[str, Any]) -> ActionEvent:
    event_type, tool, command, parameters = _extract_tool_event(agent, payload)
    session_id = str(payload.get("session_id") or payload.get("conversation_id") or f"native_{uuid.uuid4().hex[:8]}")
    invocation_id = f"inv_{uuid.uuid4().hex[:16]}"
    return ActionEvent(
        event_id=invocation_id,
        invocation_id=invocation_id,
        session_id=session_id,
        timestamp=str(payload.get("timestamp") or utc_now()),
        sequence=int(payload.get("sequence") or payload.get("seq") or 0),
        seq=int(payload.get("sequence") or payload.get("seq") or 0),
        action_type=event_type,
        operation=event_type,
        actor=agent,
        adapter=f"native_hook:{agent}",
        command=command,
        tool=tool,
        payload_summary=command or tool,
        source="agent_native_event",
        trust_level="internal",
        metadata={
            "native_payload": payload,
            "native_parameters": parameters,
            "observed_by": ["native_hook"],
            "coverage_layer": "native_hook",
            "vendor_agent": agent,
        },
    )


def render_native_response(agent: str, decision: dict[str, Any]) -> dict[str, Any]:
    effect = str(decision.get("effect") or "")
    reason = str(decision.get("reason") or decision.get("summary") or effect or "invart decision")
    allowed = effect not in {"deny", "block"}
    if agent == "claude-code":
        return {"decision": "allow" if allowed else "block", "reason": reason, "invart": decision}
    if agent == "codex":
        return {"allow": allowed, "message": reason, "invart": decision}
    if agent == "opencode":
        return {"status": "allowed" if allowed else "denied", "message": reason, "invart": decision}
    return {"allow": allowed, "message": reason, "invart": decision}


def bridge_conformance_matrix() -> dict[str, Any]:
    agents = ("claude-code", "codex", "opencode", "generic")
    cases = []
    for agent in agents:
        shell_payload = _fixture_payload(agent, "rm -rf .")
        safe_payload = _fixture_payload(agent, "echo ok")
        for payload, effect in ((shell_payload, "deny"), (safe_payload, "allow")):
            action = normalize_native_event(agent, payload)
            response = render_native_response(agent, {"effect": effect, "reason": f"{agent} {effect} conformance"})
            cases.append(
                {
                    "agent": agent,
                    "effect": effect,
                    "action_type": action.action_type,
                    "response_allowed": _response_allowed(agent, response),
                    "passed": (effect == "allow") == _response_allowed(agent, response) and action.adapter == f"native_hook:{agent}",
                    "response": response,
                }
            )
    passed = sum(1 for item in cases if item["passed"])
    return {
        "schema_version": "invart.bridge_conformance.v0.16",
        "status": "pass" if passed == len(cases) else "fail",
        "summary": {"agents": len(agents), "cases": len(cases), "passed": passed},
        "cases": cases,
    }


def _extract_tool_event(agent: str, payload: dict[str, Any]) -> tuple[str, str, str | None, dict[str, Any]]:
    if agent == "claude-code":
        tool = str(payload.get("tool_name") or payload.get("tool") or "unknown")
        parameters = dict(payload.get("tool_input") or payload.get("arguments") or {})
    elif agent == "codex":
        tool = str(payload.get("tool") or payload.get("tool_name") or "unknown")
        parameters = dict(payload.get("arguments") or payload.get("tool_input") or {})
    elif agent == "opencode":
        tool = str(payload.get("tool") or payload.get("tool_name") or "unknown")
        parameters = dict(payload.get("input") or payload.get("arguments") or {})
    else:
        tool = str(payload.get("tool") or payload.get("tool_name") or "unknown")
        parameters = dict(payload.get("arguments") or payload.get("tool_input") or {})
    command = parameters.get("command")
    event_type = "shell" if tool.lower() in {"bash", "shell", "exec"} and isinstance(command, str) else "tool"
    return event_type, tool, command if isinstance(command, str) else None, parameters


def _fixture_payload(agent: str, command: str) -> dict[str, Any]:
    if agent == "claude-code":
        return {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": command}, "session_id": "bridge-conformance"}
    if agent == "opencode":
        return {"tool": "shell", "input": {"command": command}, "session_id": "bridge-conformance"}
    return {"tool": "shell", "arguments": {"command": command}, "session_id": "bridge-conformance"}


def _response_allowed(agent: str, response: dict[str, Any]) -> bool:
    if agent == "claude-code":
        return response.get("decision") == "allow"
    if agent == "opencode":
        return response.get("status") == "allowed"
    return bool(response.get("allow"))
