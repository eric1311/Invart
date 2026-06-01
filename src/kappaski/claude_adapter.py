from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

from .daemon import RuntimeAuthority
from .postruntime import export_proof_report
from .models import utc_now
from .adapter_profiles import build_adapter_profile
from .enforcement import run_file_write_intercepted


def run_claude_code_adapter(
    *,
    target: Path,
    command: list[str],
    hook_events: Path | None = None,
    out_dir: Path | None = None,
    session_id: str | None = None,
    create_preflight: bool = False,
    enforcement: str = "off",
) -> dict[str, Any]:
    if not command:
        raise ValueError("claude-code adapter requires a child command")
    target = target.expanduser().resolve()
    resolved_out = out_dir.expanduser().resolve() if out_dir else target / ".kappaski" / "claude-code-adapter"
    ledger = resolved_out / "ledger.jsonl"
    authority = RuntimeAuthority.for_target(target)
    session = authority.create_session(
        target,
        agent="claude-code",
        goal="Claude Code adapter bridge",
        session_id=session_id,
        ledger_path=ledger,
        create_preflight=create_preflight,
        metadata={"adapter": "claude-code", "bridge": "wrapper+hook-jsonl"},
    )
    ingested = 0
    if hook_events and hook_events.exists():
        for payload in _load_hook_events(hook_events):
            metadata = dict(payload.get("metadata") or {})
            metadata.setdefault("adapter", "claude-code-hook")
            metadata.setdefault("hook_source", str(hook_events))
            payload["metadata"] = metadata
            authority.record_event(session.session_id, payload, review_mode="auto", policy_mode="advisory", reviewer="heuristic")
            ingested += 1
    process_event = {
        "type": "shell",
        "command": " ".join(command),
        "target": str(target),
        "metadata": {
            "adapter": "claude-code-process",
            "operation": "child_command",
            "process_supervision": {
                "mode": "subprocess",
                "started_at": utc_now(),
                "strong_consistency": False,
                "degraded_reason": "portable Python wrapper; native process-tree supervision not enabled",
            },
        },
    }
    if enforcement == "file-write":
        enforced = run_file_write_intercepted(command, ledger_path=ledger, session_id=session.session_id, target=target)
        returncode = int(enforced.get("returncode") if enforced.get("returncode") is not None else 1)
        child_status = str(enforced.get("status"))
    else:
        plan = authority.record_event(session.session_id, process_event, review_mode="auto", policy_mode="advisory", reviewer="heuristic")
        env = dict(os.environ)
        env["KAPPASKI_SESSION_ID"] = session.session_id
        env["KAPPASKI_LEDGER"] = str(ledger)
        env["KAPPASKI_ADAPTER"] = "claude-code"
        completed = subprocess.run(command, cwd=str(target), env=env, check=False)
        returncode = completed.returncode
        child_status = "executed" if completed.returncode == 0 else "failed"
        authority.outcome(
            session.session_id,
            "executed" if completed.returncode == 0 else "failed",
            decision_id=plan["decision"].get("decision_id"),
            actor="claude-code-adapter",
            reason=f"child exited with {completed.returncode}",
        )
    authority.transition_session(session.session_id, "stopped", reason="claude-code adapter completed")
    proof = ledger.with_name("proof.json")
    export_proof_report(ledger, proof)
    return {
        "schema_version": "kappaski.claude_adapter.v0.13",
        "session_id": session.session_id,
        "returncode": returncode,
        "hook_events_ingested": ingested,
        "ledger": str(ledger),
        "proof": str(proof),
        "status": "blocked" if child_status in {"blocked", "requires_approval"} else "passed" if returncode == 0 else "failed",
        "enforcement": enforcement,
    }


def _load_hook_events(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        payload = json.loads(line)
        if not isinstance(payload, dict):
            raise ValueError("hook event must be a JSON object")
        events.append(payload)
    return events


def check_claude_code_environment(binary: str = "claude") -> dict[str, Any]:
    resolved = shutil.which(binary) or (binary if Path(binary).exists() else None)
    profile = build_adapter_profile("claude-code")
    result: dict[str, Any] = {
        "schema_version": "kappaski.claude_environment.v0.10",
        "requested_binary": binary,
        "binary": resolved or binary,
        "available": resolved is not None,
        "adapter_profile": profile,
        "conformance": {
            "status": "not_run",
            "reason": "binary unavailable" if resolved is None else "version probe not requested",
        },
    }
    if resolved is not None:
        try:
            completed = subprocess.run([resolved, "--version"], check=False, capture_output=True, text=True, timeout=10)
            result["conformance"] = {
                "status": "pass" if completed.returncode == 0 else "warn",
                "returncode": returncode,
                "stdout": completed.stdout.strip()[:400],
                "stderr": completed.stderr.strip()[:400],
            }
        except Exception as exc:
            result["conformance"] = {"status": "warn", "reason": str(exc)}
    return result
