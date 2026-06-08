from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

DESTRUCTIVE_COMMANDS = ("rm ", "rm -", "mv ", "chmod ", "chown ", "truncate ", ">")
SECRET_PATH_MARKERS = (".env", "id_rsa", "id_ed25519", "credentials", "kubeconfig")


def check_enforcement(event: dict[str, Any], *, domain: str = "file-write", profile: dict[str, Any] | None = None) -> dict[str, Any]:
    if domain == "file-write":
        return check_file_write_guard(event, profile=profile)
    if domain == "env-secrets":
        return check_env_secrets_guard(event, profile=profile)
    if domain == "network-egress":
        return check_network_egress_guard(event, profile=profile)
    raise ValueError("unknown enforcement domain")


def check_file_write_guard(event: dict[str, Any], *, profile: dict[str, Any] | None = None) -> dict[str, Any]:
    action_type = str(event.get("type") or event.get("action_type") or event.get("operation") or "")
    command = str(event.get("command") or "")
    path = str(event.get("path") or "")
    findings = []
    if action_type in {"file_write", "delete", "shell"} and any(marker in command for marker in DESTRUCTIVE_COMMANDS):
        findings.append({"id": "file.destructive_command", "risk": "high", "title": "Potential destructive file operation"})
    if path and any(marker in path.lower() for marker in SECRET_PATH_MARKERS):
        findings.append({"id": "file.sensitive_path_write", "risk": "high", "title": "Write targets sensitive path"})
    if command and re.search(r"rm\s+-rf\s+(/|\.|\*)", command):
        findings.append({"id": "file.bulk_delete", "risk": "critical", "title": "Bulk delete pattern"})
    return _result("file-write", findings)


def check_env_secrets_guard(event: dict[str, Any], *, profile: dict[str, Any] | None = None) -> dict[str, Any]:
    text = " ".join(str(event.get(key) or "") for key in ("command", "content", "path", "url"))
    findings = []
    if re.search(r"(?i)(api[_-]?key|token|secret|password|akia|sk-)", text):
        findings.append({"id": "env.secret_reference", "risk": "high", "title": "Secret-like value or key referenced"})
    return _result("env-secrets", findings)


def check_network_egress_guard(event: dict[str, Any], *, profile: dict[str, Any] | None = None) -> dict[str, Any]:
    url = str(event.get("url") or "")
    command = str(event.get("command") or "")
    findings = []
    if url and not any(host in url for host in ("localhost", "127.0.0.1")):
        findings.append({"id": "network.external_egress", "risk": "medium", "title": "External network egress"})
    if re.search(r"(?i)(curl|wget).*(upload|post|--data|-d )", command):
        findings.append({"id": "network.upload_like", "risk": "high", "title": "Upload-like outbound command"})
    return _result("network-egress", findings)


def _result(domain: str, findings: list[dict[str, str]]) -> dict[str, Any]:
    critical = any(item.get("risk") == "critical" for item in findings)
    high = any(item.get("risk") == "high" for item in findings)
    return {
        "schema_version": "invart.enforcement.v0.13",
        "domain": domain,
        "effect": "deny" if critical else "require_approval" if high else "allow",
        "failure_mode": "fail-open-with-critical-alert",
        "findings": findings,
    }


def rust_shim_decision(event: dict[str, Any], *, crate_path: Path | None = None, binary_path: Path | None = None) -> dict[str, Any]:
    crate = crate_path or Path("rust/invart-shim")
    binary = binary_path or crate / "target" / "debug" / "invart-shim"
    if not binary.exists():
        build = rust_binary_build(crate)
        if build.get("status") != "pass":
            return _rust_shim_deterministic_fallback(event, reason="rust shim binary unavailable and build failed", build=build)
    try:
        completed = subprocess.run(
            [str(binary)],
            input=json.dumps(event, ensure_ascii=False),
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError as exc:
        return _rust_shim_deterministic_fallback(event, reason=f"rust shim binary could not execute: {exc.strerror or exc}", binary=binary, error=exc)
    try:
        payload = json.loads(completed.stdout or "{}")
    except json.JSONDecodeError:
        payload = {}
    return {
        "schema_version": "invart.rust_shim_decision.v0.13",
        "status": "pass" if completed.returncode == 0 and payload else "fail_open_alert",
        "effect": payload.get("effect", "allow"),
        "failure_mode": "fail-open-with-critical-alert",
        "returncode": completed.returncode,
        "shim": payload,
        "stdout": completed.stdout[-2000:],
        "stderr": completed.stderr[-2000:],
    }


def _rust_shim_deterministic_fallback(
    event: dict[str, Any],
    *,
    reason: str,
    binary: Path | None = None,
    build: dict[str, Any] | None = None,
    error: OSError | None = None,
) -> dict[str, Any]:
    guard = check_file_write_guard(event)
    severity_order = {"critical": 3, "high": 2, "medium": 1, "low": 0}
    finding = max(guard["findings"], key=lambda item: severity_order.get(str(item.get("risk")), -1), default={})
    payload = {
        "schema_version": "invart.rust_shim_fallback.v0.13",
        "effect": guard["effect"],
        "finding_id": finding.get("id"),
        "risk": finding.get("risk"),
        "title": finding.get("title"),
        "source": "python_deterministic_fallback",
    }
    result: dict[str, Any] = {
        "schema_version": "invart.rust_shim_decision.v0.13",
        "status": "pass",
        "effect": guard["effect"],
        "failure_mode": "fail-open-with-critical-alert",
        "fallback": True,
        "reason": reason,
        "shim": payload,
    }
    if binary is not None:
        result["binary"] = str(binary)
    if build is not None:
        result["build"] = build
    if error is not None:
        result["error"] = {"errno": error.errno, "strerror": error.strerror}
    return result


def run_file_write_intercepted(
    command: list[str],
    *,
    ledger_path: Path | None = None,
    session_id: str | None = None,
    target: Path | None = None,
    require_approval_blocks: bool = True,
    crate_path: Path | None = None,
) -> dict[str, Any]:
    if not command:
        raise ValueError("intercepted command cannot be empty")
    event = {
        "type": "shell",
        "command": " ".join(command),
        "session_id": session_id,
        "metadata": {
            "adapter": "invart-rust-file-write-shim",
            "source": "enforce.run_file_write",
            "trust_level": "internal",
        },
    }
    shim = rust_shim_decision(event, crate_path=crate_path)
    effect = str(shim.get("effect") or "allow")
    result: dict[str, Any] = {
        "schema_version": "invart.intercepted_file_write.v0.13",
        "command": command,
        "shim_decision": shim,
        "executed": False,
        "returncode": None,
        "ledger": str(ledger_path) if ledger_path else None,
    }
    decision_id = None
    invocation_id = None
    if ledger_path is not None:
        from invart.core.models import RuntimeEvent
        from invart.control.runtime import record_action, record_outcome

        action, decision, _taint = record_action(
            RuntimeEvent(type="shell", session_id=session_id, command=" ".join(command), metadata=event["metadata"]),
            ledger_path,
            review_mode="off",
            policy_mode="managed",
        )
        decision_id = decision.decision_id
        invocation_id = action.invocation_id
        result["policy_decision"] = decision.to_dict()
    if effect == "deny":
        result["status"] = "blocked"
        result["returncode"] = 126
        if ledger_path is not None:
            from invart.control.runtime import record_outcome

            record_outcome(ledger_path, "blocked", decision_id=decision_id, invocation_id=invocation_id, actor="invart-enforce", reason="rust shim denied file-write command")
        return result
    if effect == "require_approval" and require_approval_blocks:
        result["status"] = "requires_approval"
        result["returncode"] = 125
        if ledger_path is not None:
            from invart.control.runtime import record_outcome

            record_outcome(ledger_path, "blocked", decision_id=decision_id, invocation_id=invocation_id, actor="invart-enforce", reason="rust shim requires approval")
        return result
    completed = subprocess.run(command, cwd=str(target) if target else None, check=False, capture_output=True, text=True)
    result.update({
        "status": "executed" if completed.returncode == 0 else "failed",
        "executed": True,
        "returncode": completed.returncode,
        "stdout": completed.stdout[-4000:],
        "stderr": completed.stderr[-4000:],
    })
    if ledger_path is not None:
        from invart.control.runtime import record_outcome

        record_outcome(
            ledger_path,
            "executed" if completed.returncode == 0 else "failed",
            decision_id=decision_id,
            invocation_id=invocation_id,
            actor="invart-enforce",
            reason="rust shim allowed execution",
        )
    return result


def run_enforced_command(
    command: list[str],
    *,
    domain: str,
    event: dict[str, Any] | None = None,
    ledger_path: Path | None = None,
    session_id: str | None = None,
    target: Path | None = None,
    require_approval_blocks: bool = True,
    profile: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if domain == "file-write":
        return run_file_write_intercepted(
            command,
            ledger_path=ledger_path,
            session_id=session_id,
            target=target,
            require_approval_blocks=require_approval_blocks,
        )
    if not command:
        raise ValueError("enforced command cannot be empty")
    payload = dict(event or {"type": "shell", "command": " ".join(command), "session_id": session_id})
    payload.setdefault("session_id", session_id)
    guard = check_enforcement(payload, domain=domain, profile=profile)
    effect = str(guard.get("effect") or "allow")
    result: dict[str, Any] = {
        "schema_version": "invart.enforced_command.v0.13",
        "domain": domain,
        "command": command,
        "guard": guard,
        "executed": False,
        "returncode": None,
        "ledger": str(ledger_path) if ledger_path else None,
    }
    if effect == "deny" or (effect == "require_approval" and require_approval_blocks):
        result["status"] = "blocked"
        result["returncode"] = 126 if effect == "deny" else 125
        if ledger_path is not None:
            from invart.core.models import RuntimeEvent
            from invart.control.runtime import record_action, record_outcome

            action, decision, _taint = record_action(
                RuntimeEvent(type="shell", session_id=session_id, command=" ".join(command), metadata={"adapter": f"invart-{domain}-guard", "coverage_layer": "wrapper"}),
                ledger_path,
                review_mode="off",
                policy_mode="managed",
            )
            record_outcome(
                ledger_path,
                "blocked",
                decision_id=decision.decision_id,
                invocation_id=action.invocation_id,
                actor="invart-enforce",
                reason=f"{domain} guard blocked execution",
            )
        return result
    completed = subprocess.run(command, cwd=str(target) if target else None, check=False, capture_output=True, text=True)
    result.update(
        {
            "status": "executed" if completed.returncode == 0 else "failed",
            "executed": True,
            "returncode": completed.returncode,
            "stdout": completed.stdout[-4000:],
            "stderr": completed.stderr[-4000:],
        }
    )
    return result


def rust_shim_spec(domain: str = "file-write", crate_path: Path | None = None) -> dict[str, Any]:
    crate = crate_path or Path("rust/invart-shim")
    cargo = crate / "Cargo.toml"
    main_rs = crate / "src" / "main.rs"
    return {
        "schema_version": "invart.rust_shim_spec.v0.13",
        "domain": domain,
        "crate": str(crate),
        "cargo_toml_exists": cargo.exists(),
        "main_rs_exists": main_rs.exists(),
        "binary_target": "invart-shim",
        "event_contract": {"input": "JSON event on stdin or argv[1]", "output": "JSON guard decision"},
        "failure_mode": "fail-open-with-critical-alert",
    }


def rust_binary_build(crate_path: Path | None = None, *, skip_if_unavailable: bool = False) -> dict[str, Any]:
    crate = crate_path or Path("rust/invart-shim")
    cargo = shutil.which("cargo")
    if cargo is None:
        return {
            "schema_version": "invart.rust_binary_build.v0.13",
            "status": "skipped" if skip_if_unavailable else "fail",
            "cargo_available": False,
            "crate": str(crate),
            "reason": "cargo not found",
        }
    completed = subprocess.run([cargo, "build"], cwd=str(crate), check=False, capture_output=True, text=True)
    binary = crate / "target" / "debug" / "invart-shim"
    return {
        "schema_version": "invart.rust_binary_build.v0.13",
        "status": "pass" if completed.returncode == 0 and binary.exists() else "fail",
        "cargo_available": True,
        "crate": str(crate),
        "binary": str(binary),
        "binary_exists": binary.exists(),
        "returncode": completed.returncode,
        "stdout": completed.stdout[-2000:],
        "stderr": completed.stderr[-2000:],
    }


def rust_build_check(crate_path: Path | None = None, *, skip_if_unavailable: bool = False) -> dict[str, Any]:
    crate = crate_path or Path("rust/invart-shim")
    cargo = shutil.which("cargo")
    if cargo is None:
        result = {
            "schema_version": "invart.rust_build_check.v0.13",
            "status": "skipped" if skip_if_unavailable else "fail",
            "cargo_available": False,
            "crate": str(crate),
            "reason": "cargo not found",
        }
        return result
    completed = subprocess.run([cargo, "check"], cwd=str(crate), check=False, capture_output=True, text=True)
    return {
        "schema_version": "invart.rust_build_check.v0.13",
        "status": "pass" if completed.returncode == 0 else "fail",
        "cargo_available": True,
        "crate": str(crate),
        "returncode": completed.returncode,
        "stdout": completed.stdout[-2000:],
        "stderr": completed.stderr[-2000:],
    }
