from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from invart.core.artifacts import write_json_artifact
from invart.core.ledger import load_ledger_entries
from invart.control.rules import analyze_command


PATH_POLICY_SCHEMA_VERSION = "invart.path_policy.v0.21"


def check_path_policy(ledger_path: Path, *, profile: dict[str, Any] | None = None, output_path: Path | None = None) -> dict[str, Any]:
    entries, warnings = load_ledger_entries(ledger_path)
    secret_sources: list[dict[str, Any]] = []
    external_instruction_sources: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    benign_actions = 0
    for entry in entries:
        if entry.entry_type != "action" or not entry.event:
            continue
        action = dict(entry.event)
        action_type = str(action.get("action_type") or action.get("type") or "")
        inv = str(action.get("invocation_id") or action.get("event_id"))
        path = str(action.get("path") or "")
        url = str(action.get("url") or "")
        command = str(action.get("command") or "")
        content = str(action.get("metadata", {}).get("raw_content") or action.get("content") or "") if isinstance(action.get("metadata"), dict) else ""
        if _is_secret_path(path):
            secret_sources.append({"invocation_id": inv, "path": path})
        if _is_external_instruction(action, content):
            external_instruction_sources.append({"invocation_id": inv, "summary": content[:160]})
        if secret_sources and action_type == "network" and _is_external_url(url):
            findings.append(_finding("path.secret_to_external_network", "deny", "critical", inv, "Secret-tainted path reached external network egress.", secret_sources[-1]))
        if secret_sources and action_type in {"file_write", "shell"} and _is_ci_or_deploy(path, command):
            findings.append(_finding("path.secret_to_ci_deploy_mutation", "require_approval", "high", inv, "Secret-tainted path reached CI/deploy mutation.", secret_sources[-1]))
        if external_instruction_sources and command and any(item.severity in {"high", "critical"} for item in analyze_command(command)):
            findings.append(_finding("path.external_instruction_to_destructive_shell", "deny", "critical", inv, "External instruction path reached destructive shell.", external_instruction_sources[-1]))
        if not path.startswith("/repo/.env") and not _is_external_url(url) and not command:
            benign_actions += 1

    deny = sum(1 for item in findings if item["effect"] == "deny")
    approvals = sum(1 for item in findings if item["effect"] == "require_approval")
    report = {
        "schema_version": PATH_POLICY_SCHEMA_VERSION,
        "ledger": str(ledger_path),
        "status": "fail" if deny or approvals else "pass",
        "warnings": warnings,
        "summary": {
            "deny": deny,
            "require_approval": approvals,
            "findings": len(findings),
            "false_positive_proxy": 0 if not findings or benign_actions else 1,
            "benign_actions": benign_actions,
        },
        "findings": findings,
        "profile": profile or {"policy_language": "invart-native", "future_compatibility": ["Rego", "Cedar"]},
    }
    if output_path:
        write_json_artifact(output_path, report)
    return report


def _finding(rule_id: str, effect: str, risk: str, invocation_id: str, reason: str, source: dict[str, Any]) -> dict[str, Any]:
    return {
        "rule_id": rule_id,
        "effect": effect,
        "risk": risk,
        "invocation_id": invocation_id,
        "reason": reason,
        "source": source,
        "deterministic": True,
        "llm_can_downgrade": False,
    }


def _is_secret_path(path: str) -> bool:
    lowered = path.lower()
    return any(marker in lowered for marker in (".env", "id_rsa", "id_ed25519", "credentials", "kubeconfig"))


def _is_external_url(url: str) -> bool:
    return bool(url and not any(host in url for host in ("localhost", "127.0.0.1", "::1")))


def _is_ci_or_deploy(path: str, command: str) -> bool:
    text = f"{path} {command}".lower()
    return ".github/workflows" in text or "deploy" in text or "kubectl apply" in text or "terraform apply" in text


def _is_external_instruction(action: dict[str, Any], content: str) -> bool:
    metadata = action.get("metadata") if isinstance(action.get("metadata"), dict) else {}
    trust = str(action.get("trust_level") or metadata.get("trust_level") or "")
    source = str(action.get("source") or metadata.get("source") or "")
    lowered = content.lower()
    return trust == "untrusted" or source in {"issue_comment", "web", "tool_result"} or "ignore previous instructions" in lowered


__all__ = ["check_path_policy"]
