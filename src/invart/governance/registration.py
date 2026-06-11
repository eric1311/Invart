from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from invart.core.artifacts import stable_json_hash, write_json_artifact
from invart.core.models import utc_now
from invart.surfaces.adapter_profiles import get_adapter_profile
from invart.surfaces.launcher import verify_managed_launcher
from invart.surfaces.native import unmanaged_agent_inventory


REGISTRY_SCHEMA_VERSION = "invart.enterprise_agent_registry.v0.9.15"
GAPS_SCHEMA_VERSION = "invart.enterprise_registration_gaps.v0.9.15"
GATE_SCHEMA_VERSION = "invart.enterprise_registration_gate.v0.9.15"


def export_agent_registry(
    target: Path,
    *,
    agents: list[str],
    owner: str,
    scope: str = "repo",
    output_path: Path | None = None,
    launcher: str = "shell",
    distributed_by: str = "local-declaration",
) -> dict[str, Any]:
    if not owner:
        raise ValueError("agent registry owner is required")
    if scope not in {"session", "repo", "team"}:
        raise ValueError("agent registry scope must be session, repo, or team")
    target = target.expanduser().resolve()
    entries = [
        _registration_entry(target, agent=agent, owner=owner, scope=scope, launcher=launcher)
        for agent in sorted({str(agent) for agent in agents if str(agent)})
    ]
    registry = {
        "schema_version": REGISTRY_SCHEMA_VERSION,
        "status": "pass",
        "target": str(target),
        "owner": owner,
        "scope": scope,
        "distributed_by": distributed_by,
        "created_at": utc_now(),
        "agents": entries,
        "summary": {
            "registered_agents": len(entries),
            "managed_launchers": sum(1 for entry in entries if entry.get("launcher", {}).get("status") == "pass"),
            "mediated_capable": sum(1 for entry in entries if entry.get("profile", {}).get("supports_mediation") is True),
        },
        "claim_boundary": "The enterprise registry is an auditable local authority over enrolled agents and launchers; it does not discover or control agents that never enter registered launch, wrapper, bridge, or proxy boundaries.",
    }
    registry["registry_hash"] = stable_json_hash({key: value for key, value in registry.items() if key != "registry_hash"})
    if output_path:
        write_json_artifact(output_path.expanduser().resolve(), registry)
    return registry


def load_agent_registry(path: Path) -> dict[str, Any]:
    payload = json.loads(path.expanduser().resolve().read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("agent registry must be a JSON object")
    if payload.get("schema_version") != REGISTRY_SCHEMA_VERSION:
        raise ValueError("unsupported agent registry schema")
    return payload


def verify_registered_launch(
    registry: dict[str, Any] | Path,
    *,
    agent: str,
    declared_agent: str | None = None,
    principal_id: str | None = None,
    profile: dict[str, Any] | None = None,
) -> dict[str, Any]:
    registry_payload = load_agent_registry(registry) if isinstance(registry, Path) else registry
    profile = profile or {}
    registration_policy = profile.get("registration") if isinstance(profile.get("registration"), dict) else {}
    enterprise_mode = profile.get("mode") == "enterprise" or bool(registration_policy.get("required"))
    require_managed_launcher = bool(registration_policy.get("require_managed_launcher", enterprise_mode))
    findings: list[dict[str, Any]] = []
    entry = _entry_for_agent(registry_payload, agent)
    declared = declared_agent or agent

    if enterprise_mode and not principal_id:
        findings.append(_finding("registration.principal_missing", "enterprise registration gate requires accountable principal"))
    if declared != agent:
        findings.append(_finding("registration.agent_mismatch", "declared agent does not match requested launch agent"))
    if not entry:
        findings.append(_finding("registration.unregistered_agent", "agent is not enrolled in the enterprise registry"))
    if entry and require_managed_launcher and entry.get("launcher", {}).get("status") != "pass":
        findings.append(_finding("registration.managed_launcher_missing", "enterprise launch requires a verified Invart-managed launcher"))

    coverage = _coverage_for_entry(entry)
    status = "pass" if not findings else "fail"
    return {
        "schema_version": GATE_SCHEMA_VERSION,
        "status": status,
        "agent": agent,
        "declared_agent": declared,
        "accountability": {"principal_id": principal_id, "registry_owner": registry_payload.get("owner")},
        "registration": entry,
        "coverage": coverage,
        "findings": findings,
        "decision": "allow" if status == "pass" else "deny" if enterprise_mode else "audit",
        "claim_boundary": "A pass means the launch request matches an enrolled agent and required launcher boundary; it does not imply control over unmanaged direct launches outside Invart.",
    }


def unmanaged_registration_gaps(
    target: Path,
    registry: dict[str, Any] | Path,
    *,
    include_global_config: bool = False,
) -> dict[str, Any]:
    registry_payload = load_agent_registry(registry) if isinstance(registry, Path) else registry
    registered = {str(entry.get("agent")) for entry in registry_payload.get("agents", []) if isinstance(entry, dict)}
    inventory = unmanaged_agent_inventory(target, include_global_config=include_global_config)
    findings: list[dict[str, Any]] = []
    for item in inventory.get("findings", []):
        if not isinstance(item, dict):
            continue
        agent = str(item.get("agent") or "")
        registered_entry = _entry_for_agent(registry_payload, agent)
        launcher_ok = bool(registered_entry and registered_entry.get("launcher", {}).get("status") == "pass")
        if agent in registered and launcher_ok:
            continue
        findings.append(
            {
                "finding_id": f"registration-gap:{agent}:{item.get('surface')}",
                "agent": agent,
                "surface": item.get("surface"),
                "severity": "high" if agent not in registered else "medium",
                "registered": agent in registered,
                "managed_launcher": launcher_ok,
                "source_evidence": item.get("source_evidence", []),
                "coverage_fact": item.get("coverage_fact", {}),
                "recommendation": f"enroll {agent} in the enterprise registry and verify a managed launcher or bridge before claiming managed coverage",
            }
        )
    return {
        "schema_version": GAPS_SCHEMA_VERSION,
        "status": "pass",
        "target": str(target.expanduser().resolve()),
        "registry_hash": registry_payload.get("registry_hash"),
        "findings": findings,
        "summary": {"gaps": len(findings), "agents": len({item["agent"] for item in findings})},
        "claim_boundary": "Registration gaps are discovery evidence; this report does not claim runtime enforcement for unregistered or direct-launched agents.",
    }


def _registration_entry(target: Path, *, agent: str, owner: str, scope: str, launcher: str) -> dict[str, Any]:
    profile = get_adapter_profile(agent)
    launcher_report = verify_managed_launcher(target, agent=agent, launcher=launcher)
    entry = {
        "agent": agent,
        "owner": owner,
        "scope": scope,
        "profile": profile,
        "profile_hash": stable_json_hash(profile),
        "launcher": {
            "status": launcher_report.get("status"),
            "target_path": launcher_report.get("target_path"),
            "manifest_path": launcher_report.get("manifest_path"),
            "coverage": launcher_report.get("coverage", {}),
            "checks": launcher_report.get("checks", {}),
        },
        "verification_state": "verified" if launcher_report.get("status") == "pass" else "registered_without_verified_launcher",
        "registered_at": utc_now(),
    }
    entry["registration_hash"] = stable_json_hash({key: value for key, value in entry.items() if key != "registration_hash"})
    return entry


def _entry_for_agent(registry: dict[str, Any], agent: str) -> dict[str, Any] | None:
    for entry in registry.get("agents", []):
        if isinstance(entry, dict) and entry.get("agent") == agent:
            return entry
    return None


def _coverage_for_entry(entry: dict[str, Any] | None) -> dict[str, Any]:
    if not entry:
        return {"runtime_observation": "none", "runtime_enforcement": "none", "coverage_grade": "unregistered"}
    launcher = entry.get("launcher", {}) if isinstance(entry.get("launcher"), dict) else {}
    if launcher.get("status") == "pass":
        return {"runtime_observation": "mediated", "runtime_enforcement": "mediated", "coverage_grade": "registered_managed_launcher"}
    profile = entry.get("profile", {}) if isinstance(entry.get("profile"), dict) else {}
    return {
        "runtime_observation": "registered",
        "runtime_enforcement": "none",
        "coverage_grade": profile.get("coverage_grade", "registered_without_launcher"),
    }


def _finding(check_id: str, message: str) -> dict[str, Any]:
    return {"check_id": check_id, "severity": "high", "message": message}


__all__ = [
    "export_agent_registry",
    "load_agent_registry",
    "unmanaged_registration_gaps",
    "verify_registered_launch",
]
