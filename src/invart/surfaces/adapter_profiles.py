from __future__ import annotations

import os
from dataclasses import asdict, dataclass, field
from typing import Any

SECRET_KEY_MARKERS = ("KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL", "AUTH", "SSH")
PROFILE_SCHEMA_VERSION = "invart.adapter_profile.v0.10"
PROFILE_REGISTRY_SCHEMA_VERSION = "invart.agent_adapter_profile_registry.v0.9.3"


@dataclass(frozen=True)
class AgentAdapterProfile:
    agent_id: str
    display_name: str
    priority: str
    execution_modes: list[str]
    native_surfaces: list[str]
    event_sources: list[str]
    coverage_grade: str
    claim_boundary: str
    required_artifacts: list[str]
    source_urls: list[str]
    last_reviewed: str = "2026-06-10"
    binary_candidates: list[str] = field(default_factory=list)
    supports_mediation: bool = False
    can_block: bool = False
    can_pause_resume: bool = False
    integration_track: str | None = None
    track_status: str | None = None
    adapter_family: str | None = None
    control_position: str | None = None

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        derived = _derive_track(payload)
        for key, value in derived.items():
            if not payload.get(key):
                payload[key] = value
        return payload


_PROFILES: tuple[AgentAdapterProfile, ...] = (
    AgentAdapterProfile(
        agent_id="claude-code",
        display_name="Claude Code",
        priority="p0_reference_full_adapter",
        execution_modes=["managed_runtime", "native_event_bridge", "managed_wrapper"],
        native_surfaces=["hooks", "permissions", "settings", "mcp", "slash_commands"],
        event_sources=["wrapper_command", "session_env", "tool_event_bridge", "hook_jsonl"],
        coverage_grade="full_managed_adapter",
        claim_boundary="Full pre-1.0 claim only applies when Claude Code is launched through Invart-managed wrapper or hook bridge; direct unmanaged Claude runs remain coverage gaps.",
        required_artifacts=["ledger", "proof", "replay", "path_graph", "coverage", "audit", "evidence_bundle"],
        source_urls=["https://code.claude.com/docs/en/hooks", "https://code.claude.com/docs/en/permissions"],
        binary_candidates=["claude"],
        supports_mediation=True,
        can_block=True,
        can_pause_resume=True,
    ),
    AgentAdapterProfile(
        agent_id="codex",
        display_name="OpenAI Codex",
        priority="p0_local_wrapper",
        execution_modes=["managed_wrapper", "vendor_evidence_import"],
        native_surfaces=["sandbox", "approval", "network_policy", "telemetry"],
        event_sources=["wrapper_command", "sandbox_policy", "approval_log"],
        coverage_grade="managed_wrapper_adapter",
        claim_boundary="Invart-mediated claims require routing Codex-like execution through an Invart wrapper; vendor sandbox and approval facts are complementary evidence, not Invart enforcement by themselves.",
        required_artifacts=["ledger", "proof", "coverage", "audit", "evidence_bundle"],
        source_urls=["https://developers.openai.com/codex/concepts/sandboxing", "https://developers.openai.com/codex/agent-approvals-security"],
        binary_candidates=["codex"],
        supports_mediation=True,
        can_block=True,
        can_pause_resume=True,
    ),
    AgentAdapterProfile(
        agent_id="gemini-cli",
        display_name="Gemini CLI",
        priority="p1_local_wrapper",
        execution_modes=["managed_wrapper", "mcp_inventory"],
        native_surfaces=["mcp", "settings", "extensions"],
        event_sources=["wrapper_command", "mcp_config"],
        coverage_grade="managed_wrapper_adapter",
        claim_boundary="Invart can mediate Gemini CLI when launched through a managed wrapper; MCP/config discovery alone remains observed or discovered coverage.",
        required_artifacts=["ledger", "proof", "coverage", "audit"],
        source_urls=["https://github.com/google-gemini/gemini-cli", "https://geminicli.com/docs/tools/mcp-server/"],
        binary_candidates=["gemini"],
        supports_mediation=True,
        can_block=True,
        can_pause_resume=True,
    ),
    AgentAdapterProfile(
        agent_id="cursor",
        display_name="Cursor",
        priority="p1_ide_inventory",
        execution_modes=["native_event_bridge", "vendor_evidence_import", "discovery_inventory"],
        native_surfaces=["rules", "mcp", "settings", "ide_extension"],
        event_sources=["rules_config", "mcp_config", "ide_export"],
        coverage_grade="native_event_bridge",
        claim_boundary="Cursor IDE and extension surfaces can improve visibility, but Invart does not claim full runtime mediation unless actions enter an Invart bridge or wrapper.",
        required_artifacts=["native_inventory", "coverage", "audit"],
        source_urls=["https://cursor.com/docs"],
        binary_candidates=["cursor"],
        supports_mediation=True,
        can_block=False,
        can_pause_resume=False,
    ),
    AgentAdapterProfile(
        agent_id="opencode",
        display_name="OpenCode",
        priority="p1_local_wrapper",
        execution_modes=["managed_wrapper", "native_event_bridge", "plugin_inventory"],
        native_surfaces=["plugins", "agents", "mcp", "config"],
        event_sources=["wrapper_command", "plugin_config", "native_hook_payload"],
        coverage_grade="managed_wrapper_adapter",
        claim_boundary="OpenCode can be mediated when launched through Invart's managed wrapper. Plugin, agent, and MCP config inventory is pre-runtime evidence and must not be treated as mediation unless events enter Invart before side effects.",
        required_artifacts=["ledger", "proof", "coverage", "audit", "evidence_bundle"],
        source_urls=["https://opencode.ai/docs/agents/", "https://opencode.ai/docs/plugins/"],
        binary_candidates=["opencode"],
        supports_mediation=True,
        can_block=True,
        can_pause_resume=True,
    ),
    AgentAdapterProfile(
        agent_id="openclaw",
        display_name="OpenClaw",
        priority="p0_real_agent_validation",
        execution_modes=["managed_wrapper", "vendor_evidence_import", "skill_inventory"],
        native_surfaces=["permission_modes", "tools", "skills", "plugins"],
        event_sources=["host_exec_policy", "skill_config", "tool_log"],
        coverage_grade="vendor_evidence_import",
        claim_boundary="OpenClaw permission modes are product-owned control facts until host-exec events are bound to Invart mediation and ledger entries.",
        required_artifacts=["native_inventory", "coverage", "audit", "evidence_bundle"],
        source_urls=["https://docs.openclaw.ai/tools", "https://docs.openclaw.ai/gateway/security"],
        binary_candidates=["openclaw"],
        supports_mediation=False,
        can_block=False,
        can_pause_resume=False,
    ),
    AgentAdapterProfile(
        agent_id="hermes",
        display_name="Hermes Agent",
        priority="p0_real_agent_validation",
        execution_modes=["vendor_evidence_import", "managed_launcher_candidate"],
        native_surfaces=["container_backend", "terminal_safety", "credential_filter", "mcp"],
        event_sources=["backend_log", "container_policy", "security_report"],
        coverage_grade="vendor_evidence_import",
        claim_boundary="Hermes security controls are valuable vendor/runtime facts; Invart mediation requires backend events or launches to be routed through Invart.",
        required_artifacts=["native_inventory", "coverage", "audit", "evidence_bundle"],
        source_urls=["https://hermes-agent.nousresearch.com/docs/user-guide/security/"],
        binary_candidates=["hermes"],
        supports_mediation=False,
        can_block=False,
        can_pause_resume=False,
    ),
    AgentAdapterProfile(
        agent_id="cline",
        display_name="Cline",
        priority="p1_ide_inventory",
        execution_modes=["native_event_bridge", "discovery_inventory"],
        native_surfaces=["mcp_marketplace", "ide_extension", "settings"],
        event_sources=["mcp_config", "extension_config", "task_log"],
        coverage_grade="native_event_bridge",
        claim_boundary="Cline MCP and IDE extension surfaces can be inventoried or bridged, but Invart must not call them enforced without a mediation response path.",
        required_artifacts=["native_inventory", "coverage", "audit"],
        source_urls=["https://docs.cline.bot/mcp/mcp-overview", "https://cline.bot/mcp-marketplace"],
        binary_candidates=["cline"],
        supports_mediation=True,
        can_block=False,
        can_pause_resume=False,
    ),
    AgentAdapterProfile(
        agent_id="roo-code",
        display_name="Roo Code",
        priority="p1_ide_inventory",
        execution_modes=["native_event_bridge", "discovery_inventory"],
        native_surfaces=["mcp", "ide_extension", "settings"],
        event_sources=["mcp_config", "extension_config"],
        coverage_grade="native_event_bridge",
        claim_boundary="Roo Code is treated as an IDE agent surface; Invart requires explicit bridge evidence before claiming mediation.",
        required_artifacts=["native_inventory", "coverage", "audit"],
        source_urls=["https://github.com/RooVetGit/Roo-Code"],
        binary_candidates=["roo"],
        supports_mediation=True,
        can_block=False,
        can_pause_resume=False,
    ),
    AgentAdapterProfile(
        agent_id="github-copilot-cloud-agent",
        display_name="GitHub Copilot coding agent",
        priority="p1_cloud_import",
        execution_modes=["vendor_evidence_import"],
        native_surfaces=["cloud_agent", "firewall", "pull_request", "workflow_log"],
        event_sources=["github_log", "pull_request_artifact", "firewall_policy"],
        coverage_grade="vendor_evidence_import",
        claim_boundary="Cloud agent evidence can be imported and audited, but Invart cannot claim local runtime mediation unless it controls the execution boundary.",
        required_artifacts=["external_evidence_manifest", "coverage", "audit", "evidence_bundle"],
        source_urls=[
            "https://docs.github.com/en/copilot/concepts/agents/cloud-agent/about-cloud-agent",
            "https://docs.github.com/en/copilot/how-tos/use-copilot-agents/coding-agent/customize-the-agent-firewall",
        ],
        binary_candidates=["gh"],
        supports_mediation=False,
        can_block=False,
        can_pause_resume=False,
    ),
    AgentAdapterProfile(
        agent_id="aider",
        display_name="Aider",
        priority="p1_local_wrapper",
        execution_modes=["managed_wrapper"],
        native_surfaces=["repo_map", "git_worktree", "shell"],
        event_sources=["wrapper_command", "repo_context", "git_diff"],
        coverage_grade="managed_wrapper_adapter",
        claim_boundary="Aider can be mediated when invoked through Invart's managed wrapper; direct shell execution remains outside Invart coverage.",
        required_artifacts=["ledger", "proof", "coverage", "audit"],
        source_urls=["https://aider.chat/docs/repomap.html"],
        binary_candidates=["aider"],
        supports_mediation=True,
        can_block=True,
        can_pause_resume=True,
    ),
    AgentAdapterProfile(
        agent_id="openai-agents-sdk",
        display_name="OpenAI Agents SDK",
        priority="p1_framework_import",
        execution_modes=["vendor_evidence_import", "framework_trace_import"],
        native_surfaces=["guardrails", "human_in_the_loop", "tracing"],
        event_sources=["sdk_trace", "approval_interruption", "guardrail_result"],
        coverage_grade="vendor_evidence_import",
        claim_boundary="SDK traces and guardrails are application-owned facts until an Invart adapter binds them to the ledger and mediation contract.",
        required_artifacts=["external_evidence_manifest", "coverage", "audit"],
        source_urls=["https://openai.github.io/openai-agents-python/guardrails/", "https://openai.github.io/openai-agents-python/tracing/"],
        binary_candidates=["python"],
        supports_mediation=False,
        can_block=False,
        can_pause_resume=False,
    ),
    AgentAdapterProfile(
        agent_id="langgraph",
        display_name="LangGraph",
        priority="p2_framework_import",
        execution_modes=["framework_trace_import"],
        native_surfaces=["graph_state", "checkpoints", "tool_calls"],
        event_sources=["trace_export", "checkpoint_log", "tool_call_log"],
        coverage_grade="vendor_evidence_import",
        claim_boundary="LangGraph traces support audit reconstruction, but runtime mediation requires an application-side Invart adapter.",
        required_artifacts=["external_evidence_manifest", "coverage", "audit"],
        source_urls=["https://langchain-ai.github.io/langgraph/"],
        binary_candidates=["python"],
        supports_mediation=False,
        can_block=False,
        can_pause_resume=False,
    ),
    AgentAdapterProfile(
        agent_id="crewai",
        display_name="CrewAI",
        priority="p2_framework_import",
        execution_modes=["framework_trace_import"],
        native_surfaces=["crew_flow", "tool_calls", "memory"],
        event_sources=["trace_export", "tool_call_log", "flow_log"],
        coverage_grade="vendor_evidence_import",
        claim_boundary="CrewAI flow artifacts can be imported for audit; Invart cannot claim mediation unless tool calls enter Invart before side effects.",
        required_artifacts=["external_evidence_manifest", "coverage", "audit"],
        source_urls=["https://docs.crewai.com/"],
        binary_candidates=["python"],
        supports_mediation=False,
        can_block=False,
        can_pause_resume=False,
    ),
    AgentAdapterProfile(
        agent_id="generic",
        display_name="Generic local command adapter",
        priority="fallback",
        execution_modes=["managed_wrapper"],
        native_surfaces=["shell"],
        event_sources=["wrapper_command"],
        coverage_grade="managed_wrapper_adapter",
        claim_boundary="Generic adapter coverage is limited to what enters Invart's wrapper and cannot be generalized to a named vendor product.",
        required_artifacts=["ledger", "proof", "coverage", "audit"],
        source_urls=["https://github.com/eric1311/Invart"],
        binary_candidates=[],
        supports_mediation=True,
        can_block=True,
        can_pause_resume=True,
    ),
)

_PROFILE_BY_ID = {profile.agent_id: profile for profile in _PROFILES}
_ALIASES = {"roo": "roo-code", "copilot": "github-copilot-cloud-agent"}


def build_adapter_profile(kind: str, env: dict[str, str] | None = None) -> dict[str, Any]:
    env = dict(os.environ if env is None else env)
    contract = get_adapter_profile(kind)
    return {
        "schema_version": PROFILE_SCHEMA_VERSION,
        "adapter": kind,
        "agent_contract": contract,
        **contract,
        "environment": summarize_environment(env),
        "process_supervision": {
            "target": "strong_consistency",
            "mode": "best_effort_until_native_supervision",
            "degraded_mode_allowed": True,
            "degraded_mode_must_be_recorded": True,
        },
        "claude_code": {
            "first_hardened_target": kind == "claude-code",
            "expected_hooks": ["wrapper_command", "session_env", "tool_event_bridge"],
        } if kind == "claude-code" else {},
    }


def adapter_profile_ids() -> list[str]:
    return sorted(_PROFILE_BY_ID)


def get_adapter_profile(kind: str) -> dict[str, Any]:
    normalized = _ALIASES.get(kind, kind)
    profile = _PROFILE_BY_ID.get(normalized)
    if not profile:
        raise ValueError(f"unsupported adapter profile: {kind}")
    return profile.to_dict()


def list_adapter_profiles() -> list[dict[str, Any]]:
    return [profile.to_dict() for profile in _PROFILES if profile.agent_id != "generic"]


def adapter_profile_registry() -> dict[str, Any]:
    profiles = list_adapter_profiles()
    validation = validate_adapter_profile_truthfulness(profiles)
    return {
        "schema_version": PROFILE_REGISTRY_SCHEMA_VERSION,
        "status": validation["status"],
        "profiles": profiles,
        "validation": validation,
        "summary": {
            "profiles": len(profiles),
            "coverage_grades": _count_by(profiles, "coverage_grade"),
            "priorities": _count_by(profiles, "priority"),
        },
    }


def adapter_track_matrix(track: str | None = None) -> dict[str, Any]:
    profiles = list_adapter_profiles()
    if track:
        profiles = [profile for profile in profiles if profile.get("integration_track") == track]
    rows = [
        {
            "agent_id": profile["agent_id"],
            "display_name": profile["display_name"],
            "priority": profile["priority"],
            "integration_track": profile["integration_track"],
            "track_status": profile["track_status"],
            "adapter_family": profile["adapter_family"],
            "control_position": profile["control_position"],
            "coverage_grade": profile["coverage_grade"],
            "supports_mediation": profile["supports_mediation"],
            "can_block": profile["can_block"],
            "can_pause_resume": profile["can_pause_resume"],
            "required_artifacts": profile["required_artifacts"],
            "claim_boundary": profile["claim_boundary"],
        }
        for profile in profiles
    ]
    validation = validate_adapter_profile_truthfulness(profiles)
    checks = {
        "profiles_validate": validation.get("status") == "pass",
        "vendor_import_not_mediated": all(row["control_position"] == "vendor_owned_import" and not row["supports_mediation"] for row in rows if row["integration_track"] in {"vendor_evidence_import", "cloud_evidence_import", "framework_trace_import"}),
        "managed_tracks_have_blocking_path": all(row["supports_mediation"] and row["can_block"] for row in rows if row["integration_track"] in {"reference_full_adapter", "managed_wrapper"}),
        "tracks_have_claim_boundaries": all(bool(row["claim_boundary"]) for row in rows),
    }
    return {
        "schema_version": "invart.adapter_track_matrix.v0.9.5",
        "status": "pass" if all(checks.values()) else "fail",
        "track_filter": track,
        "rows": rows,
        "checks": checks,
        "validation": validation,
        "summary": {
            "profiles": len(rows),
            "tracks": _count_by(rows, "integration_track"),
            "adapter_families": _count_by(rows, "adapter_family"),
            "control_positions": _count_by(rows, "control_position"),
        },
    }


def validate_adapter_profile_truthfulness(profiles: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    profiles = profiles or list_adapter_profiles()
    required_fields = {
        "agent_id",
        "display_name",
        "priority",
        "execution_modes",
        "native_surfaces",
        "event_sources",
        "coverage_grade",
        "claim_boundary",
        "required_artifacts",
        "source_urls",
        "last_reviewed",
        "integration_track",
        "track_status",
        "adapter_family",
        "control_position",
    }
    valid_grades = {
        "full_managed_adapter",
        "managed_wrapper_adapter",
        "native_event_bridge",
        "vendor_evidence_import",
        "discovery_only",
    }
    valid_tracks = {
        "reference_full_adapter",
        "managed_wrapper",
        "native_bridge",
        "vendor_evidence_import",
        "cloud_evidence_import",
        "framework_trace_import",
        "discovery_only",
    }
    valid_control_positions = {
        "invart_mediated",
        "bridge_mediated_when_configured",
        "vendor_owned_import",
        "discovery_only",
    }
    checks = {
        "required_fields_present": all(required_fields.issubset(profile) and all(profile.get(field) for field in required_fields) for profile in profiles),
        "coverage_grades_known": all(profile.get("coverage_grade") in valid_grades for profile in profiles),
        "track_fields_present": all(all(profile.get(field) for field in ("integration_track", "track_status", "adapter_family", "control_position")) for profile in profiles),
        "tracks_known": all(profile.get("integration_track") in valid_tracks and profile.get("control_position") in valid_control_positions for profile in profiles),
        "source_urls_https": all(str(url).startswith("https://") for profile in profiles for url in profile.get("source_urls", [])),
        "claim_boundaries_present": all(bool(profile.get("claim_boundary")) for profile in profiles),
        "full_managed_requires_artifacts": all(
            {"ledger", "proof", "evidence_bundle"}.issubset(set(profile.get("required_artifacts", [])))
            and "managed_runtime" in set(profile.get("execution_modes", []))
            and profile.get("supports_mediation") is True
            and profile.get("can_block") is True
            for profile in profiles
            if profile.get("coverage_grade") == "full_managed_adapter"
        ),
        "import_only_not_mediated": all(
            profile.get("supports_mediation") is False and profile.get("can_block") is False
            for profile in profiles
            if profile.get("coverage_grade") == "vendor_evidence_import"
        ),
        "discovery_only_not_mediated": all(
            profile.get("supports_mediation") is False and profile.get("can_block") is False
            for profile in profiles
            if profile.get("coverage_grade") == "discovery_only"
        ),
        "vendor_import_track_not_mediated": all(
            profile.get("supports_mediation") is False
            and profile.get("can_block") is False
            and profile.get("control_position") == "vendor_owned_import"
            for profile in profiles
            if profile.get("integration_track") in {"vendor_evidence_import", "cloud_evidence_import", "framework_trace_import"}
        ),
        "managed_track_has_artifact_boundary": all(
            {"ledger", "proof"}.issubset(set(profile.get("required_artifacts", [])))
            and profile.get("supports_mediation") is True
            and profile.get("can_block") is True
            and profile.get("control_position") == "invart_mediated"
            for profile in profiles
            if profile.get("integration_track") in {"reference_full_adapter", "managed_wrapper"}
        ),
    }
    findings = [
        {"check_id": check_id, "status": "fail"}
        for check_id, passed in checks.items()
        if not passed
    ]
    return {
        "schema_version": "invart.adapter_profile_truthfulness.v0.9.3",
        "status": "pass" if not findings else "fail",
        "checks": checks,
        "findings": findings,
    }


def summarize_environment(env: dict[str, str], *, max_value_length: int = 96) -> dict[str, Any]:
    items = []
    for key in sorted(env):
        value = str(env[key])
        secret_like = any(marker in key.upper() for marker in SECRET_KEY_MARKERS)
        display = "[REDACTED]" if secret_like else _fold(value, max_value_length)
        items.append({
            "key": key,
            "value": display,
            "value_present": value != "",
            "secret_like_key": secret_like,
            "folded_by_default": True,
            "original_length": len(value),
            "content_note": "secret-like environment key" if secret_like else "environment value folded/truncated for audit display",
        })
    return {"count": len(items), "items": items}


def _fold(value: str, max_value_length: int) -> str:
    if len(value) <= max_value_length:
        return value
    return value[: max_value_length - 3] + "..."


def _count_by(items: list[dict[str, Any]], field_name: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items:
        key = str(item.get(field_name, "unknown"))
        counts[key] = counts.get(key, 0) + 1
    return counts


def _derive_track(profile: dict[str, Any]) -> dict[str, str]:
    agent_id = str(profile.get("agent_id", ""))
    coverage_grade = str(profile.get("coverage_grade", ""))
    execution_modes = set(profile.get("execution_modes", []))
    if agent_id == "claude-code":
        return {
            "integration_track": "reference_full_adapter",
            "track_status": "implemented",
            "adapter_family": "product_cli",
            "control_position": "invart_mediated",
        }
    if agent_id == "github-copilot-cloud-agent":
        return {
            "integration_track": "cloud_evidence_import",
            "track_status": "planned_import",
            "adapter_family": "cloud_agent",
            "control_position": "vendor_owned_import",
        }
    if coverage_grade == "managed_wrapper_adapter":
        return {
            "integration_track": "managed_wrapper",
            "track_status": "fixture_validated",
            "adapter_family": "product_cli",
            "control_position": "invart_mediated",
        }
    if coverage_grade == "native_event_bridge":
        return {
            "integration_track": "native_bridge",
            "track_status": "fixture_validated" if profile.get("supports_mediation") else "planned_import",
            "adapter_family": "ide_agent" if "ide_extension" in execution_modes or "ide_extension" in set(profile.get("native_surfaces", [])) else "product_cli",
            "control_position": "bridge_mediated_when_configured",
        }
    if coverage_grade == "vendor_evidence_import" and ("framework_trace_import" in execution_modes or agent_id in {"openai-agents-sdk", "langgraph", "crewai"}):
        return {
            "integration_track": "framework_trace_import",
            "track_status": "planned_import",
            "adapter_family": "framework",
            "control_position": "vendor_owned_import",
        }
    if coverage_grade == "vendor_evidence_import":
        return {
            "integration_track": "vendor_evidence_import",
            "track_status": "planned_import",
            "adapter_family": "product_cli",
            "control_position": "vendor_owned_import",
        }
    return {
        "integration_track": "discovery_only",
        "track_status": "planned_import",
        "adapter_family": "unknown",
        "control_position": "discovery_only",
    }


__all__ = [
    "AgentAdapterProfile",
    "adapter_profile_ids",
    "adapter_profile_registry",
    "adapter_track_matrix",
    "build_adapter_profile",
    "get_adapter_profile",
    "list_adapter_profiles",
    "summarize_environment",
    "validate_adapter_profile_truthfulness",
]
