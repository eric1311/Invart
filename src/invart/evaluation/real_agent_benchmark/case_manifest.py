from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from invart.core.models import utc_now
from invart.surfaces.adapter_profiles import get_adapter_profile

from .benchmark_quality import build_benchmark_quality_registry


SCHEMA_VERSION = "invart.p0_real_agent_benchmark_manifest.v0.1"

P0_MODES = ("baseline_agent", "invart_observe_only", "invart_mediated")
P0_AGENT_BRIDGE = "generic_cli_agent_bridge"
P0_ANCILLARY_TOOL_RUNNER = "official_ancillary_tool_runner_under_p0_supervision"
P0_BENCHMARK_FAMILIES = ("agentdojo", "agentsecbench", "skill_inject", "swe_bench_verified")
P0_BENCHMARK_QUALITY_IDS = {
    "agentdojo": "agentdojo",
    "agentsecbench": "agent_security_bench",
    "skill_inject": "skill_inject",
    "swe_bench_verified": "swe_bench",
}


@dataclass(frozen=True)
class OfficialRunnerContract:
    family: str
    runner_status: str
    official_entrypoint: str
    official_grader: str
    invart_integration: str
    claim_rule: str
    source_url: str


@dataclass(frozen=True)
class P0Case:
    case_id: str
    family: str
    benchmark_case_ref: str
    count_target: str
    expected_risk: str
    official_runner_required: bool = True
    allowed_modes: tuple[str, ...] = P0_MODES
    required_ground_truth: tuple[str, ...] = (
        "workspace_snapshot_diff",
        "process_supervision",
        "shell_transcript",
        "benchmark_grader_output",
        "timeout_crash_status",
    )
    claim_boundary: str = (
        "P0 evidence is claimable only when the case is run through the official benchmark runner or an explicitly "
        "marked generic CLI bridge, with independent side-effect evidence attached."
    )


def official_runner_contracts() -> list[OfficialRunnerContract]:
    return [
        OfficialRunnerContract(
            family="agentdojo",
            runner_status="official_runner_available",
            official_entrypoint="python -m agentdojo.scripts.benchmark",
            official_grader="AgentDojo benchmark result logs",
            invart_integration=P0_AGENT_BRIDGE,
            claim_rule="Use AgentDojo's benchmark script; Invart may wrap the model/agent/tool boundary but must not replace the benchmark task runner.",
            source_url="https://github.com/ethz-spylab/agentdojo",
        ),
        OfficialRunnerContract(
            family="swe_bench_verified",
            runner_status="official_runner_available",
            official_entrypoint="python -m swebench.harness.run_evaluation --dataset_name SWE-bench/SWE-bench_Verified",
            official_grader="SWE-Bench report JSON and instance_results.jsonl",
            invart_integration="predictions_jsonl_or_cli_patch_bridge",
            claim_rule="Generate predictions through the selected agent path, then evaluate with the official SWE-Bench harness; Invart must not substitute local tests for the official grader.",
            source_url="https://github.com/SWE-bench/SWE-bench",
        ),
        OfficialRunnerContract(
            family="agentsecbench",
            runner_status="official_ancillary_runner_available",
            official_entrypoint="python -m benchmark.run --tools semgrep --apps benchmark/apps",
            official_grader="AgentSecBench results directory and leaderboard outputs",
            invart_integration=P0_ANCILLARY_TOOL_RUNNER,
            claim_rule=(
                "Use the AgentSecBench upstream benchmark runner; semgrep/spa-hacking-agent rows are official "
                "tool-runner evidence under Invart supervision, not Codex/Claude provider behavior unless the "
                "upstream runner itself invokes that provider."
            ),
            source_url="https://github.com/Kalmantic/AgentSecBench",
        ),
        OfficialRunnerContract(
            family="skill_inject",
            runner_status="official_repository_runner_available",
            official_entrypoint="bash docker/build.sh; python scripts/smoke_test_all.py or python experiments/<suite>.py --agent <agent>",
            official_grader="Skill-Inject judge outputs and experiment result artifacts",
            invart_integration=P0_AGENT_BRIDGE,
            claim_rule="Use the upstream Docker/sandbox/experiment pipeline for official rows; local converted traces remain source-mapped adapter evidence only.",
            source_url="https://github.com/aisa-group/skill-inject",
        ),
    ]


def agent_bridge_contracts(agents: list[str]) -> list[dict[str, Any]]:
    contracts: list[dict[str, Any]] = []
    for agent in agents:
        profile = get_adapter_profile(agent)
        contracts.append({
            "agent": agent,
            "display_name": profile.get("display_name"),
            "binary_candidates": profile.get("binary_candidates", []),
            "execution_modes": profile.get("execution_modes", []),
            "supports_mediation": profile.get("supports_mediation", False),
            "standard_bridge": _standard_bridge_for_profile(profile),
            "official_runner_rule": (
                "Do not replace the official/upstream benchmark runner. Use the selected agent only through an upstream model/agent flag "
                "when the benchmark supports it, or through a provider CLI command that produces the official benchmark input artifact."
            ),
            "invart_binding_rule": (
                "Baseline rows run the same agent entrypoint without Invart mediation; observe-only and mediated rows route the same "
                "entrypoint through Invart supervision so differences can be attributed to control-plane behavior."
            ),
            "claim_boundary": profile.get("claim_boundary"),
            "required_artifacts": profile.get("required_artifacts", []),
        })
    return contracts


def default_p0_cases() -> list[P0Case]:
    return [
        P0Case("agentdojo_workspace_task_0", "agentdojo", "workspace:user_task_0", "2-3", "indirect_prompt_injection"),
        P0Case("agentdojo_workspace_task_1", "agentdojo", "workspace:user_task_1", "2-3", "indirect_prompt_injection"),
        P0Case("agentsecbench_tool_integrity_0", "agentsecbench", "official-pinned:tool-integrity-0", "2-3", "tool_use_integrity"),
        P0Case("agentsecbench_privacy_leakage_0", "agentsecbench", "official-pinned:privacy-leakage-0", "2-3", "privacy_leakage"),
        P0Case("skill_inject_malicious_skill_0", "skill_inject", "official-pinned:skill-inject-0", "2", "skill_supply_chain_injection"),
        P0Case("skill_inject_benign_skill_0", "skill_inject", "official-pinned:benign-skill-0", "2", "benign_skill_compatibility"),
        P0Case("swe_verified_astropy_12907", "swe_bench_verified", "SWE-bench/SWE-bench_Verified:test:astropy__astropy-12907", "2-4", "benign_coding_workflow"),
        P0Case("swe_verified_django_10097", "swe_bench_verified", "SWE-bench/SWE-bench_Verified:test:django__django-10097", "2-4", "benign_coding_workflow"),
    ]


def default_p0_case_manifest(*, agents: list[str] | None = None) -> dict[str, Any]:
    selected_agents = agents or ["claude-code", "codex"]
    quality_registry = build_benchmark_quality_registry()
    payload = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": utc_now(),
        "name": "p0-real-agent-official-benchmark-bridge",
        "objective": (
            "Evaluate Invart as a runtime assurance layer with real agent CLI executions, official benchmark runners "
            "where available, paired baseline/observe/mediated modes, independent side-effect ground truth, and bounded claims."
        ),
        "agent_cli_bridge_policy": {
            "schema_version": "invart.p0_agent_cli_bridge_policy.v0.1",
            "primary_agents": ["claude-code", "codex"],
            "optional_agents": ["hermes"],
            "standard_path": (
                "official benchmark row -> prepared workspace -> provider CLI process -> upstream submission artifact "
                "-> official runner/grader -> Invart evidence attachment"
            ),
            "rule": (
                "Provider CLIs such as Claude Code, Codex, or Hermes must not replace the benchmark runner. "
                "They may only produce the artifact accepted by the upstream benchmark or run through an upstream-registered adapter."
            ),
            "claim_boundary": (
                "Bridge success, native provider traces, or product approvals are runtime evidence. They are not official benchmark scores "
                "until a validated upstream grader artifact is attached."
            ),
        },
        "agents": [
            {"agent": agent, "bridge": P0_AGENT_BRIDGE, "rule": "Use the agent's normal CLI or patch-output path; avoid benchmark-specific agent shims."}
            for agent in selected_agents
        ],
        "agent_bridge_contracts": agent_bridge_contracts(selected_agents),
        "modes": [
            {"mode": "baseline_agent", "claim": "utility/cost/side-effect baseline without Invart mediation"},
            {"mode": "invart_observe_only", "claim": "low-friction observation and ledger completeness without enforcement claim"},
            {"mode": "invart_mediated", "claim": "managed-surface pause/block/enforce with pre-side-effect evidence"},
        ],
        "official_runner_contracts": [asdict(item) for item in official_runner_contracts()],
        "benchmark_qualification_registry": {
            "schema_version": quality_registry["schema_version"],
            "portfolio_hash": quality_registry["portfolio_hash"],
            "family_benchmark_ids": dict(P0_BENCHMARK_QUALITY_IDS),
            "claim_boundary": (
                "These references identify qualification records only; each live row still requires "
                "technical-validity, capability, and attack-opportunity evidence."
            ),
        },
        "cases": [asdict(item) for item in default_p0_cases()],
        "required_artifacts": [
            "p0_case_manifest.json",
            "p0_run_matrix.jsonl",
            "p0_side_effects.jsonl",
            "p0_grader_results.json",
            "p0_cost_summary.json",
            "p0_stability_summary.json",
            "p0_environment_freeze.json",
            "p0_official_setup.json",
            "p0_doctor.json",
            "p0_first_batch_plan.json",
            "p0_first_batch_commands.sh",
            "p0_claim_matrix.md",
            "p0_results_table.tex",
            "reproduce_p0.sh",
        ],
        "non_claims": [
            "local converted traces are not official upstream benchmark scores",
            "agent wrappers are not provider-side task-solving evidence unless the provider CLI actually produced the benchmark input/output artifact",
            "observe-only rows do not imply mediation or enforcement",
            "native controls do not count as Invart enforcement unless bound to Invart-managed mediation and ledger semantics",
        ],
    }
    validation = validate_p0_case_manifest(payload)
    payload["validation"] = validation
    return payload


def validate_p0_case_manifest(payload: dict[str, Any]) -> dict[str, Any]:
    errors: list[str] = []
    cases = payload.get("cases")
    if not isinstance(cases, list) or not cases:
        errors.append("cases must be a non-empty list")
        cases = []
    families = {case.get("family") for case in cases if isinstance(case, dict)}
    missing_families = [family for family in P0_BENCHMARK_FAMILIES if family not in families]
    if missing_families:
        errors.append(f"missing benchmark families: {', '.join(missing_families)}")
    qualification = payload.get("benchmark_qualification_registry")
    if not isinstance(qualification, dict):
        errors.append("benchmark_qualification_registry must be present")
    else:
        family_map = qualification.get("family_benchmark_ids")
        if not isinstance(family_map, dict):
            errors.append("benchmark qualification family map must be present")
        else:
            missing_quality = sorted(
                str(family) for family in families if family not in family_map
            )
            if missing_quality:
                errors.append(
                    "benchmark families lack qualification records: "
                    + ", ".join(missing_quality)
                )
    contracts = payload.get("official_runner_contracts")
    if not isinstance(contracts, list) or not contracts:
        errors.append("official_runner_contracts must be present")
        contracts = []
    contract_families = {contract.get("family") for contract in contracts if isinstance(contract, dict)}
    for family in families:
        if family and family not in contract_families:
            errors.append(f"case family lacks official runner contract: {family}")
    bridge_contracts = payload.get("agent_bridge_contracts")
    if not isinstance(bridge_contracts, list) or not bridge_contracts:
        errors.append("agent_bridge_contracts must be present")
        bridge_contracts = []
    bridge_agents = {item.get("agent") for item in bridge_contracts if isinstance(item, dict)}
    manifest_agents = {item.get("agent") for item in payload.get("agents", []) if isinstance(item, dict)}
    missing_bridge_agents = sorted(str(agent) for agent in manifest_agents if agent not in bridge_agents)
    if missing_bridge_agents:
        errors.append(f"missing agent bridge contracts: {', '.join(missing_bridge_agents)}")
    for mode in payload.get("modes", []):
        if isinstance(mode, dict) and mode.get("mode") not in P0_MODES:
            errors.append(f"unknown mode: {mode.get('mode')}")
    return {
        "schema_version": "invart.p0_real_agent_manifest_validation.v0.1",
        "status": "pass" if not errors else "fail",
        "errors": errors,
        "summary": {"cases": len(cases), "families": sorted(families), "contracts": len(contracts)},
    }


def _standard_bridge_for_profile(profile: dict[str, Any]) -> str:
    modes = set(profile.get("execution_modes") or [])
    if "managed_wrapper" in modes or "managed_runtime" in modes:
        return "provider_cli_process_wrapped_by_invart"
    if "managed_launcher_candidate" in modes:
        return "provider_cli_or_backend_launcher_with_explicit_evidence_import"
    if "vendor_evidence_import" in modes:
        return "vendor_native_evidence_import_only"
    return "generic_cli_process"
