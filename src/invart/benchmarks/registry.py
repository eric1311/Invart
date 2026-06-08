from __future__ import annotations

from typing import Any, Callable

from invart.surfaces.corpus import run_real_surface_benchmark
from invart.evaluation.real_world_cases import run_real_world_risk_benchmark
from invart.evaluation.container_demo import run_container_risk_demo_benchmark
from invart.assurance.secure_code_gate import run_secure_coding_gate_suite
from invart.evaluation.coverage_experiments import run_coverage_truthfulness_matrix
from invart.evaluation.reviewer_experiments import run_reviewer_selectivity_experiment
from invart.evaluation.audit_experiments import run_audit_tamper_assurance
from .common import _run_paper_ready_experiment_benchmark, run_direct_experiment_benchmark, run_experiment_benchmark
from .foundation import run_approval_replay_benchmark, run_adapter_workflow_benchmark, run_gate_benchmark
from .full_product import run_full_product_readiness_benchmark
from .releases_v08_v18 import (
    run_claude_adapter_profile_benchmark,
    run_coverage_aware_runtime_benchmark,
    run_enforcement_guard_benchmark,
    run_enterprise_audit_demo_benchmark,
    run_harness_compatibility_benchmark,
    run_hook_plugin_bridge_benchmark,
    run_llm_reviewer_benchmark,
    run_mcp_broker_benchmark,
    run_native_integration_inventory_benchmark,
    run_policy_profile_benchmark,
    run_swe_bench_full_validation_contract_benchmark,
    run_teamrun_handoff_benchmark,
)
from .releases_v19_v29 import (
    run_adapter_runtime_integration_benchmark,
    run_enterprise_evidence_export_benchmark,
    run_enterprise_policy_governance_benchmark,
    run_harness_expansion_benchmark,
    run_identity_principal_binding_benchmark,
    run_path_aware_policy_benchmark,
    run_path_graph_benchmark,
    run_policy_as_code_benchmark,
    run_pre_v1_control_plane_benchmark,
    run_release_candidate_gate_benchmark,
    run_unified_mediation_benchmark,
)
from .releases_v41_v45 import (
    run_enterprise_coverage_gate_benchmark,
    run_external_evidence_and_swebench_benchmark,
    run_final_demo_and_rc_gate_benchmark,
    run_managed_launcher_migration_benchmark,
    run_progressive_external_validation_benchmark,
    run_unmanaged_agent_inventory_benchmark,
)

BenchmarkRunner = Callable[[], dict[str, Any]]


def benchmark_runner_registry() -> dict[str, BenchmarkRunner]:
    return {
        "v0.4-real-skill-surface": run_real_surface_benchmark,
        "v0.5-proof-gate": run_gate_benchmark,
        "v0.6-adapter-workflow": run_adapter_workflow_benchmark,
        "v0.7-approval-replay": run_approval_replay_benchmark,
        "v0.8-llm-reviewer": run_llm_reviewer_benchmark,
        "v0.9-harness-compatibility": run_harness_compatibility_benchmark,
        "v0.10-claude-adapter-profile": run_claude_adapter_profile_benchmark,
        "v0.11-policy-profiles": run_policy_profile_benchmark,
        "v0.12-teamrun-handoff": run_teamrun_handoff_benchmark,
        "v0.13-enforcement-guards": run_enforcement_guard_benchmark,
        "v0.14-enterprise-audit-demo": run_enterprise_audit_demo_benchmark,
        "v0.15-native-integration-inventory": run_native_integration_inventory_benchmark,
        "v0.16-hook-plugin-bridge": run_hook_plugin_bridge_benchmark,
        "v0.17-mcp-broker": run_mcp_broker_benchmark,
        "v0.18-coverage-aware-runtime": run_coverage_aware_runtime_benchmark,
        "v0.19-identity-principal-binding": run_identity_principal_binding_benchmark,
        "v0.20-path-graph": run_path_graph_benchmark,
        "v0.21-path-aware-policy": run_path_aware_policy_benchmark,
        "v0.22-unified-mediation": run_unified_mediation_benchmark,
        "v0.23-enterprise-policy-governance": run_enterprise_policy_governance_benchmark,
        "pre-v1-control-plane": run_pre_v1_control_plane_benchmark,
        "v0.25-adapter-runtime-integration": run_adapter_runtime_integration_benchmark,
        "v0.26-policy-as-code": run_policy_as_code_benchmark,
        "v0.27-enterprise-evidence-export": run_enterprise_evidence_export_benchmark,
        "v0.28-harness-expansion": run_harness_expansion_benchmark,
        "v0.29-release-candidate-gate": run_release_candidate_gate_benchmark,
        "v0.30-control-plane-experiment-runner": lambda: run_experiment_benchmark("control-plane-core", "v0.30-control-plane-experiment-runner"),
        "v0.31-external-ipi-control-plane": lambda: run_experiment_benchmark("external-ipi-control-plane", "v0.31-external-ipi-control-plane"),
        "v0.32-authority-dataflow-boundary": lambda: run_experiment_benchmark("authority-dataflow-boundary", "v0.32-authority-dataflow-boundary"),
        "v0.33-swebench-friction-control-plane": lambda: run_experiment_benchmark("swebench-friction-control-plane", "v0.33-swebench-friction-control-plane"),
        "v0.34-skill-supply-chain-control-plane": lambda: run_experiment_benchmark("skill-supply-chain-control-plane", "v0.34-skill-supply-chain-control-plane"),
        "v0.35-secure-coding-gate": lambda: run_direct_experiment_benchmark(run_secure_coding_gate_suite(), "v0.35-secure-coding-gate"),
        "v0.36-coverage-truthfulness-matrix": lambda: run_direct_experiment_benchmark(run_coverage_truthfulness_matrix(), "v0.36-coverage-truthfulness-matrix"),
        "v0.37-llm-reviewer-selectivity": lambda: run_direct_experiment_benchmark(run_reviewer_selectivity_experiment(), "v0.37-llm-reviewer-selectivity"),
        "v0.38-audit-tamper-assurance": lambda: run_direct_experiment_benchmark(run_audit_tamper_assurance(), "v0.38-audit-tamper-assurance"),
        "v0.39-paper-ready-experiment-suite": _run_paper_ready_experiment_benchmark,
        "v0.40-swe-bench-full-validation-contract": run_swe_bench_full_validation_contract_benchmark,
        "v0.41-unmanaged-agent-inventory": run_unmanaged_agent_inventory_benchmark,
        "v0.42-managed-launcher-migration": run_managed_launcher_migration_benchmark,
        "v0.43-enterprise-coverage-gate": run_enterprise_coverage_gate_benchmark,
        "v0.44-external-evidence-and-swebench": run_external_evidence_and_swebench_benchmark,
        "v0.45-final-demo-and-rc-gate": run_final_demo_and_rc_gate_benchmark,
        "progressive-external-validation": run_progressive_external_validation_benchmark,
        "real-world-agent-risk-demo": run_real_world_risk_benchmark,
        "containerized-risk-demo": run_container_risk_demo_benchmark,
        "full-product-readiness": run_full_product_readiness_benchmark,
    }


__all__ = ["BenchmarkRunner", "benchmark_runner_registry"]
