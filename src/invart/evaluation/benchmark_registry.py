from __future__ import annotations

from typing import Any


BENCHMARK_SUITES: tuple[dict[str, Any], ...] = (
    {"suite": "v0.25-adapter-runtime-integration", "version": "v0.25", "category": "compatibility", "optional_heavy": False},
    {"suite": "v0.26-policy-as-code", "version": "v0.26", "category": "policy", "optional_heavy": False},
    {"suite": "v0.27-enterprise-evidence-export", "version": "v0.27", "category": "evidence", "optional_heavy": False},
    {"suite": "v0.28-harness-expansion", "version": "v0.28", "category": "evaluation", "optional_heavy": False},
    {"suite": "v0.29-release-candidate-gate", "version": "v0.29", "category": "release", "optional_heavy": False},
    {"suite": "v0.30-control-plane-experiment-runner", "version": "v0.30", "category": "experiment", "optional_heavy": False, "claim_scope": "local_experiment_substrate", "evidence_level": "simulated_agent_trace"},
    {"suite": "v0.31-external-ipi-control-plane", "version": "v0.31", "category": "attack", "optional_heavy": False, "claim_scope": "local_experiment_substrate", "evidence_level": "benchmark_shaped_fixture"},
    {"suite": "v0.32-authority-dataflow-boundary", "version": "v0.32", "category": "authority", "optional_heavy": False, "claim_scope": "local_experiment_substrate", "evidence_level": "benchmark_shaped_fixture"},
    {"suite": "v0.33-swebench-friction-control-plane", "version": "v0.33", "category": "compatibility", "optional_heavy": False, "claim_scope": "local_experiment_substrate", "evidence_level": "simulated_agent_trace"},
    {"suite": "v0.34-skill-supply-chain-control-plane", "version": "v0.34", "category": "supply-chain", "optional_heavy": False, "claim_scope": "local_experiment_substrate", "evidence_level": "benchmark_shaped_fixture"},
    {"suite": "v0.35-secure-coding-gate", "version": "v0.35", "category": "secure-code", "optional_heavy": False, "claim_scope": "local_experiment_substrate", "evidence_level": "benchmark_shaped_fixture"},
    {"suite": "v0.36-coverage-truthfulness-matrix", "version": "v0.36", "category": "coverage", "optional_heavy": False, "claim_scope": "local_experiment_substrate", "evidence_level": "local_truthfulness_matrix"},
    {"suite": "v0.37-llm-reviewer-selectivity", "version": "v0.37", "category": "reviewer", "optional_heavy": False, "claim_scope": "local_experiment_substrate", "evidence_level": "simulated_agent_trace"},
    {"suite": "v0.38-audit-tamper-assurance", "version": "v0.38", "category": "audit", "optional_heavy": False, "claim_scope": "local_experiment_substrate", "evidence_level": "local_tamper_fixture"},
    {"suite": "v0.39-paper-ready-experiment-suite", "version": "v0.39", "category": "paper", "optional_heavy": False, "claim_scope": "local_experiment_substrate", "evidence_level": "simulated_agent_trace"},
    {"suite": "v0.40-swe-bench-full-validation-contract", "version": "v0.40", "category": "external-validation", "optional_heavy": False, "claim_scope": "official_runner_contract", "evidence_level": "contract_test"},
    {"suite": "v0.41-unmanaged-agent-inventory", "version": "v0.41", "category": "coverage", "optional_heavy": False, "claim_scope": "local_product", "evidence_level": "local_runtime_inventory"},
    {"suite": "v0.42-managed-launcher-migration", "version": "v0.42", "category": "compatibility", "optional_heavy": False, "claim_scope": "local_product", "evidence_level": "local_runtime_fixture"},
    {"suite": "v0.43-enterprise-coverage-gate", "version": "v0.43", "category": "coverage", "optional_heavy": False, "claim_scope": "local_product", "evidence_level": "local_truthfulness_matrix"},
    {"suite": "v0.44-external-evidence-and-swebench", "version": "v0.44", "category": "evidence", "optional_heavy": False, "claim_scope": "evidence_contract", "evidence_level": "contract_test"},
    {"suite": "v0.45-final-demo-and-rc-gate", "version": "v0.45", "category": "release", "optional_heavy": False, "claim_scope": "local_product", "evidence_level": "local_runtime_with_attachable_evidence"},
    {"suite": "v0.46-paper-evidence-tables", "version": "v0.46", "category": "paper", "optional_heavy": False, "claim_scope": "local_experiment_substrate", "evidence_level": "artifact_table_export"},
    {"suite": "v0.47-coverage-mediation-pilot", "version": "v0.47", "category": "coverage", "optional_heavy": False, "claim_scope": "local_experiment_substrate", "evidence_level": "local_truthfulness_matrix"},
    {"suite": "v0.48-audit-reconstruction-study", "version": "v0.48", "category": "audit", "optional_heavy": False, "claim_scope": "local_experiment_substrate", "evidence_level": "local_tamper_fixture"},
    {"suite": "v0.49-reviewer-ablation-cost", "version": "v0.49", "category": "reviewer", "optional_heavy": False, "claim_scope": "local_experiment_substrate", "evidence_level": "simulated_agent_trace"},
    {"suite": "v0.50-product-control-matrix", "version": "v0.50", "category": "product-boundary", "optional_heavy": False, "claim_scope": "product_comparison", "evidence_level": "documented_capability_matrix"},
    {"suite": "v0.51-pre-1.0-research-ready-gate", "version": "v0.51", "category": "release", "optional_heavy": False, "claim_scope": "research_gate", "evidence_level": "local_research_artifact_bundle"},
    {"suite": "v0.9.3-agent-adapter-contract", "version": "v0.9.3", "category": "agent-adapter", "optional_heavy": False, "claim_scope": "local_agent_adapter_contract", "evidence_level": "fixture_backed_conformance"},
    {"suite": "v0.9.4-claude-reference-adapter", "version": "v0.9.4", "category": "agent-adapter", "optional_heavy": False, "claim_scope": "local_claude_reference_adapter", "evidence_level": "local_runtime_fixture"},
    {"suite": "v0.9.5-priority-agent-tracks", "version": "v0.9.5", "category": "agent-adapter", "optional_heavy": False, "claim_scope": "local_agent_track_matrix", "evidence_level": "fixture_backed_profile_matrix"},
    {"suite": "v0.9.6-layer-runtime-workflow", "version": "v0.9.6", "category": "runtime", "optional_heavy": False, "claim_scope": "local_layer_runtime_workflow", "evidence_level": "ledger_derived_runtime_fixture"},
    {"suite": "v0.9.7-evidence-workspace-gate", "version": "v0.9.7", "category": "evidence", "optional_heavy": False, "claim_scope": "local_l5_evidence_workspace", "evidence_level": "ledger_derived_runtime_fixture"},
    {"suite": "v0.9.8-claude-full-live-adapter", "version": "v0.9.8", "category": "agent-adapter", "optional_heavy": False, "claim_scope": "local_claude_live_adapter_contract", "evidence_level": "binary_backed_fixture_live_path"},
    {"suite": "progressive-external-validation", "version": "pre-release", "category": "external-validation", "optional_heavy": False, "claim_scope": "progressive_external_validation", "evidence_level": "external_progressive_sample"},
    {"suite": "real-world-agent-risk-demo", "version": "pre-release", "category": "demo", "optional_heavy": False, "claim_scope": "public_source_mapping", "evidence_level": "public_source_seed_plus_local_demo"},
    {"suite": "containerized-risk-demo", "version": "pre-release", "category": "demo", "optional_heavy": False, "claim_scope": "containerized_local_demo", "evidence_level": "per_case_container_artifact_bundle"},
    {"suite": "pre-v1-control-plane", "version": "v0.24", "category": "demo", "optional_heavy": False},
    {"suite": "full-product-readiness", "version": "v0.40", "category": "readiness", "optional_heavy": False},
    {"suite": "swe-bench-full-official-heavy", "version": "post-v0.40", "category": "external-validation", "optional_heavy": True, "claim_scope": "official_full_benchmark", "evidence_level": "external_live_run"},
    {"suite": "swe-bench-lite-official-heavy", "version": "post-v0.39", "category": "compatibility", "optional_heavy": True},
)


def list_benchmark_suites() -> dict[str, Any]:
    categories: dict[str, int] = {}
    for suite in BENCHMARK_SUITES:
        category = str(suite["category"])
        categories[category] = categories.get(category, 0) + 1
    return {
        "schema_version": "invart.benchmark_registry.v0.45",
        "suites": [dict(item) for item in BENCHMARK_SUITES],
        "summary": {"total": len(BENCHMARK_SUITES), "categories": categories},
    }


def optional_heavy_validation_status() -> dict[str, Any]:
    return {
        "status": "skipped",
        "reason": "optional external benchmark dependencies are not required for deterministic CI",
        "candidates": ["SWE-Bench full official harness", "SWE-Bench Lite official harness", "AgentDojo", "AgentDyn", "AgentSecBench", "SKILL-INJECT", "SusVibes"],
    }


__all__ = ["list_benchmark_suites", "optional_heavy_validation_status"]
