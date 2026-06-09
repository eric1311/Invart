from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

from .common import _suite_result
from invart.evaluation.audit_reconstruction import run_audit_reconstruction_study
from invart.evaluation.coverage_experiments import run_coverage_truthfulness_matrix
from invart.evaluation.experiment_cases import run_paper_suite
from invart.evaluation.paper_tables import export_paper_tables, validate_paper_table_bundle
from invart.evaluation.product_control_matrix import run_product_control_matrix
from invart.evaluation.research_readiness import verify_research_readiness
from invart.evaluation.reviewer_experiments import run_reviewer_selectivity_experiment


def run_paper_evidence_tables_benchmark() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="invart_v046_") as tmp:
        root = Path(tmp)
        paper = run_paper_suite(root / "paper")
        tables = export_paper_tables(paper, root / "tables")
        validation = validate_paper_table_bundle(tables)
        risk_rows = [
            row
            for table in tables.get("tables", [])
            if table.get("table_id") == "risk_path_outcomes"
            for row in table.get("rows", [])
        ]
        checks = {
            "paper_suite_passed": paper.get("status") == "pass",
            "tables_passed": tables.get("status") == "pass",
            "validation_passed": validation.get("status") == "pass",
            "risk_rows_link_evidence": bool(risk_rows) and all(
                all(row.get("artifacts", {}).get(key) for key in ("ledger", "proof", "replay", "path_graph", "evidence_manifest"))
                for row in risk_rows
            ),
        }
        return _suite_result("v0.46-paper-evidence-tables", checks, artifacts=tables.get("artifacts", {}))


def run_coverage_mediation_pilot_benchmark() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="invart_v047_") as tmp:
        matrix = run_coverage_truthfulness_matrix(out_dir=Path(tmp) / "coverage")
        positions = {item["surface"]: item for item in matrix.get("same_action", {}).get("positions", [])}
        checks = {
            "matrix_passed": matrix.get("status") == "pass",
            "imported_log_not_mediated": positions.get("imported_log", {}).get("actual_runtime_enforcement") == "none",
            "managed_wrapper_mediated": positions.get("managed_wrapper", {}).get("actual_runtime_enforcement") == "mediated",
            "shim_proxy_enforced": positions.get("shim_proxy", {}).get("actual_runtime_enforcement") == "enforced",
            "fail_open_not_enforced": positions.get("fail_open", {}).get("actual_runtime_enforcement") != "enforced",
            "bypass_is_gap": positions.get("bypass", {}).get("coverage_gap") is True,
        }
        return _suite_result("v0.47-coverage-mediation-pilot", checks, artifacts=matrix.get("artifacts", {}))


def run_audit_reconstruction_study_benchmark() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="invart_v048_") as tmp:
        report = run_audit_reconstruction_study(out_dir=Path(tmp) / "audit")
        scenarios = {item["scenario_id"]: item for item in report.get("scenarios", [])}
        checks = {
            "study_passed": report.get("status") == "pass",
            "blocked_path_answers_who": bool(scenarios.get("blocked_risk_path", {}).get("answers", {}).get("who")),
            "approved_path_answers_approval": bool(scenarios.get("approved_risk_path", {}).get("answers", {}).get("approval")),
            "tampered_ledger_detected": scenarios.get("tampered_ledger", {}).get("artifact_integrity") is False,
            "mismatch_detected": scenarios.get("proof_ledger_mismatch", {}).get("artifact_consistency") is False,
        }
        return _suite_result("v0.48-audit-reconstruction-study", checks, artifacts=report.get("artifacts", {}))


def run_reviewer_ablation_cost_benchmark() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="invart_v049_") as tmp:
        report = run_reviewer_selectivity_experiment(out_dir=Path(tmp) / "reviewer")
        checks = {
            "experiment_passed": report.get("status") == "pass",
            "critical_non_downgradable": report.get("critical_non_downgradable") is True,
            "selective_less_than_always": report.get("modes", {}).get("selective", {}).get("reviewer_call_rate", 1) < report.get("modes", {}).get("always_on", {}).get("reviewer_call_rate", 0),
            "async_audit_no_policy_change": report.get("modes", {}).get("async_audit", {}).get("changes_policy_outcome") is False,
            "redaction_no_raw_secret": report.get("redaction", {}).get("raw_secret_persisted") is False,
        }
        return _suite_result("v0.49-reviewer-ablation-cost", checks, artifacts=report.get("artifacts", {}))


def run_product_control_matrix_benchmark() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="invart_v050_") as tmp:
        matrix = run_product_control_matrix(out_dir=Path(tmp) / "matrix")
        baselines = {item["baseline"]: item for item in matrix.get("baselines", [])}
        checks = {
            "matrix_passed": matrix.get("status") == "pass",
            "four_products": matrix.get("summary", {}).get("products", 0) >= 4,
            "plugin_only_not_mediated": baselines.get("plugin_only", {}).get("supports_mediation") is False,
            "managed_launcher_mediated": baselines.get("invart_managed_launcher", {}).get("coverage_grade") == "mediated",
        }
        return _suite_result("v0.50-product-control-matrix", checks, artifacts=matrix.get("artifacts", {}))


def run_pre_1_0_research_ready_gate_benchmark() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="invart_v051_") as tmp:
        root = Path(tmp)
        missing = verify_research_readiness(root / "missing")
        paper = run_paper_suite(root / "paper")
        tables = export_paper_tables(paper, root / "tables")
        coverage = run_coverage_truthfulness_matrix(out_dir=root / "coverage")
        reviewer = run_reviewer_selectivity_experiment(out_dir=root / "reviewer")
        audit = run_audit_reconstruction_study(out_dir=root / "audit")
        matrix = run_product_control_matrix(out_dir=root / "matrix")
        ready = verify_research_readiness(
            root / "ready",
            paper_tables=Path(tables["artifacts"]["tables_json"]),
            coverage=Path(coverage["artifacts"]["coverage_json"]),
            reviewer=Path(reviewer["artifacts"]["reviewer_json"]),
            audit=Path(audit["artifacts"]["report_json"]),
            product_matrix=Path(matrix["artifacts"]["matrix_json"]),
        )
        checks = {
            "missing_gate_fails": missing.get("status") == "fail" and missing.get("state") == "research_incomplete",
            "complete_gate_passes": ready.get("status") == "pass" and ready.get("state") == "research_ready",
            "coverage_check_passed": ready.get("checks", {}).get("coverage_truthfulness", {}).get("status") == "pass",
            "reviewer_check_passed": ready.get("checks", {}).get("reviewer_ablation", {}).get("status") == "pass",
        }
        return _suite_result("v0.51-pre-1.0-research-ready-gate", checks, artifacts=ready.get("artifacts", {}))


__all__ = [
    "run_audit_reconstruction_study_benchmark",
    "run_coverage_mediation_pilot_benchmark",
    "run_paper_evidence_tables_benchmark",
    "run_pre_1_0_research_ready_gate_benchmark",
    "run_product_control_matrix_benchmark",
    "run_reviewer_ablation_cost_benchmark",
]
