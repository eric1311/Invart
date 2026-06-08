import json
import sys
from pathlib import Path

from invart.cli import main
from invart.core.ledger import load_ledger_entries, verify_ledger
from invart.core.models import RuntimeEvent
from invart.assurance.postruntime import export_proof_report, summarize_session, verify_proof_report
from invart.control.rules import analyze_command, analyze_runtime_event
from invart.control.preflight import save_preflight
from invart.control.runtime import append_event, close_session, explain_decision, inspect_invocation_review, record_action, record_approval, record_outcome, start_session
from invart.control.evidence import build_redacted_evidence
from invart.evaluation.evals import run_benchmark
from invart.control.daemon import RuntimeAuthority
from invart.surfaces.corpus import capability_events_from_corpus, run_capability_grant_benchmark, scan_corpus, run_real_surface_benchmark
from invart.control.review import LLMReviewer, StaticJSONProvider
from invart.evaluation.harness import compare_harness_runs, run_official_swe_bench_full_validation, run_official_swe_bench_lite_check, run_swe_bench_lite_check
from invart.surfaces.adapter_profiles import build_adapter_profile
from invart.surfaces.claude_adapter import check_claude_code_environment, run_claude_code_adapter
from invart.governance.profiles import resolve_profile
from invart.governance.teamrun import create_handoff, create_teamrun, declare_agent_identity
from invart.surfaces.enforcement import check_enforcement, run_file_write_intercepted, rust_shim_decision
from invart.evaluation.roadmap import roadmap_capabilities, verify_roadmap_coverage
from invart.assurance.audit_demo import run_enterprise_audit_demo, run_enterprise_audit_live_adapter_demo
from invart.control.gate import verify_gate
from invart.surfaces.adapter import run_adapter_command
from invart.control.approval import approve_items, list_approval_items
from invart.assurance.replay import export_replay_html
from invart.surfaces.scanner import scan_pre_runtime
from invart.assurance.coverage import (
    COVERAGE_GRADES,
    CoverageRecord,
    coverage_meets_requirement,
    default_coverage_for_layer,
    merge_coverage_records,
)
from invart.surfaces.native import install_native_integration, inventory_native_integrations
from invart.surfaces.native_bridge import normalize_native_event, render_native_response
from invart.surfaces.mcp_broker import summarize_mcp_message, transparent_broker_step
from invart.evaluation.product_readiness import reviewer_quality_corpus, optional_provider_smoke
from invart.surfaces.supervision import supervise_process_group
from invart.governance.profiles import create_profile_distribution_bundle, record_break_glass_override, review_break_glass_override
from invart.governance.teamrun import export_teamrun_timeline_html
from invart.surfaces.enforcement import run_enforced_command
from invart.assurance.audit_demo import record_audit_signoff
from invart.surfaces.native import native_conformance_report
from invart.surfaces.native_bridge import bridge_conformance_matrix
from invart.surfaces.mcp_broker import run_stdio_broker
from invart.assurance.coverage import export_coverage_html_report
from invart.governance.identity import (
    bind_agent_identity,
    create_capability_grant,
    credential_inventory,
    declare_principal,
    record_identity_binding,
)
from invart.assurance.path_graph import build_execution_graph, export_execution_graph_html, query_execution_graph
from invart.control.path_policy import check_path_policy
from invart.control.mediation import mediate_event, replay_mediation, resolve_mediation
from invart.evaluation.pre_v1 import run_pre_v1_control_plane_demo
from invart.governance.profiles import apply_raw_content_policy, create_profile_registry, pin_profile_bundle, verify_profile_bundle

def test_v14_enterprise_audit_demo_exports_security_artifacts(tmp_path: Path) -> None:
    result = run_enterprise_audit_demo(tmp_path / "demo")
    assert result["schema_version"] == "invart.enterprise_audit_demo.v0.14"
    for key in ["ledger", "proof", "replay", "audit_report", "audit_json"]:
        assert Path(result[key]).exists()
    audit = json.loads(Path(result["audit_json"]).read_text(encoding="utf-8"))
    assert audit["audience"] == "enterprise_security_team"
    assert audit["summary"]["critical_or_high_findings"] >= 2
    assert "secret_leak" in audit["risk_scenarios"]
    assert "unsafe_deletion" in audit["risk_scenarios"]
    html = Path(result["audit_report"]).read_text(encoding="utf-8")
    assert "Enterprise Runtime Audit" in html
    assert "<details" in html
    assert "Raw Evidence" in html


def test_v14_enterprise_audit_demo_cli_benchmark_and_roadmap(tmp_path: Path) -> None:
    out_dir = tmp_path / "cli-demo"
    assert main(["demo", "enterprise-audit", "--out-dir", str(out_dir)]) == 0
    assert (out_dir / "audit-report.html").exists()
    assert main(["eval", "benchmark", "--suite", "v0.14-enterprise-audit-demo"]) == 0
    assert main(["demo", "enterprise-audit", "--mode", "live-adapter", "--out-dir", str(tmp_path / "live-cli-demo")]) == 0
    statuses = {item["capability_id"]: item["status"] for item in roadmap_capabilities()}
    assert statuses["enterprise_audit_demo"] == "implemented"


def test_roadmap_full_requirement_passes_for_product_ready_versions() -> None:
    report = verify_roadmap_coverage(require_full=True)
    assert report["passed"] is True
    assert report["not_fully_implemented"] == []
    boundaries = {item["capability_id"]: item["product_boundaries"] for item in report["capabilities"]}
    assert any("kernel/OS-level" in boundary for boundary in boundaries["native_enforcement"])
    assert any("optional" in boundary.lower() for boundary in boundaries["swe_bench_lite_harness"])
    assert any("signoff" in boundary.lower() for boundary in boundaries["enterprise_audit_demo"])


def test_roadmap_cli_status_and_require_full(tmp_path: Path) -> None:
    assert main(["roadmap", "status"]) == 0
    assert main(["roadmap", "status", "--require-full"]) == 0


def test_full_v14_audit_signoff_is_ledger_backed(tmp_path: Path) -> None:
    result = run_enterprise_audit_demo(tmp_path / "audit")
    signoff = record_audit_signoff(
        Path(result["ledger"]),
        actor="security-lead",
        status="approved",
        reason="demo evidence reviewed",
        report_path=Path(result["audit_report"]),
    )
    assert signoff["signoff"]["status"] == "approved"
    entries, _warnings = load_ledger_entries(Path(result["ledger"]))
    assert entries[-1].entry_type == "audit_signoff"


def test_roadmap_full_product_is_ready() -> None:
    report = verify_roadmap_coverage(require_full=True)
    assert report["passed"] is True
    assert report["summary"]["full_product_ready"] is True
    assert report["not_fully_implemented"] == []


def test_v024_pre_v1_control_plane_demo_and_benchmark_close_product_loop(tmp_path: Path) -> None:
    demo = run_pre_v1_control_plane_demo(tmp_path / "demo")
    assert demo["schema_version"] == "invart.pre_v1_demo.v0.24"
    for key in ["ledger", "proof", "replay", "path_graph", "coverage_report", "audit_report"]:
        assert Path(demo["artifacts"][key]).exists()
    assert demo["metrics"]["proof_completeness"] == 1.0
    assert demo["gate"]["status"] == "fail"
    benchmark = run_benchmark("pre-v1-control-plane")
    assert benchmark["passed"] is True
    assert benchmark["metrics"]["block_rate"] > 0
    assert benchmark["metrics"]["audit_reconstruction_success"] == 1.0


def test_real_world_risk_demo_uses_public_sources_and_product_artifacts(tmp_path: Path) -> None:
    from invart.evaluation.real_world_cases import list_real_world_risk_sources, run_real_world_risk_demo, validate_public_risk_catalog

    validation = validate_public_risk_catalog()
    assert validation["valid"] is True
    assert validation["catalog_hash"].startswith("sha256:")
    catalog = list_real_world_risk_sources()
    assert catalog["summary"]["total"] == 12
    assert catalog["catalog_hash"] == validation["catalog_hash"]
    assert any("clawhub" in item["source_id"] for item in catalog["sources"])
    assert any("credential" in item["observed_risk"] or "secret" in item["observed_risk"] for item in catalog["sources"])
    assert all(item["before_signal"] and item["during_signal"] and item["after_signal"] for item in catalog["sources"])
    assert all(item["short_excerpt"] and len(item["short_excerpt"].split()) <= 25 for item in catalog["sources"])
    assert all({"pre", "during", "after"}.issubset({step["stage"] for step in item["mapped_trajectory"]}) for item in catalog["sources"])

    result = run_real_world_risk_demo(tmp_path / "real-world-demo")
    assert result["status"] == "pass"
    assert result["catalog_hash"] == validation["catalog_hash"]
    assert Path(result["artifacts"]["source_catalog"]).exists()
    exported = json.loads(Path(result["artifacts"]["source_catalog"]).read_text(encoding="utf-8"))
    assert exported["catalog_id"] == "public-risk-sources.v2026-06-02"
    assert exported["summary"]["trajectory_stages"]["during"] >= 12
    html_path = Path(result["artifacts"]["html"])
    html = html_path.read_text(encoding="utf-8")
    assert "Real-World Risk Demo" in html
    assert "Evidence anchor" in html
    assert "sha256:" in html
    assert "live-adapter-demo/audit-report.html" in html
    assert "pre-v1-demo/path-graph.html" in html
    assert result["artifacts"]["live_adapter_demo"]["adapter"]["status"] == "blocked"
    assert result["artifacts"]["pre_v1_demo"]["status"] == "pass"

    benchmark = run_benchmark("real-world-agent-risk-demo")
    assert benchmark["passed"] is True
    assert benchmark["checks"]["all_sources_have_structured_trajectory"] is True
    assert benchmark["checks"]["has_mcp_or_tool_misuse_sources"] is True
    assert main(["demo", "real-world-risk-cases", "--out-dir", str(tmp_path / "cli-demo")]) == 0
    assert main(["eval", "benchmark", "--suite", "real-world-agent-risk-demo"]) == 0


def test_public_risk_catalog_validator_rejects_weak_evidence_fixture(tmp_path: Path) -> None:
    from invart.evaluation.real_world_cases import load_public_risk_catalog, validate_public_risk_catalog

    catalog = load_public_risk_catalog()
    broken = json.loads(json.dumps({key: value for key, value in catalog.items() if key not in {"catalog_path", "catalog_hash", "validation"}}))
    broken["sources"][0]["short_excerpt"] = " ".join(f"word{i}" for i in range(26))
    broken["sources"][0]["excerpt_word_count"] = 26
    broken["sources"][0]["mapped_trajectory"] = [{"stage": "pre", "surface": "skill_registry"}]
    broken["sources"][0]["claim_boundary"] = "Public source seed only."
    path = tmp_path / "broken-public-risk-sources.json"
    path.write_text(json.dumps(broken), encoding="utf-8")

    validation = validate_public_risk_catalog(path)
    assert validation["valid"] is False
    assert any("short_excerpt exceeds" in error for error in validation["errors"])
    assert any("mapped_trajectory must include pre, during, and after" in error for error in validation["errors"])
    assert any("claim_boundary must disclose" in error for error in validation["errors"])


def test_containerized_risk_demo_generates_per_case_artifact_bundles(tmp_path: Path) -> None:
    from invart.evaluation.container_demo import run_container_risk_case, run_container_risk_suite

    secret_case = run_container_risk_case("secret-egress", tmp_path / "secret-egress")
    assert secret_case["status"] == "pass"
    assert secret_case["case"]["case_id"] == "secret-egress"
    assert secret_case["public_sources"]
    assert secret_case["summary"]["blocked_or_paused"] is True
    for key in ["ledger", "proof", "replay", "path_graph", "coverage_report", "audit_report", "case_json"]:
        assert Path(secret_case["artifacts"][key]).exists()

    suite = run_container_risk_suite(tmp_path / "suite")
    assert suite["status"] == "pass"
    assert suite["summary"]["cases"] == 3
    assert suite["summary"]["blocked_or_paused_cases"] == 3
    assert suite["summary"]["source_mapped_cases"] == 3
    html = Path(suite["artifacts"]["suite_html"]).read_text(encoding="utf-8")
    assert "Invart Containerized Risk Demo" in html
    assert "isolated container" in html

    benchmark = run_benchmark("containerized-risk-demo")
    assert benchmark["passed"] is True
    assert main(["demo", "container-risk-case", "--case", "unsafe-delete", "--out-dir", str(tmp_path / "cli-case")]) == 0
    assert main(["demo", "container-risk-suite", "--out-dir", str(tmp_path / "cli-suite")]) == 0
    assert main(["eval", "benchmark", "--suite", "containerized-risk-demo"]) == 0


def test_container_demo_script_runs_one_readonly_container_per_case() -> None:
    script = Path("scripts/container-demo.sh").read_text(encoding="utf-8")
    assert "container-risk-case" in script
    assert 'cases=(unfriendly-skill secret-egress unsafe-delete)' in script
    assert '-v "$ROOT:/workspace:ro"' in script
    assert "--collect-existing" in script


def test_v045_pre_1_0_final_demo_links_control_plane_evidence(tmp_path: Path) -> None:
    from invart.evaluation.pre_1_0 import run_pre_1_0_final_demo

    demo = run_pre_1_0_final_demo(tmp_path / "final-demo")
    assert demo["schema_version"] == "invart.pre_1_0_final_demo.v0.45"
    assert demo["status"] == "pass"
    assert Path(demo["artifacts"]["entrypoint"]).exists()
    assert Path(demo["artifacts"]["vendor_matrix"]).exists()
    assert Path(demo["artifacts"]["unmanaged_inventory"]).exists()
    assert Path(demo["artifacts"]["pre_v1_demo"]["artifacts"]["proof"]).exists()
    html = Path(demo["artifacts"]["entrypoint"]).read_text(encoding="utf-8")
    assert "Invart Pre-1.0 Final Demo" in html
    assert "Invart actions" in html
    assert "vendor-matrix.json" in html
    assert "external validation" in html.lower()
    assert main(["demo", "pre-1.0-final", "--out-dir", str(tmp_path / "cli-final-demo")]) == 0


def test_v041_to_v045_roadmap_benchmarks_and_docs_are_registered() -> None:
    capabilities = {item["version"]: item for item in roadmap_capabilities()}
    for version in ["v0.41", "v0.42", "v0.43", "v0.44", "v0.45"]:
        assert capabilities[version]["status"] == "implemented"
        assert capabilities[version]["docs"]
        assert capabilities[version]["tests"]
        assert capabilities[version]["truthfulness"]["claim_integrity"] is True

    for suite in [
        "v0.41-unmanaged-agent-inventory",
        "v0.42-managed-launcher-migration",
        "v0.43-enterprise-coverage-gate",
        "v0.44-external-evidence-and-swebench",
        "v0.45-final-demo-and-rc-gate",
    ]:
        assert run_benchmark(suite)["passed"] is True
        assert main(["eval", "benchmark", "--suite", suite]) == 0
