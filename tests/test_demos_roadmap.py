import json
import sys
from pathlib import Path

from kappaski.cli import main
from kappaski.ledger import load_ledger_entries, verify_ledger
from kappaski.models import RuntimeEvent
from kappaski.postruntime import export_proof_report, summarize_session, verify_proof_report
from kappaski.rules import analyze_command, analyze_runtime_event
from kappaski.preflight import save_preflight
from kappaski.runtime import append_event, close_session, explain_decision, inspect_invocation_review, record_action, record_approval, record_outcome, start_session
from kappaski.evidence import build_redacted_evidence
from kappaski.evals import run_benchmark
from kappaski.daemon import RuntimeAuthority
from kappaski.corpus import capability_events_from_corpus, run_capability_grant_benchmark, scan_corpus, run_real_surface_benchmark
from kappaski.review import LLMReviewer, StaticJSONProvider
from kappaski.harness import compare_harness_runs, run_official_swe_bench_full_validation, run_official_swe_bench_lite_check, run_swe_bench_lite_check
from kappaski.adapter_profiles import build_adapter_profile
from kappaski.claude_adapter import check_claude_code_environment, run_claude_code_adapter
from kappaski.profiles import resolve_profile
from kappaski.teamrun import create_handoff, create_teamrun, declare_agent_identity
from kappaski.enforcement import check_enforcement, run_file_write_intercepted, rust_shim_decision
from kappaski.roadmap import roadmap_capabilities, verify_roadmap_coverage
from kappaski.audit_demo import run_enterprise_audit_demo, run_enterprise_audit_live_adapter_demo
from kappaski.gate import verify_gate
from kappaski.adapter import run_adapter_command
from kappaski.approval import approve_items, list_approval_items
from kappaski.replay import export_replay_html
from kappaski.scanner import scan_pre_runtime
from kappaski.coverage import (
    COVERAGE_GRADES,
    CoverageRecord,
    coverage_meets_requirement,
    default_coverage_for_layer,
    merge_coverage_records,
)
from kappaski.native import install_native_integration, inventory_native_integrations
from kappaski.native_bridge import normalize_native_event, render_native_response
from kappaski.mcp_broker import summarize_mcp_message, transparent_broker_step
from kappaski.product_readiness import reviewer_quality_corpus, optional_provider_smoke
from kappaski.supervision import supervise_process_group
from kappaski.profiles import create_profile_distribution_bundle, record_break_glass_override, review_break_glass_override
from kappaski.teamrun import export_teamrun_timeline_html
from kappaski.enforcement import run_enforced_command
from kappaski.audit_demo import record_audit_signoff
from kappaski.native import native_conformance_report
from kappaski.native_bridge import bridge_conformance_matrix
from kappaski.mcp_broker import run_stdio_broker
from kappaski.coverage import export_coverage_html_report
from kappaski.identity import (
    bind_agent_identity,
    create_capability_grant,
    credential_inventory,
    declare_principal,
    record_identity_binding,
)
from kappaski.path_graph import build_execution_graph, export_execution_graph_html, query_execution_graph
from kappaski.path_policy import check_path_policy
from kappaski.mediation import mediate_event, replay_mediation, resolve_mediation
from kappaski.pre_v1 import run_pre_v1_control_plane_demo
from kappaski.profiles import apply_raw_content_policy, create_profile_registry, pin_profile_bundle, verify_profile_bundle

def test_v14_enterprise_audit_demo_exports_security_artifacts(tmp_path: Path) -> None:
    result = run_enterprise_audit_demo(tmp_path / "demo")
    assert result["schema_version"] == "kappaski.enterprise_audit_demo.v0.14"
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
    assert demo["schema_version"] == "kappaski.pre_v1_demo.v0.24"
    for key in ["ledger", "proof", "replay", "path_graph", "coverage_report", "audit_report"]:
        assert Path(demo["artifacts"][key]).exists()
    assert demo["metrics"]["proof_completeness"] == 1.0
    assert demo["gate"]["status"] == "fail"
    benchmark = run_benchmark("pre-v1-control-plane")
    assert benchmark["passed"] is True
    assert benchmark["metrics"]["block_rate"] > 0
    assert benchmark["metrics"]["audit_reconstruction_success"] == 1.0


def test_real_world_risk_demo_uses_public_sources_and_product_artifacts(tmp_path: Path) -> None:
    from kappaski.real_world_cases import list_real_world_risk_sources, run_real_world_risk_demo

    catalog = list_real_world_risk_sources()
    assert catalog["summary"]["total"] >= 5
    assert any("clawhub" in item["source_id"] for item in catalog["sources"])
    assert any("credential" in item["observed_risk"] or "secret" in item["observed_risk"] for item in catalog["sources"])
    assert all(item["before_signal"] and item["during_signal"] and item["after_signal"] for item in catalog["sources"])

    result = run_real_world_risk_demo(tmp_path / "real-world-demo")
    assert result["status"] == "pass"
    assert Path(result["artifacts"]["source_catalog"]).exists()
    html_path = Path(result["artifacts"]["html"])
    html = html_path.read_text(encoding="utf-8")
    assert "Real-World Risk Demo" in html
    assert "live-adapter-demo/audit-report.html" in html
    assert "pre-v1-demo/path-graph.html" in html
    assert result["artifacts"]["live_adapter_demo"]["adapter"]["status"] == "blocked"
    assert result["artifacts"]["pre_v1_demo"]["status"] == "pass"

    benchmark = run_benchmark("real-world-agent-risk-demo")
    assert benchmark["passed"] is True
    assert main(["demo", "real-world-risk-cases", "--out-dir", str(tmp_path / "cli-demo")]) == 0
    assert main(["eval", "benchmark", "--suite", "real-world-agent-risk-demo"]) == 0

