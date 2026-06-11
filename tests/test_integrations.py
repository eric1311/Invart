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
from invart.assurance.evidence_bundle import verify_evidence_bundle
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


def test_v041_native_matrix_and_unmanaged_inventory_report_truthful_coverage(tmp_path: Path) -> None:
    from invart.surfaces.native import native_capability_matrix, unmanaged_agent_inventory

    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "settings.json").write_text(json.dumps({"hooks": {"PreToolUse": []}, "mcpServers": {"fs": {}}}), encoding="utf-8")
    (tmp_path / ".codex").mkdir()
    (tmp_path / ".codex" / "config.toml").write_text("[mcp]\nserver = 'local'\n", encoding="utf-8")
    (tmp_path / ".gemini").mkdir()
    (tmp_path / ".gemini" / "settings.json").write_text(json.dumps({"sandbox": True, "mcpServers": {}}), encoding="utf-8")
    (tmp_path / ".cursor").mkdir()
    (tmp_path / ".cursor" / "mcp.json").write_text(json.dumps({"mcpServers": {}}), encoding="utf-8")
    (tmp_path / "opencode.json").write_text(json.dumps({"plugin": ["sample"]}), encoding="utf-8")
    (tmp_path / "hermes.json").write_text(json.dumps({"mcp": {}}), encoding="utf-8")

    matrix = native_capability_matrix(tmp_path)
    assert matrix["schema_version"] == "invart.native_capability_matrix.v0.41"
    by_agent = {item["agent"]: item for item in matrix["agents"]}
    assert {"claude-code", "codex", "gemini-cli", "cursor", "opencode", "hermes"}.issubset(by_agent)
    assert by_agent["claude-code"]["surfaces"]["hooks"]["coverage_state"] in {"observed", "mediated"}
    assert by_agent["hermes"]["surfaces"]["config"]["coverage_state"] == "vendor_owned"
    assert by_agent["claude-code"]["surfaces"]["hooks"]["enforcement_claim"] != "enforced"
    assert by_agent["codex"]["surfaces"]["mcp"]["source_evidence"]

    unmanaged = unmanaged_agent_inventory(tmp_path)
    assert unmanaged["schema_version"] == "invart.unmanaged_agent_inventory.v0.41"
    assert unmanaged["summary"]["unmanaged_detected"] >= 1
    assert any(item["coverage_fact"]["state"] == "unmanaged_detected" for item in unmanaged["findings"])
    assert main(["native", "matrix", "--target", str(tmp_path)]) == 0
    assert main(["native", "unmanaged", "--target", str(tmp_path)]) == 0


def test_v042_launcher_migration_preview_confirm_and_coverage_gate(tmp_path: Path) -> None:
    from invart.surfaces.launcher import install_managed_launcher, preview_managed_launcher, verify_managed_launcher
    from invart.assurance.coverage import evaluate_coverage_gate

    preview = preview_managed_launcher(tmp_path, agent="claude-code", launcher="shell")
    assert preview["schema_version"] == "invart.managed_launcher.v0.42"
    assert preview["mode"] == "preview"
    assert preview["written"] is False
    assert not Path(preview["target_path"]).exists()
    assert preview["planned_writes"]

    installed = install_managed_launcher(tmp_path, agent="claude-code", launcher="shell")
    assert installed["mode"] == "confirm"
    assert installed["written"] is True
    assert Path(installed["target_path"]).exists()
    verified = verify_managed_launcher(tmp_path, agent="claude-code")
    assert verified["status"] == "pass"
    assert verified["coverage"]["runtime_enforcement"] == "mediated"

    fail_gate = evaluate_coverage_gate(
        {"runtime_enforcement": "vendor_owned", "unmanaged_detected": True},
        profile={"mode": "enterprise", "required_runtime_enforcement": "mediated", "allow_unmanaged": False},
    )
    assert fail_gate["status"] == "fail"
    assert any(finding["check_id"] == "coverage.unmanaged_detected" for finding in fail_gate["findings"])
    warn_gate = evaluate_coverage_gate(
        {"runtime_enforcement": "vendor_owned", "unmanaged_detected": True},
        profile={"mode": "audit", "required_runtime_enforcement": "mediated", "allow_unmanaged": False},
    )
    assert warn_gate["status"] == "warn"
    assert main(["launcher", "preview", "--target", str(tmp_path), "--agent", "codex"]) == 0
    assert main(["launcher", "install", "--target", str(tmp_path), "--agent", "codex"]) == 0
    assert main(["launcher", "verify", "--target", str(tmp_path), "--agent", "codex"]) == 0

def test_v04_real_corpus_scan_uses_pinned_snapshots() -> None:
    report = scan_corpus(Path("benchmarks/corpora"))
    assert report["summary"]["snapshots"] >= 5
    assert report["summary"]["by_capability"]
    assert report["summary"]["by_risk"]
    assert all(surface["metadata"].get("repo") for surface in report["surfaces"])
    assert any(surface["kind"] == "skill" for surface in report["surfaces"])
    assert any(surface["kind"] == "mcp" for surface in report["surfaces"])


def test_v04_real_skill_surface_benchmark_passes() -> None:
    result = run_real_surface_benchmark(Path("benchmarks/corpora"))
    assert result["passed"] is True
    assert result["checks"]["has_real_snapshots"] is True
    assert result["checks"]["detects_capabilities"] is True


def test_v04_cli_corpus_scan_and_eval() -> None:
    assert main(["corpus", "scan", "--root", "benchmarks/corpora"]) == 0
    assert main(["eval", "benchmark", "--suite", "v0.4-real-skill-surface"]) == 0


def test_v04_capability_grants_enter_policy_and_proof(tmp_path: Path) -> None:
    authority = RuntimeAuthority.for_target(tmp_path)
    authority.create_session(tmp_path, agent="codex", session_id="ks_caps", create_preflight=False)
    result = authority.register_capabilities("ks_caps", Path("benchmarks/corpora"), adapter="codex-wrapper")
    assert result["registered"] is True
    assert result["summary"]["total"] >= 5
    assert result["summary"]["pending_approvals"] >= 1

    registry = authority.get_session("ks_caps")
    assert registry.metadata["capability_grants"]
    assert any(grant["effect"] == "ask" for grant in registry.metadata["capability_grants"])

    proof = export_proof_report(Path(registry.ledger_path))
    assert proof["summary"]["capability_grants"] == result["summary"]["total"]
    assert len(proof["capability_grants"]) == result["summary"]["total"]


def test_v04_capability_event_builder_is_deterministic() -> None:
    events_a = capability_events_from_corpus(Path("benchmarks/corpora"), "ks_deterministic", adapter="test-adapter")
    events_b = capability_events_from_corpus(Path("benchmarks/corpora"), "ks_deterministic", adapter="test-adapter")
    ids_a = [event["metadata"]["capability_grant_id"] for event in events_a]
    ids_b = [event["metadata"]["capability_grant_id"] for event in events_b]
    assert ids_a == ids_b
    assert all(event["metadata"]["capability_surface"]["content_sha256"] for event in events_a)


def test_v04_capability_grant_benchmark_closes_loop() -> None:
    result = run_capability_grant_benchmark(Path("benchmarks/corpora"))
    assert result["summary"]["grants"] >= 5
    assert result["summary"]["high_risk_approval_failures"] == 0
    assert result["proof"]["capability_grants"] == result["summary"]["grants"]


def test_v06_adapter_run_exports_artifacts_and_gate_report(tmp_path: Path) -> None:
    out_dir = tmp_path / "artifacts"
    result = run_adapter_command(
        target=tmp_path,
        command=["python3", "-c", "print('adapter ok')"],
        agent="codex",
        goal="adapter smoke",
        session_id="ks_adapter",
        out_dir=out_dir,
        capabilities="audit",
        gate_mode="ci",
        create_preflight=False,
    )
    assert result.returncode == 0
    assert result.status == "passed"
    assert Path(result.ledger).exists()
    assert Path(result.proof).exists()
    assert result.gate_report is not None
    assert Path(result.gate_report).exists()
    gate = json.loads(Path(result.gate_report).read_text(encoding="utf-8"))
    assert gate["status"] == "pass"
    proof = export_proof_report(Path(result.ledger))
    assert proof["summary"]["capability_grants"] >= 5


def test_v06_adapter_run_managed_capabilities_fail_gate(tmp_path: Path) -> None:
    out_dir = tmp_path / "artifacts"
    result = run_adapter_command(
        target=tmp_path,
        command=["python3", "-c", "print('adapter risk')"],
        agent="codex",
        goal="adapter managed caps",
        session_id="ks_adapter_fail",
        out_dir=out_dir,
        capabilities="managed",
        gate_mode="managed",
        create_preflight=False,
    )
    assert result.returncode == 0
    assert result.status == "failed"
    assert result.gate_status == "fail"
    gate = json.loads(Path(result.gate_report).read_text(encoding="utf-8"))
    assert any(finding["check_id"] == "approval.missing" for finding in gate["findings"])


def test_v06_cli_adapter_run(tmp_path: Path) -> None:
    out_dir = tmp_path / "artifacts"
    assert main([
        "adapter",
        "run",
        "--target",
        str(tmp_path),
        "--session-id",
        "ks_cli_adapter",
        "--out-dir",
        str(out_dir),
        "--capabilities",
        "audit",
        "--gate",
        "ci",
        "--no-preflight",
        "--",
        "python3",
        "-c",
        "print('cli adapter ok')",
    ]) == 0
    assert (out_dir / "ledger.jsonl").exists()
    assert (out_dir / "proof.json").exists()
    assert (out_dir / "gate-report.json").exists()


def test_v06_adapter_workflow_benchmark() -> None:
    assert main(["eval", "benchmark", "--suite", "v0.6-adapter-workflow"]) == 0


def test_v09_harness_compatibility_accepts_metadata_drift() -> None:
    baseline = {"exit_code": 0, "grading_result": "passed", "artifacts": ["report.json"], "metadata": {"duration": 10}}
    wrapped = {"exit_code": 0, "grading_result": "passed", "artifacts": ["report.json"], "metadata": {"duration": 12, "invart": True}}
    report = compare_harness_runs(baseline, wrapped, case={"instance_id": "django__django-11001"})
    assert report["status"] == "pass"
    assert report["checks"]["exit_code"] is True
    assert report["metadata_diff"]


def test_v13_enforcement_order_and_file_guard() -> None:
    report = check_enforcement({"type": "shell", "command": "rm -rf ."}, domain="file-write")
    assert report["effect"] == "deny"
    assert report["failure_mode"] == "fail-open-with-critical-alert"
    secret = check_enforcement({"type": "shell", "command": "echo $OPENAI_API_KEY"}, domain="env-secrets")
    assert secret["effect"] == "require_approval"


def test_v08_to_v13_cli_smoke(tmp_path: Path) -> None:
    baseline = tmp_path / "baseline.json"
    wrapped = tmp_path / "wrapped.json"
    baseline.write_text(json.dumps({"exit_code": 0, "grading_result": "passed", "artifacts": ["a"]}), encoding="utf-8")
    wrapped.write_text(json.dumps({"exit_code": 0, "grading_result": "passed", "artifacts": ["a"], "metadata": {"invart": True}}), encoding="utf-8")
    profile = tmp_path / "profile.toml"
    profile.write_text('name = "session"\n[taint]\nhandoff_inheritance = "resource-reference"\n', encoding="utf-8")
    assert main(["harness", "compare", "--baseline", str(baseline), "--wrapped", str(wrapped)]) == 0
    assert main(["adapter", "profile", "--kind", "claude-code"]) == 0
    assert main(["profile", "resolve", "--session", str(profile)]) == 0
    assert main(["teamrun", "create", "--name", "demo", "--user", "alice", "--user", "bob"]) == 0
    assert main(["teamrun", "handoff", "--source-agent", "a", "--target-agent", "b", "--resource", "tainted:.env"]) == 0
    assert main(["enforce", "check", "--domain", "file-write", "--event", '{"type":"file_read","path":"README.md"}']) == 0


def test_v09_official_swe_bench_lite_command_reports_real_harness_shape(tmp_path: Path) -> None:
    fake = tmp_path / "fake_swebench.py"
    report = tmp_path / "gold.fake_run.json"
    fake.write_text(
        "import json, pathlib, sys\n"
        "path = pathlib.Path(sys.argv[1])\n"
        "path.write_text(json.dumps({\"total_instances\": 1, \"submitted_instances\": 1, \"completed_instances\": 1, \"resolved_instances\": 1, \"unresolved_instances\": 0, \"error_instances\": 0, \"completed_ids\": [\"django__django-11001\"], \"resolved_ids\": [\"django__django-11001\"]}))\n",
        encoding="utf-8",
    )
    result = run_official_swe_bench_lite_check(
        command=[sys.executable, str(fake), str(report)],
        report_path=report,
        run_id="fake_run",
        work_dir=tmp_path,
    )
    assert result["status"] == "pass"
    assert result["runner"]["mode"] == "official_swebench_harness"
    assert result["checks"]["completed_instances_positive"] is True
    assert result["official_report"]["resolved_instances"] == 1


def test_v09_cli_official_swe_bench_lite_command_override(tmp_path: Path) -> None:
    fake = tmp_path / "fake_swebench.py"
    report = tmp_path / "gold.fake_cli.json"
    out = tmp_path / "official.json"
    fake.write_text(
        "import json, pathlib, sys\n"
        "path = pathlib.Path(sys.argv[1])\n"
        "path.write_text(json.dumps({\"total_instances\": 1, \"completed_instances\": 1, \"resolved_instances\": 1, \"error_instances\": 0}))\n",
        encoding="utf-8",
    )
    command = f'{sys.executable} {fake} {report}'
    assert main([
        "harness",
        "swe-bench-official",
        "--command",
        command,
        "--report-path",
        str(report),
        "--work-dir",
        str(tmp_path),
        "--out",
        str(out),
    ]) == 0
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["status"] == "pass"
    assert payload["checks"]["report_json_parsed"] is True


def test_full_claude_adapter_environment_check_reports_real_binary() -> None:
    result = check_claude_code_environment(binary="python3")
    assert result["schema_version"] == "invart.claude_environment.v0.10"
    assert result["available"] is True
    assert result["binary"].endswith("python3") or result["binary"] == "python3"
    assert "adapter_profile" in result
    assert isinstance(result["conformance"]["returncode"], int)


def test_v093_adapter_profile_registry_reports_truthful_agent_contracts() -> None:
    from invart.surfaces.adapter_profiles import get_adapter_profile, list_adapter_profiles, validate_adapter_profile_truthfulness

    profiles = list_adapter_profiles()
    by_agent = {profile["agent_id"]: profile for profile in profiles}
    required = {
        "claude-code",
        "codex",
        "gemini-cli",
        "cursor",
        "opencode",
        "openclaw",
        "hermes",
        "cline",
        "roo-code",
        "github-copilot-cloud-agent",
        "aider",
        "openai-agents-sdk",
        "langgraph",
        "crewai",
    }
    assert required.issubset(by_agent)
    assert by_agent["claude-code"]["coverage_grade"] == "full_managed_adapter"
    assert by_agent["github-copilot-cloud-agent"]["coverage_grade"] == "vendor_evidence_import"
    assert by_agent["cursor"]["coverage_grade"] in {"native_event_bridge", "discovery_only", "vendor_evidence_import"}
    assert all(profile["claim_boundary"] for profile in profiles)
    assert all(profile["source_urls"] for profile in profiles)

    validation = validate_adapter_profile_truthfulness(profiles)
    assert validation["status"] == "pass"
    assert validation["checks"]["full_managed_requires_artifacts"] is True
    assert validation["checks"]["import_only_not_mediated"] is True
    assert validation["checks"]["discovery_only_not_mediated"] is True

    claude = get_adapter_profile("claude-code")
    assert {"ledger", "proof", "evidence_bundle"}.issubset(set(claude["required_artifacts"]))


def test_v093_adapter_profile_cli_accepts_priority_agents() -> None:
    assert main(["adapter", "profile", "--kind", "gemini-cli"]) == 0
    assert main(["adapter", "profile", "--kind", "github-copilot-cloud-agent"]) == 0


def test_v093_real_agent_conformance_fixture_and_strict_live_modes(tmp_path: Path) -> None:
    from invart.evaluation.real_agent_conformance import run_real_agent_conformance

    fake = tmp_path / "fake-agent"
    fake.write_text("#!/usr/bin/env python3\nimport sys\nsys.exit(0)\n", encoding="utf-8")
    fake.chmod(0o755)

    report = run_real_agent_conformance(
        out_dir=tmp_path / "pass",
        agents=["claude-code", "codex"],
        binary_overrides={"claude-code": str(fake), "codex": str(fake)},
        require_live=True,
    )
    assert report["schema_version"] == "invart.real_agent_conformance.v0.9.3"
    assert report["status"] == "pass"
    assert report["summary"]["passed_agents"] == 2
    assert all(agent["binary"]["status"] == "found" for agent in report["agents"])
    assert all(agent["managed_run"]["status"] == "pass" for agent in report["agents"])
    assert Path(report["artifacts"]["report_json"]).exists()
    assert Path(report["artifacts"]["report_html"]).exists()

    advisory_missing = run_real_agent_conformance(
        out_dir=tmp_path / "advisory-missing",
        agents=["hermes"],
        binary_overrides={"hermes": str(tmp_path / "missing-hermes")},
        require_live=False,
    )
    assert advisory_missing["status"] == "pass"
    assert advisory_missing["agents"][0]["status"] == "blocked_missing_binary"
    assert advisory_missing["agents"][0]["claim_boundary"]

    strict_missing = run_real_agent_conformance(
        out_dir=tmp_path / "strict-missing",
        agents=["hermes"],
        binary_overrides={"hermes": str(tmp_path / "missing-hermes")},
        require_live=True,
    )
    assert strict_missing["status"] == "fail"
    assert strict_missing["agents"][0]["status"] == "blocked_missing_binary"


def test_v093_real_agent_cli_and_benchmark(tmp_path: Path) -> None:
    fake = tmp_path / "fake-agent"
    fake.write_text("#!/usr/bin/env python3\nimport sys\nsys.exit(0)\n", encoding="utf-8")
    fake.chmod(0o755)
    out = tmp_path / "cli"

    assert main([
        "real-agent",
        "check",
        "--agent",
        "claude-code",
        "--agent",
        "codex",
        "--binary",
        f"claude-code={fake}",
        "--binary",
        f"codex={fake}",
        "--require-live",
        "--out-dir",
        str(out),
    ]) == 0
    assert (out / "real-agent-conformance.json").exists()
    assert main(["real-agent", "report", "--run-dir", str(out), "--out", str(tmp_path / "report.html")]) == 0
    assert main(["eval", "benchmark", "--suite", "v0.9.3-agent-adapter-contract"]) == 0


def test_v13_adapter_run_uses_file_write_enforcement(tmp_path: Path) -> None:
    out = tmp_path / "artifacts"
    marker = tmp_path / "blocked.txt"
    result = run_adapter_command(
        target=tmp_path,
        command=["sh", "-c", f"touch {marker}; rm -rf ."],
        agent="test-agent",
        session_id="ks_adapter_enforced",
        out_dir=out,
        capabilities="off",
        enforcement="file-write",
        create_preflight=False,
    )
    assert result.status == "blocked"
    assert result.returncode == 126
    assert marker.exists() is False
    entries, _warnings = load_ledger_entries(Path(result.ledger))
    assert any(entry.outcome and entry.outcome.get("status") == "blocked" for entry in entries)


def test_v13_claude_adapter_uses_file_write_enforcement(tmp_path: Path) -> None:
    marker = tmp_path / "blocked.txt"
    result = run_claude_code_adapter(
        target=tmp_path,
        command=["sh", "-c", f"touch {marker}; rm -rf ."],
        out_dir=tmp_path / "claude-artifacts",
        session_id="ks_claude_enforced",
        enforcement="file-write",
    )
    assert result["status"] == "blocked"
    assert result["returncode"] == 126
    assert marker.exists() is False


def test_v14_live_adapter_enterprise_audit_demo_blocks_command(tmp_path: Path) -> None:
    result = run_enterprise_audit_live_adapter_demo(tmp_path / "live-demo")
    assert result["mode"] == "live_adapter_enforced"
    assert Path(result["audit_report"]).exists()
    assert result["adapter"]["status"] == "blocked"
    assert result["summary"]["blocked_before_execution"] is True
    audit = json.loads(Path(result["audit_json"]).read_text(encoding="utf-8"))
    assert audit["demo_mode"] == "live_adapter_enforced"
    assert "secret_leak" in audit["risk_scenarios"]


def test_roadmap_coverage_reports_full_product_readiness() -> None:
    report = verify_roadmap_coverage()
    assert report["passed"] is True
    summary = report["summary"]
    assert summary["milestone_complete_through_v0_12"] is True
    assert summary["local_slice_ready_through_v0_13"] is True
    assert summary["full_product_ready"] is True
    statuses = {item["capability_id"]: item["status"] for item in roadmap_capabilities()}
    assert statuses["native_enforcement"] == "implemented"
    assert statuses["swe_bench_lite_harness"] == "implemented"
    assert statuses["enterprise_audit_demo"] == "implemented"


def test_v10_claude_code_adapter_ingests_hook_events_and_runs_child(tmp_path: Path) -> None:
    hooks = tmp_path / "hooks.jsonl"
    hooks.write_text(
        json.dumps({"type": "file_read", "path": "/repo/.env", "metadata": {"source": "claude_code_hook", "trust_level": "trusted"}}) + "\n" +
        json.dumps({"type": "tool", "tool": "Bash", "metadata": {"operation": "tool_call", "source": "claude_code_hook"}}) + "\n",
        encoding="utf-8",
    )
    out_dir = tmp_path / "claude-artifacts"
    assert main([
        "adapter", "claude-code",
        "--target", str(tmp_path),
        "--out-dir", str(out_dir),
        "--hook-events", str(hooks),
        "--session-id", "ks_claude_adapter",
        "--",
        "python3", "-c", "print('claude adapter ok')",
    ]) == 0
    ledger = out_dir / "ledger.jsonl"
    proof = out_dir / "proof.json"
    assert ledger.exists()
    assert proof.exists()
    entries, _warnings = load_ledger_entries(ledger)
    action_events = [entry.event for entry in entries if entry.entry_type == "action" and entry.event]
    assert any(event.get("metadata", {}).get("adapter") == "claude-code-hook" for event in action_events)
    assert any(event.get("metadata", {}).get("adapter") == "claude-code-process" for event in action_events)
    assert any(event.get("metadata", {}).get("process_supervision", {}).get("mode") == "subprocess" for event in action_events)


def test_v094_claude_adapter_exports_full_package_and_mediates_hooks(tmp_path: Path) -> None:
    hooks = tmp_path / "hooks.jsonl"
    hooks.write_text(
        json.dumps({"type": "file_read", "path": str(tmp_path / ".env"), "metadata": {"source": "claude_code_hook"}}) + "\n",
        encoding="utf-8",
    )
    out_dir = tmp_path / "claude-v094"
    result = run_claude_code_adapter(
        target=tmp_path,
        command=[sys.executable, "-c", "print('ok')"],
        hook_events=hooks,
        out_dir=out_dir,
        session_id="ks_v094_claude_package",
        policy_mode="advisory",
    )
    assert result["status"] == "passed"
    assert result["adapter_package"]["status"] == "pass"
    assert result["adapter_package"]["manifest_path"].endswith("manifest.json")
    verification = verify_evidence_bundle(Path(result["adapter_package"]["manifest_path"]))
    assert verification["status"] == "pass"
    for artifact in ("ledger", "proof", "replay", "path_graph_json", "path_graph_html", "coverage", "audit_html"):
        assert Path(result["adapter_package"]["artifacts"][artifact]).exists()
    assert result["supervision"]["strong_consistency"] is False
    assert result["supervision"]["coverage_grade"] == "mediated_without_process_tree"
    assert result["permission_inventory"]["status"] == "recorded"

    entries, _warnings = load_ledger_entries(Path(result["ledger"]))
    mediation_entries = [entry for entry in entries if entry.entry_type == "mediation"]
    assert any(entry.result["request"]["surface"] == "file" for entry in mediation_entries)
    assert any(entry.result["decision"]["effect"] in {"allow", "require_approval"} for entry in mediation_entries)


def test_v094_claude_adapter_managed_risk_pauses_before_side_effect(tmp_path: Path) -> None:
    marker = tmp_path / "should_not_exist.txt"
    result = run_claude_code_adapter(
        target=tmp_path,
        command=["sh", "-c", f"touch {marker}; rm -rf ."],
        out_dir=tmp_path / "claude-managed",
        session_id="ks_v094_claude_managed",
        policy_mode="managed",
    )
    assert result["status"] in {"blocked", "requires_approval"}
    assert result["returncode"] == 126
    assert marker.exists() is False
    entries, _warnings = load_ledger_entries(Path(result["ledger"]))
    process_mediations = [
        entry.result for entry in entries
        if entry.entry_type == "mediation" and entry.result.get("request", {}).get("surface") == "command"
    ]
    assert process_mediations
    assert process_mediations[-1]["decision"]["effect"] in {"deny", "require_approval"}
    assert process_mediations[-1]["outcome"]["status"] in {"blocked", "paused"}


def test_v094_claude_adapter_advisory_benign_keeps_autonomy(tmp_path: Path) -> None:
    marker = tmp_path / "safe.txt"
    result = run_claude_code_adapter(
        target=tmp_path,
        command=[sys.executable, "-c", f"from pathlib import Path; Path({str(marker)!r}).write_text('ok')"],
        out_dir=tmp_path / "claude-advisory",
        session_id="ks_v094_claude_advisory",
        policy_mode="advisory",
    )
    assert result["status"] == "passed"
    assert result["returncode"] == 0
    assert marker.read_text(encoding="utf-8") == "ok"
    entries, _warnings = load_ledger_entries(Path(result["ledger"]))
    action_events = [entry for entry in entries if entry.entry_type == "action" and entry.event]
    process_actions = [entry for entry in action_events if entry.event.get("metadata", {}).get("adapter") == "claude-code-process"]
    assert process_actions
    assert process_actions[-1].decision["effect"] == "allow"


def test_v094_claude_adapter_cli_and_benchmark_are_registered(tmp_path: Path) -> None:
    marker = tmp_path / "cli_should_not_exist.txt"
    out_dir = tmp_path / "claude-cli"
    assert main([
        "adapter",
        "claude-code",
        "--target",
        str(tmp_path),
        "--out-dir",
        str(out_dir),
        "--session-id",
        "ks_v094_claude_cli",
        "--policy-mode",
        "managed",
        "--",
        "sh",
        "-c",
        f"touch {marker}; rm -rf .",
    ]) == 126
    assert marker.exists() is False
    assert (out_dir / "adapter-package.json").exists()
    assert main(["eval", "benchmark", "--suite", "v0.9.4-claude-reference-adapter"]) == 0


def test_v095_priority_agent_profiles_emit_tracks_and_control_positions() -> None:
    from invart.surfaces.adapter_profiles import adapter_track_matrix, list_adapter_profiles, validate_adapter_profile_truthfulness

    profiles = list_adapter_profiles()
    by_agent = {profile["agent_id"]: profile for profile in profiles}
    expected_tracks = {
        "claude-code": ("reference_full_adapter", "invart_mediated"),
        "codex": ("managed_wrapper", "invart_mediated"),
        "gemini-cli": ("managed_wrapper", "invart_mediated"),
        "cursor": ("native_bridge", "bridge_mediated_when_configured"),
        "opencode": ("native_bridge", "bridge_mediated_when_configured"),
        "openclaw": ("vendor_evidence_import", "vendor_owned_import"),
        "hermes": ("vendor_evidence_import", "vendor_owned_import"),
        "github-copilot-cloud-agent": ("cloud_evidence_import", "vendor_owned_import"),
    }
    for agent_id, (track, control_position) in expected_tracks.items():
        profile = by_agent[agent_id]
        assert profile["integration_track"] == track
        assert profile["control_position"] == control_position
        assert profile["adapter_family"]
        assert profile["track_status"] in {"implemented", "fixture_validated", "planned_import"}

    validation = validate_adapter_profile_truthfulness(profiles)
    assert validation["status"] == "pass"
    assert validation["checks"]["track_fields_present"] is True
    assert validation["checks"]["vendor_import_track_not_mediated"] is True

    matrix = adapter_track_matrix()
    assert matrix["schema_version"] == "invart.adapter_track_matrix.v0.9.5"
    assert matrix["status"] == "pass"
    assert matrix["summary"]["tracks"]["reference_full_adapter"] >= 1


def test_v095_managed_local_tracks_produce_fixture_evidence(tmp_path: Path) -> None:
    from invart.assurance.evidence_bundle import verify_evidence_bundle

    claude = run_claude_code_adapter(
        target=tmp_path,
        command=[sys.executable, "-c", "pass"],
        out_dir=tmp_path / "claude",
        session_id="ks_v095_claude",
        policy_mode="advisory",
    )
    assert claude["status"] == "passed"
    assert verify_evidence_bundle(Path(claude["adapter_package"]["manifest_path"]))["status"] == "pass"

    codex = run_adapter_command(
        target=tmp_path,
        command=[sys.executable, "-c", "print('codex track')"],
        agent="codex",
        goal="v0.9.5 track fixture",
        session_id="ks_v095_codex",
        out_dir=tmp_path / "codex",
        capabilities="audit",
        gate_mode="audit",
        create_preflight=False,
    )
    assert codex.status == "passed"
    assert Path(codex.ledger).exists()
    assert Path(codex.proof).exists()
    assert codex.package is not None and Path(codex.package).exists()


def test_v095_product_matrix_uses_profile_track_vocabulary(tmp_path: Path) -> None:
    from invart.evaluation.product_control_matrix import run_product_control_matrix

    matrix = run_product_control_matrix(out_dir=tmp_path / "matrix")
    rows = [row for row in matrix["rows"] if row.get("source_kind") == "invart_adapter_profile"]
    by_agent = {row["agent_id"]: row for row in rows}
    assert by_agent["claude-code"]["integration_track"] == "reference_full_adapter"
    assert by_agent["claude-code"]["coverage_grade"] == "mediated"
    assert by_agent["github-copilot-cloud-agent"]["coverage_grade"] == "vendor_owned"
    assert by_agent["github-copilot-cloud-agent"]["supports_mediation"] is False
    assert matrix["checks"]["profile_rows_match_track_vocabulary"] is True


def test_v095_cli_and_benchmark_are_registered() -> None:
    assert main(["adapter", "profiles"]) == 0
    assert main(["adapter", "profiles", "--track", "managed_wrapper"]) == 0
    assert main(["eval", "benchmark", "--suite", "v0.9.5-priority-agent-tracks"]) == 0


def test_v09_swe_bench_lite_runner_skips_cleanly_without_dependencies(tmp_path: Path) -> None:
    out = tmp_path / "swebench-report.json"
    assert main([
        "harness", "swe-bench-lite",
        "--case", "benchmarks/cases/swe-bench-lite/pinned_cases.json",
        "--out", str(out),
        "--skip-if-unavailable",
        "--dependency", "definitely_missing_swebench_binary_for_test",
    ]) == 0
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["status"] == "skipped"
    assert payload["case"]["instance_id"] == "django__django-11001"


def test_v09_swe_bench_lite_runner_compares_supplied_artifacts(tmp_path: Path) -> None:
    baseline = tmp_path / "baseline.json"
    wrapped = tmp_path / "wrapped.json"
    out = tmp_path / "swebench-report.json"
    baseline.write_text(json.dumps({"exit_code": 0, "grading_result": "passed", "artifacts": ["report.json"]}), encoding="utf-8")
    wrapped.write_text(json.dumps({"exit_code": 0, "grading_result": "passed", "artifacts": ["report.json"], "metadata": {"invart": True}}), encoding="utf-8")
    assert main([
        "harness", "swe-bench-lite",
        "--case", "benchmarks/cases/swe-bench-lite/pinned_cases.json",
        "--baseline-artifact", str(baseline),
        "--wrapped-artifact", str(wrapped),
        "--out", str(out),
    ]) == 0
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["status"] == "pass"
    assert payload["checks"]["exit_code"] is True
    assert payload["case"]["instance_id"] == "django__django-11001"


def test_v13_rust_shim_decision_blocks_bulk_delete() -> None:
    result = rust_shim_decision({"type": "shell", "command": "rm -rf ."})
    assert result["status"] == "pass"
    assert result["effect"] == "deny"
    assert result["shim"]["finding_id"] == "file.bulk_delete"


def test_v13_rust_shim_uses_deterministic_fallback_for_incompatible_binary(tmp_path: Path) -> None:
    bad_binary = tmp_path / "invart-shim"
    bad_binary.write_text("not a native executable", encoding="utf-8")
    bad_binary.chmod(0o755)
    result = rust_shim_decision({"type": "shell", "command": "rm -rf ."}, binary_path=bad_binary)
    assert result["status"] == "pass"
    assert result["effect"] == "deny"
    assert result["fallback"] is True
    assert result["shim"]["finding_id"] == "file.bulk_delete"


def test_v13_intercepted_file_write_blocks_before_execution_and_records_outcome(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.jsonl"
    session = start_session(tmp_path, ledger, agent="test", goal="v0.13 interception", create_preflight=False)
    marker = tmp_path / "should_not_exist"
    result = run_file_write_intercepted(
        ["sh", "-c", f"touch {marker}; rm -rf ."],
        ledger_path=ledger,
        session_id=session.session_id,
        target=tmp_path,
    )
    assert result["status"] == "blocked"
    assert result["returncode"] == 126
    assert marker.exists() is False
    entries, _warnings = load_ledger_entries(ledger)
    assert entries[-1].entry_type == "outcome"
    assert entries[-1].outcome["status"] == "blocked"


def test_v13_intercepted_file_write_allows_safe_command_and_records_outcome(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.jsonl"
    session = start_session(tmp_path, ledger, agent="test", goal="v0.13 safe interception", create_preflight=False)
    marker = tmp_path / "safe.txt"
    result = run_file_write_intercepted(
        ["sh", "-c", f"touch {marker}"],
        ledger_path=ledger,
        session_id=session.session_id,
        target=tmp_path,
    )
    assert result["status"] == "executed"
    assert result["returncode"] == 0
    assert marker.exists() is True
    entries, _warnings = load_ledger_entries(ledger)
    assert entries[-1].entry_type == "outcome"
    assert entries[-1].outcome["status"] == "executed"


def test_v13_cli_run_file_write_intercepts_command(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.jsonl"
    assert main(["session", "start", "--target", str(tmp_path), "--session-id", "ks_v13_cli", "--ledger", str(ledger), "--no-preflight"]) == 0
    marker = tmp_path / "cli_safe.txt"
    assert main(["enforce", "run-file-write", "--ledger", str(ledger), "--session", "ks_v13_cli", "--target", str(tmp_path), "--", "sh", "-c", f"touch {marker}"]) == 0
    assert marker.exists() is True
    marker2 = tmp_path / "cli_blocked.txt"
    assert main(["enforce", "run-file-write", "--ledger", str(ledger), "--session", "ks_v13_cli", "--target", str(tmp_path), "--", "sh", "-c", f"touch {marker2}; rm -rf ."]) == 126
    assert marker2.exists() is False


def test_v13_rust_file_write_shim_source_and_cli_spec_exist() -> None:
    cargo = Path("rust/invart-shim/Cargo.toml")
    main_rs = Path("rust/invart-shim/src/main.rs")
    assert cargo.exists()
    assert main_rs.exists()
    assert "invart-shim" in cargo.read_text(encoding="utf-8")
    assert "file.destructive_command" in main_rs.read_text(encoding="utf-8")
    assert main(["enforce", "shim-spec", "--domain", "file-write"]) == 0


def test_v13_rust_shim_build_check_skips_without_cargo() -> None:
    assert main(["enforce", "rust-build-check", "--skip-if-unavailable"]) == 0


def test_v18_coverage_grade_order_and_layer_defaults() -> None:
    assert COVERAGE_GRADES == ("none", "declared", "observed", "mediated", "enforced")
    hook = default_coverage_for_layer("native_hook")
    assert hook.runtime_observation == "mediated"
    assert hook.runtime_enforcement == "mediated"
    shim = default_coverage_for_layer("rust_shim")
    assert shim.runtime_enforcement == "enforced"


def test_v18_coverage_merge_keeps_strongest_dimension() -> None:
    observed = CoverageRecord(runtime_observation="observed", runtime_enforcement="none", observed_by=["agent_log"])
    enforced = CoverageRecord(runtime_observation="mediated", runtime_enforcement="enforced", enforced_by=["rust_shim"])
    merged = merge_coverage_records([observed, enforced])
    assert merged.runtime_observation == "mediated"
    assert merged.runtime_enforcement == "enforced"
    assert merged.observed_by == ["agent_log"]
    assert merged.enforced_by == ["rust_shim"]


def test_v18_coverage_requirement_comparison() -> None:
    record = CoverageRecord(runtime_observation="mediated", runtime_enforcement="observed")
    assert coverage_meets_requirement(record, {"runtime_observation": "observed"}) is True
    assert coverage_meets_requirement(record, {"runtime_enforcement": "enforced"}) is False


def test_v15_native_inventory_detects_repo_local_agent_surfaces(tmp_path: Path) -> None:
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "settings.json").write_text(json.dumps({"hooks": {"PreToolUse": []}}), encoding="utf-8")
    (tmp_path / ".codex").mkdir()
    (tmp_path / ".codex" / "config.toml").write_text('[hooks]\npre_tool_use = "invart bridge"\n', encoding="utf-8")
    (tmp_path / ".cursor").mkdir()
    (tmp_path / ".cursor" / "rules").mkdir()
    (tmp_path / ".cursor" / "rules" / "security.mdc").write_text("Never expose secrets", encoding="utf-8")
    (tmp_path / ".gemini").mkdir()
    (tmp_path / ".gemini" / "settings.json").write_text(json.dumps({"mcpServers": {"fs": {"command": "node"}}}), encoding="utf-8")
    (tmp_path / "opencode.json").write_text(json.dumps({"plugin": ["./plugin.js"], "mcp": {"fs": {}}}), encoding="utf-8")

    report = inventory_native_integrations(tmp_path, include_global_config=False)
    by_agent = {profile["agent"]: profile for profile in report["profiles"]}
    assert by_agent["claude-code"]["surfaces"]["hooks"]["grade"] == "declared"
    assert by_agent["codex"]["surfaces"]["hooks"]["grade"] == "declared"
    assert by_agent["cursor"]["surfaces"]["rules"]["grade"] == "declared"
    assert by_agent["gemini-cli"]["surfaces"]["mcp"]["grade"] == "declared"
    assert by_agent["opencode"]["surfaces"]["plugins"]["grade"] == "declared"


def test_v15_native_inventory_global_config_is_opt_in(tmp_path: Path, monkeypatch) -> None:
    fake_home = tmp_path / "home"
    (fake_home / ".claude").mkdir(parents=True)
    (fake_home / ".claude" / "settings.json").write_text("{}", encoding="utf-8")
    monkeypatch.setenv("HOME", str(fake_home))
    repo = tmp_path / "repo"
    repo.mkdir()
    without_global = inventory_native_integrations(repo, include_global_config=False)
    with_global = inventory_native_integrations(repo, include_global_config=True)
    assert without_global["global_config_included"] is False
    assert with_global["global_config_included"] is True
    assert any(surface["scope"] == "global" for profile in with_global["profiles"] for surface in profile["surfaces"].values())


def test_v15_native_install_preview_does_not_write(tmp_path: Path) -> None:
    result = install_native_integration(tmp_path, agent="claude-code", mode="preview")
    assert result["mode"] == "preview"
    assert result["would_write"]
    assert not (tmp_path / ".claude" / "settings.json").exists()


def test_v15_native_install_confirm_writes_backup_on_existing_file(tmp_path: Path) -> None:
    settings = tmp_path / ".claude" / "settings.json"
    settings.parent.mkdir()
    settings.write_text(json.dumps({"hooks": {}}), encoding="utf-8")
    result = install_native_integration(tmp_path, agent="claude-code", mode="confirm")
    assert result["mode"] == "confirm"
    assert result["written"]
    assert result["backup_path"]
    payload = json.loads(settings.read_text(encoding="utf-8"))
    assert "invart" in json.dumps(payload)


def test_v15_native_cli_inventory_and_install(tmp_path: Path) -> None:
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "settings.json").write_text("{}", encoding="utf-8")
    assert main(["native", "inventory", "--target", str(tmp_path)]) == 0
    install_target = tmp_path / "install"
    assert main(["native", "install", "--target", str(install_target), "--agent", "claude-code"]) == 0
    assert not (install_target / ".claude" / "settings.json").exists()
    assert main(["native", "install", "--target", str(install_target), "--agent", "claude-code", "--confirm"]) == 0
    assert (install_target / ".claude" / "settings.json").exists()


def test_v16_claude_pretool_event_normalizes_to_invocation() -> None:
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "rm -rf ."},
        "session_id": "claude-session",
    }
    action = normalize_native_event("claude-code", payload)
    assert action.action_type == "shell"
    assert action.command == "rm -rf ."
    assert action.adapter == "native_hook:claude-code"
    assert "native_hook" in action.metadata["observed_by"]


def test_v16_codex_event_response_can_block() -> None:
    response = render_native_response("codex", {"effect": "deny", "reason": "dangerous deletion"})
    assert response["allow"] is False
    assert "dangerous deletion" in response["message"]


def test_v16_bridge_cli_can_block_native_shell_event() -> None:
    event = json.dumps({"tool": "shell", "arguments": {"command": "rm -rf ."}, "session_id": "codex-session"})
    assert main(["bridge", "native", "--agent", "codex", "--event", event]) == 1


def test_v17_mcp_broker_summarizes_tool_call_without_raw_content_loss() -> None:
    message = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "write_file", "arguments": {"path": ".env", "content": "SECRET=abc"}}}
    summary = summarize_mcp_message(message, max_raw_length=12)
    assert summary["kind"] == "tool_call"
    assert summary["tool_name"] == "write_file"
    assert summary["raw_content_folded"] is True
    assert summary["raw_content_length"] > len(summary["raw_content_preview"])


def test_v17_transparent_mcp_broker_step_preserves_message() -> None:
    message = {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}
    forwarded, evidence = transparent_broker_step(message)
    assert forwarded == message
    assert evidence["mode"] == "transparent"
    assert evidence["summary"]["kind"] == "tools_list"


def test_v17_mcp_broker_cli_step_is_transparent() -> None:
    message = json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    assert main(["mcp", "broker-step", "--message", message]) == 0


def test_v18_runtime_event_coverage_is_exported_to_proof(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.jsonl"
    session = start_session(tmp_path, ledger, agent="claude-code", goal="coverage", create_preflight=False)
    record_action(
        RuntimeEvent(type="shell", session_id=session.session_id, command="echo ok", metadata={"coverage_layer": "native_hook"}),
        ledger,
    )
    close_session(ledger)
    proof = export_proof_report(ledger, tmp_path / "proof.json")
    assert proof["coverage"]["summary"]["runtime_observation"]["mediated"] >= 1


def test_v15_to_v18_benchmarks_are_registered() -> None:
    for suite in (
        "v0.15-native-integration-inventory",
        "v0.16-hook-plugin-bridge",
        "v0.17-mcp-broker",
        "v0.18-coverage-aware-runtime",
    ):
        result = run_benchmark(suite)
        assert result["passed"] is True


def test_v15_to_v18_roadmap_entries_are_planned_or_complete() -> None:
    capabilities = roadmap_capabilities()
    versions = {cap["version"] for cap in capabilities}
    assert {"v0.15", "v0.16", "v0.17", "v0.18"}.issubset(versions)


def test_full_v09_managed_harness_pause_resume_records_approval(tmp_path: Path) -> None:
    from invart.evaluation.harness import run_managed_harness_check

    artifact = tmp_path / "wrapped.json"
    result = run_managed_harness_check(
        target=tmp_path,
        command=[sys.executable, "-c", "import json,sys; json.dump({'exit_code': 0, 'grading_result': 'passed', 'artifacts': ['report.json']}, open(sys.argv[1], 'w'))", str(artifact)],
        case={"instance_id": "django__django-11001"},
        approval_actor="security-reviewer",
    )
    assert result["status"] == "pass"
    assert result["managed_pause"]["paused"] is True
    assert result["managed_pause"]["approval_status"] == "approved"
    assert Path(result["ledger"]).exists()


def test_full_v10_process_supervision_captures_process_group(tmp_path: Path) -> None:
    result = supervise_process_group([sys.executable, "-c", "print('supervised')"], cwd=tmp_path)
    assert result["schema_version"] == "invart.process_supervision.v0.10"
    assert result["returncode"] == 0
    assert result["process_group"]["pid"]
    assert result["process_group"]["pgid"] is not None
    assert result["process_group"]["strong_consistency"] is True


def test_full_v13_enforce_run_domains_cover_env_and_network(tmp_path: Path) -> None:
    env_block = run_enforced_command(
        ["sh", "-c", "touch should_not_exist && echo $OPENAI_API_KEY"],
        domain="env-secrets",
        target=tmp_path,
        event={"type": "shell", "command": "echo $OPENAI_API_KEY"},
    )
    assert env_block["status"] == "blocked"
    assert not (tmp_path / "should_not_exist").exists()
    safe = run_enforced_command(
        [sys.executable, "-c", "open('safe.txt','w').write('ok')"],
        domain="network-egress",
        target=tmp_path,
        event={"type": "shell", "command": "echo local"},
    )
    assert safe["status"] == "executed"
    assert (tmp_path / "safe.txt").exists()


def test_full_v15_native_conformance_hashes_and_validates_surfaces(tmp_path: Path) -> None:
    settings = tmp_path / ".claude" / "settings.json"
    settings.parent.mkdir()
    settings.write_text(json.dumps({"hooks": {"PreToolUse": []}}), encoding="utf-8")
    report = native_conformance_report(tmp_path)
    assert report["schema_version"] == "invart.native_conformance.v0.15"
    assert report["status"] == "pass"
    surface = report["profiles"][0]["surfaces"]["hooks"]
    assert surface["hash"].startswith("sha256:")
    assert surface["parse_status"] == "pass"


def test_full_v16_bridge_conformance_fuzzes_vendor_responses() -> None:
    matrix = bridge_conformance_matrix()
    assert matrix["schema_version"] == "invart.bridge_conformance.v0.16"
    assert matrix["status"] == "pass"
    assert matrix["summary"]["agents"] >= 3
    assert matrix["summary"]["cases"] >= 6


def test_full_v17_mcp_stdio_broker_records_transcript(tmp_path: Path) -> None:
    input_path = tmp_path / "input.jsonl"
    output_path = tmp_path / "output.jsonl"
    transcript = tmp_path / "transcript.jsonl"
    input_path.write_text(
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}) + "\n" +
        json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "read_file", "arguments": {"path": ".env"}}}) + "\n",
        encoding="utf-8",
    )
    result = run_stdio_broker(input_path=input_path, output_path=output_path, transcript_path=transcript)
    assert result["schema_version"] == "invart.mcp_stdio_broker.v0.17"
    assert result["summary"]["messages"] == 2
    assert output_path.read_text(encoding="utf-8") == input_path.read_text(encoding="utf-8")
    assert "tool_call" in transcript.read_text(encoding="utf-8")


def test_full_v18_coverage_html_report_exports_gap_matrix(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.jsonl"
    session = start_session(tmp_path, ledger, agent="coverage", goal="html", create_preflight=False)
    record_action(RuntimeEvent(type="shell", session_id=session.session_id, command="echo ok", metadata={"coverage_layer": "native_hook"}), ledger)
    close_session(ledger)
    proof_path = tmp_path / "proof.json"
    export_proof_report(ledger, proof_path)
    out = tmp_path / "coverage.html"
    result = export_coverage_html_report(proof_path, out)
    html = out.read_text(encoding="utf-8")
    assert result["status"] == "pass"
    assert "Coverage Matrix" in html
    assert "runtime_enforcement" in html


def test_v022_unified_mediation_contract_records_pause_resume_and_fail_open_coverage(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.jsonl"
    session = start_session(tmp_path, ledger, agent="claude-code", goal="mediation", create_preflight=False)
    mediated = mediate_event(
        ledger,
        session_id=session.session_id,
        surface="network",
        event={"type": "network", "url": "https://api.example.com/upload", "metadata": {"tainted": True}},
        mode="managed",
    )
    assert mediated["decision"]["effect"] == "require_approval"
    assert mediated["request"]["surface"] == "network"
    assert mediated["outcome"]["status"] == "paused"
    resolved = resolve_mediation(ledger, mediation_id=mediated["decision"]["mediation_id"], actor="security", status="approved", reason="expected upload")
    assert resolved["outcome"]["status"] == "resumed"
    replay = replay_mediation(ledger)
    assert replay["summary"]["paused"] == 1
    assert replay["summary"]["resumed"] == 1

    fail_open = mediate_event(
        ledger,
        session_id=session.session_id,
        surface="command",
        event={"type": "shell", "command": "echo ok"},
        mode="managed",
        simulate_failure=True,
    )
    assert fail_open["decision"]["effect"] == "fail_open_alert"
    proof = export_proof_report(ledger)
    fail_open_action = [item for item in proof["actions"] if item.get("metadata", {}).get("mediation_id") == fail_open["decision"]["mediation_id"]][0]
    coverage = fail_open_action["metadata"]["coverage"]["coverage_grade"]
    assert coverage["runtime_enforcement"] != "enforced"


def test_v025_adapter_runtime_package_closes_product_loop(tmp_path: Path) -> None:
    from invart.surfaces.adapter import inspect_adapter_package, run_adapter_runtime
    from invart.control.mediation import replay_mediation

    result = run_adapter_runtime(
        target=tmp_path,
        command=[sys.executable, "-c", "print('adapter-ok')"],
        adapter_kind="claude-code",
        agent="claude-code",
        principal_id="alice@example.com",
        env={"OPENAI_API_KEY": "sk-testsecret", "PATH": "/bin"},
        out_dir=tmp_path / "artifacts",
        profile={"mode": "managed", "identity": {"required": True, "allowed_agents": ["claude-code"]}},
        create_preflight=False,
    )
    assert result["schema_version"] == "invart.adapter_runtime.v0.25"
    assert result["status"] == "passed"
    for key in ["ledger", "proof", "replay", "path_graph", "coverage_report", "audit_report", "package"]:
        assert Path(result["artifacts"][key]).exists()
    proof = json.loads(Path(result["artifacts"]["proof"]).read_text(encoding="utf-8"))
    assert proof["accountability"]["principal"]["principal_id"] == "alice@example.com"
    assert proof["accountability"]["credential_boundary"]["redacted_values"] == 1
    mediation = replay_mediation(Path(result["artifacts"]["ledger"]))
    assert mediation["summary"].get("allowed", 0) >= 1
    package = inspect_adapter_package(Path(result["artifacts"]["package"]))
    assert package["status"] == "pass"
    assert package["manifest"]["adapter"]["kind"] == "claude-code"
    assert "proof" in package["manifest"]["artifacts"]

    generic = run_adapter_runtime(
        target=tmp_path / "generic",
        command=[sys.executable, "-c", "print('generic-ok')"],
        adapter_kind="generic",
        agent="generic-agent",
        principal_id="bob@example.com",
        out_dir=tmp_path / "generic-artifacts",
        create_preflight=False,
    )
    assert generic["adapter"]["kind"] == "generic"
    assert generic["status"] == "passed"

    try:
        run_adapter_runtime(
            target=tmp_path / "mismatch",
            command=[sys.executable, "-c", "print('bad')"],
            adapter_kind="claude-code",
            agent="codex",
            principal_id="alice@example.com",
            out_dir=tmp_path / "bad-artifacts",
            profile={"mode": "managed", "identity": {"required": True, "allowed_agents": ["claude-code"]}},
            create_preflight=False,
        )
    except ValueError as exc:
        assert "agent identity mismatch" in str(exc)
    else:
        raise AssertionError("managed adapter runtime should reject declared agent mismatch")


def test_v028_benchmark_harness_registry_expands_product_metrics() -> None:
    from invart.evaluation.benchmark_registry import list_benchmark_suites

    suites = list_benchmark_suites()
    assert "v0.28-harness-expansion" in {item["suite"] for item in suites["suites"]}
    result = run_benchmark("v0.28-harness-expansion")
    assert result["passed"] is True
    categories = {case["category"] for case in result["cases"]}
    assert {"attack", "benign", "compatibility", "evidence"}.issubset(categories)
    assert result["metrics"]["block_rate"] > 0
    assert result["metrics"]["benign_false_positive_proxy"] == 0
    assert result["optional_heavy_validation"]["status"] == "skipped"
    assert main(["eval", "list"]) == 0
    assert main(["eval", "benchmark", "--suite", "v0.28-harness-expansion"]) == 0
