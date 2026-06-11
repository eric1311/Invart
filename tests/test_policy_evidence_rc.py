import json
import sys
from html.parser import HTMLParser
from pathlib import Path

from invart.core.artifacts import relative_href, sha256_file, stable_json_dumps, stable_json_hash, write_html_artifact, write_json_artifact
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


class _DocLinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.hrefs: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        for name, value in attrs:
            if name == "href" and value:
                self.hrefs.append(value)


def _write_full_swebench_evidence_fixture(root: Path, *, run_id: str = "invart_full", total: int = 3) -> dict[str, Path]:
    results = root / "results"
    run_dir = results / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    completed_ids = [f"repo__pkg-{index}" for index in range(total)]
    report = {
        "total_instances": total,
        "submitted_instances": total,
        "completed_instances": total,
        "resolved_instances": max(total - 1, 0),
        "unresolved_instances": 1 if total else 0,
        "error_instances": 0,
        "completed_ids": completed_ids,
        "resolved_ids": completed_ids[:-1],
        "error_ids": [],
    }
    report_path = results / f"{run_id}.json"
    instance_results = run_dir / "instance_results.jsonl"
    predictions = root / "predictions.jsonl"
    logs = root / "logs" / "run_evaluation" / run_id
    logs.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report), encoding="utf-8")
    instance_results.write_text("\n".join(json.dumps({"instance_id": item, "resolved": item != completed_ids[-1]}) for item in completed_ids) + "\n", encoding="utf-8")
    predictions.write_text("\n".join(json.dumps({"instance_id": item, "model_patch": "diff --git"}) for item in completed_ids) + "\n", encoding="utf-8")
    (logs / "run.log").write_text("official runner log fixture\n", encoding="utf-8")
    return {"report": report_path, "instance_results": instance_results, "predictions": predictions, "logs": logs}


def test_v044_swe_bench_full_evidence_manifest_verifies_complete_artifacts(tmp_path: Path) -> None:
    from invart.evaluation.external_evidence import attach_swe_bench_full_evidence, verify_external_evidence

    fixture = _write_full_swebench_evidence_fixture(tmp_path)
    manifest = attach_swe_bench_full_evidence(
        report_path=fixture["report"],
        instance_results_path=fixture["instance_results"],
        predictions_path=fixture["predictions"],
        logs_path=fixture["logs"],
        out_dir=tmp_path / "evidence",
        run_id="invart_full",
        expected_total_instances=3,
        invart_mode="managed",
    )
    assert manifest["status"] == "pass"
    assert manifest["evidence_level"] == "external_live_run"
    assert manifest["checks"]["all_instances_complete"] is True
    assert manifest["checks"]["predictions_hash_present"] is True
    assert manifest["invart_mode"] == "managed"
    verified = verify_external_evidence(Path(manifest["manifest_path"]))
    assert verified["status"] == "pass"
    assert main(["external-evidence", "verify", "--manifest", manifest["manifest_path"]]) == 0

    bad = attach_swe_bench_full_evidence(
        report_path=fixture["report"],
        instance_results_path=fixture["instance_results"],
        predictions_path=fixture["predictions"],
        logs_path=fixture["logs"],
        out_dir=tmp_path / "bad-evidence",
        run_id="invart_full",
        expected_total_instances=4,
        invart_mode="managed",
    )
    assert bad["status"] == "fail"
    assert bad["checks"]["expected_total_instances_match"] is False


def test_v045_final_release_candidate_distinguishes_external_pending_and_attached(tmp_path: Path) -> None:
    from invart.evaluation.external_evidence import attach_swe_bench_full_evidence
    from invart.evaluation.release_candidate import verify_release_candidate

    pending = verify_release_candidate(tmp_path / "pending-rc", run_pytest=False, final=True)
    assert pending["status"] == "pass"
    assert pending["final_readiness"]["state"] == "external_pending"
    assert pending["checks"]["external_evidence"]["status"] == "skipped"

    required = verify_release_candidate(tmp_path / "required-rc", run_pytest=False, final=True, require_external_validation=True)
    assert required["status"] == "fail"
    assert required["final_readiness"]["state"] == "external_pending"

    fixture = _write_full_swebench_evidence_fixture(tmp_path / "swe")
    attached = attach_swe_bench_full_evidence(
        report_path=fixture["report"],
        instance_results_path=fixture["instance_results"],
        predictions_path=fixture["predictions"],
        logs_path=fixture["logs"],
        out_dir=tmp_path / "swe-evidence",
        run_id="invart_full",
        expected_total_instances=3,
        invart_mode="managed",
    )
    final = verify_release_candidate(
        tmp_path / "final-rc",
        run_pytest=False,
        final=True,
        require_external_validation=True,
        external_evidence_manifest=Path(attached["manifest_path"]),
    )
    assert final["status"] == "pass"
    assert final["final_readiness"]["state"] == "final_ready"
    assert final["checks"]["external_evidence"]["status"] == "pass"
    assert main(["release-candidate", "verify", "--out-dir", str(tmp_path / "cli-final"), "--skip-pytest", "--final", "--external-evidence", attached["manifest_path"]]) == 0

def test_v02_redacted_evidence_does_not_expose_secret_values(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.jsonl"
    session = start_session(tmp_path, ledger, agent="codex", goal="test")
    action, _decision, _taint = record_action(
        RuntimeEvent(
            type="shell",
            session_id=session.session_id,
            command="echo sk-testsecret123456789 > /tmp/out && cat /repo/.env",
            metadata={"instruction": "use token=abcd123456789 to continue"},
        ),
        ledger,
        review_mode="off",
    )
    evidence = build_redacted_evidence(action)
    payload = json.dumps(evidence.to_dict(), ensure_ascii=False)
    assert "sk-testsecret123456789" not in payload
    assert "token=abcd123456789" not in payload
    assert "[OPENAI_KEY_REDACTED]" in payload
    assert evidence.redactions
    assert evidence.input_hash


def test_v05_gate_clean_ci_passes(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.jsonl"
    proof = tmp_path / "proof.json"
    session = start_session(tmp_path, ledger, agent="codex", goal="gate clean", create_preflight=False)
    record_action(RuntimeEvent(type="file_read", session_id=session.session_id, path="/repo/README.md"), ledger, review_mode="off")
    export_proof_report(ledger, proof)

    report = verify_gate(ledger_path=ledger, proof_path=proof, mode="ci")
    assert report["status"] == "pass"
    assert report["passed"] is True


def test_v05_gate_missing_approval_fails_managed(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.jsonl"
    proof = tmp_path / "proof.json"
    session = start_session(tmp_path, ledger, agent="codex", goal="gate missing", create_preflight=False)
    record_action(RuntimeEvent(type="file_read", session_id=session.session_id, path="/repo/.env"), ledger)
    export_proof_report(ledger, proof)

    report = verify_gate(ledger_path=ledger, proof_path=proof, mode="managed")
    assert report["status"] == "fail"
    assert any(finding["check_id"] == "approval.missing" for finding in report["findings"])


def test_v05_gate_audit_warns_on_missing_approval(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.jsonl"
    proof = tmp_path / "proof.json"
    session = start_session(tmp_path, ledger, agent="codex", goal="gate audit", create_preflight=False)
    record_action(RuntimeEvent(type="file_read", session_id=session.session_id, path="/repo/.env"), ledger)
    export_proof_report(ledger, proof)

    report = verify_gate(ledger_path=ledger, proof_path=proof, mode="audit")
    assert report["status"] == "warn"
    assert report["passed"] is True


def test_v05_gate_approved_capability_grants_pass(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.jsonl"
    proof = tmp_path / "proof.json"
    session = start_session(tmp_path, ledger, agent="codex", goal="gate caps", create_preflight=False)
    for event_payload in capability_events_from_corpus(Path("benchmarks/corpora"), session.session_id, adapter="codex-wrapper"):
        _action, decision, _taint = record_action(RuntimeEvent.from_dict(event_payload), ledger, review_mode="off", policy_mode="managed")
        if decision.requires_approval:
            record_approval(ledger, decision.decision_id, "approved", approver="tester", reason="approved for test")
    export_proof_report(ledger, proof)

    report = verify_gate(ledger_path=ledger, proof_path=proof, mode="managed")
    assert report["status"] == "pass"
    assert not any(finding["check_id"] == "capability_grant.high_risk_unresolved" for finding in report["findings"])


def test_v05_cli_gate_and_benchmark(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.jsonl"
    proof = tmp_path / "proof.json"
    assert main(["session", "start", "--target", str(tmp_path), "--session-id", "ks_gate", "--ledger", str(ledger), "--no-preflight"]) == 0
    assert main(["runtime", "record-event", "--session", "ks_gate", "--ledger", str(ledger), "--review", "off", "--event", '{"type":"file_read","path":"/repo/README.md"}']) == 0
    assert main(["proof", "export", "--ledger", str(ledger), "--out", str(proof)]) == 0
    assert main(["gate", "verify", "--proof", str(proof), "--ledger", str(ledger), "--mode", "ci"]) == 0
    assert main(["eval", "benchmark", "--suite", "v0.5-proof-gate"]) == 0


def test_v07_approval_list_and_approve_all_closes_gate(tmp_path: Path) -> None:
    out_dir = tmp_path / "artifacts"
    result = run_adapter_command(
        target=tmp_path,
        command=["python3", "-c", "pass"],
        agent="codex",
        goal="v07 approval",
        session_id="ks_v07_approval",
        out_dir=out_dir,
        capabilities="managed",
        gate_mode="managed",
        create_preflight=False,
    )
    assert result.gate_status == "fail"
    inbox = list_approval_items(Path(result.ledger), status="missing")
    missing = inbox["summary"]["by_status"].get("missing", 0)
    assert missing >= 1
    approved = approve_items(Path(result.ledger), all_missing=True, approver="tester", reason="trusted v0.7 test corpus")
    assert approved["resolved"] == missing
    export_proof_report(Path(result.ledger), Path(result.proof))
    gate = verify_gate(ledger_path=Path(result.ledger), proof_path=Path(result.proof), mode="managed")
    assert gate["status"] == "pass"


def test_v040_full_swe_bench_validation_uses_official_all_data_contract(tmp_path: Path) -> None:
    fake = tmp_path / "fake_full_swebench.py"
    fake.write_text(
        "import json, pathlib\n"
        "results = pathlib.Path('results')\n"
        "run_dir = results / 'invart_full'\n"
        "run_dir.mkdir(parents=True, exist_ok=True)\n"
        "payload = {\n"
        "  'total_instances': 3,\n"
        "  'submitted_instances': 3,\n"
        "  'completed_instances': 3,\n"
        "  'resolved_instances': 2,\n"
        "  'unresolved_instances': 1,\n"
        "  'error_instances': 0,\n"
        "  'completed_ids': ['a__a-1', 'b__b-2', 'c__c-3'],\n"
        "  'resolved_ids': ['a__a-1', 'b__b-2'],\n"
        "  'error_ids': []\n"
        "}\n"
        "(results / 'invart_full.json').write_text(json.dumps(payload))\n"
        "(run_dir / 'instance_results.jsonl').write_text('\\n'.join(json.dumps({'instance_id': item, 'resolved': item != 'c__c-3'}) for item in payload['completed_ids']) + '\\n')\n",
        encoding="utf-8",
    )
    result = run_official_swe_bench_full_validation(
        command=[sys.executable, str(fake)],
        work_dir=tmp_path,
        run_id="invart_full",
        expected_total_instances=3,
    )
    assert result["schema_version"] == "invart.swe_bench_full_validation.v0.40"
    assert result["status"] == "pass"
    assert result["runner"]["dataset_name"] == "SWE-bench/SWE-bench"
    assert result["external_validation"]["all_instances_required"] is True
    assert result["checks"]["all_data_mode"] is True
    assert result["checks"]["submitted_equals_total"] is True
    assert result["checks"]["completed_equals_submitted"] is True
    assert result["checks"]["instance_results_complete"] is True
    assert result["artifacts"]["official_report"].endswith("results/invart_full.json")
    assert result["artifacts"]["instance_results"].endswith("results/invart_full/instance_results.jsonl")


def test_v040_full_swe_bench_validation_rejects_subset_or_incomplete_data(tmp_path: Path) -> None:
    fake = tmp_path / "fake_subset_swebench.py"
    fake.write_text(
        "import json, pathlib\n"
        "results = pathlib.Path('results')\n"
        "run_dir = results / 'subset'\n"
        "run_dir.mkdir(parents=True, exist_ok=True)\n"
        "payload = {'total_instances': 3, 'submitted_instances': 1, 'completed_instances': 1, 'resolved_instances': 1, 'error_instances': 0, 'completed_ids': ['a__a-1'], 'error_ids': []}\n"
        "(results / 'subset.json').write_text(json.dumps(payload))\n"
        "(run_dir / 'instance_results.jsonl').write_text(json.dumps({'instance_id': 'a__a-1', 'resolved': True}) + '\\n')\n",
        encoding="utf-8",
    )
    result = run_official_swe_bench_full_validation(
        command=[sys.executable, str(fake)],
        work_dir=tmp_path,
        run_id="subset",
        instance_ids=["a__a-1"],
        expected_total_instances=3,
    )
    assert result["status"] == "fail"
    assert result["checks"]["all_data_mode"] is False
    assert result["checks"]["submitted_equals_total"] is False
    assert result["external_validation"]["status"] == "failed"


def test_v040_full_swe_bench_validation_accepts_official_log_report_shape(tmp_path: Path) -> None:
    fake = tmp_path / "fake_swebench_v41.py"
    fake.write_text(
        "import json, pathlib\n"
        "payload = {'total_instances': 2, 'submitted_instances': 2, 'completed_instances': 2, 'resolved_instances': 1, 'error_instances': 0, 'completed_ids': ['a__a-1', 'b__b-2'], 'error_ids': []}\n"
        "pathlib.Path('gold.full_v41.json').write_text(json.dumps(payload))\n"
        "for item in payload['completed_ids']:\n"
        "    report_dir = pathlib.Path('logs/run_evaluation/full_v41/gold') / item\n"
        "    report_dir.mkdir(parents=True, exist_ok=True)\n"
        "    (report_dir / 'report.json').write_text(json.dumps({item: {'resolved': item == 'a__a-1'}}))\n",
        encoding="utf-8",
    )
    result = run_official_swe_bench_full_validation(
        command=[sys.executable, str(fake)],
        work_dir=tmp_path,
        run_id="full_v41",
        expected_total_instances=2,
    )
    assert result["status"] == "pass"
    assert result["checks"]["instance_results_found"] is True
    assert result["checks"]["instance_results_complete"] is True
    assert result["instance_results_summary"]["source"] == "official_log_reports"


def test_v040_cli_external_validation_swe_bench_full(tmp_path: Path) -> None:
    fake = tmp_path / "fake_cli_swebench.py"
    out = tmp_path / "full-validation.json"
    fake.write_text(
        "import json, pathlib\n"
        "results = pathlib.Path('results')\n"
        "run_dir = results / 'cli_full'\n"
        "run_dir.mkdir(parents=True, exist_ok=True)\n"
        "payload = {'total_instances': 2, 'submitted_instances': 2, 'completed_instances': 2, 'resolved_instances': 1, 'error_instances': 0, 'completed_ids': ['a__a-1', 'b__b-2'], 'error_ids': []}\n"
        "(results / 'cli_full.json').write_text(json.dumps(payload))\n"
        "(run_dir / 'instance_results.jsonl').write_text('\\n'.join(json.dumps({'instance_id': item, 'resolved': True}) for item in payload['completed_ids']) + '\\n')\n",
        encoding="utf-8",
    )
    assert main([
        "external-validation",
        "swe-bench-full",
        "--command",
        f"{sys.executable} {fake}",
        "--work-dir",
        str(tmp_path),
        "--run-id",
        "cli_full",
        "--expected-total-instances",
        "2",
        "--out",
        str(out),
    ]) == 0
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["status"] == "pass"
    assert payload["checks"]["official_command_exited_zero"] is True
    assert payload["checks"]["instance_results_complete"] is True


def test_v040_benchmark_and_roadmap_register_full_swe_bench_contract() -> None:
    result = run_benchmark("v0.40-swe-bench-full-validation-contract")
    assert result["passed"] is True
    assert result["checks"]["subset_does_not_satisfy_full_validation"] is True

    capabilities = {item["capability_id"]: item for item in roadmap_capabilities()}
    capability = capabilities["swe_bench_full_validation_contract"]
    assert capability["status"] == "implemented"
    assert capability["claim_scope"] == "official_runner_contract"
    assert capability["external_validation"] == "not_run_optional"
    assert capability["truthfulness"]["claim_integrity"] is True
    assert main(["eval", "benchmark", "--suite", "v0.40-swe-bench-full-validation-contract"]) == 0


def test_full_product_benchmark_is_registered() -> None:
    result = run_benchmark("full-product-readiness")
    assert result["passed"] is True
    assert result["summary"]["passed"] == result["summary"]["total"]


def test_v020_execution_graph_traces_secret_to_network_path(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.jsonl"
    session = start_session(tmp_path, ledger, agent="codex", goal="path graph", create_preflight=False)
    first, _decision, _taint = record_action(RuntimeEvent(type="file_read", session_id=session.session_id, path="/repo/.env"), ledger)
    second, _decision2, _taint2 = record_action(RuntimeEvent(type="network", session_id=session.session_id, url="https://api.example.com/upload"), ledger)
    graph = build_execution_graph(ledger)
    assert graph["schema_version"] == "invart.execution_graph.v0.20"
    assert any(node["kind"] == "taint" for node in graph["nodes"])
    assert any(edge["kind"] == "taints" for edge in graph["edges"])
    upstream = query_execution_graph(graph, target_id=str(second.invocation_id), direction="upstream")
    assert str(first.invocation_id) in upstream["reachable_node_ids"]
    assert any(edge["kind"] == "taints" for edge in upstream["edges"])
    html_out = tmp_path / "graph.html"
    result = export_execution_graph_html(ledger, html_out)
    assert result["status"] == "pass"
    assert "Execution Path Graph" in html_out.read_text(encoding="utf-8")


def test_v021_path_aware_policy_blocks_tainted_secret_egress_but_allows_benign(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.jsonl"
    session = start_session(tmp_path, ledger, agent="codex", goal="path policy", create_preflight=False)
    record_action(RuntimeEvent(type="file_read", session_id=session.session_id, path="/repo/.env"), ledger)
    record_action(RuntimeEvent(type="network", session_id=session.session_id, url="https://evil.example/upload"), ledger)
    report = check_path_policy(ledger)
    assert report["status"] == "fail"
    assert report["summary"]["deny"] >= 1
    assert any(item["rule_id"] == "path.secret_to_external_network" for item in report["findings"])

    benign = tmp_path / "benign.jsonl"
    benign_session = start_session(tmp_path, benign, agent="codex", goal="benign", create_preflight=False)
    record_action(RuntimeEvent(type="file_read", session_id=benign_session.session_id, path="/repo/README.md"), benign)
    benign_report = check_path_policy(benign)
    assert benign_report["status"] == "pass"
    assert benign_report["summary"]["false_positive_proxy"] == 0


def test_v026_policy_as_code_validates_and_applies_path_rules(tmp_path: Path) -> None:
    from invart.control.policy_as_code import check_policy_profile, test_policy_profile, validate_policy_profile

    profile = tmp_path / "policy.toml"
    profile.write_text(
        """
schema_version = "invart.policy_as_code.v0.26"
name = "enterprise-path-policy"

[[policy.rules]]
id = "deny_secret_egress"
source = "secret"
sink = "external_network"
effect = "deny"
critical = true

[[policy.rules]]
id = "approve_ci_mutation"
source = "secret"
sink = "ci_deploy_mutation"
effect = "require_approval"

[[policy.rules]]
id = "deny_external_destructive_shell"
source = "external_instruction"
sink = "destructive_shell"
effect = "deny"
critical = true
""".strip(),
        encoding="utf-8",
    )
    validated = validate_policy_profile(profile)
    assert validated["status"] == "pass"
    assert validated["summary"]["rules"] == 3

    bad = tmp_path / "bad.toml"
    bad.write_text('[[policy.rules]]\nid = "bad"\neffect = "maybe"\n', encoding="utf-8")
    assert validate_policy_profile(bad)["status"] == "fail"

    ledger = tmp_path / "ledger.jsonl"
    session = start_session(tmp_path, ledger, agent="codex", goal="policy-as-code", create_preflight=False)
    record_action(RuntimeEvent(type="file_read", session_id=session.session_id, path="/repo/.env"), ledger)
    record_action(RuntimeEvent(type="network", session_id=session.session_id, url="https://evil.example/upload"), ledger)
    report = check_policy_profile(ledger, profile)
    assert report["schema_version"] == "invart.policy_as_code_result.v0.26"
    assert report["status"] == "fail"
    assert report["summary"]["deny"] >= 1
    assert report["findings"][0]["llm_can_downgrade"] is False

    benign = tmp_path / "benign.jsonl"
    benign_session = start_session(tmp_path, benign, agent="codex", goal="benign", create_preflight=False)
    record_action(RuntimeEvent(type="file_read", session_id=benign_session.session_id, path="/repo/README.md"), benign)
    benign_report = check_policy_profile(benign, profile)
    assert benign_report["status"] == "pass"
    assert benign_report["summary"]["false_positive_proxy"] == 0

    profile_test = test_policy_profile(profile)
    assert profile_test["status"] == "pass"
    assert profile_test["metrics"]["block_rate"] > 0
    assert main(["policy", "validate", "--profile", str(profile)]) == 0
    assert main(["policy", "test", "--profile", str(profile)]) == 0
    assert main(["policy", "check-path", "--ledger", str(ledger), "--profile", str(profile), "--out", str(tmp_path / "path-policy.json")]) == 1


def test_v027_enterprise_evidence_bundle_exports_and_verifies(tmp_path: Path) -> None:
    from invart.assurance.evidence_bundle import export_evidence_bundle, verify_evidence_bundle

    ledger = tmp_path / "ledger.jsonl"
    session = start_session(tmp_path, ledger, agent="claude-code", goal="evidence", create_preflight=False)
    principal = declare_principal("security@example.com")
    agent_identity = bind_agent_identity("claude-code", declared_by=principal.principal_id, adapter_agent="claude-code")
    grant = create_capability_grant(principal_id=principal.principal_id, agent_id=agent_identity.agent_id, scopes=["file_read", "network"], resources=["/repo/.env"])
    record_identity_binding(ledger, session_id=session.session_id, principal=principal, agent_identity=agent_identity, credentials=credential_inventory({"OPENAI_API_KEY": "sk-secret"}, owner=principal.principal_id), grants=[grant])
    record_action(RuntimeEvent(type="file_read", session_id=session.session_id, path="/repo/.env", metadata={"capability_grant_id": grant.grant_id}), ledger)
    record_action(RuntimeEvent(type="network", session_id=session.session_id, url="https://api.example.com/upload"), ledger)
    close_session(ledger)

    bundle = export_evidence_bundle(ledger, tmp_path / "bundle", profile={"name": "enterprise", "mode": "managed"})
    assert bundle["schema_version"] == "invart.evidence_bundle.v0.27"
    assert bundle["status"] == "pass"
    assert Path(bundle["manifest_path"]).exists()
    assert Path(bundle["artifacts"]["audit_html"]).exists()
    assert Path(bundle["artifacts"]["audit_json"]).exists()
    audit_html = Path(bundle["artifacts"]["audit_html"]).read_text(encoding="utf-8")
    for phrase in ["Accountability", "Path Graph", "Policy", "Coverage"]:
        assert phrase in audit_html
    verified = verify_evidence_bundle(Path(bundle["manifest_path"]))
    assert verified["status"] == "pass"
    assert verified["summary"]["tampered"] == 0

    proof_path = Path(bundle["artifacts"]["proof"])
    proof_payload = json.loads(proof_path.read_text(encoding="utf-8"))
    proof_payload["summary"]["total_actions"] = 999
    proof_path.write_text(json.dumps(proof_payload, ensure_ascii=False, sort_keys=True), encoding="utf-8")
    tampered = verify_evidence_bundle(Path(bundle["manifest_path"]))
    assert tampered["status"] == "fail"
    assert tampered["summary"]["tampered"] >= 1


def test_artifact_writer_uses_stable_json_html_and_hash_helpers(tmp_path: Path) -> None:
    payload = {"z": 2, "a": {"b": 1}}
    json_path = write_json_artifact(tmp_path / "nested" / "artifact.json", payload)
    html_path = write_html_artifact(tmp_path / "nested" / "artifact.html", "<h1>Audit</h1>")

    assert json_path.read_text(encoding="utf-8") == stable_json_dumps(payload)
    assert html_path.read_text(encoding="utf-8") == "<h1>Audit</h1>"
    assert stable_json_hash(payload).startswith("sha256:")
    assert sha256_file(json_path) == sha256_file(json_path)
    assert relative_href(tmp_path, html_path) == "nested/artifact.html"


def test_public_docs_include_api_sdk_page_and_valid_local_links() -> None:
    root = Path(__file__).resolve().parents[1]
    docs_dir = root / "docs"
    html_dir = docs_dir / "html"
    api_doc = html_dir / "api-sdk.html"
    api_markdown = docs_dir / "api-sdk.md"
    runtime_effect_doc = html_dir / "runtime-effect-demo.html"
    runtime_effect_markdown = docs_dir / "runtime-effect-demo.md"
    operator_doc = html_dir / "five-layer-operator-guide.html"
    operator_markdown = docs_dir / "five-layer-operator-guide.md"

    assert api_doc.exists()
    assert api_markdown.exists()
    assert runtime_effect_doc.exists()
    assert runtime_effect_markdown.exists()
    assert operator_doc.exists()
    assert operator_markdown.exists()
    assert 'href="api-sdk.html"' in (html_dir / "index.html").read_text(encoding="utf-8")
    assert 'href="runtime-effect-demo.html"' in (html_dir / "index.html").read_text(encoding="utf-8")
    assert 'href="five-layer-operator-guide.html"' in (html_dir / "index.html").read_text(encoding="utf-8")
    docs_readme = (docs_dir / "README.md").read_text(encoding="utf-8")
    assert "[`api-sdk.md`](api-sdk.md)" in docs_readme
    assert "[`html/api-sdk.html`](html/api-sdk.html)" in docs_readme
    assert "[`runtime-effect-demo.md`](runtime-effect-demo.md)" in docs_readme
    assert "[`html/runtime-effect-demo.html`](html/runtime-effect-demo.html)" in docs_readme
    assert "[`five-layer-operator-guide.md`](five-layer-operator-guide.md)" in docs_readme
    assert "[`html/five-layer-operator-guide.html`](html/five-layer-operator-guide.html)" in docs_readme
    assert "[API and SDK](docs/api-sdk.md)" in (root / "README.md").read_text(encoding="utf-8")
    assert "[Runtime effect demo](docs/runtime-effect-demo.md)" in (root / "README.md").read_text(encoding="utf-8")
    assert "[Five-layer operator guide](docs/five-layer-operator-guide.md)" in (root / "README.md").read_text(encoding="utf-8")
    assert "[HTML docs home](docs/html/index.html)" in (root / "README.md").read_text(encoding="utf-8")
    assert sorted(path.name for path in docs_dir.glob("*.html")) == []

    markdown_pages = [path for path in docs_dir.glob("*.md") if path.name != "README.md"]
    missing_html = [path.name for path in markdown_pages if not (html_dir / f"{path.stem}.html").exists()]
    assert missing_html == []

    for html_path in sorted(html_dir.glob("*.html")):
        parser = _DocLinkParser()
        parser.feed(html_path.read_text(encoding="utf-8"))
        parser.close()
        for href in parser.hrefs:
            if href.startswith(("http://", "https://", "mailto:", "#")):
                continue
            local = href.split("#", 1)[0]
            if not local:
                continue
            assert (html_path.parent / local).resolve().exists(), f"{html_path} links to missing {href}"


def test_public_docs_are_organized_by_user_journey() -> None:
    root = Path(__file__).resolve().parents[1]
    markdown_index = (root / "docs" / "index.md").read_text(encoding="utf-8")
    html_index = (root / "docs" / "html" / "index.html").read_text(encoding="utf-8")

    for section in ("## Start", "## Operate", "## Integrate", "## Evaluate", "## Reference"):
        assert section in markdown_index
    for section in ("Start", "Operate", "Integrate", "Evaluate", "Reference"):
        assert f"<h2>{section}</h2>" in html_index
    assert markdown_index.index("## Operate") < markdown_index.index("## Reference")
    assert "five-layer-operator-guide.md" in markdown_index
    assert "five-layer-operator-guide.html" in html_index
    assert "release-history.md" in markdown_index[markdown_index.index("## Reference") :]


def test_five_layer_operator_guide_documents_operational_path() -> None:
    root = Path(__file__).resolve().parents[1]
    markdown_page = (root / "docs" / "five-layer-operator-guide.md").read_text(encoding="utf-8")
    html_page = (root / "docs" / "html" / "five-layer-operator-guide.html").read_text(encoding="utf-8")

    for phrase in (
        "L1 Execution Surface",
        "L2 Runtime Fact Model",
        "L3 Decision Plane",
        "L4 Mediation Plane",
        "L5 Evidence Plane",
        "before-runtime",
        "during-runtime",
        "after-runtime",
        "observed",
        "mediated",
        "enforced",
        "fail-open",
        "invart pre-runtime",
        "invart runtime layers",
        "invart policy check-path",
        "invart mediation inspect",
        "invart evidence inspect",
    ):
        assert phrase in markdown_page

    for href in ("runtime-effect-demo.html", "cli-reference.html", "evaluation.html"):
        assert f'href="{href}"' in html_page
    assert "Which layer should I use?" in html_page
    assert "Healthy signal" in markdown_page
    assert "Failure signal" in markdown_page


def test_api_sdk_page_documents_real_python_helpers() -> None:
    from invart.core.ledger import load_ledger_entries as documented_load_ledger_entries
    from invart.core.ledger import verify_ledger as documented_verify_ledger
    from invart.core.models import RuntimeEvent as DocumentedRuntimeEvent
    from invart.assurance.postruntime import export_proof_report as documented_export_proof_report
    from invart.assurance.postruntime import verify_proof_report as documented_verify_proof_report
    from invart.evaluation.release_candidate import DEFAULT_REQUIRED_DOCS

    root = Path(__file__).resolve().parents[1]
    page = (root / "docs" / "html" / "api-sdk.html").read_text(encoding="utf-8")
    markdown_page = (root / "docs" / "api-sdk.md").read_text(encoding="utf-8")
    assert "from invart.core.ledger import load_ledger_entries, verify_ledger" in page
    assert "from invart.assurance.postruntime import export_proof_report, verify_proof_report" in page
    assert "from invart.core.models import RuntimeEvent" in page
    assert "from invart.core.ledger import load_ledger_entries, verify_ledger" in markdown_page
    assert "Hosted API" in page
    assert "Not available in 0.9" in page
    assert "docs/api-sdk.md" in DEFAULT_REQUIRED_DOCS
    assert "docs/html/api-sdk.html" in DEFAULT_REQUIRED_DOCS
    assert "docs/runtime-effect-demo.md" in DEFAULT_REQUIRED_DOCS
    assert "docs/html/runtime-effect-demo.html" in DEFAULT_REQUIRED_DOCS
    assert "docs/five-layer-operator-guide.md" in DEFAULT_REQUIRED_DOCS
    assert "docs/html/five-layer-operator-guide.html" in DEFAULT_REQUIRED_DOCS

    assert callable(documented_load_ledger_entries)
    assert callable(documented_verify_ledger)
    assert callable(documented_export_proof_report)
    assert callable(documented_verify_proof_report)
    assert DocumentedRuntimeEvent.from_dict({"type": "shell", "command": "true"}).to_dict()["type"] == "shell"


def test_v029_release_candidate_gate_requires_complete_product_artifacts(tmp_path: Path) -> None:
    from invart.evaluation.release_candidate import verify_release_candidate

    report = verify_release_candidate(tmp_path / "rc", run_pytest=False)
    assert report["schema_version"] == "invart.release_candidate.v0.45"
    assert report["status"] == "pass"
    assert Path(report["artifacts"]["report_json"]).exists()
    assert Path(report["artifacts"]["report_html"]).exists()
    assert report["checks"]["roadmap_full"]["status"] == "pass"
    assert report["checks"]["claim_integrity"]["status"] == "pass"
    assert report["checks"]["brand_assets"]["status"] == "pass"
    assert report["checks"]["external_validation"]["status"] == "skipped"
    assert report["checks"]["external_validation"]["summary"]["gaps"] >= 1
    assert report["checks"]["benchmarks"]["status"] == "pass"

    missing = verify_release_candidate(tmp_path / "bad-rc", run_pytest=False, required_docs=[tmp_path / "missing.html"])
    assert missing["status"] == "fail"
    assert missing["checks"]["docs"]["status"] == "fail"

    assert main(["release-candidate", "verify", "--out-dir", str(tmp_path / "cli-rc"), "--skip-pytest"]) == 0
    assert main(["rc", "verify", "--out-dir", str(tmp_path / "cli-rc-alias"), "--skip-pytest"]) == 0


def test_v051_research_ready_gate_is_separate_from_product_rc(tmp_path: Path) -> None:
    from invart.evaluation.paper_tables import export_paper_tables
    from invart.evaluation.research_readiness import verify_research_readiness
    from invart.evaluation.experiment_cases import run_paper_suite
    from invart.evaluation.coverage_experiments import run_coverage_truthfulness_matrix
    from invart.evaluation.reviewer_experiments import run_reviewer_selectivity_experiment
    from invart.evaluation.audit_reconstruction import run_audit_reconstruction_study
    from invart.evaluation.product_control_matrix import run_product_control_matrix
    from invart.evaluation.release_candidate import verify_release_candidate

    product = verify_release_candidate(tmp_path / "product-rc", run_pytest=False, benchmark_suites=["v0.46-paper-evidence-tables"])
    assert product["status"] == "pass"
    assert product["final_readiness"]["state"] == "local_rc_ready"

    missing = verify_research_readiness(tmp_path / "missing-research")
    assert missing["status"] == "fail"
    assert missing["state"] == "research_incomplete"
    assert "paper_tables" in missing["missing"]

    paper = run_paper_suite(tmp_path / "paper")
    tables = export_paper_tables(paper, tmp_path / "tables")
    coverage = run_coverage_truthfulness_matrix(out_dir=tmp_path / "coverage")
    reviewer = run_reviewer_selectivity_experiment(out_dir=tmp_path / "reviewer")
    audit = run_audit_reconstruction_study(out_dir=tmp_path / "audit")
    matrix = run_product_control_matrix(out_dir=tmp_path / "matrix")
    ready = verify_research_readiness(
        tmp_path / "ready-research",
        paper_tables=Path(tables["artifacts"]["tables_json"]),
        coverage=Path(coverage["artifacts"]["coverage_json"]),
        reviewer=Path(reviewer["artifacts"]["reviewer_json"]),
        audit=Path(audit["artifacts"]["report_json"]),
        product_matrix=Path(matrix["artifacts"]["matrix_json"]),
    )
    assert ready["status"] == "pass"
    assert ready["state"] == "research_ready"
    assert ready["checks"]["coverage_truthfulness"]["status"] == "pass"
    assert ready["checks"]["reviewer_ablation"]["status"] == "pass"
    assert Path(ready["artifacts"]["report_html"]).exists()

    assert main(
        [
            "release-candidate",
            "verify",
            "--out-dir",
            str(tmp_path / "cli-paper-rc"),
            "--skip-pytest",
            "--paper",
            "--paper-tables",
            tables["artifacts"]["tables_json"],
            "--coverage",
            coverage["artifacts"]["coverage_json"],
            "--reviewer",
            reviewer["artifacts"]["reviewer_json"],
            "--audit",
            audit["artifacts"]["report_json"],
            "--product-matrix",
            matrix["artifacts"]["matrix_json"],
        ]
    ) == 0
    assert run_benchmark("v0.51-pre-1.0-research-ready-gate")["passed"] is True


def test_v025_to_v029_benchmarks_and_roadmap_are_registered() -> None:
    for suite in [
        "v0.25-adapter-runtime-integration",
        "v0.26-policy-as-code",
        "v0.27-enterprise-evidence-export",
        "v0.28-harness-expansion",
        "v0.29-release-candidate-gate",
    ]:
        result = run_benchmark(suite)
        assert result["passed"] is True
    report = verify_roadmap_coverage(require_full=True)
    assert report["passed"] is True
    assert report["summary"]["schema_version"] == "invart.roadmap_coverage.full_product.v0.45"
    versions = {item["version"] for item in report["capabilities"]}
    assert {"v0.25", "v0.26", "v0.27", "v0.28", "v0.29"}.issubset(versions)
