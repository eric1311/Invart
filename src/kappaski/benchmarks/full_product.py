from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path
from typing import Any

from ..models import RuntimeEvent
from ..runtime import close_session, record_action, start_session
from ..postruntime import export_proof_report
from ..harness import run_managed_harness_check
from ..profiles import create_profile_distribution_bundle, record_break_glass_override, review_break_glass_override
from ..teamrun import append_teamrun_fact, create_handoff, create_teamrun, export_teamrun_timeline_html
from ..enforcement import run_enforced_command
from ..audit_demo import record_audit_signoff, run_enterprise_audit_demo
from ..coverage import export_coverage_html_report
from ..native import native_conformance_report
from ..native_bridge import bridge_conformance_matrix
from ..mcp_broker import run_stdio_broker
from ..product_readiness import optional_provider_smoke, reviewer_quality_corpus
from ..supervision import supervise_process_group
from ..experiment_cases import run_paper_suite
from ..coverage_experiments import run_coverage_truthfulness_matrix
from ..reviewer_experiments import run_reviewer_selectivity_experiment
from ..audit_experiments import run_audit_tamper_assurance
from ..secure_code_gate import run_secure_coding_gate_suite
from ..roadmap import verify_roadmap_coverage



from .common import _suite_result, run_direct_experiment_benchmark, run_experiment_benchmark
from .releases_v08_v18 import (
    run_swe_bench_full_validation_contract_benchmark,
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

def run_full_product_readiness_benchmark() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="kappaski_full_product_") as tmp:
        root = Path(tmp)
        reviewer = reviewer_quality_corpus()
        provider = optional_provider_smoke()

        harness_artifact = root / "wrapped.json"
        harness = run_managed_harness_check(
            target=root,
            command=[
                sys.executable,
                "-c",
                "import json,sys; json.dump({'exit_code': 0, 'grading_result': 'passed', 'artifacts': ['report.json']}, open(sys.argv[1], 'w'))",
                str(harness_artifact),
            ],
            case={"instance_id": "django__django-11001"},
            approval_actor="benchmark-security",
        )
        supervision = supervise_process_group([sys.executable, "-c", "print('ok')"], cwd=root)
        bundle = create_profile_distribution_bundle({"name": "enterprise", "mode": "managed", "approval": {"local_approval": False}}, scope="team", distributed_by="benchmark")
        profile_ledger = root / "profile.jsonl"
        profile_session = start_session(root, profile_ledger, session_id="ks_full_profile", create_preflight=False)
        override = record_break_glass_override(profile_ledger, session_id=profile_session.session_id, actor="alice", reason="benchmark", scope="repo")
        profile_review = review_break_glass_override(profile_ledger, override_id=override["override"]["override_id"], reviewer="security", status="approved", reason="benchmark review")

        team_a = root / "team-a.jsonl"
        team_b = root / "team-b.jsonl"
        start_session(root, team_a, session_id="ks_full_team_a", create_preflight=False)
        start_session(root, team_b, session_id="ks_full_team_b", create_preflight=False)
        append_teamrun_fact(team_a, "teamrun", create_teamrun("benchmark", ["alice", "bob"]))
        append_teamrun_fact(team_b, "handoff", create_handoff("claude", "codex", [{"kind": "file", "value": ".env", "tainted": "true"}]))
        timeline = export_teamrun_timeline_html([team_a, team_b], root / "teamrun-timeline.html")

        enforced_env = run_enforced_command(["sh", "-c", "touch should_not_exist && echo $OPENAI_API_KEY"], domain="env-secrets", target=root, event={"type": "shell", "command": "echo $OPENAI_API_KEY"})
        enforced_network = run_enforced_command([sys.executable, "-c", "open('network-safe.txt','w').write('ok')"], domain="network-egress", target=root, event={"type": "shell", "command": "echo local"})

        audit = run_enterprise_audit_demo(root / "audit")
        signoff = record_audit_signoff(Path(audit["ledger"]), actor="security-lead", status="approved", reason="benchmark signoff", report_path=Path(audit["audit_report"]))

        claude_settings = root / ".claude" / "settings.json"
        claude_settings.parent.mkdir(parents=True, exist_ok=True)
        claude_settings.write_text(json.dumps({"hooks": {"PreToolUse": []}}), encoding="utf-8")
        native = native_conformance_report(root)
        bridge = bridge_conformance_matrix()

        mcp_in = root / "mcp-in.jsonl"
        mcp_out = root / "mcp-out.jsonl"
        mcp_transcript = root / "mcp-transcript.jsonl"
        mcp_in.write_text(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}) + "\n", encoding="utf-8")
        mcp = run_stdio_broker(input_path=mcp_in, output_path=mcp_out, transcript_path=mcp_transcript)

        coverage_ledger = root / "coverage.jsonl"
        coverage_session = start_session(root, coverage_ledger, session_id="ks_full_coverage", create_preflight=False)
        record_action(RuntimeEvent(type="shell", session_id=coverage_session.session_id, command="echo ok", metadata={"coverage_layer": "native_hook"}), coverage_ledger)
        close_session(coverage_ledger)
        proof_path = root / "coverage-proof.json"
        export_proof_report(coverage_ledger, proof_path)
        coverage_html = export_coverage_html_report(proof_path, root / "coverage.html")
        v19 = run_identity_principal_binding_benchmark()
        v20 = run_path_graph_benchmark()
        v21 = run_path_aware_policy_benchmark()
        v22 = run_unified_mediation_benchmark()
        v23 = run_enterprise_policy_governance_benchmark()
        v24 = run_pre_v1_control_plane_benchmark()
        v25 = run_adapter_runtime_integration_benchmark()
        v26 = run_policy_as_code_benchmark()
        v27 = run_enterprise_evidence_export_benchmark()
        v28 = run_harness_expansion_benchmark()
        v29 = run_release_candidate_gate_benchmark()
        v30 = run_experiment_benchmark("control-plane-core", "v0.30-control-plane-experiment-runner")
        v31 = run_experiment_benchmark("external-ipi-control-plane", "v0.31-external-ipi-control-plane")
        v32 = run_experiment_benchmark("authority-dataflow-boundary", "v0.32-authority-dataflow-boundary")
        v33 = run_experiment_benchmark("swebench-friction-control-plane", "v0.33-swebench-friction-control-plane")
        v34 = run_experiment_benchmark("skill-supply-chain-control-plane", "v0.34-skill-supply-chain-control-plane")
        v35 = run_direct_experiment_benchmark(run_secure_coding_gate_suite(), "v0.35-secure-coding-gate")
        v36 = run_direct_experiment_benchmark(run_coverage_truthfulness_matrix(), "v0.36-coverage-truthfulness-matrix")
        v37 = run_direct_experiment_benchmark(run_reviewer_selectivity_experiment(), "v0.37-llm-reviewer-selectivity")
        v38 = run_direct_experiment_benchmark(run_audit_tamper_assurance(), "v0.38-audit-tamper-assurance")
        v39 = run_direct_experiment_benchmark(run_paper_suite(root / "paper-suite"), "v0.39-paper-ready-experiment-suite")
        v40 = run_swe_bench_full_validation_contract_benchmark()
        roadmap_local = verify_roadmap_coverage(require_full=True)
        roadmap_external = verify_roadmap_coverage(require_external_validation=True)

        checks = {
            "claim_integrity": roadmap_local["passed"] is True and not roadmap_local["claim_integrity_findings"],
            "external_validation_not_misreported": roadmap_external["passed"] is False and len(roadmap_external["external_validation_gaps"]) >= 1,
            "v08_reviewer_quality": reviewer["status"] == "pass" and provider["status"] in {"pass", "skipped"},
            "v09_managed_harness_pause_resume": harness["status"] == "pass" and harness["managed_pause"]["approval_status"] == "approved",
            "v10_process_supervision": supervision["process_group"]["strong_consistency"] is True and supervision["returncode"] == 0,
            "v11_profile_distribution_review": bundle["hash"].startswith("sha256:") and profile_review["review"]["status"] == "approved",
            "v12_teamrun_timeline": timeline["status"] == "pass" and timeline["summary"]["ledgers"] == 2,
            "v13_multi_domain_enforcement": enforced_env["status"] == "blocked" and enforced_network["status"] == "executed",
            "v14_audit_signoff": signoff["signoff"]["status"] == "approved",
            "v15_native_conformance": native["status"] == "pass" and native["summary"]["hashed_matches"] >= 1,
            "v16_bridge_conformance": bridge["status"] == "pass",
            "v17_mcp_stdio_broker": mcp["summary"]["messages"] == 1 and mcp_out.read_text(encoding="utf-8") == mcp_in.read_text(encoding="utf-8"),
            "v18_coverage_html": coverage_html["status"] == "pass" and Path(coverage_html["output"]).exists(),
            "v19_identity_binding": v19["passed"] is True,
            "v20_path_graph": v20["passed"] is True,
            "v21_path_policy": v21["passed"] is True,
            "v22_unified_mediation": v22["passed"] is True,
            "v23_profile_governance": v23["passed"] is True,
            "v24_pre_v1_demo": v24["passed"] is True,
            "v25_adapter_runtime": v25["passed"] is True,
            "v26_policy_as_code": v26["passed"] is True,
            "v27_evidence_export": v27["passed"] is True,
            "v28_harness_expansion": v28["passed"] is True,
            "v29_rc_gate": v29["passed"] is True,
            "v30_experiment_runner": v30["passed"] is True,
            "v31_external_ipi": v31["passed"] is True,
            "v32_authority_dataflow": v32["passed"] is True,
            "v33_swebench_friction": v33["passed"] is True,
            "v34_skill_supply_chain": v34["passed"] is True,
            "v35_secure_code_gate": v35["passed"] is True,
            "v36_coverage_truthfulness": v36["passed"] is True,
            "v37_reviewer_selectivity": v37["passed"] is True,
            "v38_audit_tamper": v38["passed"] is True,
            "v39_paper_suite": v39["passed"] is True,
            "v40_swebench_full_contract": v40["passed"] is True,
        }
        return _suite_result(
            "full-product-readiness",
            checks,
            artifacts={
                "harness_ledger": harness["ledger"],
                "teamrun_timeline": timeline["output"],
                "audit_report": audit["audit_report"],
                "coverage_report": coverage_html["output"],
            },
        )



__all__ = ["run_full_product_readiness_benchmark"]
