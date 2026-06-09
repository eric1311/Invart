from __future__ import annotations

import argparse
import json
from pathlib import Path

from invart.core.artifacts import write_json_artifact
from invart.evaluation.evals import run_benchmark
from invart.evaluation.benchmark_registry import list_benchmark_suites
from invart.governance.profiles import load_profile_file
from invart.evaluation.roadmap import verify_roadmap_coverage
from invart.assurance.audit_demo import record_audit_signoff, run_enterprise_audit_demo, run_enterprise_audit_live_adapter_demo
from invart.evaluation.pre_v1 import run_pre_v1_control_plane_demo
from invart.assurance.evidence_bundle import export_evidence_bundle, verify_evidence_bundle
from invart.evaluation.release_candidate import verify_release_candidate
from invart.evaluation.experiment_cases import export_experiment_report, list_experiment_suites, run_experiment_suite, run_paper_suite
from invart.evaluation.audit_reconstruction import run_audit_reconstruction_study
from invart.evaluation.coverage_experiments import run_coverage_truthfulness_matrix
from invart.evaluation.paper_tables import export_paper_tables_from_file
from invart.evaluation.product_control_matrix import run_product_control_matrix
from invart.evaluation.research_readiness import verify_research_readiness
from invart.evaluation.reviewer_experiments import run_reviewer_selectivity_experiment
from invart.evaluation.experiment_fixtures import validate_experiment_fixture_root
from invart.evaluation.real_world_cases import run_real_world_risk_demo
from invart.evaluation.pre_1_0 import run_pre_1_0_final_demo
from invart.evaluation.external_evidence import attach_swe_bench_full_evidence, import_external_evidence, verify_external_evidence
from invart.evaluation.progressive_validation import run_progressive_validation
from invart.evaluation.container_demo import run_container_risk_case, run_container_risk_suite


def handle_experiment(args: argparse.Namespace) -> int:
    if args.experiment_command == "list":
        print(json.dumps(list_experiment_suites(), ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    if args.experiment_command == "run":
        result = run_experiment_suite(args.suite, out_dir=Path(args.out_dir))
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0 if result.get("status") == "pass" else 1
    if args.experiment_command == "report":
        run = json.loads(Path(args.run).read_text(encoding="utf-8"))
        result = export_experiment_report(run, Path(args.out))
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0 if result.get("status") == "pass" else 1
    if args.experiment_command == "validate-fixtures":
        result = validate_experiment_fixture_root(Path(args.root))
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0 if result.get("status") == "pass" else 1
    if args.experiment_command == "paper-suite":
        result = run_paper_suite(Path(args.out_dir))
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0 if result.get("status") == "pass" else 1
    if args.experiment_command == "paper-tables":
        result = export_paper_tables_from_file(Path(args.paper_suite), Path(args.out_dir))
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0 if result.get("status") == "pass" else 1
    if args.experiment_command == "coverage-matrix":
        result = run_coverage_truthfulness_matrix(out_dir=Path(args.out_dir))
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0 if result.get("status") == "pass" else 1
    if args.experiment_command == "audit-reconstruction":
        result = run_audit_reconstruction_study(out_dir=Path(args.out_dir))
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0 if result.get("status") == "pass" else 1
    if args.experiment_command == "reviewer-ablation":
        result = run_reviewer_selectivity_experiment(out_dir=Path(args.out_dir))
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0 if result.get("status") == "pass" else 1
    if args.experiment_command == "product-control-matrix":
        result = run_product_control_matrix(out_dir=Path(args.out_dir))
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0 if result.get("status") == "pass" else 1
    return 2

def handle_roadmap(args: argparse.Namespace) -> int:
    if args.roadmap_command == "status":
        result = verify_roadmap_coverage(require_full=args.require_full, require_external_validation=args.require_external_validation)
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0 if result.get("passed") else 1
    return 2

def handle_demo(args: argparse.Namespace) -> int:
    if args.demo_command == "enterprise-audit":
        if args.mode == "live-adapter":
            result = run_enterprise_audit_live_adapter_demo(Path(args.out_dir))
        else:
            result = run_enterprise_audit_demo(Path(args.out_dir))
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    if args.demo_command == "pre-v1-control-plane":
        result = run_pre_v1_control_plane_demo(Path(args.out_dir))
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0 if result.get("status") == "pass" else 1
    if args.demo_command == "real-world-risk-cases":
        result = run_real_world_risk_demo(Path(args.out_dir))
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0 if result.get("status") == "pass" else 1
    if args.demo_command == "container-risk-case":
        result = run_container_risk_case(args.case, Path(args.out_dir))
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0 if result.get("status") == "pass" else 1
    if args.demo_command == "container-risk-suite":
        result = run_container_risk_suite(Path(args.out_dir), collect_existing=args.collect_existing)
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0 if result.get("status") == "pass" else 1
    if args.demo_command == "pre-1.0-final":
        result = run_pre_1_0_final_demo(Path(args.out_dir), external_evidence_manifest=Path(args.external_evidence) if args.external_evidence else None)
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0 if result.get("status") == "pass" else 1
    if args.demo_command == "signoff":
        result = record_audit_signoff(
            Path(args.ledger),
            actor=args.actor,
            status=args.status,
            reason=args.reason,
            report_path=Path(args.report) if args.report else None,
        )
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    return 2

def handle_eval(args: argparse.Namespace) -> int:
    if args.eval_command == "list":
        result = list_benchmark_suites()
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    if args.eval_command == "report":
        result = run_benchmark(args.suite)
        out = Path(args.out)
        write_json_artifact(out, result)
        print(json.dumps({"report": str(out), "suite": args.suite, "passed": result.get("passed", False)}, ensure_ascii=False, indent=2, sort_keys=True))
        return 0 if result.get("passed") is True or result.get("summary", {}).get("passed") == result.get("summary", {}).get("total") else 1
    if args.eval_command == "benchmark":
        result = run_benchmark(args.suite, reviewer=args.reviewer, policy_profile=args.policy_profile)
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        if "summary" in result and "passed" in result["summary"] and "total" in result["summary"]:
            return 0 if result["summary"]["passed"] == result["summary"]["total"] else 1
        return 0 if result.get("passed") is True else 1
    return 2

def handle_evidence(args: argparse.Namespace) -> int:
    if args.evidence_command == "export":
        profile = load_profile_file(Path(args.profile)) if args.profile else None
        result = export_evidence_bundle(Path(args.ledger), Path(args.out_dir), profile=profile)
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0 if result.get("status") == "pass" else 1
    if args.evidence_command == "verify":
        result = verify_evidence_bundle(Path(args.bundle))
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0 if result.get("status") == "pass" else 1
    return 2


def handle_external_evidence(args: argparse.Namespace) -> int:
    if args.external_evidence_command == "import":
        result = import_external_evidence(Path(args.snapshot), Path(args.out_dir))
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0 if result.get("status") == "pass" else 1
    if args.external_evidence_command == "attach":
        result = attach_swe_bench_full_evidence(
            report_path=Path(args.report),
            instance_results_path=Path(args.instance_results),
            predictions_path=Path(args.predictions),
            logs_path=Path(args.logs),
            out_dir=Path(args.out_dir),
            run_id=args.run_id,
            expected_total_instances=args.expected_total_instances,
            invart_mode=args.invart_mode,
        )
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0 if result.get("status") == "pass" else 1
    if args.external_evidence_command == "verify":
        result = verify_external_evidence(Path(args.manifest))
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0 if result.get("status") == "pass" else 1
    if args.external_evidence_command == "progressive":
        result = run_progressive_validation(
            out_dir=Path(args.out_dir),
            stage=args.stage,
            categories=args.category,
            max_cases=args.max_cases,
            public_risk_catalog=Path(args.public_risk_catalog) if args.public_risk_catalog else None,
            snapshot_path=Path(args.snapshot) if args.snapshot else None,
            swe_report_path=Path(args.swe_report) if args.swe_report else None,
            swe_instance_results_path=Path(args.swe_instance_results) if args.swe_instance_results else None,
            swe_predictions_path=Path(args.swe_predictions) if args.swe_predictions else None,
            swe_logs_path=Path(args.swe_logs) if args.swe_logs else None,
            swe_run_id=args.swe_run_id,
        )
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0 if result.get("status") == "pass" else 1
    return 2

def handle_audit(args: argparse.Namespace) -> int:
    if args.audit_command == "report":
        result = export_evidence_bundle(Path(args.ledger), Path(args.out_dir), profile={"name": "audit-report", "mode": "managed"})
        print(json.dumps({"audit_report": result}, ensure_ascii=False, indent=2, sort_keys=True))
        return 0 if result.get("status") == "pass" else 1
    return 2

def handle_release_candidate(args: argparse.Namespace) -> int:
    if args.rc_command == "verify":
        result = verify_release_candidate(
            Path(args.out_dir),
            run_pytest=not args.skip_pytest,
            final=args.final,
            require_external_validation=args.require_external_validation,
            external_evidence_manifest=Path(args.external_evidence) if args.external_evidence else None,
        )
        if args.paper:
            research = verify_research_readiness(
                Path(args.out_dir) / "research-readiness",
                paper_tables=Path(args.paper_tables) if args.paper_tables else None,
                coverage=Path(args.coverage) if args.coverage else None,
                reviewer=Path(args.reviewer) if args.reviewer else None,
                audit=Path(args.audit) if args.audit else None,
                product_matrix=Path(args.product_matrix) if args.product_matrix else None,
                external_evidence=Path(args.external_evidence) if args.external_evidence else None,
                require_external_validation=args.require_external_validation,
            )
            result["research_readiness"] = research
            result["final_readiness"]["research_state"] = research.get("state")
            result["status"] = "pass" if result.get("status") == "pass" and research.get("status") == "pass" else "fail"
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0 if result.get("status") == "pass" else 1
    return 2
