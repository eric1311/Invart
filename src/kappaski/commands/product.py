from __future__ import annotations

import argparse
import json
from pathlib import Path

from ..artifacts import write_json_artifact
from ..evals import run_benchmark
from ..benchmark_registry import list_benchmark_suites
from ..profiles import load_profile_file
from ..roadmap import verify_roadmap_coverage
from ..audit_demo import record_audit_signoff, run_enterprise_audit_demo, run_enterprise_audit_live_adapter_demo
from ..pre_v1 import run_pre_v1_control_plane_demo
from ..evidence_bundle import export_evidence_bundle, verify_evidence_bundle
from ..release_candidate import verify_release_candidate
from ..experiment_cases import export_experiment_report, list_experiment_suites, run_experiment_suite, run_paper_suite
from ..experiment_fixtures import validate_experiment_fixture_root
from ..real_world_cases import run_real_world_risk_demo


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

def handle_audit(args: argparse.Namespace) -> int:
    if args.audit_command == "report":
        result = export_evidence_bundle(Path(args.ledger), Path(args.out_dir), profile={"name": "audit-report", "mode": "managed"})
        print(json.dumps({"audit_report": result}, ensure_ascii=False, indent=2, sort_keys=True))
        return 0 if result.get("status") == "pass" else 1
    return 2

def handle_release_candidate(args: argparse.Namespace) -> int:
    if args.rc_command == "verify":
        result = verify_release_candidate(Path(args.out_dir), run_pytest=not args.skip_pytest)
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0 if result.get("status") == "pass" else 1
    return 2
