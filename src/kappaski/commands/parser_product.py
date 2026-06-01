from __future__ import annotations

import argparse

from .product import handle_audit, handle_demo, handle_eval, handle_evidence, handle_experiment, handle_release_candidate, handle_roadmap


def register_product_commands(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    eval_parser = subparsers.add_parser("eval", help="Run Kappaski effectiveness benchmarks.")
    eval_parser.set_defaults(handler=handle_eval)
    eval_sub = eval_parser.add_subparsers(dest="eval_command", required=True)
    eval_list = eval_sub.add_parser("list", help="List built-in benchmark suites.")
    eval_report = eval_sub.add_parser("report", help="Run a benchmark suite and write a JSON report.")
    eval_report.add_argument("--suite", default="full-product-readiness")
    eval_report.add_argument("--out", required=True)
    benchmark = eval_sub.add_parser("benchmark", help="Run a built-in benchmark suite through the runtime pipeline.")
    benchmark.add_argument("--suite", default="v0.2-semantic")
    benchmark.add_argument("--reviewer", choices=("heuristic", "llm"), default="heuristic")
    benchmark.add_argument("--policy-profile", choices=("balanced", "strict", "audit"), default="balanced")

    experiment = subparsers.add_parser("experiment", help="Run benchmark-derived LLM agent experiment suites.")
    experiment.set_defaults(handler=handle_experiment)
    experiment_sub = experiment.add_subparsers(dest="experiment_command", required=True)
    experiment_list = experiment_sub.add_parser("list", help="List benchmark experiment suites.")
    experiment_run = experiment_sub.add_parser("run", help="Run an experiment suite and write artifacts.")
    experiment_run.add_argument("--suite", default="control-plane-core")
    experiment_run.add_argument("--out-dir", required=True)
    experiment_report = experiment_sub.add_parser("report", help="Render an experiment run JSON as HTML.")
    experiment_report.add_argument("--run", required=True)
    experiment_report.add_argument("--out", required=True)
    experiment_validate = experiment_sub.add_parser("validate-fixtures", help="Validate benchmark-derived experiment fixture JSON files.")
    experiment_validate.add_argument("--root", default="benchmarks/experiments")
    experiment_paper = experiment_sub.add_parser("paper-suite", help="Generate the v0.39 paper-ready experiment bundle.")
    experiment_paper.add_argument("--out-dir", required=True)

    evidence = subparsers.add_parser("evidence", help="Export and verify enterprise evidence bundles.")
    evidence.set_defaults(handler=handle_evidence)
    evidence_sub = evidence.add_subparsers(dest="evidence_command", required=True)
    evidence_export = evidence_sub.add_parser("export", help="Export a v0.27 evidence bundle from a ledger.")
    evidence_export.add_argument("--ledger", required=True)
    evidence_export.add_argument("--out-dir", required=True)
    evidence_export.add_argument("--profile", default=None)
    evidence_verify = evidence_sub.add_parser("verify", help="Verify an evidence bundle manifest.")
    evidence_verify.add_argument("--bundle", required=True)

    audit = subparsers.add_parser("audit", help="Generate audit reports from runtime evidence.")
    audit.set_defaults(handler=handle_audit)
    audit_sub = audit.add_subparsers(dest="audit_command", required=True)
    audit_report = audit_sub.add_parser("report", help="Export audit JSON/HTML through an evidence bundle.")
    audit_report.add_argument("--ledger", required=True)
    audit_report.add_argument("--out-dir", required=True)


    roadmap = subparsers.add_parser("roadmap", help="Inspect implementation coverage against the roadmap.")
    roadmap.set_defaults(handler=handle_roadmap)
    roadmap_sub = roadmap.add_subparsers(dest="roadmap_command", required=True)
    roadmap_status = roadmap_sub.add_parser("status", help="Show roadmap implementation coverage and gaps.")
    roadmap_status.add_argument("--require-full", action="store_true")
    roadmap_status.add_argument("--require-external-validation", action="store_true", help="Fail if optional external/live benchmark validation has not been run.")

    demo = subparsers.add_parser("demo", help="Generate packaged product demos and audit artifacts.")
    demo.set_defaults(handler=handle_demo)
    demo_sub = demo.add_subparsers(dest="demo_command", required=True)
    demo_enterprise = demo_sub.add_parser("enterprise-audit", help="Generate the v0.14 enterprise security audit demo.")
    demo_enterprise.add_argument("--out-dir", required=True)
    demo_enterprise.add_argument("--mode", choices=("scripted", "live-adapter"), default="scripted")
    demo_pre_v1 = demo_sub.add_parser("pre-v1-control-plane", help="Generate the v0.24 pre-v1 control-plane demo package.")
    demo_pre_v1.add_argument("--out-dir", required=True)
    demo_real_world = demo_sub.add_parser("real-world-risk-cases", help="Generate public-source risk mapping plus before/during/after Kappaski demo artifacts.")
    demo_real_world.add_argument("--out-dir", required=True)
    demo_signoff = demo_sub.add_parser("signoff", help="Record ledger-backed enterprise audit signoff.")
    demo_signoff.add_argument("--ledger", required=True)
    demo_signoff.add_argument("--actor", required=True)
    demo_signoff.add_argument("--status", choices=("approved", "rejected", "needs_followup"), required=True)
    demo_signoff.add_argument("--reason", required=True)
    demo_signoff.add_argument("--report", default=None)

    for rc_name in ("release-candidate", "rc"):
        rc_parser = subparsers.add_parser(rc_name, help="Run the v0.40 release-candidate readiness gate.")
        rc_parser.set_defaults(handler=handle_release_candidate)
        rc_sub = rc_parser.add_subparsers(dest="rc_command", required=True)
        rc_verify = rc_sub.add_parser("verify", help="Verify pytest, roadmap, benchmarks, docs, and artifacts.")
        rc_verify.add_argument("--out-dir", required=True)
        rc_verify.add_argument("--skip-pytest", action="store_true")
