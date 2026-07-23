from __future__ import annotations

import argparse

from invart.surfaces.adapter_profiles import adapter_profile_ids
from .product import handle_audit, handle_demo, handle_eval, handle_evidence, handle_experiment, handle_external_evidence, handle_release_candidate, handle_roadmap


def register_product_commands(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    eval_parser = subparsers.add_parser("eval", help="Run Invart effectiveness benchmarks.")
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
    experiment_tables = experiment_sub.add_parser("paper-tables", help="Export v0.46 paper evidence tables from a paper suite JSON artifact.")
    experiment_tables.add_argument("--paper-suite", required=True)
    experiment_tables.add_argument("--out-dir", required=True)
    experiment_coverage = experiment_sub.add_parser("coverage-matrix", help="Generate the v0.47 same-action coverage mediation matrix.")
    experiment_coverage.add_argument("--out-dir", required=True)
    experiment_audit_reconstruction = experiment_sub.add_parser("audit-reconstruction", help="Generate the v0.48 audit reconstruction study artifacts.")
    experiment_audit_reconstruction.add_argument("--out-dir", required=True)
    experiment_reviewer = experiment_sub.add_parser("reviewer-ablation", help="Generate the v0.49 reviewer ablation and cost artifacts.")
    experiment_reviewer.add_argument("--out-dir", required=True)
    experiment_product_matrix = experiment_sub.add_parser("product-control-matrix", help="Generate the v0.50 product control matrix artifacts.")
    experiment_product_matrix.add_argument("--out-dir", required=True)
    experiment_policy_sensitivity = experiment_sub.add_parser("policy-sensitivity", help="Generate the v0.52 local policy sensitivity slice.")
    experiment_policy_sensitivity.add_argument("--out-dir", required=True)
    experiment_task_agent = experiment_sub.add_parser("task-agent", help="Generate the v0.53 task-level installed-agent managed-wrapper slice.")
    experiment_task_agent.add_argument("--out-dir", required=True)
    experiment_task_agent.add_argument("--agent", action="append", choices=adapter_profile_ids(), default=[])
    experiment_task_agent.add_argument("--binary", action="append", default=[], help="Override an agent binary as agent-id=/path/to/binary.")
    experiment_task_agent.add_argument("--require-installed", action="store_true", help="Fail if requested product binaries are unavailable.")
    experiment_layer_path = experiment_sub.add_parser("layer-path", help="Generate the v0.54 layer path-completeness claim-loss slice.")
    experiment_layer_path.add_argument("--out-dir", required=True)
    experiment_full_benchmark = experiment_sub.add_parser(
        "full-benchmark",
        help="Freeze and audit the official full-benchmark evidence program without implicitly running providers.",
    )
    experiment_full_benchmark_sub = experiment_full_benchmark.add_subparsers(dest="full_benchmark_command", required=True)
    experiment_agentdojo_census = experiment_full_benchmark_sub.add_parser(
        "agentdojo-census",
        help="Enumerate the full official AgentDojo denominator from a pinned Python environment.",
    )
    experiment_agentdojo_census.add_argument("--out-dir", required=True)
    experiment_agentdojo_census.add_argument("--python", dest="python_executable", default="python3")
    experiment_agentdojo_census.add_argument("--benchmark-version", default="v1.2.2")
    experiment_agentdojo_census.add_argument("--module-to-load", action="append", default=[])
    experiment_agentdojo_manifest = experiment_full_benchmark_sub.add_parser(
        "agentdojo-manifest",
        help="Freeze suite-level AgentDojo jobs for every selected agent, mode, trial, and condition.",
    )
    experiment_agentdojo_manifest.add_argument("--census", required=True)
    experiment_agentdojo_manifest.add_argument("--out-dir", required=True)
    experiment_agentdojo_manifest.add_argument("--agent", action="append", choices=adapter_profile_ids(), required=True)
    experiment_agentdojo_manifest.add_argument(
        "--suite",
        action="append",
        default=[],
        help="Optional suite subset for a frozen pilot; omit to include the complete census.",
    )
    experiment_agentdojo_manifest.add_argument(
        "--user-task",
        action="append",
        default=[],
        help="Optional task filter for a single-suite smoke manifest.",
    )
    experiment_agentdojo_manifest.add_argument(
        "--injection-task",
        action="append",
        default=[],
        help="Optional injection-task filter for a single-suite smoke manifest.",
    )
    experiment_agentdojo_manifest.add_argument(
        "--mode",
        action="append",
        choices=("baseline_agent", "invart_observe_only", "invart_mediated"),
        default=[],
    )
    experiment_agentdojo_manifest.add_argument(
        "--policy-variant",
        action="append",
        choices=("V0", "V1", "V2", "V2H", "V3", "V4", "V5"),
        default=[],
        help="Freeze prompt/policy ablations; mutually exclusive with --mode.",
    )
    experiment_agentdojo_manifest.add_argument("--trials", type=int, default=1)
    experiment_agentdojo_manifest.add_argument("--attack", default="tool_knowledge")
    experiment_agentdojo_manifest.add_argument("--defense", default=None)
    experiment_agentdojo_manifest.add_argument("--policy-hash", default=None)
    experiment_agentdojo_audit = experiment_full_benchmark_sub.add_parser(
        "agentdojo-audit",
        help="Audit expected, launched, completed, graded, timeout, crash, partial, and missing full-run jobs.",
    )
    experiment_agentdojo_audit.add_argument("--manifest", required=True)
    experiment_agentdojo_audit.add_argument("--run-records", required=True)
    experiment_agentdojo_audit.add_argument("--out-dir", required=True)
    experiment_agentdojo_readiness = experiment_full_benchmark_sub.add_parser(
        "agentdojo-readiness",
        help="Validate official environment, mode isolation, command shape, and provider-call scale without executing jobs.",
    )
    experiment_agentdojo_readiness.add_argument("--manifest", required=True)
    experiment_agentdojo_readiness.add_argument("--out-dir", required=True)
    experiment_agentdojo_readiness.add_argument("--python", dest="python_executable", required=True)
    experiment_agentdojo_readiness.add_argument("--model", default="LOCAL")
    experiment_agentdojo_readiness.add_argument("--model-id", default=None)
    experiment_agentdojo_readiness.add_argument("--module-to-load", default=None)
    experiment_agentdojo_readiness.add_argument("--job-id", action="append", default=[])
    experiment_agentdojo_readiness.add_argument("--mode", action="append", default=[])
    experiment_agentdojo_readiness.add_argument("--condition", action="append", default=[])
    experiment_agentdojo_readiness.add_argument("--max-jobs", type=int, default=None)
    experiment_agentdojo_readiness.add_argument("--max-workers", type=int, default=1)
    experiment_agentdojo_readiness.add_argument("--reviewer-provider", default=None)
    experiment_agentdojo_readiness.add_argument("--reviewer-model", default=None)
    experiment_agentdojo_readiness.add_argument("--reviewer-approval", default=None)
    experiment_agentdojo_readiness.add_argument("--reviewer-budget-state", default=None)
    experiment_agentdojo_readiness.add_argument(
        "--reviewer-retention-posture", default="no_prompt_retention_requested"
    )
    experiment_agentdojo_readiness.add_argument("--reviewer-timeout", type=float, default=120.0)
    experiment_agentdojo_readiness.add_argument("--reviewer-max-tokens", type=int, default=256)
    experiment_agentdojo_readiness.add_argument("--max-continuation-replans", type=int, default=2)
    experiment_agentdojo_readiness.add_argument("--agent-provider", default=None)
    experiment_agentdojo_readiness.add_argument("--agent-model", default=None)
    experiment_agentdojo_readiness.add_argument("--agent-version", default=None)
    experiment_agentdojo_readiness.add_argument("--agent-approval", default=None)
    experiment_agentdojo_readiness.add_argument("--agent-budget-state", default=None)
    experiment_agentdojo_readiness.add_argument("--agent-provider-timeout", type=float, default=120.0)
    experiment_agentdojo_readiness.add_argument(
        "--agent-max-tokens-per-call", type=int, default=4096
    )
    experiment_agentdojo_run = experiment_full_benchmark_sub.add_parser(
        "agentdojo-run",
        help="Execute frozen AgentDojo jobs through the resumable suite-level scheduler.",
    )
    experiment_agentdojo_run.add_argument("--manifest", required=True)
    experiment_agentdojo_run.add_argument("--out-dir", required=True)
    experiment_agentdojo_run.add_argument("--python", dest="python_executable", required=True)
    experiment_agentdojo_run.add_argument("--model", default="LOCAL")
    experiment_agentdojo_run.add_argument("--model-id", default=None)
    experiment_agentdojo_run.add_argument("--module-to-load", default=None)
    experiment_agentdojo_run.add_argument("--job-id", action="append", default=[])
    experiment_agentdojo_run.add_argument("--mode", action="append", default=[])
    experiment_agentdojo_run.add_argument("--condition", action="append", default=[])
    experiment_agentdojo_run.add_argument("--max-jobs", type=int, default=None)
    experiment_agentdojo_run.add_argument("--max-workers", type=int, default=1)
    experiment_agentdojo_run.add_argument("--official-timeout", type=float, default=7200.0)
    experiment_agentdojo_run.add_argument("--provider-timeout", type=float, default=180.0)
    experiment_agentdojo_run.add_argument("--retry-incomplete", action="store_true")
    experiment_agentdojo_run.add_argument("--reviewer-provider", default=None)
    experiment_agentdojo_run.add_argument("--reviewer-model", default=None)
    experiment_agentdojo_run.add_argument("--reviewer-approval", default=None)
    experiment_agentdojo_run.add_argument("--reviewer-budget-state", default=None)
    experiment_agentdojo_run.add_argument(
        "--reviewer-retention-posture", default="no_prompt_retention_requested"
    )
    experiment_agentdojo_run.add_argument("--reviewer-timeout", type=float, default=120.0)
    experiment_agentdojo_run.add_argument("--reviewer-max-tokens", type=int, default=256)
    experiment_agentdojo_run.add_argument("--max-continuation-replans", type=int, default=2)
    experiment_agentdojo_run.add_argument("--agent-provider", default=None)
    experiment_agentdojo_run.add_argument("--agent-model", default=None)
    experiment_agentdojo_run.add_argument("--agent-version", default=None)
    experiment_agentdojo_run.add_argument("--agent-approval", default=None)
    experiment_agentdojo_run.add_argument("--agent-budget-state", default=None)
    experiment_agentdojo_run.add_argument("--agent-provider-timeout", type=float, default=120.0)
    experiment_agentdojo_run.add_argument("--agent-max-tokens-per-call", type=int, default=4096)
    experiment_agentdojo_analyze = experiment_full_benchmark_sub.add_parser(
        "agentdojo-analyze",
        help="Analyze official AgentDojo task results with explicit attack-success semantics and proxy mediation counts.",
    )
    experiment_agentdojo_analyze.add_argument("--manifest", required=True)
    experiment_agentdojo_analyze.add_argument("--run-records", required=True)
    experiment_agentdojo_analyze.add_argument("--out-dir", required=True)
    experiment_p0_real_agent = experiment_sub.add_parser("p0-real-agent", help="Plan and summarize the P0 real-agent official benchmark protocol.")
    experiment_p0_real_agent_sub = experiment_p0_real_agent.add_subparsers(dest="p0_command", required=True)
    experiment_p0_plan = experiment_p0_real_agent_sub.add_parser("plan", help="Write the P0 case manifest and reproducibility skeleton.")
    experiment_p0_plan.add_argument("--out-dir", required=True)
    experiment_p0_plan.add_argument("--agent", action="append", choices=adapter_profile_ids(), default=[])
    experiment_p0_run = experiment_p0_real_agent_sub.add_parser("run", help="Materialize the P0 run matrix from a manifest without replacing official benchmark runners.")
    experiment_p0_run.add_argument("--manifest", required=True)
    experiment_p0_run.add_argument("--out-dir", required=True)
    experiment_p0_run.add_argument("--mode", action="append", choices=("baseline_agent", "invart_observe_only", "invart_mediated"), default=[])
    experiment_p0_run.add_argument("--agent", action="append", choices=adapter_profile_ids(), default=[])
    experiment_p0_setup = experiment_p0_real_agent_sub.add_parser("setup-official", help="Preflight or prepare isolated official benchmark dependencies for P0.")
    experiment_p0_setup.add_argument("--manifest", required=True)
    experiment_p0_setup.add_argument("--out-dir", required=True)
    experiment_p0_setup.add_argument("--family", action="append", choices=("agentdojo", "agentsecbench", "skill_inject", "swe_bench_verified"), default=[])
    experiment_p0_setup.add_argument("--python", dest="python_executable", default=None)
    experiment_p0_setup.add_argument("--create-venv", action="store_true")
    experiment_p0_setup.add_argument("--install", action="store_true")
    experiment_p0_first_batch = experiment_p0_real_agent_sub.add_parser("first-batch", help="Generate the first-batch Claude Code/Codex AgentDojo + SWE-Bench execution recipe.")
    experiment_p0_first_batch.add_argument("--manifest", required=True)
    experiment_p0_first_batch.add_argument("--out-dir", required=True)
    experiment_p0_first_batch.add_argument("--python", dest="python_executable", default="python")
    experiment_p0_select_first_batch = experiment_p0_real_agent_sub.add_parser("select-first-batch", help="Select a narrow first-batch official benchmark run recipe without executing provider CLIs.")
    experiment_p0_select_first_batch.add_argument("--plan", required=True)
    experiment_p0_select_first_batch.add_argument("--out-dir", required=True)
    experiment_p0_select_first_batch.add_argument("--family", action="append", choices=("agentdojo", "swe_bench_verified"), default=[])
    experiment_p0_select_first_batch.add_argument("--agent", action="append", choices=adapter_profile_ids(), default=[])
    experiment_p0_select_first_batch.add_argument("--mode", action="append", choices=("baseline_agent", "invart_observe_only", "invart_mediated"), default=[])
    experiment_p0_select_first_batch.add_argument("--case-id", action="append", default=[])
    experiment_p0_select_first_batch.add_argument("--limit", type=int, default=None)
    experiment_p0_selected_doctor = experiment_p0_real_agent_sub.add_parser("selected-doctor", help="Check a selected first-batch mini-package before running provider CLIs.")
    experiment_p0_selected_doctor.add_argument("--run-dir", required=True)
    experiment_p0_selected_doctor.add_argument("--python", dest="python_executable", default=None)
    experiment_p0_prepare_swe = experiment_p0_real_agent_sub.add_parser("prepare-swe-workspace", help="Prepare one official SWE-Bench instance checkout for a generic agent command.")
    experiment_p0_prepare_swe.add_argument("--instance-json", required=True)
    experiment_p0_prepare_swe.add_argument("--out-dir", required=True)
    experiment_p0_prepare_swe.add_argument("--repo-cache", default=None)
    experiment_p0_prepare_swe.add_argument("--force", action="store_true")
    experiment_p0_export_swe = experiment_p0_real_agent_sub.add_parser("export-swe-instances", help="Export official SWE-Bench Verified instance rows used by the P0 manifest.")
    experiment_p0_export_swe.add_argument("--manifest", required=True)
    experiment_p0_export_swe.add_argument("--out-dir", required=True)
    experiment_p0_export_swe.add_argument("--dataset", default="SWE-bench/SWE-bench_Verified")
    experiment_p0_export_swe.add_argument("--config", default="default")
    experiment_p0_export_swe.add_argument("--split", default="test")
    experiment_p0_export_swe.add_argument("--rows-json", default=None, help="Optional local rows fixture for offline reproduction.")
    experiment_p0_export_swe.add_argument("--page-size", type=int, default=100)
    experiment_p0_export_swe.add_argument("--max-rows", type=int, default=1000)
    experiment_p0_agentdojo_boundary = experiment_p0_real_agent_sub.add_parser("agentdojo-boundary", help="Record why a CLI-agent row is not yet an official AgentDojo score.")
    experiment_p0_agentdojo_boundary.add_argument("--out-dir", required=True)
    experiment_p0_agentdojo_boundary.add_argument("--case-id", required=True)
    experiment_p0_agentdojo_boundary.add_argument("--benchmark-case-ref", required=True)
    experiment_p0_agentdojo_boundary.add_argument("--agent", required=True, choices=adapter_profile_ids())
    experiment_p0_agentdojo_boundary.add_argument("--mode", required=True, choices=("baseline_agent", "invart_observe_only", "invart_mediated"))
    experiment_p0_agentdojo_boundary.add_argument("--suite", default="workspace")
    experiment_p0_agentdojo_boundary.add_argument("--user-task", default=None)
    experiment_p0_agentdojo_boundary.add_argument("--model-env", required=True)
    experiment_p0_agentdojo_boundary.add_argument("--module-to-load", default=None)
    experiment_p0_agentdojo_boundary.add_argument("--python", dest="python_executable", default="python")
    experiment_p0_agentdojo_boundary.add_argument("--attack", default="tool_knowledge")
    experiment_p0_agentdojo_boundary.add_argument("--defense", default=None)
    experiment_p0_execute = experiment_p0_real_agent_sub.add_parser("execute-command", help="Execute one P0 row command under supervision and write artifact rows.")
    experiment_p0_execute.add_argument("--manifest", required=True)
    experiment_p0_execute.add_argument("--out-dir", required=True)
    experiment_p0_execute.add_argument("--case-id", required=True)
    experiment_p0_execute.add_argument("--agent", required=True, choices=adapter_profile_ids())
    experiment_p0_execute.add_argument("--mode", required=True, choices=("baseline_agent", "invart_observe_only", "invart_mediated"))
    experiment_p0_execute.add_argument("--cwd", required=True)
    experiment_p0_execute.add_argument("--timeout", type=float, default=120.0)
    experiment_p0_execute.add_argument("--command", nargs=argparse.REMAINDER, required=True)
    experiment_p0_execute_official = experiment_p0_real_agent_sub.add_parser("execute-official", help="Execute one P0 official-runner row and attach its grader artifact.")
    experiment_p0_execute_official.add_argument("--manifest", required=True)
    experiment_p0_execute_official.add_argument("--out-dir", required=True)
    experiment_p0_execute_official.add_argument("--family", required=True, choices=("agentdojo", "agentsecbench", "skill_inject", "swe_bench_verified"))
    experiment_p0_execute_official.add_argument("--case-id", required=True)
    experiment_p0_execute_official.add_argument("--agent", required=True, choices=adapter_profile_ids())
    experiment_p0_execute_official.add_argument("--mode", required=True, choices=("baseline_agent", "invart_observe_only", "invart_mediated"))
    experiment_p0_execute_official.add_argument("--cwd", required=True)
    experiment_p0_execute_official.add_argument("--grader-artifact", required=True)
    experiment_p0_execute_official.add_argument("--timeout", type=float, default=2400.0)
    experiment_p0_execute_official.add_argument("--python", dest="python_executable", default="python")
    experiment_p0_execute_official.add_argument("--predictions-path", default=None)
    experiment_p0_execute_official.add_argument("--run-id", default=None)
    experiment_p0_execute_official.add_argument("--report-dir", default=None)
    experiment_p0_execute_official.add_argument("--instance-id", action="append", default=[])
    experiment_p0_execute_official.add_argument("--model", default=None)
    experiment_p0_execute_official.add_argument("--model-id", default=None)
    experiment_p0_execute_official.add_argument("--suite", default="workspace")
    experiment_p0_execute_official.add_argument("--module-to-load", default=None)
    experiment_p0_execute_official.add_argument("--user-task", action="append", default=[])
    experiment_p0_execute_official.add_argument("--injection-task", action="append", default=[])
    experiment_p0_execute_official.add_argument("--attack", default="tool_knowledge")
    experiment_p0_execute_official.add_argument("--defense", default=None)
    experiment_p0_execute_official.add_argument("--logdir", default=None)
    experiment_p0_execute_official.add_argument("--tools", default="semgrep")
    experiment_p0_execute_official.add_argument("--apps", default="benchmark/apps")
    experiment_p0_execute_official.add_argument("--runner", default="scripts/smoke_test_all.py")
    experiment_p0_execute_official.add_argument("--output-dir", default=None)
    experiment_p0_execute_official.add_argument("--extra-arg", action="append", default=[])
    experiment_p0_execute_official.add_argument("--bridge-report", default=None, help="Optional provider bridge report produced before the official runner.")
    experiment_p0_execute_official.add_argument("--command", nargs=argparse.REMAINDER, default=[])
    experiment_p0_swe_prediction = experiment_p0_real_agent_sub.add_parser("swe-prediction", help="Run an agent command and convert its patch output to SWE-Bench predictions JSONL.")
    experiment_p0_swe_prediction.add_argument("--cwd", required=True)
    experiment_p0_swe_prediction.add_argument("--instance-id", required=True)
    experiment_p0_swe_prediction.add_argument("--patch-path", required=True)
    experiment_p0_swe_prediction.add_argument("--predictions-path", required=True)
    experiment_p0_swe_prediction.add_argument("--agent", required=True, choices=adapter_profile_ids())
    experiment_p0_swe_prediction.add_argument("--mode", required=True, choices=("baseline_agent", "invart_observe_only", "invart_mediated"))
    experiment_p0_swe_prediction.add_argument("--model-name", default=None)
    experiment_p0_swe_prediction.add_argument("--out-dir", default=None)
    experiment_p0_swe_prediction.add_argument("--timeout", type=float, default=300.0)
    experiment_p0_swe_prediction.add_argument("--command", nargs=argparse.REMAINDER, required=True)
    experiment_p0_attach_grader = experiment_p0_real_agent_sub.add_parser("attach-grader", help="Attach an official benchmark grader artifact to a P0 run directory.")
    experiment_p0_attach_grader.add_argument("--run-dir", required=True)
    experiment_p0_attach_grader.add_argument("--family", required=True, choices=("agentdojo", "agentsecbench", "skill_inject", "swe_bench_verified"))
    experiment_p0_attach_grader.add_argument("--artifact", required=True)
    experiment_p0_attach_grader.add_argument("--status", default="attached", choices=("attached", "pass", "pending"))
    experiment_p0_official_command = experiment_p0_real_agent_sub.add_parser("official-command", help="Print an official benchmark runner command spec for a P0 family.")
    experiment_p0_official_command.add_argument("--family", required=True, choices=("agentdojo", "agentsecbench", "skill_inject", "swe_bench_verified"))
    experiment_p0_official_command.add_argument("--python", dest="python_executable", default="python")
    experiment_p0_official_command.add_argument("--predictions-path", default=None)
    experiment_p0_official_command.add_argument("--run-id", default=None)
    experiment_p0_official_command.add_argument("--report-dir", default=None)
    experiment_p0_official_command.add_argument("--instance-id", action="append", default=[])
    experiment_p0_official_command.add_argument("--model", default=None)
    experiment_p0_official_command.add_argument("--model-id", default=None)
    experiment_p0_official_command.add_argument("--suite", default="workspace")
    experiment_p0_official_command.add_argument("--module-to-load", default=None)
    experiment_p0_official_command.add_argument("--user-task", action="append", default=[])
    experiment_p0_official_command.add_argument("--injection-task", action="append", default=[])
    experiment_p0_official_command.add_argument("--attack", default="tool_knowledge")
    experiment_p0_official_command.add_argument("--defense", default=None)
    experiment_p0_official_command.add_argument("--logdir", default=None)
    experiment_p0_official_command.add_argument("--bridge-agent", default=None)
    experiment_p0_official_command.add_argument("--tools", default="semgrep")
    experiment_p0_official_command.add_argument("--apps", default="benchmark/apps")
    experiment_p0_official_command.add_argument("--runner", default="scripts/smoke_test_all.py")
    experiment_p0_official_command.add_argument("--output-dir", default=None)
    experiment_p0_official_command.add_argument("--extra-arg", action="append", default=[])
    experiment_p0_validate_grader = experiment_p0_real_agent_sub.add_parser("validate-grader", help="Validate a P0 official grader artifact without attaching it.")
    experiment_p0_validate_grader.add_argument("--family", required=True, choices=("agentdojo", "agentsecbench", "skill_inject", "swe_bench_verified"))
    experiment_p0_validate_grader.add_argument("--artifact", required=True)
    experiment_p0_summarize = experiment_p0_real_agent_sub.add_parser("summarize", help="Summarize a P0 artifact package.")
    experiment_p0_summarize.add_argument("--run-dir", required=True)
    experiment_p0_rebuild_tables = experiment_p0_real_agent_sub.add_parser("rebuild-tables", help="Regenerate P0 paper tables and claim matrix from package artifacts.")
    experiment_p0_rebuild_tables.add_argument("--run-dir", required=True)
    experiment_p0_remaining = experiment_p0_real_agent_sub.add_parser("remaining", help="Refresh and summarize missing P0 rows plus guarded continuation commands.")
    experiment_p0_remaining.add_argument("--run-dir", required=True)
    experiment_p0_target_continuation = experiment_p0_real_agent_sub.add_parser("target-continuation", help="Refresh full P0 target-scope continuation manifest, plan, and guarded commands.")
    experiment_p0_target_continuation.add_argument("--run-dir", required=True)
    experiment_p0_completion_audit = experiment_p0_real_agent_sub.add_parser("completion-audit", help="Refresh the P0 requirement-by-requirement completion audit.")
    experiment_p0_completion_audit.add_argument("--run-dir", required=True)
    experiment_p0_review_artifact = experiment_p0_real_agent_sub.add_parser("export-review-artifact", help="Export a sanitized reviewer-facing P0 evidence bundle.")
    experiment_p0_review_artifact.add_argument("--run-dir", required=True)
    experiment_p0_review_artifact.add_argument("--out-dir", required=True)
    experiment_p0_collect_runs = experiment_p0_real_agent_sub.add_parser("collect-runs", help="Aggregate child row packages under runs/ back into a P0 root package.")
    experiment_p0_collect_runs.add_argument("--run-dir", required=True)
    experiment_p0_collect_runs.add_argument("--child-runs-dir", default=None)
    experiment_p0_merge_packages = experiment_p0_real_agent_sub.add_parser("merge-packages", help="Merge independent P0 artifact packages into one paper-facing package.")
    experiment_p0_merge_packages.add_argument("--out-dir", required=True)
    experiment_p0_merge_packages.add_argument("--package-dir", action="append", required=True)
    experiment_p0_merge_packages.add_argument("--manifest", default=None)
    experiment_p0_reproduce = experiment_p0_real_agent_sub.add_parser("reproduce", help="Regenerate and run the P0 reproducibility script.")
    experiment_p0_reproduce.add_argument("--run-dir", required=True)
    experiment_p0_doctor = experiment_p0_real_agent_sub.add_parser("doctor", help="Check whether a P0 package is ready to attempt real first-batch execution.")
    experiment_p0_doctor.add_argument("--run-dir", required=True)
    experiment_p0_doctor.add_argument("--python", dest="python_executable", default=None)
    experiment_p1_oracle = experiment_sub.add_parser("p1-external-oracle", help="Plan and run P1 externally-oracled real-agent evaluation rows.")
    experiment_p1_oracle_sub = experiment_p1_oracle.add_subparsers(dest="p1_command", required=True)
    experiment_p1_plan = experiment_p1_oracle_sub.add_parser("plan", help="Write the P1 externally-oracled case manifest.")
    experiment_p1_plan.add_argument("--out-dir", required=True)
    experiment_p1_plan.add_argument("--agent", action="append", choices=adapter_profile_ids(), default=[])
    experiment_p1_run = experiment_p1_oracle_sub.add_parser("run", help="Materialize the P1 held-out run matrix from a manifest.")
    experiment_p1_run.add_argument("--manifest", required=True)
    experiment_p1_run.add_argument("--out-dir", required=True)
    experiment_p1_run.add_argument("--mode", action="append", choices=("baseline_agent", "invart_observe_only", "invart_mediated"), default=[])
    experiment_p1_run.add_argument("--agent", action="append", choices=adapter_profile_ids(), default=[])
    experiment_p1_bootstrap_queue = experiment_p1_oracle_sub.add_parser(
        "bootstrap-queue",
        help="Turn a frozen P1 manifest into a first-run source package, queue, and preflight without executing providers.",
    )
    experiment_p1_bootstrap_queue.add_argument("--manifest", required=True)
    experiment_p1_bootstrap_queue.add_argument("--out-dir", required=True)
    experiment_p1_bootstrap_queue.add_argument("--agent", action="append", choices=adapter_profile_ids(), default=[])
    experiment_p1_bootstrap_queue.add_argument(
        "--family",
        action="append",
        choices=("agentdojo", "agentsecbench", "skill_inject", "swe_bench_verified", "bypass_controls"),
        default=[],
    )
    experiment_p1_bootstrap_queue.add_argument("--risk-group-limit-per-agent", type=int, default=1)
    experiment_p1_bootstrap_queue.add_argument("--utility-group-limit-per-agent", type=int, default=1)
    experiment_p1_bootstrap_queue.add_argument("--family-group-limit-per-family", type=int, default=1)
    experiment_p1_bootstrap_queue.add_argument("--python", dest="python_executable", default=None)
    experiment_p1_execute = experiment_p1_oracle_sub.add_parser("execute-command", help="Execute one P1 row command with an independent side-effect oracle.")
    experiment_p1_execute.add_argument("--manifest", required=True)
    experiment_p1_execute.add_argument("--out-dir", required=True)
    experiment_p1_execute.add_argument("--case-id", required=True)
    experiment_p1_execute.add_argument("--agent", required=True, choices=adapter_profile_ids())
    experiment_p1_execute.add_argument("--mode", required=True, choices=("baseline_agent", "invart_observe_only", "invart_mediated"))
    experiment_p1_execute.add_argument("--cwd", required=True)
    experiment_p1_execute.add_argument("--timeout", type=float, default=120.0)
    experiment_p1_execute.add_argument(
        "--allow-provider-run",
        action="store_true",
        help="Explicitly allow this row command to execute.",
    )
    experiment_p1_execute.add_argument("--command", nargs=argparse.REMAINDER, required=True)
    experiment_p1_attach_grader = experiment_p1_oracle_sub.add_parser("attach-grader", help="Attach an official grader artifact as a P1 utility oracle.")
    experiment_p1_attach_grader.add_argument("--run-dir", required=True)
    experiment_p1_attach_grader.add_argument("--family", required=True, choices=("agentdojo", "agentsecbench", "skill_inject", "swe_bench_verified"))
    experiment_p1_attach_grader.add_argument("--artifact", required=True)
    experiment_p1_attach_grader.add_argument("--status", default="attached", choices=("attached", "pass", "pending"))
    experiment_p1_merge = experiment_p1_oracle_sub.add_parser("merge-packages", help="Merge independent P1 row packages into one comparison package.")
    experiment_p1_merge.add_argument("--out-dir", required=True)
    experiment_p1_merge.add_argument("--package-dir", action="append", required=True)
    experiment_p1_merge.add_argument("--manifest", default=None)
    experiment_p1_summarize = experiment_p1_oracle_sub.add_parser("summarize", help="Summarize a P1 externally-oracled artifact package.")
    experiment_p1_summarize.add_argument("--run-dir", required=True)
    experiment_p1_remaining = experiment_p1_oracle_sub.add_parser(
        "remaining",
        help="Refresh guarded commands for missing P1 rows from the completion audit.",
    )
    experiment_p1_remaining.add_argument("--run-dir", required=True)
    experiment_p1_select = experiment_p1_oracle_sub.add_parser(
        "select-remaining",
        help="Select a narrow, group-preserving subset of P1 missing rows for the next continuation run.",
    )
    experiment_p1_select.add_argument("--run-dir", required=True)
    experiment_p1_select.add_argument("--out-dir", required=True)
    experiment_p1_select.add_argument("--family", action="append", choices=("agentdojo", "agentsecbench", "skill_inject", "swe_bench_verified", "bypass_controls"), default=[])
    experiment_p1_select.add_argument("--agent", action="append", choices=adapter_profile_ids(), default=[])
    experiment_p1_select.add_argument("--mode", action="append", choices=("baseline_agent", "invart_observe_only", "invart_mediated"), default=[])
    experiment_p1_select.add_argument("--case-id", action="append", default=[])
    experiment_p1_select.add_argument("--limit", type=int, default=None)
    experiment_p1_select.add_argument("--group-limit", type=int, default=None)
    experiment_p1_select.add_argument("--strategy", choices=("balanced", "risk_first", "utility_first"), default="balanced")
    experiment_p1_risk_pack = experiment_p1_oracle_sub.add_parser(
        "risk-pack",
        help="Build a P1-small selected continuation pack for held-out risky mode groups per agent.",
    )
    experiment_p1_risk_pack.add_argument("--run-dir", required=True)
    experiment_p1_risk_pack.add_argument("--out-dir", required=True)
    experiment_p1_risk_pack.add_argument("--agent", action="append", choices=adapter_profile_ids(), default=[])
    experiment_p1_risk_pack.add_argument("--family", action="append", choices=("agentdojo", "agentsecbench", "skill_inject"), default=[])
    experiment_p1_risk_pack.add_argument("--group-limit-per-agent", type=int, default=1)
    experiment_p1_risk_readiness = experiment_p1_oracle_sub.add_parser(
        "risk-readiness",
        help="Refresh non-spending readiness checks before executing a selected P1 risk package.",
    )
    experiment_p1_risk_readiness.add_argument("--run-dir", required=True)
    experiment_p1_risk_readiness.add_argument("--env-file", default=None)
    experiment_p1_risk_readiness.add_argument("--python", dest="python_executable", default=None)
    experiment_p1_family_pack = experiment_p1_oracle_sub.add_parser(
        "family-pack",
        help="Build a P1-broad selected continuation pack across benchmark families without executing rows.",
    )
    experiment_p1_family_pack.add_argument("--run-dir", required=True)
    experiment_p1_family_pack.add_argument("--out-dir", required=True)
    experiment_p1_family_pack.add_argument("--agent", action="append", choices=adapter_profile_ids(), default=[])
    experiment_p1_family_pack.add_argument("--family", action="append", choices=("agentdojo", "agentsecbench", "skill_inject", "swe_bench_verified", "bypass_controls"), default=[])
    experiment_p1_family_pack.add_argument("--group-limit-per-family", type=int, default=1)
    experiment_p1_execute_risk_pack = experiment_p1_oracle_sub.add_parser(
        "execute-risk-pack",
        help="Build, doctor, execute, and gate a P1-small risk-group pack when provider setup is ready.",
    )
    experiment_p1_execute_risk_pack.add_argument("--run-dir", required=True)
    experiment_p1_execute_risk_pack.add_argument("--out-dir", required=True)
    experiment_p1_execute_risk_pack.add_argument("--agent", action="append", choices=adapter_profile_ids(), default=[])
    experiment_p1_execute_risk_pack.add_argument("--family", action="append", choices=("agentdojo", "agentsecbench", "skill_inject"), default=[])
    experiment_p1_execute_risk_pack.add_argument("--group-limit-per-agent", type=int, default=1)
    experiment_p1_execute_risk_pack.add_argument("--env-file", default=None)
    experiment_p1_execute_risk_pack.add_argument("--approval-packet", default=None)
    experiment_p1_execute_risk_pack.add_argument("--python", dest="python_executable", default=None)
    experiment_p1_execute_risk_pack.add_argument("--timeout", type=float, default=3600.0)
    experiment_p1_execute_risk_pack.add_argument(
        "--allow-provider-run",
        action="store_true",
        help="Explicitly allow provider/official-runner command execution for this selected risk pack.",
    )
    experiment_p1_utility_pack = experiment_p1_oracle_sub.add_parser(
        "utility-pack",
        help="Build a P1-small selected continuation pack for held-out benign utility groups per agent.",
    )
    experiment_p1_utility_pack.add_argument("--run-dir", required=True)
    experiment_p1_utility_pack.add_argument("--out-dir", required=True)
    experiment_p1_utility_pack.add_argument("--agent", action="append", choices=adapter_profile_ids(), default=[])
    experiment_p1_utility_pack.add_argument("--family", action="append", choices=("swe_bench_verified",), default=[])
    experiment_p1_utility_pack.add_argument("--case-id", action="append", default=[])
    experiment_p1_utility_pack.add_argument("--group-limit-per-agent", type=int, default=1)
    experiment_p1_expand_swe_utility = experiment_p1_oracle_sub.add_parser(
        "expand-swe-utility-manifest",
        help="Import one SWE instance row as a held-out P1 benign utility case without executing agents.",
    )
    experiment_p1_expand_swe_utility.add_argument("--manifest", required=True)
    experiment_p1_expand_swe_utility.add_argument("--instance-json", required=True)
    experiment_p1_expand_swe_utility.add_argument("--out-dir", required=True)
    experiment_p1_expand_swe_utility.add_argument("--case-id", default=None)
    experiment_p1_expand_swe_utility.add_argument("--expected-patch-marker", action="append", default=[])
    experiment_p1_expand_swe_utility.add_argument("--case-role", choices=("held_out", "calibration"), default="held_out")
    experiment_p1_expand_swe_utility.add_argument("--replace", action="store_true")
    experiment_p1_execute_utility_pack = experiment_p1_oracle_sub.add_parser(
        "execute-utility-pack",
        help="Build, doctor, execute, attach utility graders, and gate a P1-small utility group.",
    )
    experiment_p1_execute_utility_pack.add_argument("--run-dir", required=True)
    experiment_p1_execute_utility_pack.add_argument("--out-dir", required=True)
    experiment_p1_execute_utility_pack.add_argument("--agent", action="append", choices=adapter_profile_ids(), default=[])
    experiment_p1_execute_utility_pack.add_argument("--family", action="append", choices=("swe_bench_verified",), default=[])
    experiment_p1_execute_utility_pack.add_argument("--case-id", action="append", default=[])
    experiment_p1_execute_utility_pack.add_argument("--group-limit-per-agent", type=int, default=1)
    experiment_p1_execute_utility_pack.add_argument("--env-file", default=None)
    experiment_p1_execute_utility_pack.add_argument("--approval-packet", default=None)
    experiment_p1_execute_utility_pack.add_argument("--python", dest="python_executable", default=None)
    experiment_p1_execute_utility_pack.add_argument("--timeout", type=float, default=3600.0)
    experiment_p1_execute_utility_pack.add_argument(
        "--allow-provider-run",
        action="store_true",
        help="Explicitly allow provider/official-runner command execution for this selected utility pack.",
    )
    experiment_p1_execute_utility_pack.add_argument(
        "--allow-deferred-row-artifact-grader",
        action="store_true",
        help="Allow SWE-style utility rows to execute before automatically generating and attaching row-artifact graders.",
    )
    experiment_p1_utility_readiness = experiment_p1_oracle_sub.add_parser(
        "utility-readiness",
        help="Refresh non-spending readiness checks before executing a selected P1 utility package.",
    )
    experiment_p1_utility_readiness.add_argument("--run-dir", required=True)
    experiment_p1_utility_readiness.add_argument("--env-file", default=None)
    experiment_p1_utility_readiness.add_argument("--python", dest="python_executable", default=None)
    experiment_p1_utility_readiness.add_argument(
        "--allow-deferred-row-artifact-grader",
        action="store_true",
        help="Check readiness assuming SWE row-artifact graders will be generated after provider execution.",
    )
    experiment_p1_utility_row_grader = experiment_p1_oracle_sub.add_parser(
        "utility-row-grader",
        help="Generate a row-artifact repository-replication grader for a selected SWE utility slice.",
    )
    experiment_p1_utility_row_grader.add_argument("--run-dir", required=True)
    experiment_p1_utility_row_grader.add_argument("--out-dir", required=True)
    experiment_p1_utility_row_grader.add_argument("--case-id", required=True)
    experiment_p1_utility_row_grader.add_argument("--instance-id", required=True)
    experiment_p1_utility_row_grader.add_argument("--expected-patch-marker", required=True)
    experiment_p1_utility_row_grader.add_argument("--agent", default=None)
    experiment_p1_row_artifact_check = experiment_p1_oracle_sub.add_parser(
        "row-artifact-check",
        help="Check selected SWE row artifacts after execution and before deferred utility grading.",
    )
    experiment_p1_row_artifact_check.add_argument("--run-dir", required=True)
    experiment_p1_swe_official_predictions = experiment_p1_oracle_sub.add_parser(
        "swe-official-predictions",
        help="Export selected SWE row artifacts as official-compatible SWE-Bench prediction files and preflight the runner.",
    )
    experiment_p1_swe_official_predictions.add_argument("--run-dir", required=True)
    experiment_p1_swe_official_predictions.add_argument("--out-dir", required=True)
    experiment_p1_swe_official_predictions.add_argument("--python", dest="python_executable", default="python")
    experiment_p1_swe_official_predictions.add_argument("--model-name", default=None)
    experiment_p1_swe_official_predictions.add_argument("--max-workers", type=int, default=1)
    experiment_p1_swe_official_predictions.add_argument("--timeout", type=int, default=1800)
    experiment_p1_swe_official_smoke = experiment_p1_oracle_sub.add_parser(
        "swe-official-smoke",
        help="Select one exported SWE-Bench-compatible prediction row and optionally run its official harness command.",
    )
    experiment_p1_swe_official_smoke.add_argument("--predictions-report", required=True)
    experiment_p1_swe_official_smoke.add_argument("--out-dir", default=None)
    experiment_p1_swe_official_smoke.add_argument("--row-id", default=None)
    experiment_p1_swe_official_smoke.add_argument("--case-id", default=None)
    experiment_p1_swe_official_smoke.add_argument("--mode", default=None)
    experiment_p1_swe_official_smoke.add_argument("--execute", action="store_true")
    experiment_p1_swe_official_smoke.add_argument("--collect-existing", action="store_true")
    experiment_p1_swe_official_smoke.add_argument("--timeout", type=float, default=3600.0)
    experiment_p1_swe_official_summary = experiment_p1_oracle_sub.add_parser(
        "swe-official-summary",
        help="Summarize one or more row-scoped SWE-Bench official smoke reports for P1 attachment.",
    )
    experiment_p1_swe_official_summary.add_argument("--smoke-report", action="append", required=True)
    experiment_p1_swe_official_summary.add_argument("--out-dir", required=True)
    experiment_p1_swe_official_summary.add_argument("--case-id", default=None)
    experiment_p1_swe_official_summary.add_argument("--agent", default=None)
    experiment_p1_selected_doctor = experiment_p1_oracle_sub.add_parser(
        "selected-doctor",
        help="Check a selected P1 continuation package before running provider CLIs.",
    )
    experiment_p1_selected_doctor.add_argument("--run-dir", required=True)
    experiment_p1_selected_doctor.add_argument("--python", dest="python_executable", default=None)
    experiment_p1_selected_doctor.add_argument("--env-file", default=None)
    experiment_p1_selected_doctor.add_argument(
        "--allow-deferred-row-artifact-grader",
        action="store_true",
        help="Allow SWE-style utility rows to execute before attaching a row-artifact repository-replication grader.",
    )
    experiment_p1_workspace_preflight = experiment_p1_oracle_sub.add_parser(
        "workspace-preflight",
        help="Prepare selected SWE utility workspaces before provider spend without running agents.",
    )
    experiment_p1_workspace_preflight.add_argument("--run-dir", required=True)
    experiment_p1_workspace_preflight.add_argument("--env-file", default=None)
    experiment_p1_workspace_preflight.add_argument("--repo-cache", default=None)
    experiment_p1_workspace_preflight.add_argument("--force", action="store_true")
    experiment_p1_selected_inputs = experiment_p1_oracle_sub.add_parser(
        "selected-inputs",
        help="Render external command and grader input specifications for a selected P1 continuation package.",
    )
    experiment_p1_selected_inputs.add_argument("--run-dir", required=True)
    experiment_p1_candidate_env = experiment_p1_oracle_sub.add_parser(
        "candidate-env",
        help="Materialize reviewable provider CLI candidate commands into a selected P1 env file.",
    )
    experiment_p1_candidate_env.add_argument("--run-dir", required=True)
    experiment_p1_candidate_env.add_argument("--out-file", default=None)
    experiment_p1_execute_selected = experiment_p1_oracle_sub.add_parser(
        "execute-selected",
        help="Execute a selected P1 continuation package after selected-doctor readiness passes.",
    )
    experiment_p1_execute_selected.add_argument("--run-dir", required=True)
    experiment_p1_execute_selected.add_argument("--env-file", required=True)
    experiment_p1_execute_selected.add_argument("--python", dest="python_executable", default=None)
    experiment_p1_execute_selected.add_argument("--timeout", type=float, default=3600.0)
    experiment_p1_execute_selected.add_argument(
        "--allow-provider-run",
        action="store_true",
        help="Explicitly allow selected row command execution for this package.",
    )
    experiment_p1_execute_selected.add_argument(
        "--allow-deferred-row-artifact-grader",
        action="store_true",
        help="Allow SWE-style utility rows to execute before attaching a row-artifact repository-replication grader.",
    )
    experiment_p1_selected_gate = experiment_p1_oracle_sub.add_parser(
        "selected-gate",
        help="Gate a selected P1 execution run for paper-claimable external-oracle evidence.",
    )
    experiment_p1_selected_gate.add_argument("--run-dir", required=True)
    experiment_p1_completion_audit = experiment_p1_oracle_sub.add_parser(
        "completion-audit",
        help="Refresh the P1 requirement-by-requirement completion audit.",
    )
    experiment_p1_completion_audit.add_argument("--run-dir", required=True)
    experiment_p1_result_analysis = experiment_p1_oracle_sub.add_parser(
        "result-analysis",
        help="Refresh P1 paper-facing findings from row evidence, selected gates, and execution artifacts.",
    )
    experiment_p1_result_analysis.add_argument("--run-dir", required=True)
    experiment_p1_result_analysis.add_argument(
        "--artifact",
        action="append",
        default=[],
        help="Optional P1 execution/gate/planning artifact file or directory to include in the paper-facing analysis.",
    )
    experiment_p1_paper_brief = experiment_p1_oracle_sub.add_parser(
        "paper-brief",
        help="Generate paper-integration snippets from P1 result analysis without editing the draft.",
    )
    experiment_p1_paper_brief.add_argument("--run-dir", required=True)
    experiment_p1_paper_brief.add_argument(
        "--artifact",
        action="append",
        default=[],
        help="Optional P1 execution/gate/planning artifact file or directory to include before rendering the brief.",
    )
    experiment_p1_paper_sync = experiment_p1_oracle_sub.add_parser(
        "paper-sync",
        help="Generate a non-mutating preview for syncing P1 findings into claims/evaluation documents.",
    )
    experiment_p1_paper_sync.add_argument("--run-dir", required=True)
    experiment_p1_paper_sync.add_argument(
        "--artifact",
        action="append",
        default=[],
        help="Optional P1 execution/gate/planning artifact file or directory to include before rendering the sync preview.",
    )
    experiment_p1_paper_sync.add_argument("--claims-doc", default=None)
    experiment_p1_paper_sync.add_argument("--draft-tex", default=None)
    experiment_p1_claim_audit = experiment_p1_oracle_sub.add_parser(
        "claim-audit",
        help="Audit P1 paper-sync candidates for external-oracle backing before draft edits.",
    )
    experiment_p1_claim_audit.add_argument("--run-dir", required=True)
    experiment_p1_claim_audit.add_argument(
        "--artifact",
        action="append",
        default=[],
        help="Optional P1 execution/gate/planning artifact file or directory to include before auditing claims.",
    )
    experiment_p1_claim_audit.add_argument("--claims-doc", default=None)
    experiment_p1_claim_audit.add_argument("--draft-tex", default=None)
    experiment_p1_active_status = experiment_p1_oracle_sub.add_parser(
        "active-status",
        help="Summarize supplied P1 readiness, execution, gate, audit, or launch artifacts into one active-lane dashboard.",
    )
    experiment_p1_active_status.add_argument("--out-dir", required=True)
    experiment_p1_active_status.add_argument("--artifact", action="append", required=True)
    experiment_p1_iteration_record = experiment_p1_oracle_sub.add_parser(
        "iteration-record",
        help="Write a non-executing P1 iteration ledger record from active-status or related artifacts.",
    )
    experiment_p1_iteration_record.add_argument("--out-dir", required=True)
    experiment_p1_iteration_record.add_argument("--artifact", action="append", required=True)
    experiment_p1_iteration_record.add_argument("--iteration", default=None)
    experiment_p1_iteration_record.add_argument("--reviewer-risk", default=None)
    experiment_p1_iteration_record.add_argument("--notes", default=None)
    experiment_p1_iteration_handoff = experiment_p1_oracle_sub.add_parser(
        "iteration-handoff",
        help="Prioritize one or more P1 iteration records into the next-loop handoff queue.",
    )
    experiment_p1_iteration_handoff.add_argument("--out-dir", required=True)
    experiment_p1_iteration_handoff.add_argument("--artifact", action="append", required=True)
    experiment_p1_iteration_experiment_report = experiment_p1_oracle_sub.add_parser(
        "iteration-experiment-report",
        help="Synthesize a no-spend V1-V5 P1 iteration experiment report from claim-audited artifacts.",
    )
    experiment_p1_iteration_experiment_report.add_argument("--out-dir", required=True)
    experiment_p1_iteration_experiment_report.add_argument("--artifact", action="append", required=True)
    experiment_p1_iteration_experiment_report.add_argument("--iteration-focus", default=None)
    experiment_p1_iteration_experiment_report.add_argument("--final-version", default="V5")
    experiment_p1_iteration_plan_report = experiment_p1_oracle_sub.add_parser(
        "iteration-plan-report",
        help="Synthesize a no-spend E1-E5 Version A iteration plan report from claim-audited artifacts.",
    )
    experiment_p1_iteration_plan_report.add_argument("--out-dir", required=True)
    experiment_p1_iteration_plan_report.add_argument("--artifact", action="append", required=True)
    experiment_p1_iteration_plan_report.add_argument("--plan-focus", default=None)
    experiment_p1_approval_packet = experiment_p1_oracle_sub.add_parser(
        "approval-packet",
        help="Create a reviewable provider/official-runner approval packet from P1 active lane artifacts without executing commands.",
    )
    experiment_p1_approval_packet.add_argument("--out-dir", required=True)
    experiment_p1_approval_packet.add_argument("--artifact", action="append", required=True)
    experiment_p1_approval_packet.add_argument("--lane-id", default=None)
    experiment_p1_approval_packet.add_argument("--lane-kind", choices=("risk", "utility", "launch_report"), default=None)
    experiment_p1_run_queue = experiment_p1_oracle_sub.add_parser(
        "run-queue",
        help="Build a non-executing P1 real-run launch queue across risk, utility, and family-broadening lanes.",
    )
    experiment_p1_run_queue.add_argument("--run-dir", required=True)
    experiment_p1_run_queue.add_argument("--out-dir", required=True)
    experiment_p1_run_queue.add_argument("--agent", action="append", choices=adapter_profile_ids(), default=[])
    experiment_p1_run_queue.add_argument(
        "--family",
        action="append",
        choices=("agentdojo", "agentsecbench", "skill_inject", "swe_bench_verified", "bypass_controls"),
        default=[],
    )
    experiment_p1_run_queue.add_argument("--risk-group-limit-per-agent", type=int, default=1)
    experiment_p1_run_queue.add_argument("--utility-group-limit-per-agent", type=int, default=1)
    experiment_p1_run_queue.add_argument("--family-group-limit-per-family", type=int, default=1)
    experiment_p1_run_queue.add_argument("--python", dest="python_executable", default=None)
    experiment_p1_launch_preflight = experiment_p1_oracle_sub.add_parser(
        "launch-preflight",
        help="Check whether a P1 real-run queue is ready to launch without executing provider CLIs or row commands.",
    )
    experiment_p1_launch_preflight.add_argument("--run-dir", required=True)
    experiment_p1_launch_preflight.add_argument("--queue-env", default=None)
    experiment_p1_launch_preflight.add_argument("--python", dest="python_executable", default=None)
    experiment_p1_prepare_launch_env = experiment_p1_oracle_sub.add_parser(
        "prepare-launch-env",
        help="Copy candidate lane envs, write a private queue env, and run launch preflight without executing providers.",
    )
    experiment_p1_prepare_launch_env.add_argument("--run-dir", required=True)
    experiment_p1_prepare_launch_env.add_argument("--enable-lane", action="append", default=[])
    experiment_p1_prepare_launch_env.add_argument("--queue-env", default=None)
    experiment_p1_prepare_launch_env.add_argument("--overwrite", action="store_true")
    experiment_p1_prepare_launch_env.add_argument("--python", dest="python_executable", default=None)
    experiment_p1_launch_report = experiment_p1_oracle_sub.add_parser(
        "launch-report",
        help="Summarize post-launch P1 queue outcomes without promoting setup or skip records into paper evidence.",
    )
    experiment_p1_launch_report.add_argument("--run-dir", required=True)
    experiment_p1_timeout_triage = experiment_p1_oracle_sub.add_parser(
        "timeout-triage",
        help="Summarize P1 timeout rows and next remediation steps without promoting them into paper evidence.",
    )
    experiment_p1_timeout_triage.add_argument("--run-dir", required=True)

    evidence = subparsers.add_parser("evidence", help="Export and verify enterprise evidence bundles.")
    evidence.set_defaults(handler=handle_evidence)
    evidence_sub = evidence.add_subparsers(dest="evidence_command", required=True)
    evidence_export = evidence_sub.add_parser("export", help="Export a v0.27 evidence bundle from a ledger.")
    evidence_export.add_argument("--ledger", required=True)
    evidence_export.add_argument("--out-dir", required=True)
    evidence_export.add_argument("--profile", default=None)
    evidence_verify = evidence_sub.add_parser("verify", help="Verify an evidence bundle manifest.")
    evidence_verify.add_argument("--bundle", required=True)
    evidence_inspect = evidence_sub.add_parser("inspect", help="Inspect a bundle as an L5 evidence workspace.")
    evidence_inspect.add_argument("--manifest", "--bundle", dest="manifest", required=True)
    evidence_inspect.add_argument("--out-dir", default=None)
    evidence_inspect.add_argument("--require-questions", dest="require_questions", action="store_true", default=True)
    evidence_inspect.add_argument("--no-require-questions", dest="require_questions", action="store_false")
    evidence_inspect.add_argument("--require-layer-workflow", action="store_true")
    evidence_inspect.add_argument("--require-adapter-package", action="store_true")

    external_evidence = subparsers.add_parser("external-evidence", help="Import, attach, and verify external benchmark evidence manifests.")
    external_evidence.set_defaults(handler=handle_external_evidence)
    external_evidence_sub = external_evidence.add_subparsers(dest="external_evidence_command", required=True)
    external_import = external_evidence_sub.add_parser("import", help="Import a pinned external corpus snapshot.")
    external_import.add_argument("--snapshot", required=True)
    external_import.add_argument("--out-dir", required=True)
    external_attach = external_evidence_sub.add_parser("attach", help="Attach full SWE-Bench evidence artifacts.")
    external_attach.add_argument("--report", required=True)
    external_attach.add_argument("--instance-results", required=True)
    external_attach.add_argument("--predictions", required=True)
    external_attach.add_argument("--logs", required=True)
    external_attach.add_argument("--out-dir", required=True)
    external_attach.add_argument("--run-id", default="invart_full")
    external_attach.add_argument("--expected-total-instances", type=int, default=2294)
    external_attach.add_argument("--invart-mode", "--kappaski-mode", dest="invart_mode", choices=("raw", "plugin-only", "audit", "managed", "enforced"), default="managed")
    external_verify = external_evidence_sub.add_parser("verify", help="Verify an external evidence manifest.")
    external_verify.add_argument("--manifest", required=True)
    external_progressive = external_evidence_sub.add_parser("progressive", help="Run progressive sample validation across external evidence categories.")
    external_progressive.add_argument("--out-dir", required=True)
    external_progressive.add_argument("--stage", choices=("smoke", "sample", "scale"), default="smoke")
    external_progressive.add_argument("--category", action="append", choices=("public-risk-catalog", "external-corpus-snapshot", "swe-bench"), default=[])
    external_progressive.add_argument("--max-cases", type=int, default=None)
    external_progressive.add_argument("--public-risk-catalog", default=None)
    external_progressive.add_argument("--snapshot", default=None)
    external_progressive.add_argument("--swe-report", default=None)
    external_progressive.add_argument("--swe-instance-results", default=None)
    external_progressive.add_argument("--swe-predictions", default=None)
    external_progressive.add_argument("--swe-logs", default=None)
    external_progressive.add_argument("--swe-run-id", default="invart_progressive_sample")

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
    demo_real_world = demo_sub.add_parser("real-world-risk-cases", help="Generate public-source risk mapping plus before/during/after Invart demo artifacts.")
    demo_real_world.add_argument("--out-dir", required=True)
    demo_container_case = demo_sub.add_parser("container-risk-case", help="Generate one container-isolated risk demo case artifact bundle.")
    demo_container_case.add_argument("--case", required=True, choices=("unfriendly-skill", "secret-egress", "unsafe-delete"))
    demo_container_case.add_argument("--out-dir", required=True)
    demo_container_suite = demo_sub.add_parser("container-risk-suite", help="Generate or collect the containerized risk demo suite.")
    demo_container_suite.add_argument("--out-dir", required=True)
    demo_container_suite.add_argument("--collect-existing", action="store_true", help="Collect existing per-case container outputs instead of running cases locally.")
    demo_final = demo_sub.add_parser("pre-1.0-final", help="Generate the pre-1.0 final demo entrypoint and linked artifacts.")
    demo_final.add_argument("--out-dir", required=True)
    demo_final.add_argument("--external-evidence", default=None)
    demo_signoff = demo_sub.add_parser("signoff", help="Record ledger-backed enterprise audit signoff.")
    demo_signoff.add_argument("--ledger", required=True)
    demo_signoff.add_argument("--actor", required=True)
    demo_signoff.add_argument("--status", choices=("approved", "rejected", "needs_followup"), required=True)
    demo_signoff.add_argument("--reason", required=True)
    demo_signoff.add_argument("--report", default=None)

    for rc_name in ("release-candidate", "rc"):
        rc_parser = subparsers.add_parser(rc_name, help="Run the pre-1.0 release-candidate readiness gate.")
        rc_parser.set_defaults(handler=handle_release_candidate)
        rc_sub = rc_parser.add_subparsers(dest="rc_command", required=True)
        rc_verify = rc_sub.add_parser("verify", help="Verify pytest, roadmap, benchmarks, docs, and artifacts.")
        rc_verify.add_argument("--out-dir", required=True)
        rc_verify.add_argument("--skip-pytest", action="store_true")
        rc_verify.add_argument("--final", action="store_true")
        rc_verify.add_argument("--require-external-validation", action="store_true")
        rc_verify.add_argument("--external-evidence", default=None)
        rc_verify.add_argument("--evidence-workspace-manifest", default=None)
        rc_verify.add_argument("--require-evidence-layer-workflow", action="store_true")
        rc_verify.add_argument("--require-evidence-adapter-package", action="store_true")
        rc_verify.add_argument("--paper", action="store_true", help="Run the separate v0.51 research-readiness gate after product RC checks.")
        rc_verify.add_argument("--paper-tables", default=None)
        rc_verify.add_argument("--coverage", default=None)
        rc_verify.add_argument("--reviewer", default=None)
        rc_verify.add_argument("--audit", default=None)
        rc_verify.add_argument("--product-matrix", default=None)
