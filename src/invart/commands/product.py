from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from invart.core.artifacts import write_json_artifact
from invart.evaluation.evals import run_benchmark
from invart.evaluation.benchmark_registry import list_benchmark_suites
from invart.governance.profiles import load_profile_file
from invart.evaluation.roadmap import verify_roadmap_coverage
from invart.assurance.audit_demo import record_audit_signoff, run_enterprise_audit_demo, run_enterprise_audit_live_adapter_demo
from invart.evaluation.pre_v1 import run_pre_v1_control_plane_demo
from invart.assurance.evidence_bundle import export_evidence_bundle, verify_evidence_bundle
from invart.assurance.evidence_workspace import inspect_evidence_workspace
from invart.evaluation.release_candidate import verify_release_candidate
from invart.evaluation.experiment_cases import export_experiment_report, list_experiment_suites, run_experiment_suite, run_paper_suite
from invart.evaluation.audit_reconstruction import run_audit_reconstruction_study
from invart.evaluation.coverage_experiments import run_coverage_truthfulness_matrix
from invart.evaluation.paper_tables import export_paper_tables_from_file
from invart.evaluation.policy_sensitivity import run_policy_sensitivity_experiment
from invart.evaluation.product_control_matrix import run_product_control_matrix
from invart.evaluation.research_readiness import verify_research_readiness
from invart.evaluation.reviewer_experiments import run_reviewer_selectivity_experiment
from invart.evaluation.task_agent_benchmark import run_task_agent_benchmark
from invart.evaluation.layer_path_completeness import run_layer_path_completeness_experiment
from invart.evaluation.real_agent_benchmark import (
    analyze_agentdojo_full_results,
    audit_agentdojo_full_completeness,
    attach_p0_official_grader,
    attach_p1_official_grader,
    build_agentdojo_command,
    build_agentdojo_full_manifest,
    build_agentsecbench_command,
    build_skill_inject_command,
    build_swe_bench_verified_command,
    collect_p0_child_runs,
    collect_agentdojo_full_census,
    doctor_p0_first_batch_selection,
    doctor_p1_remaining_selection,
    execute_swe_prediction_command,
    execute_p1_external_oracled_command,
    execute_p1_risk_group_pack,
    execute_p1_selected_continuation,
    execute_p1_utility_group_pack,
    execute_p0_real_agent_command,
    execute_p0_official_runner,
    execute_agentdojo_full_jobs,
    expand_p1_manifest_with_swe_utility_case,
    export_p0_review_artifact,
    generate_p0_first_batch_plan,
    generate_p0_completion_audit,
    generate_p0_remaining_artifacts,
    generate_p0_reproduce_script,
    generate_p0_target_continuation,
    generate_p1_active_lane_status,
    generate_p1_provider_approval_packet,
    generate_p1_iteration_experiment_report,
    generate_p1_iteration_plan_report,
    generate_p1_iteration_handoff,
    generate_p1_iteration_record,
    generate_p1_family_broadening_pack,
    generate_p1_bootstrap_real_run_queue,
    generate_p1_claim_validity_audit,
    generate_p1_completion_audit,
    generate_p1_paper_brief,
    generate_p1_paper_sync_preview,
    generate_p1_remaining_artifacts,
    generate_p1_real_run_launch_env,
    generate_p1_real_run_launch_preflight,
    generate_p1_real_run_launch_report,
    generate_p1_real_run_queue,
    generate_p1_result_analysis,
    generate_p1_risk_execution_readiness,
    generate_p1_risk_group_pack,
    generate_p1_selected_candidate_env,
    generate_p1_selected_evidence_gate,
    generate_p1_selected_execution_inputs,
    generate_p1_swe_row_artifact_grader,
    generate_p1_swe_official_smoke_summary,
    generate_p1_timeout_triage,
    generate_p1_utility_execution_readiness,
    generate_p1_utility_group_pack,
    check_p1_selected_swe_row_artifacts,
    export_p1_swe_official_predictions,
    run_p1_swe_official_smoke,
    export_swe_bench_verified_instances_from_manifest,
    materialize_p0_run_matrix,
    materialize_p1_run_matrix,
    merge_p0_artifact_packages,
    merge_p1_artifact_packages,
    prepare_p0_official_environment,
    prepare_agentdojo_full_run,
    preflight_p1_selected_swe_workspaces,
    prepare_swe_instance_workspace_from_json,
    rebuild_p0_paper_artifacts,
    run_p0_doctor,
    run_p1_external_oracled_plan,
    run_p0_real_agent_plan,
    select_p0_first_batch_rows,
    select_p1_remaining_rows,
    summarize_p0_real_agent_package,
    summarize_p1_external_oracled_package,
    validate_official_grader_artifact,
    write_agentdojo_adapter_boundary,
    write_p0_reproduce_report,
)
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
    if args.experiment_command == "full-benchmark":
        if args.full_benchmark_command == "agentdojo-census":
            result = collect_agentdojo_full_census(
                out_dir=Path(args.out_dir),
                python_executable=args.python_executable,
                benchmark_version=args.benchmark_version,
                modules_to_load=args.module_to_load,
            )
            print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
            return 0 if result.get("status") == "pass" else 1
        if args.full_benchmark_command == "agentdojo-manifest":
            try:
                result = build_agentdojo_full_manifest(
                    census_path=Path(args.census),
                    out_dir=Path(args.out_dir),
                    agents=args.agent,
                    suites=args.suite or None,
                    user_tasks=args.user_task or None,
                    injection_tasks=args.injection_task or None,
                    modes=args.mode or None,
                    policy_variants=args.policy_variant or None,
                    trials=args.trials,
                    attack=args.attack,
                    defense=args.defense,
                    policy_hash=args.policy_hash,
                )
            except ValueError as exc:
                print(str(exc), file=sys.stderr)
                return 2
            print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
            return 0 if result.get("status") == "frozen" else 1
        if args.full_benchmark_command == "agentdojo-audit":
            try:
                result = audit_agentdojo_full_completeness(
                    manifest_path=Path(args.manifest),
                    run_records_path=Path(args.run_records),
                    out_dir=Path(args.out_dir),
                )
            except ValueError as exc:
                print(str(exc), file=sys.stderr)
                return 2
            print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
            return 0 if result.get("status") == "complete" else 1
        if args.full_benchmark_command == "agentdojo-readiness":
            try:
                result = prepare_agentdojo_full_run(
                    manifest_path=Path(args.manifest),
                    out_dir=Path(args.out_dir),
                    python_executable=args.python_executable,
                    model=args.model,
                    model_id=args.model_id,
                    module_to_load=args.module_to_load,
                    job_ids=args.job_id or None,
                    modes=args.mode or None,
                    conditions=args.condition or None,
                    max_jobs=args.max_jobs,
                    max_workers=args.max_workers,
                    reviewer_provider=args.reviewer_provider,
                    reviewer_model=args.reviewer_model,
                    reviewer_approval_path=(
                        Path(args.reviewer_approval) if args.reviewer_approval else None
                    ),
                    reviewer_budget_state_path=(
                        Path(args.reviewer_budget_state) if args.reviewer_budget_state else None
                    ),
                    reviewer_retention_posture=args.reviewer_retention_posture,
                    reviewer_timeout=args.reviewer_timeout,
                    reviewer_max_tokens=args.reviewer_max_tokens,
                    max_continuation_replans=args.max_continuation_replans,
                    agent_provider=args.agent_provider,
                    agent_model=args.agent_model,
                    agent_version=args.agent_version,
                    agent_approval_path=(
                        Path(args.agent_approval) if args.agent_approval else None
                    ),
                    agent_budget_state_path=(
                        Path(args.agent_budget_state) if args.agent_budget_state else None
                    ),
                    agent_provider_timeout=args.agent_provider_timeout,
                    agent_max_tokens_per_call=args.agent_max_tokens_per_call,
                )
            except ValueError as exc:
                print(str(exc), file=sys.stderr)
                return 2
            print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
            return 0 if result.get("status") == "ready" else 1
        if args.full_benchmark_command == "agentdojo-run":
            try:
                result = execute_agentdojo_full_jobs(
                    manifest_path=Path(args.manifest),
                    out_dir=Path(args.out_dir),
                    python_executable=args.python_executable,
                    model=args.model,
                    model_id=args.model_id,
                    module_to_load=args.module_to_load,
                    job_ids=args.job_id or None,
                    modes=args.mode or None,
                    conditions=args.condition or None,
                    max_jobs=args.max_jobs,
                    official_timeout=args.official_timeout,
                    provider_timeout=args.provider_timeout,
                    retry_incomplete=args.retry_incomplete,
                    max_workers=args.max_workers,
                    reviewer_provider=args.reviewer_provider,
                    reviewer_model=args.reviewer_model,
                    reviewer_approval_path=(
                        Path(args.reviewer_approval) if args.reviewer_approval else None
                    ),
                    reviewer_budget_state_path=(
                        Path(args.reviewer_budget_state) if args.reviewer_budget_state else None
                    ),
                    reviewer_retention_posture=args.reviewer_retention_posture,
                    reviewer_timeout=args.reviewer_timeout,
                    reviewer_max_tokens=args.reviewer_max_tokens,
                    max_continuation_replans=args.max_continuation_replans,
                    agent_provider=args.agent_provider,
                    agent_model=args.agent_model,
                    agent_version=args.agent_version,
                    agent_approval_path=(
                        Path(args.agent_approval) if args.agent_approval else None
                    ),
                    agent_budget_state_path=(
                        Path(args.agent_budget_state) if args.agent_budget_state else None
                    ),
                    agent_provider_timeout=args.agent_provider_timeout,
                    agent_max_tokens_per_call=args.agent_max_tokens_per_call,
                )
            except (RuntimeError, TimeoutError, ValueError) as exc:
                print(str(exc), file=sys.stderr)
                return 2
            print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
            return 0 if result.get("status") in {"completed", "no_jobs_executed"} else 1
        if args.full_benchmark_command == "agentdojo-analyze":
            try:
                result = analyze_agentdojo_full_results(
                    manifest_path=Path(args.manifest),
                    run_records_path=Path(args.run_records),
                    out_dir=Path(args.out_dir),
                )
            except ValueError as exc:
                print(str(exc), file=sys.stderr)
                return 2
            print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
            return 0 if result.get("status") == "complete" else 1
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
    if args.experiment_command == "policy-sensitivity":
        result = run_policy_sensitivity_experiment(out_dir=Path(args.out_dir))
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0 if result.get("status") == "pass" else 1
    if args.experiment_command == "task-agent":
        try:
            result = run_task_agent_benchmark(
                out_dir=Path(args.out_dir),
                agents=args.agent or None,
                binary_overrides=_parse_binary_overrides(args.binary),
                require_installed=args.require_installed,
            )
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0 if result.get("status") == "pass" else 1
    if args.experiment_command == "layer-path":
        result = run_layer_path_completeness_experiment(out_dir=Path(args.out_dir))
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0 if result.get("status") == "pass" else 1
    if args.experiment_command == "p0-real-agent":
        if args.p0_command == "plan":
            result = run_p0_real_agent_plan(out_dir=Path(args.out_dir), agents=args.agent or None)
            print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
            return 0 if result.get("status") in {"pass", "incomplete"} else 1
        if args.p0_command == "run":
            result = materialize_p0_run_matrix(
                manifest_path=Path(args.manifest),
                out_dir=Path(args.out_dir),
                modes=args.mode or None,
                agents=args.agent or None,
            )
            print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
            return 0 if result.get("status") == "pass" else 1
        if args.p0_command == "setup-official":
            manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
            if not isinstance(manifest, dict):
                print("--manifest must point to a JSON object", file=sys.stderr)
                return 2
            result = prepare_p0_official_environment(
                manifest=manifest,
                out_dir=Path(args.out_dir),
                families=args.family or None,
                python_executable=args.python_executable,
                create_venv=args.create_venv,
                install=args.install,
            )
            print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
            return 0 if result.get("status") in {"ready", "planned"} else 1
        if args.p0_command == "first-batch":
            manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
            if not isinstance(manifest, dict):
                print("--manifest must point to a JSON object", file=sys.stderr)
                return 2
            result = generate_p0_first_batch_plan(
                manifest=manifest,
                out_dir=Path(args.out_dir),
                python_executable=args.python_executable,
            )
            print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
            return 0
        if args.p0_command == "select-first-batch":
            try:
                result = select_p0_first_batch_rows(
                    plan_path=Path(args.plan),
                    out_dir=Path(args.out_dir),
                    families=args.family or None,
                    agents=args.agent or None,
                    modes=args.mode or None,
                    case_ids=args.case_id or None,
                    limit=args.limit,
                )
            except ValueError as exc:
                print(str(exc), file=sys.stderr)
                return 2
            print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
            return 0
        if args.p0_command == "selected-doctor":
            result = doctor_p0_first_batch_selection(
                run_dir=Path(args.run_dir),
                python_executable=args.python_executable,
            )
            print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
            return 0 if result.get("status") == "ready" else 1
        if args.p0_command == "prepare-swe-workspace":
            try:
                result = prepare_swe_instance_workspace_from_json(
                    instance_json=Path(args.instance_json),
                    out_dir=Path(args.out_dir),
                    repo_cache=Path(args.repo_cache) if args.repo_cache else None,
                    force=args.force,
                )
            except ValueError as exc:
                print(str(exc), file=sys.stderr)
                return 2
            print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
            return 0 if result.get("status") == "pass" else 1
        if args.p0_command == "export-swe-instances":
            manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
            if not isinstance(manifest, dict):
                print("--manifest must point to a JSON object", file=sys.stderr)
                return 2
            try:
                result = export_swe_bench_verified_instances_from_manifest(
                    manifest=manifest,
                    out_dir=Path(args.out_dir),
                    dataset=args.dataset,
                    config=args.config,
                    split=args.split,
                    rows_json=Path(args.rows_json) if args.rows_json else None,
                    page_size=args.page_size,
                    max_rows=args.max_rows,
                )
            except ValueError as exc:
                print(str(exc), file=sys.stderr)
                return 2
            print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
            return 0 if result.get("status") == "pass" else 1
        if args.p0_command == "agentdojo-boundary":
            result = write_agentdojo_adapter_boundary(
                out_dir=Path(args.out_dir),
                case_id=args.case_id,
                benchmark_case_ref=args.benchmark_case_ref,
                agent=args.agent,
                mode=args.mode,
                suite=args.suite,
                user_task=args.user_task,
                model_env=args.model_env,
                module_to_load=args.module_to_load,
                python_executable=args.python_executable,
                attack=args.attack,
                defense=args.defense,
            )
            print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
            return 0
        if args.p0_command == "execute-command":
            command = list(args.command or [])
            if command and command[0] == "--":
                command = command[1:]
            if not command:
                print("--command must include a command to execute", file=sys.stderr)
                return 2
            result = execute_p0_real_agent_command(
                manifest_path=Path(args.manifest),
                out_dir=Path(args.out_dir),
                command=command,
                cwd=Path(args.cwd),
                case_id=args.case_id,
                agent=args.agent,
                mode=args.mode,
                timeout=args.timeout,
            )
            print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
            return 0 if result.get("status") == "pass" else 1
        if args.p0_command == "execute-official":
            command_override = list(args.command or [])
            if command_override and command_override[0] == "--":
                command_override = command_override[1:]
            try:
                result = execute_p0_official_runner(
                    manifest_path=Path(args.manifest),
                    out_dir=Path(args.out_dir),
                    family=args.family,
                    case_id=args.case_id,
                    agent=args.agent,
                    mode=args.mode,
                    cwd=Path(args.cwd),
                    grader_artifact=Path(args.grader_artifact),
                    timeout=args.timeout,
                    command_override=command_override or None,
                    python_executable=args.python_executable,
                    predictions_path=args.predictions_path,
                    run_id=args.run_id,
                    report_dir=args.report_dir,
                    instance_ids=args.instance_id or None,
                    model=args.model,
                    model_id=args.model_id,
                    suite=args.suite,
                    module_to_load=args.module_to_load,
                    user_tasks=args.user_task or None,
                    injection_tasks=args.injection_task or None,
                    attack=args.attack,
                    defense=args.defense,
                    logdir=args.logdir,
                    tools=args.tools,
                    apps=args.apps,
                    runner=args.runner,
                    output_dir=args.output_dir,
                    extra_args=args.extra_arg or None,
                    bridge_report=Path(args.bridge_report) if args.bridge_report else None,
                )
            except ValueError as exc:
                print(str(exc), file=sys.stderr)
                return 2
            print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
            return 0 if result.get("status") == "pass" else 1
        if args.p0_command == "swe-prediction":
            command = list(args.command or [])
            if command and command[0] == "--":
                command = command[1:]
            if not command:
                print("--command must include an agent command that writes --patch-path", file=sys.stderr)
                return 2
            result = execute_swe_prediction_command(
                command=command,
                cwd=Path(args.cwd),
                instance_id=args.instance_id,
                patch_path=Path(args.patch_path),
                predictions_path=Path(args.predictions_path),
                agent=args.agent,
                mode=args.mode,
                timeout=args.timeout,
                model_name_or_path=args.model_name,
                out_dir=Path(args.out_dir) if args.out_dir else None,
            )
            print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
            return 0 if result.get("status") == "pass" else 1
        if args.p0_command == "attach-grader":
            result = attach_p0_official_grader(
                run_dir=Path(args.run_dir),
                family=args.family,
                artifact=Path(args.artifact),
                status=args.status,
            )
            print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
            return 0 if result.get("status") == "pass" else 1
        if args.p0_command == "official-command":
            if args.family == "swe_bench_verified":
                if not args.predictions_path:
                    print("--predictions-path is required for swe_bench_verified", file=sys.stderr)
                    return 2
                result = build_swe_bench_verified_command(
                    python_executable=args.python_executable,
                    predictions_path=args.predictions_path,
                    run_id=args.run_id or "invart_p0_swe_verified",
                    report_dir=args.report_dir,
                    instance_ids=args.instance_id or None,
                )
            elif args.family == "agentdojo":
                if not args.model:
                    print("--model is required for agentdojo", file=sys.stderr)
                    return 2
                result = build_agentdojo_command(
                    python_executable=args.python_executable,
                    model=args.model,
                    model_id=args.model_id,
                    suite=args.suite,
                    module_to_load=args.module_to_load,
                    user_tasks=args.user_task or None,
                    injection_tasks=args.injection_task or None,
                    attack=args.attack,
                    defense=args.defense,
                    logdir=args.logdir,
                )
            elif args.family == "agentsecbench":
                result = build_agentsecbench_command(
                    python_executable=args.python_executable,
                    tools=args.tools,
                    apps=args.apps,
                    output_dir=args.output_dir,
                    extra_args=args.extra_arg or None,
                )
            else:
                result = build_skill_inject_command(
                    python_executable=args.python_executable,
                    runner=args.runner,
                    agent=args.bridge_agent,
                    model=args.model,
                    output_dir=args.output_dir,
                    extra_args=args.extra_arg or None,
                )
            print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
            return 0
        if args.p0_command == "validate-grader":
            result = validate_official_grader_artifact(family=args.family, artifact=Path(args.artifact))
            print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
            return 0 if result.get("status") == "pass" else 1
        if args.p0_command == "summarize":
            result = summarize_p0_real_agent_package(Path(args.run_dir))
            print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
            return 0 if result.get("status") == "pass" else 1
        if args.p0_command == "rebuild-tables":
            result = rebuild_p0_paper_artifacts(Path(args.run_dir))
            print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
            return 0 if result.get("status") == "pass" else 1
        if args.p0_command == "remaining":
            result = generate_p0_remaining_artifacts(Path(args.run_dir))
            print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
            return 0
        if args.p0_command == "target-continuation":
            result = generate_p0_target_continuation(Path(args.run_dir))
            print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
            return 0
        if args.p0_command == "completion-audit":
            result = generate_p0_completion_audit(Path(args.run_dir))
            print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
            return 0 if result.get("status") in {
                "complete",
                "blocked_by_external_keys",
                "blocked_by_external_credentials",
                "incomplete",
            } else 1
        if args.p0_command == "export-review-artifact":
            result = export_p0_review_artifact(run_dir=Path(args.run_dir), out_dir=Path(args.out_dir))
            print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
            return 0 if result.get("status") == "pass" else 1
        if args.p0_command == "collect-runs":
            result = collect_p0_child_runs(
                run_dir=Path(args.run_dir),
                child_runs_dir=Path(args.child_runs_dir) if args.child_runs_dir else None,
            )
            print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
            return 0 if result.get("status") == "pass" else 1
        if args.p0_command == "merge-packages":
            result = merge_p0_artifact_packages(
                out_dir=Path(args.out_dir),
                package_dirs=[Path(item) for item in args.package_dir],
                manifest_path=Path(args.manifest) if args.manifest else None,
            )
            print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
            return 0 if result.get("status") == "pass" else 1
        if args.p0_command == "reproduce":
            script = generate_p0_reproduce_script(Path(args.run_dir))
            result = summarize_p0_real_agent_package(Path(args.run_dir))
            report = write_p0_reproduce_report(
                run_dir=Path(args.run_dir),
                reproduce_script=script,
                package_summary=result,
            )
            result["reproduce_script"] = str(script)
            result["reproduce_report"] = report
            print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
            return 0 if result.get("status") == "pass" else 1
        if args.p0_command == "doctor":
            result = run_p0_doctor(run_dir=Path(args.run_dir), python_executable=args.python_executable)
            print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
            return 0 if result.get("status") == "ready" else 1
    if args.experiment_command == "p1-external-oracle":
        if args.p1_command == "plan":
            result = run_p1_external_oracled_plan(out_dir=Path(args.out_dir), agents=args.agent or None)
            print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
            return 0 if result.get("status") == "pass" else 1
        if args.p1_command == "run":
            result = materialize_p1_run_matrix(
                manifest_path=Path(args.manifest),
                out_dir=Path(args.out_dir),
                modes=args.mode or None,
                agents=args.agent or None,
            )
            print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
            return 0 if result.get("status") == "pass" else 1
        if args.p1_command == "bootstrap-queue":
            result = generate_p1_bootstrap_real_run_queue(
                manifest_path=Path(args.manifest),
                out_dir=Path(args.out_dir),
                agents=args.agent,
                families=args.family,
                risk_group_limit_per_agent=args.risk_group_limit_per_agent,
                utility_group_limit_per_agent=args.utility_group_limit_per_agent,
                family_group_limit_per_family=args.family_group_limit_per_family,
                python_executable=args.python_executable,
            )
            print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
            return 0 if result.get("status") in {"ready_for_execution", "ready_for_secret_env", "needs_command_input", "setup_blocked", "empty"} else 1
        if args.p1_command == "execute-command":
            command = list(args.command or [])
            if command and command[0] == "--":
                command = command[1:]
            if not command:
                print("--command must include a command to execute", file=sys.stderr)
                return 2
            try:
                result = execute_p1_external_oracled_command(
                    manifest_path=Path(args.manifest),
                    out_dir=Path(args.out_dir),
                    command=command,
                    cwd=Path(args.cwd),
                    case_id=args.case_id,
                    agent=args.agent,
                    mode=args.mode,
                    timeout=args.timeout,
                    allow_provider_run=args.allow_provider_run,
                )
            except ValueError as exc:
                print(str(exc), file=sys.stderr)
                return 2
            print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
            return 0 if result.get("status") == "pass" else 1
        if args.p1_command == "attach-grader":
            result = attach_p1_official_grader(
                run_dir=Path(args.run_dir),
                family=args.family,
                artifact=Path(args.artifact),
                status=args.status,
            )
            print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
            return 0 if result.get("status") == "pass" else 1
        if args.p1_command == "merge-packages":
            result = merge_p1_artifact_packages(
                out_dir=Path(args.out_dir),
                package_dirs=[Path(item) for item in args.package_dir],
                manifest_path=Path(args.manifest) if args.manifest else None,
            )
            print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
            return 0 if result.get("status") == "pass" else 1
        if args.p1_command == "summarize":
            result = summarize_p1_external_oracled_package(Path(args.run_dir))
            print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
            return 0 if result.get("status") == "pass" else 1
        if args.p1_command == "remaining":
            result = generate_p1_remaining_artifacts(Path(args.run_dir))
            print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
            return 0 if result.get("status") in {"complete", "runnable", "needs_manual_continuation"} else 1
        if args.p1_command == "select-remaining":
            try:
                result = select_p1_remaining_rows(
                    run_dir=Path(args.run_dir),
                    out_dir=Path(args.out_dir),
                    families=args.family or None,
                    agents=args.agent or None,
                    modes=args.mode or None,
                    case_ids=args.case_id or None,
                    limit=args.limit,
                    group_limit=args.group_limit,
                    strategy=args.strategy,
                )
            except ValueError as exc:
                print(str(exc), file=sys.stderr)
                return 2
            print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
            return 0 if result.get("status") in {"selected", "empty"} else 1
        if args.p1_command == "risk-pack":
            try:
                result = generate_p1_risk_group_pack(
                    run_dir=Path(args.run_dir),
                    out_dir=Path(args.out_dir),
                    agents=args.agent or None,
                    families=args.family or None,
                    group_limit_per_agent=args.group_limit_per_agent,
                )
            except ValueError as exc:
                print(str(exc), file=sys.stderr)
                return 2
            print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
            return 0 if result.get("status") in {"selected", "empty"} else 1
        if args.p1_command == "risk-readiness":
            result = generate_p1_risk_execution_readiness(
                run_dir=Path(args.run_dir),
                env_file=Path(args.env_file) if args.env_file else None,
                python_executable=args.python_executable,
            )
            print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
            return 0 if result.get("status") == "ready_for_provider_execution" else 1
        if args.p1_command == "family-pack":
            try:
                result = generate_p1_family_broadening_pack(
                    run_dir=Path(args.run_dir),
                    out_dir=Path(args.out_dir),
                    agents=args.agent or None,
                    families=args.family or None,
                    group_limit_per_family=args.group_limit_per_family,
                )
            except ValueError as exc:
                print(str(exc), file=sys.stderr)
                return 2
            print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
            return 0 if result.get("status") in {"selected", "empty"} else 1
        if args.p1_command == "execute-risk-pack":
            try:
                result = execute_p1_risk_group_pack(
                    run_dir=Path(args.run_dir),
                    out_dir=Path(args.out_dir),
                    agents=args.agent or None,
                    families=args.family or None,
                    group_limit_per_agent=args.group_limit_per_agent,
                    env_file=Path(args.env_file) if args.env_file else None,
                    approval_packet=Path(args.approval_packet) if args.approval_packet else None,
                    python_executable=args.python_executable,
                    timeout=args.timeout,
                    allow_provider_run=args.allow_provider_run,
                )
            except ValueError as exc:
                print(str(exc), file=sys.stderr)
                return 2
            print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
            return 0 if result.get("status") in {"executed_claimable_positive", "executed_claimable_with_downgrade"} else 1
        if args.p1_command == "utility-pack":
            try:
                result = generate_p1_utility_group_pack(
                    run_dir=Path(args.run_dir),
                    out_dir=Path(args.out_dir),
                    agents=args.agent or None,
                    families=args.family or None,
                    case_ids=args.case_id or None,
                    group_limit_per_agent=args.group_limit_per_agent,
                )
            except ValueError as exc:
                print(str(exc), file=sys.stderr)
                return 2
            print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
            return 0 if result.get("status") in {"selected", "empty"} else 1
        if args.p1_command == "expand-swe-utility-manifest":
            try:
                result = expand_p1_manifest_with_swe_utility_case(
                    manifest_path=Path(args.manifest),
                    instance_json=Path(args.instance_json),
                    out_dir=Path(args.out_dir),
                    case_id=args.case_id,
                    expected_patch_markers=args.expected_patch_marker,
                    case_role=args.case_role,
                    replace=args.replace,
                )
            except ValueError as exc:
                print(str(exc), file=sys.stderr)
                return 2
            print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
            return 0 if result.get("status") == "expanded" else 1
        if args.p1_command == "execute-utility-pack":
            try:
                result = execute_p1_utility_group_pack(
                    run_dir=Path(args.run_dir),
                    out_dir=Path(args.out_dir),
                    agents=args.agent or None,
                    families=args.family or None,
                    case_ids=args.case_id or None,
                    group_limit_per_agent=args.group_limit_per_agent,
                    env_file=Path(args.env_file) if args.env_file else None,
                    approval_packet=Path(args.approval_packet) if args.approval_packet else None,
                    python_executable=args.python_executable,
                    timeout=args.timeout,
                    allow_provider_run=args.allow_provider_run,
                    allow_deferred_row_artifact_grader=args.allow_deferred_row_artifact_grader,
                )
            except ValueError as exc:
                print(str(exc), file=sys.stderr)
                return 2
            print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
            return (
                0
                if result.get("status")
                in {
                    "executed_utility_preserved",
                    "executed_utility_regression",
                    "executed_utility_no_success",
                    "executed_utility_partial",
                }
                else 1
            )
        if args.p1_command == "utility-readiness":
            result = generate_p1_utility_execution_readiness(
                run_dir=Path(args.run_dir),
                env_file=Path(args.env_file) if args.env_file else None,
                python_executable=args.python_executable,
                allow_deferred_row_artifact_grader=args.allow_deferred_row_artifact_grader,
            )
            print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
            return 0 if result.get("status") == "ready_for_provider_execution" else 1
        if args.p1_command == "utility-row-grader":
            result = generate_p1_swe_row_artifact_grader(
                run_dir=Path(args.run_dir),
                out_dir=Path(args.out_dir),
                case_id=args.case_id,
                instance_id=args.instance_id,
                expected_patch_marker=args.expected_patch_marker,
                agent=args.agent,
            )
            print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
            return 0 if result.get("status") == "pass" else 1
        if args.p1_command == "row-artifact-check":
            result = check_p1_selected_swe_row_artifacts(run_dir=Path(args.run_dir))
            print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
            return 0 if result.get("status") == "pass" else 1
        if args.p1_command == "swe-official-predictions":
            result = export_p1_swe_official_predictions(
                run_dir=Path(args.run_dir),
                out_dir=Path(args.out_dir),
                python_executable=args.python_executable,
                model_name_or_path=args.model_name,
                max_workers=args.max_workers,
                timeout=args.timeout,
            )
            print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
            return 0 if result.get("status") in {"ready_for_official_runner", "predictions_ready_runner_blocked"} else 1
        if args.p1_command == "swe-official-smoke":
            result = run_p1_swe_official_smoke(
                predictions_report=Path(args.predictions_report),
                out_dir=Path(args.out_dir) if args.out_dir else None,
                row_id=args.row_id,
                case_id=args.case_id,
                mode=args.mode,
                execute=args.execute,
                collect_existing=args.collect_existing,
                command_timeout=args.timeout,
            )
            print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
            return 0 if result.get("status") in {"ready_to_execute", "executed_pass", "collected_existing_official_output"} else 1
        if args.p1_command == "swe-official-summary":
            result = generate_p1_swe_official_smoke_summary(
                smoke_reports=[Path(item) for item in args.smoke_report],
                out_dir=Path(args.out_dir),
                case_id=args.case_id,
                agent=args.agent,
            )
            print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
            return 0 if result.get("status") in {"pass", "partial"} else 1
        if args.p1_command == "selected-doctor":
            result = doctor_p1_remaining_selection(
                run_dir=Path(args.run_dir),
                python_executable=args.python_executable,
                env_file=Path(args.env_file) if args.env_file else None,
                allow_deferred_row_artifact_grader=args.allow_deferred_row_artifact_grader,
            )
            print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
            return 0 if result.get("status") == "ready" else 1
        if args.p1_command == "workspace-preflight":
            result = preflight_p1_selected_swe_workspaces(
                run_dir=Path(args.run_dir),
                env_file=Path(args.env_file) if args.env_file else None,
                repo_cache=Path(args.repo_cache) if args.repo_cache else None,
                force=args.force,
            )
            print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
            return 0 if result.get("status") in {"pass", "empty"} else 1
        if args.p1_command == "selected-inputs":
            result = generate_p1_selected_execution_inputs(Path(args.run_dir))
            print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
            return 0 if result.get("status") in {"ready_to_fill", "empty"} else 1
        if args.p1_command == "candidate-env":
            result = generate_p1_selected_candidate_env(
                Path(args.run_dir),
                out_file=Path(args.out_file) if args.out_file else None,
            )
            print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
            return 0 if result.get("status") in {"ready_for_doctor", "needs_manual_commands", "empty"} else 1
        if args.p1_command == "execute-selected":
            result = execute_p1_selected_continuation(
                run_dir=Path(args.run_dir),
                env_file=Path(args.env_file),
                python_executable=args.python_executable,
                timeout=args.timeout,
                allow_provider_run=args.allow_provider_run,
                allow_deferred_row_artifact_grader=args.allow_deferred_row_artifact_grader,
            )
            print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
            return 0 if result.get("status") == "pass" else 1
        if args.p1_command == "selected-gate":
            result = generate_p1_selected_evidence_gate(Path(args.run_dir))
            print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
            return 0 if result.get("status") in {"claimable_positive", "claimable_with_downgrade", "claimable_partial"} else 1
        if args.p1_command == "completion-audit":
            result = generate_p1_completion_audit(Path(args.run_dir))
            print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
            return 0 if result.get("status") in {"complete", "incomplete"} else 1
        if args.p1_command == "result-analysis":
            result = generate_p1_result_analysis(
                Path(args.run_dir),
                artifact_paths=[Path(path) for path in args.artifact],
            )
            print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
            return 0 if result.get("status") in {"findings_available", "pending_evidence", "setup_limited"} else 1
        if args.p1_command == "paper-brief":
            result = generate_p1_paper_brief(
                Path(args.run_dir),
                artifact_paths=[Path(path) for path in args.artifact],
            )
            print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
            return 0 if result.get("status") in {"ready_for_draft_sync", "pending_evidence", "setup_limited"} else 1
        if args.p1_command == "paper-sync":
            result = generate_p1_paper_sync_preview(
                Path(args.run_dir),
                artifact_paths=[Path(path) for path in args.artifact],
                claims_doc=Path(args.claims_doc) if args.claims_doc else None,
                draft_tex=Path(args.draft_tex) if args.draft_tex else None,
            )
            print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
            return 0 if result.get("status") in {"ready_for_manual_sync", "pending_evidence", "target_missing"} else 1
        if args.p1_command == "claim-audit":
            result = generate_p1_claim_validity_audit(
                Path(args.run_dir),
                artifact_paths=[Path(path) for path in args.artifact],
                claims_doc=Path(args.claims_doc) if args.claims_doc else None,
                draft_tex=Path(args.draft_tex) if args.draft_tex else None,
            )
            print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
            return 0 if result.get("status") in {"paper_claims_guarded", "pending_evidence"} else 1
        if args.p1_command == "active-status":
            result = generate_p1_active_lane_status(
                out_dir=Path(args.out_dir),
                artifact_paths=[Path(path) for path in args.artifact],
            )
            print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
            return 0 if result.get("status") != "empty" else 1
        if args.p1_command == "approval-packet":
            result = generate_p1_provider_approval_packet(
                out_dir=Path(args.out_dir),
                artifact_paths=[Path(path) for path in args.artifact],
                lane_id=args.lane_id,
                lane_kind=args.lane_kind,
            )
            print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
            return 0 if result.get("status") in {"approval_required", "ready_for_approval"} else 1
        if args.p1_command == "iteration-record":
            result = generate_p1_iteration_record(
                out_dir=Path(args.out_dir),
                artifact_paths=[Path(path) for path in args.artifact],
                iteration=args.iteration,
                reviewer_risk=args.reviewer_risk,
                notes=args.notes,
            )
            print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
            return 0 if result.get("status") != "empty" else 1
        if args.p1_command == "iteration-handoff":
            result = generate_p1_iteration_handoff(
                out_dir=Path(args.out_dir),
                artifact_paths=[Path(path) for path in args.artifact],
            )
            print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
            return 0 if result.get("status") != "empty" else 1
        if args.p1_command == "iteration-experiment-report":
            result = generate_p1_iteration_experiment_report(
                out_dir=Path(args.out_dir),
                artifact_paths=[Path(path) for path in args.artifact],
                iteration_focus=args.iteration_focus,
                final_version=args.final_version,
            )
            print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
            return 0 if result.get("status") == "v5_completed" else 1
        if args.p1_command == "iteration-plan-report":
            result = generate_p1_iteration_plan_report(
                out_dir=Path(args.out_dir),
                artifact_paths=[Path(path) for path in args.artifact],
                plan_focus=args.plan_focus,
            )
            print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
            return 0 if result.get("status") == "full_plan_completed" else 1
        if args.p1_command == "run-queue":
            result = generate_p1_real_run_queue(
                run_dir=Path(args.run_dir),
                out_dir=Path(args.out_dir),
                agents=args.agent,
                families=args.family,
                risk_group_limit_per_agent=args.risk_group_limit_per_agent,
                utility_group_limit_per_agent=args.utility_group_limit_per_agent,
                family_group_limit_per_family=args.family_group_limit_per_family,
                python_executable=args.python_executable,
            )
            print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
            return 0 if result.get("status") in {"ready_for_execution", "ready_for_secret_env", "needs_command_input", "setup_blocked", "empty"} else 1
        if args.p1_command == "launch-preflight":
            result = generate_p1_real_run_launch_preflight(
                Path(args.run_dir),
                queue_env=Path(args.queue_env) if args.queue_env else None,
                python_executable=args.python_executable,
            )
            print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
            return 0 if result.get("status") in {"ready_to_launch", "ready_but_disabled", "needs_private_env", "blocked_setup", "empty"} else 1
        if args.p1_command == "prepare-launch-env":
            result = generate_p1_real_run_launch_env(
                Path(args.run_dir),
                enable_lanes=args.enable_lane,
                queue_env=Path(args.queue_env) if args.queue_env else None,
                overwrite=args.overwrite,
                python_executable=args.python_executable,
            )
            print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
            return 0 if result.get("status") in {"ready_to_launch", "ready_but_disabled", "needs_private_env", "blocked_setup", "empty"} else 1
        if args.p1_command == "launch-report":
            result = generate_p1_real_run_launch_report(Path(args.run_dir))
            print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
            return 0 if result.get("status") in {"executed_claimable", "executed_not_claimable", "launched_with_skips", "pending_execution"} else 1
        if args.p1_command == "timeout-triage":
            result = generate_p1_timeout_triage(Path(args.run_dir))
            print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
            return 0 if result.get("status") in {"no_timeouts", "timeout_blocking"} else 1
    return 2


def _parse_binary_overrides(values: list[str]) -> dict[str, str]:
    overrides: dict[str, str] = {}
    for value in values:
        if "=" not in value:
            raise ValueError("--binary must use agent-id=/path/to/binary")
        agent, path = value.split("=", 1)
        if not agent or not path:
            raise ValueError("--binary must use agent-id=/path/to/binary")
        overrides[agent] = path
    return overrides

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
    if args.evidence_command == "inspect":
        result = inspect_evidence_workspace(
            Path(args.manifest),
            out_dir=Path(args.out_dir) if args.out_dir else None,
            require_questions=args.require_questions,
            require_layer_workflow=args.require_layer_workflow,
            require_adapter_package=args.require_adapter_package,
        )
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
            evidence_workspace_manifest=Path(args.evidence_workspace_manifest) if args.evidence_workspace_manifest else None,
            require_evidence_layer_workflow=args.require_evidence_layer_workflow,
            require_evidence_adapter_package=args.require_evidence_adapter_package,
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
