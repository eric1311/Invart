from __future__ import annotations

import argparse
import json
import shlex
import sys
from pathlib import Path

from ..runtime import (
    analyze_event_payload,
)
from ..claude_adapter import check_claude_code_environment, run_claude_code_adapter
from ..adapter import inspect_adapter_package, run_adapter_command
from ..harness import (
    compare_harness_artifact_files,
    run_managed_harness_check,
    run_official_swe_bench_full_validation,
    run_official_swe_bench_lite_check,
    run_swe_bench_lite_check,
)
from ..adapter_profiles import build_adapter_profile
from ..enforcement import check_enforcement, run_enforced_command, run_file_write_intercepted, rust_build_check, rust_shim_decision, rust_shim_spec
from ..native import install_native_integration, inventory_native_integrations, native_conformance_report
from ..native_bridge import bridge_conformance_matrix, normalize_native_event, render_native_response
from ..mcp_broker import run_stdio_broker, transparent_broker_step
from ..coverage import export_coverage_html_report
from ..supervision import supervise_process_group
from ..path_graph import build_execution_graph, export_execution_graph_html, export_execution_graph_json, query_execution_graph
from ..mediation import replay_mediation, resolve_mediation
from ..evidence_bundle import export_evidence_bundle

from .common import resolved_profile_from_args

def handle_adapter(args: argparse.Namespace) -> int:
    if args.adapter_command == "inspect":
        result = inspect_adapter_package(Path(args.package))
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0 if result.get("status") == "pass" else 1
    if args.adapter_command == "package":
        result = export_evidence_bundle(Path(args.ledger), Path(args.out_dir), profile={"name": "adapter-package", "mode": "managed"})
        print(json.dumps({"adapter_package": result}, ensure_ascii=False, indent=2, sort_keys=True))
        return 0 if result.get("status") == "pass" else 1
    if args.adapter_command == "profile":
        print(json.dumps(build_adapter_profile(args.kind), ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    if args.adapter_command == "claude-code-check":
        result = check_claude_code_environment(binary=args.binary)
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0 if result.get("available") else 1
    if args.adapter_command == "claude-code":
        command = args.cmd
        if command and command[0] == "--":
            command = command[1:]
        if not command:
            print("kappaski adapter claude-code requires a command after --", file=sys.stderr)
            return 2
        result = run_claude_code_adapter(
            target=Path(args.target),
            command=command,
            hook_events=Path(args.hook_events) if args.hook_events else None,
            out_dir=Path(args.out_dir) if args.out_dir else None,
            session_id=args.session_id,
            create_preflight=not args.no_preflight,
            enforcement=args.enforcement,
        )
        print(json.dumps({"claude_code_adapter": result}, ensure_ascii=False, indent=2, sort_keys=True))
        return int(result.get("returncode", 1))
    if args.adapter_command == "run":
        command = args.cmd
        if command and command[0] == "--":
            command = command[1:]
        if not command:
            print("kappaski adapter run requires a command after --", file=sys.stderr)
            return 2
        result = run_adapter_command(
            target=Path(args.target),
            command=command,
            agent=args.agent,
            goal=args.goal,
            session_id=args.session_id,
            out_dir=Path(args.out_dir) if args.out_dir else None,
            corpus_root=Path(args.corpus_root),
            capabilities=args.capabilities,
            gate_mode=args.gate,
            policy_mode=args.policy_mode,
            create_preflight=not args.no_preflight,
            enforcement=args.enforcement,
        )
        print(json.dumps({"adapter_run": result.to_dict()}, ensure_ascii=False, indent=2, sort_keys=True))
        if result.status == "blocked":
            return 126
        if result.gate_status == "fail":
            return 1
        return result.returncode
    return 2

def handle_harness(args: argparse.Namespace) -> int:
    if args.harness_command == "compare":
        result = compare_harness_artifact_files(Path(args.baseline), Path(args.wrapped), Path(args.case) if args.case else None)
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0 if result.get("status") == "pass" else 1
    if args.harness_command == "swe-bench-lite":
        try:
            result = run_swe_bench_lite_check(
                case_path=Path(args.case),
                output_path=Path(args.out) if args.out else None,
                baseline_artifact=Path(args.baseline_artifact) if args.baseline_artifact else None,
                wrapped_artifact=Path(args.wrapped_artifact) if args.wrapped_artifact else None,
                dependency=args.dependency,
                skip_if_unavailable=args.skip_if_unavailable,
                baseline_command=shlex.split(args.baseline_command) if args.baseline_command else None,
                wrapped_command=shlex.split(args.wrapped_command) if args.wrapped_command else None,
            )
        except RuntimeError as exc:
            print(str(exc), file=sys.stderr)
            return 1
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0 if result.get("status") in {"pass", "skipped"} else 1
    if args.harness_command == "swe-bench-official":
        result = run_official_swe_bench_lite_check(
            output_path=Path(args.out) if args.out else None,
            python_executable=args.python,
            dataset_name=args.dataset_name,
            split=args.split,
            instance_ids=args.instance_id,
            predictions_path=args.predictions_path,
            run_id=args.run_id,
            report_dir=Path(args.report_dir) if args.report_dir else None,
            timeout=args.timeout,
            max_workers=args.max_workers,
            cache_level=args.cache_level,
            clean=args.clean,
            work_dir=Path(args.work_dir) if args.work_dir else None,
            command=shlex.split(args.override_command) if args.override_command else None,
            report_path=Path(args.report_path) if args.report_path else None,
        )
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0 if result.get("status") == "pass" else 1
    if args.harness_command == "managed-check":
        command = args.cmd
        if command and command[0] == "--":
            command = command[1:]
        if not command:
            print("kappaski harness managed-check requires a command after --", file=sys.stderr)
            return 2
        case = json.loads(Path(args.case).read_text(encoding="utf-8")) if args.case else None
        result = run_managed_harness_check(target=Path(args.target), command=command, case=case, approval_actor=args.approval_actor)
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0 if result.get("status") == "pass" else 1
    return 2

def handle_external_validation(args: argparse.Namespace) -> int:
    if args.external_validation_command == "swe-bench-full":
        result = run_official_swe_bench_full_validation(
            output_path=Path(args.out) if args.out else None,
            python_executable=args.python,
            dataset_name=args.dataset_name,
            split=args.split,
            predictions_path=args.predictions_path,
            run_id=args.run_id,
            report_dir=Path(args.report_dir) if args.report_dir else None,
            timeout=args.timeout,
            max_workers=args.max_workers,
            cache_level=args.cache_level,
            clean=args.clean,
            work_dir=Path(args.work_dir) if args.work_dir else None,
            command=shlex.split(args.override_command) if args.override_command else None,
            report_path=Path(args.report_path) if args.report_path else None,
            instance_results_path=Path(args.instance_results_path) if args.instance_results_path else None,
            expected_total_instances=args.expected_total_instances,
            allow_subset=args.allow_subset,
        )
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0 if result.get("status") == "pass" else 1
    return 2

def handle_enforce(args: argparse.Namespace) -> int:
    if args.enforce_command == "check":
        profile_config = resolved_profile_from_args(args)
        result = check_enforcement(json.loads(args.event), domain=args.domain, profile=profile_config)
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0 if result.get("effect") == "allow" else 1
    if args.enforce_command == "shim-spec":
        result = rust_shim_spec(args.domain)
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0 if result.get("cargo_toml_exists") and result.get("main_rs_exists") else 1
    if args.enforce_command == "rust-build-check":
        result = rust_build_check(skip_if_unavailable=args.skip_if_unavailable)
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0 if result.get("status") in {"pass", "skipped"} else 1
    if args.enforce_command == "shim-decision":
        result = rust_shim_decision(json.loads(args.event), crate_path=Path(args.crate) if args.crate else None)
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0 if result.get("status") == "pass" else 1
    if args.enforce_command == "run-file-write":
        command = args.cmd
        if command and command[0] == "--":
            command = command[1:]
        if not command:
            print("kappaski enforce run-file-write requires a command after --", file=sys.stderr)
            return 2
        result = run_file_write_intercepted(
            command,
            ledger_path=Path(args.ledger) if args.ledger else None,
            session_id=args.session,
            target=Path(args.target) if args.target else None,
            require_approval_blocks=not args.allow_approval_required,
            crate_path=Path(args.crate) if args.crate else None,
        )
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return int(result.get("returncode") if result.get("returncode") is not None else 1)
    if args.enforce_command == "run":
        command = args.cmd
        if command and command[0] == "--":
            command = command[1:]
        if not command:
            print("kappaski enforce run requires a command after --", file=sys.stderr)
            return 2
        result = run_enforced_command(
            command,
            domain=args.domain,
            event=json.loads(args.event) if args.event else None,
            ledger_path=Path(args.ledger) if args.ledger else None,
            session_id=args.session,
            target=Path(args.target) if args.target else None,
            require_approval_blocks=not args.allow_approval_required,
        )
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return int(result.get("returncode") if result.get("returncode") is not None else 1)
    return 2

def handle_native(args: argparse.Namespace) -> int:
    if args.native_command == "inventory":
        result = inventory_native_integrations(Path(args.target), include_global_config=args.include_global_config)
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    if args.native_command == "install":
        mode = "confirm" if args.confirm else "preview"
        result = install_native_integration(Path(args.target), agent=args.agent, mode=mode)
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    if args.native_command == "conformance":
        result = native_conformance_report(Path(args.target), include_global_config=args.include_global_config)
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0 if result.get("status") == "pass" else 1
    return 2

def handle_bridge(args: argparse.Namespace) -> int:
    if args.bridge_command == "native":
        action = normalize_native_event(args.agent, json.loads(args.event))
        event_payload = {
            "type": action.action_type,
            "session_id": action.session_id,
            "command": action.command,
            "tool": action.tool,
            "metadata": action.metadata,
        }
        event, findings = analyze_event_payload(event_payload)
        effect = "deny" if any(finding.severity in {"high", "critical"} for finding in findings) else "allow"
        response = render_native_response(
            args.agent,
            {
                "effect": effect,
                "reason": "kappaski native bridge decision",
                "action": action.to_dict(),
                "findings": [finding.to_dict() for finding in findings],
            },
        )
        print(json.dumps(response, ensure_ascii=False, indent=2, sort_keys=True))
        return 0 if effect == "allow" else 1
    if args.bridge_command == "conformance":
        result = bridge_conformance_matrix()
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0 if result.get("status") == "pass" else 1
    return 2

def handle_mcp(args: argparse.Namespace) -> int:
    if args.mcp_command == "broker-step":
        forwarded, evidence = transparent_broker_step(json.loads(args.message))
        print(json.dumps({"forwarded": forwarded, "evidence": evidence}, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    if args.mcp_command == "broker-stdio":
        result = run_stdio_broker(input_path=Path(args.input), output_path=Path(args.output), transcript_path=Path(args.transcript))
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0 if result.get("status") == "pass" else 1
    return 2

def handle_coverage(args: argparse.Namespace) -> int:
    if args.coverage_command == "html":
        result = export_coverage_html_report(Path(args.proof), Path(args.out))
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0 if result.get("status") == "pass" else 1
    return 2

def handle_graph(args: argparse.Namespace) -> int:
    if args.graph_command == "export":
        result = export_execution_graph_json(Path(args.ledger), Path(args.out))
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0 if result.get("status") == "pass" else 1
    if args.graph_command == "html":
        result = export_execution_graph_html(Path(args.ledger), Path(args.out))
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0 if result.get("status") == "pass" else 1
    if args.graph_command == "query":
        graph = build_execution_graph(Path(args.ledger))
        result = query_execution_graph(graph, target_id=args.target, direction=args.direction)
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    return 2

def handle_mediation(args: argparse.Namespace) -> int:
    if args.mediation_command in {"inspect", "replay"}:
        result = replay_mediation(Path(args.ledger))
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    if args.mediation_command == "resolve":
        result = resolve_mediation(Path(args.ledger), mediation_id=args.mediation, actor=args.actor, status=args.status, reason=args.reason)
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    return 2

def handle_supervise(args: argparse.Namespace) -> int:
    if args.supervise_command == "run":
        command = args.cmd
        if command and command[0] == "--":
            command = command[1:]
        if not command:
            print("kappaski supervise run requires a command after --", file=sys.stderr)
            return 2
        result = supervise_process_group(command, cwd=Path(args.target) if args.target else None)
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return int(result.get("returncode") if result.get("returncode") is not None else 1)
    return 2
