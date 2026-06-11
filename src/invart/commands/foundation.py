from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

from invart.assurance.postruntime import export_proof_report, summarize_session, verify_proof_report
from invart.assurance.layer_runtime import export_layer_runtime_workflow
from invart.control.runtime import (
    analyze_event_payload,
    close_session,
    explain_decision,
    inspect_invocation_review,
    record_action,
    record_approval,
    record_outcome,
    run_shell_with_audit,
    start_session,
)
from invart.control.preflight import save_preflight
from invart.surfaces.scanner import scan_pre_runtime
from invart.control.gate import verify_gate
from invart.control.approval import approve_items, list_approval_items
from invart.assurance.replay import export_replay_html
from invart.governance.profiles import gate_coverage_requirements, gate_requires_closed_session, include_raw_replay, policy_mode_from_profile
from invart.control.path_policy import check_path_policy
from invart.control.policy_as_code import check_policy_profile, test_policy_profile, validate_policy_profile
from invart.core.env import child_env, invart_session_env

from .common import emit, resolved_profile_from_args

def handle_pre_runtime(args: argparse.Namespace) -> int:
    if args.save:
        preflight = save_preflight(Path(args.target), Path(args.preflight) if args.preflight else None, include_home=not args.no_home)
        return emit(preflight, args.output)
    report = scan_pre_runtime(Path(args.target), include_home=not args.no_home)
    return emit(report.to_dict(), args.output)


def handle_run_alias(args: argparse.Namespace) -> int:
    args.session_command = "run"
    return handle_session(args)


def handle_post_runtime(args: argparse.Namespace) -> int:
    print(json.dumps(summarize_session(Path(args.events)), ensure_ascii=False, indent=2, sort_keys=True))
    return 0

def handle_session(args: argparse.Namespace) -> int:
    if args.session_command == "start":
        session = start_session(
            Path(args.target),
            ledger_path=Path(args.ledger) if args.ledger else None,
            agent=args.agent,
            goal=args.goal,
            session_id=args.session_id,
            preflight_path=Path(args.preflight) if args.preflight else None,
            create_preflight=not args.no_preflight,
        )
        proof_path = str(Path(session.ledger_path).with_name("proof.json"))
        print(
            json.dumps(
                {
                    "session_id": session.session_id,
                    "ledger": session.ledger_path,
                    "proof": proof_path,
                    "env": invart_session_env(session_id=session.session_id, ledger=session.ledger_path, include_legacy=False),
                },
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    if args.session_command == "run":
        session = start_session(
            Path(args.target),
            ledger_path=Path(args.ledger) if args.ledger else None,
            agent=args.agent,
            goal=args.goal,
            session_id=args.session_id,
            preflight_path=Path(args.preflight) if args.preflight else None,
            create_preflight=not args.no_preflight,
        )
        command = args.cmd
        if command and command[0] == "--":
            command = command[1:]
        if not command:
            print("invart session run requires a command after --", file=sys.stderr)
            return 2
        env = child_env(os.environ, session_id=session.session_id, ledger=session.ledger_path)
        completed = subprocess.run(command, check=False, env=env)
        close_session(Path(session.ledger_path), status="closed" if completed.returncode == 0 else "aborted")
        return completed.returncode
    if args.session_command == "close":
        entry = close_session(Path(args.ledger), status=args.status)
        print(json.dumps({"closed": True, "entry": entry.to_dict()}, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    return 2

def handle_runtime(args: argparse.Namespace) -> int:
    if args.runtime_command == "analyze-event":
        profile_config = resolved_profile_from_args(args)
        payload = json.loads(args.event)
        event, findings = analyze_event_payload(payload, session_id=args.session)
        response = {"event": event.to_dict(), "findings": [finding.to_dict() for finding in findings]}
        if args.ledger:
            _action, decision, taint = record_action(
                event,
                Path(args.ledger),
                review_mode=args.review,
                policy_mode=policy_mode_from_profile(profile_config, args.policy_mode),
                reviewer=args.reviewer,
                policy_profile=args.policy_profile,
                policy_profile_config=profile_config,
            )
            response["decision"] = decision.to_dict()
            response["taint"] = taint.to_dict()
        print(json.dumps(response, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    if args.runtime_command == "record-event":
        profile_config = resolved_profile_from_args(args)
        payload = json.loads(args.event)
        if args.session and "session_id" not in payload:
            payload["session_id"] = args.session
        event, _findings = analyze_event_payload(payload)
        action, decision, taint = record_action(
            event,
            Path(args.ledger),
            review_mode=args.review,
            policy_mode=policy_mode_from_profile(profile_config, args.policy_mode),
            reviewer=args.reviewer,
            policy_profile=args.policy_profile,
            policy_profile_config=profile_config,
        )
        print(
            json.dumps(
                {
                    "recorded": True,
                    "event": action.to_dict(),
                    "decision": decision.to_dict(),
                    "taint": taint.to_dict(),
                },
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    if args.runtime_command == "shell":
        command = args.cmd
        if command and command[0] == "--":
            command = command[1:]
        if not command:
            print("invart runtime shell requires a command after --", file=sys.stderr)
            return 2
        profile_config = resolved_profile_from_args(args)
        return run_shell_with_audit(
            command,
            Path(args.ledger),
            agent=args.agent,
            target=args.target,
            session_id=args.session,
            review_mode=args.review,
            policy_mode=policy_mode_from_profile(profile_config, args.policy_mode),
            reviewer=args.reviewer,
            policy_profile=args.policy_profile,
            policy_profile_config=profile_config,
        )
    if args.runtime_command == "approve":
        approval = record_approval(Path(args.ledger), args.decision, "approved", approver=args.approver, reason=args.reason)
        print(json.dumps({"approval": approval.to_dict()}, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    if args.runtime_command == "reject":
        approval = record_approval(Path(args.ledger), args.decision, "rejected", approver=args.approver, reason=args.reason)
        print(json.dumps({"approval": approval.to_dict()}, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    if args.runtime_command == "outcome":
        if not args.decision and not args.invocation:
            print("invart runtime outcome requires --decision or --invocation", file=sys.stderr)
            return 2
        outcome = record_outcome(
            Path(args.ledger),
            args.status,
            decision_id=args.decision,
            invocation_id=args.invocation,
            actor=args.actor,
            reason=args.reason,
        )
        print(json.dumps({"outcome": outcome.to_dict()}, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    if args.runtime_command == "layers":
        report = export_layer_runtime_workflow(Path(args.ledger), Path(args.out_dir))
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
        return 0 if report.get("status") == "pass" else 1
    return 2

def handle_approval(args: argparse.Namespace) -> int:
    if args.approval_command == "list":
        result = list_approval_items(Path(args.ledger), status=args.status)
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    if args.approval_command in {"approve", "reject"}:
        try:
            result = approve_items(
                Path(args.ledger),
                decision_id=args.decision,
                all_missing=args.all,
                approver=args.approver,
                reason=args.reason,
                status="approved" if args.approval_command == "approve" else "rejected",
            )
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    return 2

def handle_replay(args: argparse.Namespace) -> int:
    if args.replay_command == "export":
        profile_config = resolved_profile_from_args(args)
        include_raw = include_raw_replay(profile_config, fallback=not args.no_raw)
        result = export_replay_html(
            Path(args.ledger),
            Path(args.out),
            gate_mode=args.gate_mode,
            case_path=Path(args.case) if args.case else None,
            include_raw=include_raw,
        )
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    return 2

def handle_policy(args: argparse.Namespace) -> int:
    if args.policy_command == "validate":
        response = validate_policy_profile(Path(args.profile))
        print(json.dumps(response, ensure_ascii=False, indent=2, sort_keys=True))
        return 0 if response.get("status") == "pass" else 1
    if args.policy_command == "test":
        response = test_policy_profile(Path(args.profile))
        print(json.dumps(response, ensure_ascii=False, indent=2, sort_keys=True))
        return 0 if response.get("status") == "pass" else 1
    if args.policy_command == "explain":
        if not args.decision and not args.invocation:
            print("invart policy explain requires --decision or --invocation", file=sys.stderr)
            return 2
        response = explain_decision(Path(args.ledger), decision_id=args.decision, invocation_id=args.invocation)
        print(json.dumps(response, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    if args.policy_command == "check-path":
        if args.profile:
            response = check_policy_profile(Path(args.ledger), Path(args.profile), output_path=Path(args.out) if args.out else None)
        else:
            response = check_path_policy(Path(args.ledger), output_path=Path(args.out) if args.out else None)
        print(json.dumps(response, ensure_ascii=False, indent=2, sort_keys=True))
        return 0 if response.get("status") == "pass" else 1
    return 2

def handle_review(args: argparse.Namespace) -> int:
    if args.review_command == "invocation":
        response = inspect_invocation_review(Path(args.ledger), args.invocation, review_id=args.review)
        print(json.dumps(response, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    return 2

def handle_gate(args: argparse.Namespace) -> int:
    if args.gate_command == "verify":
        if not args.proof and not args.ledger:
            print("invart gate verify requires --proof, --ledger, or both", file=sys.stderr)
            return 2
        profile_config = resolved_profile_from_args(args)
        report = verify_gate(
            ledger_path=Path(args.ledger) if args.ledger else None,
            proof_path=Path(args.proof) if args.proof else None,
            mode=args.mode,
            output_path=Path(args.out) if args.out else None,
            require_closed_session=gate_requires_closed_session(profile_config),
            coverage_requirements=gate_coverage_requirements(profile_config),
        )
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
        return 0 if report.get("status") in {"pass", "warn"} else 1
    return 2

def handle_proof(args: argparse.Namespace) -> int:
    if args.proof_command == "export":
        report = export_proof_report(Path(args.ledger), Path(args.out) if args.out else None)
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    if args.proof_command == "verify":
        if args.proof:
            result = verify_proof_report(Path(args.proof), Path(args.ledger) if args.ledger else None)
        elif args.ledger:
            result = verify_proof_report(None, Path(args.ledger))
        else:
            result = verify_proof_report(None, None)
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0 if result["valid"] else 1
    return 2
