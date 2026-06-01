from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from ..artifacts import write_json_artifact
from ..daemon import RuntimeAuthority
from ..corpus import scan_corpus
from ..profiles import create_profile_distribution_bundle, load_profile_file, record_break_glass_override, resolve_profile, review_break_glass_override
from ..teamrun import append_teamrun_fact, create_blackboard_entry, create_handoff, create_teamrun, declare_agent_identity, delegate_grant, export_teamrun_aggregate, export_teamrun_proof, export_teamrun_timeline_html
from ..identity import accountability_from_ledger, bind_agent_identity, create_capability_grant, credential_inventory, declare_principal, record_identity_binding

from .common import resolved_profile_from_args

def handle_corpus(args: argparse.Namespace) -> int:
    if args.corpus_command == "scan":
        result = scan_corpus(Path(args.root))
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    return 2

def handle_identity(args: argparse.Namespace) -> int:
    if args.identity_command == "declare":
        principal = declare_principal(args.principal, display_name=args.display_name, source=args.source)
        payload = {"principal": principal.to_dict()}
        if args.out:
            write_json_artifact(Path(args.out), payload)
        print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    if args.identity_command == "bind":
        principal = declare_principal(args.principal)
        agent = bind_agent_identity(args.agent, declared_by=principal.principal_id, adapter_agent=args.adapter_agent or args.agent)
        env = {key: os.environ.get(key, "") for key in args.env_key}
        credentials = credential_inventory(env, owner=principal.principal_id)
        grant = create_capability_grant(
            principal_id=principal.principal_id,
            agent_id=agent.agent_id,
            scopes=args.scope or ["session"],
            resources=args.resource or ["*"],
        )
        result = record_identity_binding(Path(args.ledger), session_id=args.session, principal=principal, agent_identity=agent, credentials=credentials, grants=[grant])
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    if args.identity_command == "inspect":
        result = accountability_from_ledger(Path(args.ledger))
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    return 2

def handle_daemon(args: argparse.Namespace) -> int:
    authority = RuntimeAuthority.for_target(Path(args.target))
    if args.daemon_command == "init":
        print(json.dumps(authority.init(), ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    if args.daemon_command == "status":
        print(json.dumps(authority.status(), ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    if args.daemon_command == "record-event":
        result = authority.record_event(
            args.session,
            json.loads(args.event),
            review_mode=args.review,
            policy_mode=args.policy_mode,
            reviewer=args.reviewer,
            policy_profile=args.policy_profile,
            policy_profile_config=resolved_profile_from_args(args),
        )
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    if args.daemon_command == "heartbeat":
        session = authority.heartbeat(args.session, actor=args.actor)
        print(json.dumps({"session": session.to_dict()}, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    if args.daemon_command == "register-capabilities":
        result = authority.register_capabilities(
            args.session,
            Path(args.corpus_root),
            adapter=args.adapter,
            review_mode=args.review,
            policy_mode=args.policy_mode,
            reviewer=args.reviewer,
            policy_profile=args.policy_profile,
            policy_profile_config=resolved_profile_from_args(args),
        )
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    if args.daemon_command == "approve":
        result = authority.approve(args.session, args.decision, "approved", approver=args.approver, reason=args.reason)
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    if args.daemon_command == "reject":
        result = authority.approve(args.session, args.decision, "rejected", approver=args.approver, reason=args.reason)
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    if args.daemon_command == "outcome":
        if not args.decision and not args.invocation:
            print("kappaski daemon outcome requires --decision or --invocation", file=sys.stderr)
            return 2
        result = authority.outcome(
            args.session,
            args.status,
            decision_id=args.decision,
            invocation_id=args.invocation,
            actor=args.actor,
            reason=args.reason,
        )
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    if args.daemon_command == "session":
        return handle_daemon_session(args, authority)
    return 2

def handle_daemon_session(args: argparse.Namespace, authority: RuntimeAuthority) -> int:
    command = args.daemon_session_command
    if command == "create":
        session = authority.create_session(
            Path(args.target),
            agent=args.agent,
            goal=args.goal,
            session_id=args.session_id,
            ledger_path=Path(args.ledger) if args.ledger else None,
            preflight_path=Path(args.preflight) if args.preflight else None,
            create_preflight=not args.no_preflight,
            metadata={"policy_profile_config": resolved_profile_from_args(args)} if resolved_profile_from_args(args) else None,
        )
        print(json.dumps({"session": session.to_dict()}, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    if command == "list":
        print(json.dumps({"sessions": authority.list_sessions(include_deleted=args.include_deleted)}, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    if command == "show":
        session = authority.get_session(args.session)
        print(json.dumps({"session": session.to_dict()}, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    transitions = {"pause": "paused", "resume": "active", "interrupt": "interrupted", "stop": "stopped", "delete": "deleted"}
    if command in transitions:
        session = authority.transition_session(args.session, transitions[command], reason=args.reason)
        print(json.dumps({"session": session.to_dict()}, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    return 2

def handle_profile(args: argparse.Namespace) -> int:
    if args.profile_command == "resolve":
        result = resolve_profile(
            team=Path(args.team) if args.team else None,
            repo=Path(args.repo) if args.repo else None,
            session=Path(args.session) if args.session else None,
        )
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    if args.profile_command == "break-glass":
        result = record_break_glass_override(
            Path(args.ledger),
            session_id=args.session,
            actor=args.actor,
            reason=args.reason,
            scope=args.scope,
            expires_at=args.expires_at,
        )
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    if args.profile_command == "distribute":
        result = create_profile_distribution_bundle(load_profile_file(Path(args.profile)), scope=args.scope, distributed_by=args.distributed_by)
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    if args.profile_command == "review-override":
        result = review_break_glass_override(Path(args.ledger), override_id=args.override, reviewer=args.reviewer, status=args.status, reason=args.reason)
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    if args.profile_command == "registry":
        profiles = []
        for item in args.profile:
            payload = json.loads(item)
            scope = str(payload.get("scope", "repo"))
            profiles.append((scope, payload))
        from ..profiles import create_profile_registry

        result = create_profile_registry(owner=args.owner, profiles=profiles)
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    if args.profile_command == "pin":
        from ..profiles import pin_profile_bundle

        registry = json.loads(Path(args.registry).read_text(encoding="utf-8"))
        result = pin_profile_bundle(registry, scope=args.scope, profile_name=args.name, distributed_by=args.distributed_by)
        if args.out:
            write_json_artifact(Path(args.out), result)
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    if args.profile_command == "verify":
        from ..profiles import verify_profile_bundle

        registry = json.loads(Path(args.registry).read_text(encoding="utf-8"))
        bundle = json.loads(Path(args.bundle).read_text(encoding="utf-8"))
        result = verify_profile_bundle(bundle, registry)
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0 if result.get("status") == "pass" else 1
    return 2

def handle_teamrun(args: argparse.Namespace) -> int:
    if args.teamrun_command == "create":
        record = create_teamrun(args.name, args.user)
        result = append_teamrun_fact(Path(args.ledger), "teamrun", record) if args.ledger else record
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    if args.teamrun_command == "identity":
        facts = {"agent_id": args.adapter_agent} if args.adapter_agent else {}
        record = declare_agent_identity(args.agent, args.declared_by, facts)
        result = append_teamrun_fact(Path(args.ledger), "agent_identity", record) if args.ledger else record
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    if args.teamrun_command == "handoff":
        refs = []
        for item in args.resource:
            refs.append({"kind": "resource", "value": item, "tainted": "true" if item.startswith("tainted:") else "false"})
        record = create_handoff(args.source_agent, args.target_agent, refs, taint_mode=args.taint_mode, session_tainted=args.session_tainted)
        result = append_teamrun_fact(Path(args.ledger), "handoff", record) if args.ledger else record
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    if args.teamrun_command == "blackboard":
        record = create_blackboard_entry(args.teamrun, args.author, args.content, args.resource)
        result = append_teamrun_fact(Path(args.ledger), "blackboard", record)
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    if args.teamrun_command == "delegate-grant":
        try:
            record = delegate_grant(args.source_agent, args.target_agent, args.parent_scope, args.delegate_scope)
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 1
        result = append_teamrun_fact(Path(args.ledger), "grant_delegation", record)
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    if args.teamrun_command == "proof":
        result = export_teamrun_proof(Path(args.ledger), Path(args.out) if args.out else None)
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    if args.teamrun_command == "aggregate":
        result = export_teamrun_aggregate([Path(item) for item in args.ledger], Path(args.out) if args.out else None)
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0 if all(item.get("valid") for item in result.get("ledger_verification", [])) else 1
    if args.teamrun_command == "timeline":
        result = export_teamrun_timeline_html([Path(item) for item in args.ledger], Path(args.out))
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0 if result.get("status") == "pass" else 1
    return 2
