from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import sys
from pathlib import Path

from .ledger import verify_ledger
from .postruntime import export_proof_report, summarize_session, verify_proof_report
from .runtime import (
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
from .preflight import save_preflight
from .scanner import scan_pre_runtime
from .evals import run_benchmark
from .benchmark_registry import list_benchmark_suites
from .daemon import RuntimeAuthority
from .corpus import scan_corpus
from .claude_adapter import check_claude_code_environment, run_claude_code_adapter
from .gate import verify_gate
from .adapter import inspect_adapter_package, run_adapter_command, run_adapter_runtime
from .approval import approve_items, list_approval_items
from .replay import export_replay_html
from .harness import (
    SWE_BENCH_FULL_DATASET,
    SWE_BENCH_FULL_EXPECTED_INSTANCES,
    SWE_BENCH_LITE_DATASET,
    compare_harness_artifact_files,
    run_managed_harness_check,
    run_official_swe_bench_full_validation,
    run_official_swe_bench_lite_check,
    run_swe_bench_lite_check,
)
from .adapter_profiles import build_adapter_profile
from .profiles import create_profile_distribution_bundle, gate_coverage_requirements, gate_requires_closed_session, include_raw_replay, load_profile_file, policy_mode_from_profile, record_break_glass_override, resolve_profile, resolve_profile_from_paths, review_break_glass_override
from .teamrun import append_teamrun_fact, create_blackboard_entry, create_handoff, create_teamrun, declare_agent_identity, delegate_grant, export_teamrun_aggregate, export_teamrun_proof, export_teamrun_timeline_html
from .enforcement import check_enforcement, run_enforced_command, run_file_write_intercepted, rust_build_check, rust_shim_decision, rust_shim_spec
from .roadmap import verify_roadmap_coverage
from .audit_demo import record_audit_signoff, run_enterprise_audit_demo, run_enterprise_audit_live_adapter_demo
from .native import install_native_integration, inventory_native_integrations, native_conformance_report
from .native_bridge import bridge_conformance_matrix, normalize_native_event, render_native_response
from .mcp_broker import run_stdio_broker, transparent_broker_step
from .coverage import export_coverage_html_report
from .supervision import supervise_process_group
from .identity import accountability_from_ledger, bind_agent_identity, create_capability_grant, credential_inventory, declare_principal, record_identity_binding
from .path_graph import build_execution_graph, export_execution_graph_html, export_execution_graph_json, query_execution_graph
from .path_policy import check_path_policy
from .mediation import mediate_event, replay_mediation, resolve_mediation
from .pre_v1 import run_pre_v1_control_plane_demo
from .policy_as_code import check_policy_profile, test_policy_profile, validate_policy_profile
from .evidence_bundle import export_evidence_bundle, verify_evidence_bundle
from .release_candidate import verify_release_candidate
from .experiment_cases import export_experiment_report, list_experiment_suites, run_experiment_suite, run_paper_suite
from .experiment_fixtures import validate_experiment_fixture_root
from .real_world_cases import run_real_world_risk_demo


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="kappaski", description="AI coding agent runtime proof prototype.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    corpus = subparsers.add_parser("corpus", help="Inspect pinned real-world Skill/tool corpora.")
    corpus_sub = corpus.add_subparsers(dest="corpus_command", required=True)
    corpus_scan = corpus_sub.add_parser("scan", help="Scan pinned real corpus snapshots for capability and risk surface.")
    corpus_scan.add_argument("--root", default="benchmarks/corpora")

    identity = subparsers.add_parser("identity", help="Declare principals, bind agent identity, and inspect accountability facts.")
    identity_sub = identity.add_subparsers(dest="identity_command", required=True)
    identity_declare = identity_sub.add_parser("declare", help="Declare a local principal.")
    identity_declare.add_argument("--principal", required=True)
    identity_declare.add_argument("--display-name", default=None)
    identity_declare.add_argument("--source", default="local")
    identity_declare.add_argument("--out", default=None)
    identity_bind = identity_sub.add_parser("bind", help="Append principal, agent, credential, and grant facts to a ledger.")
    identity_bind.add_argument("--ledger", required=True)
    identity_bind.add_argument("--session", required=True)
    identity_bind.add_argument("--principal", required=True)
    identity_bind.add_argument("--agent", required=True)
    identity_bind.add_argument("--adapter-agent", default=None)
    identity_bind.add_argument("--scope", action="append", default=[])
    identity_bind.add_argument("--resource", action="append", default=[])
    identity_bind.add_argument("--env-key", action="append", default=[])
    identity_inspect = identity_sub.add_parser("inspect", help="Inspect accountability facts from a ledger.")
    identity_inspect.add_argument("--ledger", required=True)

    daemon = subparsers.add_parser("daemon", help="Runtime authority and session registry commands.")
    daemon_sub = daemon.add_subparsers(dest="daemon_command", required=True)
    daemon_init = daemon_sub.add_parser("init", help="Initialize the local runtime authority registry.")
    daemon_init.add_argument("--target", default=".")
    daemon_status = daemon_sub.add_parser("status", help="Show local runtime authority status.")
    daemon_status.add_argument("--target", default=".")
    daemon_record = daemon_sub.add_parser("record-event", help="Record a runtime event through the authority.")
    daemon_record.add_argument("--target", default=".")
    daemon_record.add_argument("--session", required=True)
    daemon_record.add_argument("--event", required=True)
    daemon_record.add_argument("--review", choices=("off", "auto", "always", "required"), default="auto")
    daemon_record.add_argument("--policy-mode", choices=("audit", "advisory", "managed", "ci"), default="advisory")
    daemon_record.add_argument("--policy-profile", choices=("balanced", "strict", "audit"), default="balanced")
    daemon_record.add_argument("--reviewer", choices=("heuristic", "llm"), default="heuristic")
    add_profile_args(daemon_record)
    daemon_heartbeat = daemon_sub.add_parser("heartbeat", help="Update session heartbeat metadata.")
    daemon_heartbeat.add_argument("--target", default=".")
    daemon_heartbeat.add_argument("--session", required=True)
    daemon_heartbeat.add_argument("--actor", default=None)
    daemon_register = daemon_sub.add_parser("register-capabilities", help="Register scanned adapter/skill capabilities into a session ledger.")
    daemon_register.add_argument("--target", default=".")
    daemon_register.add_argument("--session", required=True)
    daemon_register.add_argument("--corpus-root", default="benchmarks/corpora")
    daemon_register.add_argument("--adapter", default="unknown")
    daemon_register.add_argument("--review", choices=("off", "auto", "always", "required"), default="off")
    daemon_register.add_argument("--policy-mode", choices=("audit", "advisory", "managed", "ci"), default="managed")
    daemon_register.add_argument("--policy-profile", choices=("balanced", "strict", "audit"), default="balanced")
    daemon_register.add_argument("--reviewer", choices=("heuristic", "llm"), default="heuristic")
    add_profile_args(daemon_register)
    daemon_approve = daemon_sub.add_parser("approve", help="Resolve a pending approval through the authority.")
    daemon_approve.add_argument("--target", default=".")
    daemon_approve.add_argument("--session", required=True)
    daemon_approve.add_argument("--decision", required=True)
    daemon_approve.add_argument("--approver", default=None)
    daemon_approve.add_argument("--reason", default=None)
    daemon_reject = daemon_sub.add_parser("reject", help="Reject a pending approval through the authority.")
    daemon_reject.add_argument("--target", default=".")
    daemon_reject.add_argument("--session", required=True)
    daemon_reject.add_argument("--decision", required=True)
    daemon_reject.add_argument("--approver", default=None)
    daemon_reject.add_argument("--reason", default=None)
    daemon_outcome = daemon_sub.add_parser("outcome", help="Record execution outcome through the authority.")
    daemon_outcome.add_argument("--target", default=".")
    daemon_outcome.add_argument("--session", required=True)
    daemon_outcome.add_argument("--decision", default=None)
    daemon_outcome.add_argument("--invocation", default=None)
    daemon_outcome.add_argument("--status", choices=("executed", "blocked", "skipped", "overridden", "failed"), required=True)
    daemon_outcome.add_argument("--actor", default=None)
    daemon_outcome.add_argument("--reason", default=None)
    daemon_session = daemon_sub.add_parser("session", help="Manage authority sessions.")
    daemon_session_sub = daemon_session.add_subparsers(dest="daemon_session_command", required=True)
    daemon_session_create = daemon_session_sub.add_parser("create", help="Create and register a managed session.")
    daemon_session_create.add_argument("--target", default=".")
    daemon_session_create.add_argument("--agent", default=None)
    daemon_session_create.add_argument("--goal", default=None)
    daemon_session_create.add_argument("--session-id", default=None)
    daemon_session_create.add_argument("--ledger", default=None)
    daemon_session_create.add_argument("--preflight", default=None)
    daemon_session_create.add_argument("--no-preflight", action="store_true")
    add_profile_args(daemon_session_create)
    daemon_session_list = daemon_session_sub.add_parser("list", help="List registered sessions.")
    daemon_session_list.add_argument("--target", default=".")
    daemon_session_list.add_argument("--include-deleted", action="store_true")
    daemon_session_show = daemon_session_sub.add_parser("show", help="Show a registered session.")
    daemon_session_show.add_argument("--target", default=".")
    daemon_session_show.add_argument("--session", required=True)
    for _name in ("pause", "resume", "interrupt", "stop", "delete"):
        _parser = daemon_session_sub.add_parser(_name, help=f"{_name.capitalize()} a registered session.")
        _parser.add_argument("--target", default=".")
        _parser.add_argument("--session", required=True)
        _parser.add_argument("--reason", default=None)

    pre = subparsers.add_parser("pre-runtime", help="Scan environment, target, agent config, MCP, and Skills.")
    pre.add_argument("--target", default=".", help="Runtime target directory to scan.")
    pre.add_argument("--no-home", action="store_true", help="Do not inspect user-level agent config.")
    pre.add_argument("--output", choices=("json", "text"), default="json")
    pre.add_argument("--save", action="store_true", help="Persist the preflight baseline for later session/proof reference.")
    pre.add_argument("--preflight", default=None, help="Path to write the preflight baseline when --save is used.")

    session = subparsers.add_parser("session", help="Managed session helpers.")
    session_sub = session.add_subparsers(dest="session_command", required=True)
    session_start = session_sub.add_parser("start", help="Start a managed session and create a ledger.")
    session_start.add_argument("--target", default=".")
    session_start.add_argument("--agent", default=None)
    session_start.add_argument("--goal", default=None)
    session_start.add_argument("--session-id", default=None)
    session_start.add_argument("--ledger", default=None)
    session_start.add_argument("--preflight", default=None)
    session_start.add_argument("--no-preflight", action="store_true")
    session_run = session_sub.add_parser("run", help="Start a session, run a child command, and close the session.")
    session_run.add_argument("--target", default=".")
    session_run.add_argument("--agent", default=None)
    session_run.add_argument("--goal", default=None)
    session_run.add_argument("--session-id", default=None)
    session_run.add_argument("--ledger", default=None)
    session_run.add_argument("--preflight", default=None)
    session_run.add_argument("--no-preflight", action="store_true")
    session_run.add_argument("cmd", nargs=argparse.REMAINDER)
    session_close = session_sub.add_parser("close", help="Close a managed session ledger.")
    session_close.add_argument("--ledger", required=True)
    session_close.add_argument("--status", choices=("closed", "aborted"), default="closed")

    run = subparsers.add_parser("run", help="Alias for session run: start a managed session, run a child command, and close it.")
    run.add_argument("--target", default=".")
    run.add_argument("--agent", default=None)
    run.add_argument("--goal", default=None)
    run.add_argument("--session-id", default=None)
    run.add_argument("--ledger", default=None)
    run.add_argument("--preflight", default=None)
    run.add_argument("--no-preflight", action="store_true")
    run.add_argument("cmd", nargs=argparse.REMAINDER)

    adapter = subparsers.add_parser("adapter", help="Reference adapter wrapper workflows.")
    adapter_sub = adapter.add_subparsers(dest="adapter_command", required=True)
    adapter_run = adapter_sub.add_parser("run", help="Run a child command through a Kappaski reference adapter wrapper.")
    adapter_run.add_argument("--target", default=".")
    adapter_run.add_argument("--agent", default=None)
    adapter_run.add_argument("--goal", default=None)
    adapter_run.add_argument("--session-id", default=None)
    adapter_run.add_argument("--out-dir", default=None)
    adapter_run.add_argument("--corpus-root", default="benchmarks/corpora")
    adapter_run.add_argument("--capabilities", choices=("off", "audit", "managed"), default="audit")
    adapter_run.add_argument("--gate", choices=("off", "audit", "managed", "ci"), default="off")
    adapter_run.add_argument("--policy-mode", choices=("audit", "advisory", "managed", "ci"), default="advisory")
    adapter_run.add_argument("--enforcement", choices=("off", "file-write"), default="off")
    adapter_run.add_argument("--no-preflight", action="store_true")
    adapter_run.add_argument("cmd", nargs=argparse.REMAINDER)
    adapter_inspect = adapter_sub.add_parser("inspect", help="Inspect and verify an adapter runtime package manifest.")
    adapter_inspect.add_argument("--package", required=True)
    adapter_package = adapter_sub.add_parser("package", help="Package an existing adapter ledger into an evidence bundle.")
    adapter_package.add_argument("--ledger", required=True)
    adapter_package.add_argument("--out-dir", required=True)
    adapter_profile = adapter_sub.add_parser("profile", help="Inspect a hardened adapter profile.")
    adapter_profile.add_argument("--kind", choices=("claude-code", "codex", "generic"), default="claude-code")
    adapter_claude_check = adapter_sub.add_parser("claude-code-check", help="Check a real Claude Code binary environment when available.")
    adapter_claude_check.add_argument("--binary", default="claude")
    adapter_claude = adapter_sub.add_parser("claude-code", help="Run a command through the Claude Code wrapper/hook bridge.")
    adapter_claude.add_argument("--target", default=".")
    adapter_claude.add_argument("--out-dir", default=None)
    adapter_claude.add_argument("--hook-events", default=None)
    adapter_claude.add_argument("--session-id", default=None)
    adapter_claude.add_argument("--no-preflight", action="store_true")
    adapter_claude.add_argument("--enforcement", choices=("off", "file-write"), default="off")
    adapter_claude.add_argument("cmd", nargs=argparse.REMAINDER)

    harness = subparsers.add_parser("harness", help="Compare real agent harness compatibility artifacts.")
    harness_sub = harness.add_subparsers(dest="harness_command", required=True)
    harness_compare = harness_sub.add_parser("compare", help="Compare baseline and Kappaski-wrapped harness artifacts.")
    harness_compare.add_argument("--baseline", required=True)
    harness_compare.add_argument("--wrapped", required=True)
    harness_compare.add_argument("--case", default=None)
    harness_swe = harness_sub.add_parser("swe-bench-lite", help="Run or compare optional SWE-Bench Lite harness artifacts.")
    harness_swe.add_argument("--case", required=True)
    harness_swe.add_argument("--baseline-artifact", default=None)
    harness_swe.add_argument("--wrapped-artifact", default=None)
    harness_swe.add_argument("--out", default=None)
    harness_swe.add_argument("--dependency", default="docker")
    harness_swe.add_argument("--skip-if-unavailable", action="store_true")
    harness_swe.add_argument("--baseline-command", default=None, help="Command that produces the baseline artifact as its last argument.")
    harness_swe.add_argument("--wrapped-command", default=None, help="Command that produces the Kappaski-wrapped artifact as its last argument.")
    harness_official = harness_sub.add_parser("swe-bench-official", help="Run the official SWE-Bench Lite harness entrypoint when installed.")
    harness_official.add_argument("--python", default="python")
    harness_official.add_argument("--dataset-name", default=SWE_BENCH_LITE_DATASET)
    harness_official.add_argument("--split", default="test")
    harness_official.add_argument("--instance-id", action="append", default=[])
    harness_official.add_argument("--predictions-path", default="gold")
    harness_official.add_argument("--run-id", default="kappaski_smoke")
    harness_official.add_argument("--report-dir", default=None)
    harness_official.add_argument("--timeout", type=int, default=60)
    harness_official.add_argument("--max-workers", type=int, default=1)
    harness_official.add_argument("--cache-level", default="instance")
    harness_official.add_argument("--clean", action="store_true")
    harness_official.add_argument("--work-dir", default=None)
    harness_official.add_argument("--out", default=None)
    harness_official.add_argument("--command", dest="override_command", default=None, help="Override command for test or custom harness use.")
    harness_official.add_argument("--report-path", default=None, help="Explicit official report JSON path for command override.")
    harness_managed = harness_sub.add_parser("managed-check", help="Run a command through managed harness pause/approval/resume compatibility flow.")
    harness_managed.add_argument("--target", default=".")
    harness_managed.add_argument("--case", default=None)
    harness_managed.add_argument("--approval-actor", default="human-approver")
    harness_managed.add_argument("cmd", nargs=argparse.REMAINDER)

    external_validation = subparsers.add_parser("external-validation", help="Run explicit optional upstream/live benchmark validation.")
    external_validation_sub = external_validation.add_subparsers(dest="external_validation_command", required=True)
    swe_full = external_validation_sub.add_parser("swe-bench-full", help="Run and validate the official full SWE-Bench evaluation chain.")
    swe_full.add_argument("--python", default="python")
    swe_full.add_argument("--dataset-name", default=SWE_BENCH_FULL_DATASET)
    swe_full.add_argument("--split", default="test")
    swe_full.add_argument("--predictions-path", default="gold")
    swe_full.add_argument("--run-id", default="kappaski_swe_bench_full")
    swe_full.add_argument("--report-dir", default=None)
    swe_full.add_argument("--timeout", type=int, default=1800)
    swe_full.add_argument("--max-workers", type=int, default=1)
    swe_full.add_argument("--cache-level", default="instance")
    swe_full.add_argument("--clean", action="store_true")
    swe_full.add_argument("--work-dir", default=None)
    swe_full.add_argument("--out", default=None)
    swe_full.add_argument("--command", dest="override_command", default=None, help="Override command for contract tests or custom official harness use.")
    swe_full.add_argument("--report-path", default=None, help="Explicit official report JSON path.")
    swe_full.add_argument("--instance-results-path", default=None, help="Explicit official instance_results.jsonl path.")
    swe_full.add_argument("--expected-total-instances", type=int, default=SWE_BENCH_FULL_EXPECTED_INSTANCES)
    swe_full.add_argument("--allow-subset", action="store_true", help="Mark this as a subset smoke run; it will not satisfy full external validation.")

    profile = subparsers.add_parser("profile", help="Resolve TOML/JSON policy profiles with session > repo > team precedence.")
    profile_sub = profile.add_subparsers(dest="profile_command", required=True)
    profile_resolve = profile_sub.add_parser("resolve", help="Resolve policy profile precedence.")
    profile_resolve.add_argument("--team", default=None)
    profile_resolve.add_argument("--repo", default=None)
    profile_resolve.add_argument("--session", default=None)
    profile_break_glass = profile_sub.add_parser("break-glass", help="Record a ledger-backed break-glass override.")
    profile_break_glass.add_argument("--ledger", required=True)
    profile_break_glass.add_argument("--session", required=True)
    profile_break_glass.add_argument("--actor", required=True)
    profile_break_glass.add_argument("--reason", required=True)
    profile_break_glass.add_argument("--scope", required=True)
    profile_break_glass.add_argument("--expires-at", default=None)
    profile_distribute = profile_sub.add_parser("distribute", help="Create a signed profile distribution bundle.")
    profile_distribute.add_argument("--profile", required=True)
    profile_distribute.add_argument("--scope", choices=("team", "repo", "session"), required=True)
    profile_distribute.add_argument("--distributed-by", required=True)
    profile_review = profile_sub.add_parser("review-override", help="Record administrator/auditor review of a break-glass override.")
    profile_review.add_argument("--ledger", required=True)
    profile_review.add_argument("--override", required=True)
    profile_review.add_argument("--reviewer", required=True)
    profile_review.add_argument("--status", choices=("approved", "rejected"), required=True)
    profile_review.add_argument("--reason", required=True)
    profile_registry = profile_sub.add_parser("registry", help="Create an enterprise profile registry from inline profile JSON.")
    profile_registry.add_argument("--owner", required=True)
    profile_registry.add_argument("--profile", action="append", required=True)
    profile_pin = profile_sub.add_parser("pin", help="Pin a profile from a registry JSON file.")
    profile_pin.add_argument("--registry", required=True)
    profile_pin.add_argument("--scope", choices=("team", "repo", "session"), required=True)
    profile_pin.add_argument("--name", required=True)
    profile_pin.add_argument("--distributed-by", required=True)
    profile_pin.add_argument("--out", default=None)
    profile_verify = profile_sub.add_parser("verify", help="Verify a pinned profile bundle against a registry.")
    profile_verify.add_argument("--registry", required=True)
    profile_verify.add_argument("--bundle", required=True)

    teamrun = subparsers.add_parser("teamrun", help="Create and inspect multi-user TeamRun and Handoff records.")
    teamrun_sub = teamrun.add_subparsers(dest="teamrun_command", required=True)
    teamrun_create = teamrun_sub.add_parser("create", help="Create a TeamRun record.")
    teamrun_create.add_argument("--ledger", default=None)
    teamrun_create.add_argument("--name", required=True)
    teamrun_create.add_argument("--user", action="append", default=[])
    teamrun_identity = teamrun_sub.add_parser("identity", help="Declare and validate agent identity.")
    teamrun_identity.add_argument("--ledger", default=None)
    teamrun_identity.add_argument("--agent", required=True)
    teamrun_identity.add_argument("--declared-by", required=True)
    teamrun_identity.add_argument("--adapter-agent", default=None)
    teamrun_handoff = teamrun_sub.add_parser("handoff", help="Create a Handoff record.")
    teamrun_handoff.add_argument("--ledger", default=None)
    teamrun_handoff.add_argument("--source-agent", required=True)
    teamrun_handoff.add_argument("--target-agent", required=True)
    teamrun_handoff.add_argument("--resource", action="append", default=[])
    teamrun_handoff.add_argument("--taint-mode", choices=("resource-reference", "session-wide"), default="resource-reference")
    teamrun_handoff.add_argument("--session-tainted", action="store_true")
    teamrun_blackboard = teamrun_sub.add_parser("blackboard", help="Record a TeamRun blackboard entry.")
    teamrun_blackboard.add_argument("--ledger", required=True)
    teamrun_blackboard.add_argument("--teamrun", required=True)
    teamrun_blackboard.add_argument("--author", required=True)
    teamrun_blackboard.add_argument("--content", required=True)
    teamrun_blackboard.add_argument("--resource", action="append", default=[])
    teamrun_delegate = teamrun_sub.add_parser("delegate-grant", help="Record a restrict-only grant delegation.")
    teamrun_delegate.add_argument("--ledger", required=True)
    teamrun_delegate.add_argument("--source-agent", required=True)
    teamrun_delegate.add_argument("--target-agent", required=True)
    teamrun_delegate.add_argument("--parent-scope", required=True)
    teamrun_delegate.add_argument("--delegate-scope", required=True)
    teamrun_proof = teamrun_sub.add_parser("proof", help="Export TeamRun proof facts from a ledger.")
    teamrun_proof.add_argument("--ledger", required=True)
    teamrun_proof.add_argument("--out", default=None)
    teamrun_aggregate = teamrun_sub.add_parser("aggregate", help="Aggregate TeamRun proof facts across multiple ledgers.")
    teamrun_aggregate.add_argument("--ledger", action="append", required=True)
    teamrun_aggregate.add_argument("--out", default=None)
    teamrun_timeline = teamrun_sub.add_parser("timeline", help="Export a multi-ledger TeamRun timeline HTML report.")
    teamrun_timeline.add_argument("--ledger", action="append", required=True)
    teamrun_timeline.add_argument("--out", required=True)

    enforce = subparsers.add_parser("enforce", help="Evaluate enforcement guard decisions.")
    enforce_sub = enforce.add_subparsers(dest="enforce_command", required=True)
    enforce_check = enforce_sub.add_parser("check", help="Check an event against an enforcement domain.")
    enforce_check.add_argument("--event", required=True)
    enforce_check.add_argument("--domain", choices=("file-write", "env-secrets", "network-egress"), default="file-write")
    add_profile_args(enforce_check)
    enforce_shim_spec = enforce_sub.add_parser("shim-spec", help="Show Rust shim contract and source availability.")
    enforce_shim_spec.add_argument("--domain", choices=("file-write",), default="file-write")
    enforce_build = enforce_sub.add_parser("rust-build-check", help="Run cargo check for the Rust shim when cargo is available.")
    enforce_build.add_argument("--skip-if-unavailable", action="store_true")
    enforce_shim_decision = enforce_sub.add_parser("shim-decision", help="Evaluate an event with the compiled Rust shim.")
    enforce_shim_decision.add_argument("--event", required=True)
    enforce_shim_decision.add_argument("--crate", default=None)
    enforce_run = enforce_sub.add_parser("run-file-write", help="Run a command through the Rust file-write shim before execution.")
    enforce_run.add_argument("--ledger", default=None)
    enforce_run.add_argument("--session", default=None)
    enforce_run.add_argument("--target", default=None)
    enforce_run.add_argument("--allow-approval-required", action="store_true", help="Execute require_approval commands in open/audit-style mode.")
    enforce_run.add_argument("--crate", default=None)
    enforce_run.add_argument("cmd", nargs=argparse.REMAINDER)
    enforce_run_domain = enforce_sub.add_parser("run", help="Run a command through a selected enforcement domain before execution.")
    enforce_run_domain.add_argument("--domain", choices=("file-write", "env-secrets", "network-egress"), required=True)
    enforce_run_domain.add_argument("--event", default=None)
    enforce_run_domain.add_argument("--ledger", default=None)
    enforce_run_domain.add_argument("--session", default=None)
    enforce_run_domain.add_argument("--target", default=None)
    enforce_run_domain.add_argument("--allow-approval-required", action="store_true")
    enforce_run_domain.add_argument("cmd", nargs=argparse.REMAINDER)

    native = subparsers.add_parser("native", help="Inspect and manage native agent integration surfaces.")
    native_sub = native.add_subparsers(dest="native_command", required=True)
    native_inventory = native_sub.add_parser("inventory", help="Inventory hooks, plugins, extensions, rules, MCP, sandbox, and config surfaces.")
    native_inventory.add_argument("--target", default=".")
    native_inventory.add_argument("--include-global-config", action="store_true")
    native_install = native_sub.add_parser("install", help="Preview or install native Kappaski hook/plugin config.")
    native_install.add_argument("--target", default=".")
    native_install.add_argument("--agent", choices=("claude-code", "codex", "opencode"), required=True)
    native_install.add_argument("--confirm", action="store_true")
    native_conformance = native_sub.add_parser("conformance", help="Hash and validate discovered native integration surfaces.")
    native_conformance.add_argument("--target", default=".")
    native_conformance.add_argument("--include-global-config", action="store_true")

    bridge = subparsers.add_parser("bridge", help="Native hook/plugin bridge commands.")
    bridge_sub = bridge.add_subparsers(dest="bridge_command", required=True)
    bridge_native = bridge_sub.add_parser("native", help="Normalize a native hook payload and return a native response.")
    bridge_native.add_argument("--agent", choices=("claude-code", "codex", "opencode", "generic"), required=True)
    bridge_native.add_argument("--event", required=True)
    bridge_conformance = bridge_sub.add_parser("conformance", help="Run native bridge response-shape conformance checks.")

    mcp = subparsers.add_parser("mcp", help="MCP broker and inspection commands.")
    mcp_sub = mcp.add_subparsers(dest="mcp_command", required=True)
    mcp_broker = mcp_sub.add_parser("broker-step", help="Run one transparent MCP broker step for a JSON message.")
    mcp_broker.add_argument("--message", required=True)
    mcp_stdio = mcp_sub.add_parser("broker-stdio", help="Run a transparent JSONL stdio broker with transcript capture.")
    mcp_stdio.add_argument("--input", required=True)
    mcp_stdio.add_argument("--output", required=True)
    mcp_stdio.add_argument("--transcript", required=True)

    coverage = subparsers.add_parser("coverage", help="Export coverage-aware proof reports.")
    coverage_sub = coverage.add_subparsers(dest="coverage_command", required=True)
    coverage_html = coverage_sub.add_parser("html", help="Export a coverage matrix HTML report from proof JSON.")
    coverage_html.add_argument("--proof", required=True)
    coverage_html.add_argument("--out", required=True)

    graph = subparsers.add_parser("graph", help="Export and query ledger-derived execution path graphs.")
    graph_sub = graph.add_subparsers(dest="graph_command", required=True)
    graph_export = graph_sub.add_parser("export", help="Export execution graph JSON.")
    graph_export.add_argument("--ledger", required=True)
    graph_export.add_argument("--out", required=True)
    graph_html = graph_sub.add_parser("html", help="Export execution graph HTML.")
    graph_html.add_argument("--ledger", required=True)
    graph_html.add_argument("--out", required=True)
    graph_query = graph_sub.add_parser("query", help="Query graph upstream or downstream from a node.")
    graph_query.add_argument("--ledger", required=True)
    graph_query.add_argument("--target", required=True)
    graph_query.add_argument("--direction", choices=("upstream", "downstream"), default="upstream")

    mediation = subparsers.add_parser("mediation", help="Inspect and resolve unified mediation records.")
    mediation_sub = mediation.add_subparsers(dest="mediation_command", required=True)
    mediation_inspect = mediation_sub.add_parser("inspect", help="Replay mediation events from a ledger.")
    mediation_inspect.add_argument("--ledger", required=True)
    mediation_resolve = mediation_sub.add_parser("resolve", help="Resolve a paused mediation item.")
    mediation_resolve.add_argument("--ledger", required=True)
    mediation_resolve.add_argument("--mediation", required=True)
    mediation_resolve.add_argument("--actor", required=True)
    mediation_resolve.add_argument("--status", choices=("approved", "rejected"), required=True)
    mediation_resolve.add_argument("--reason", required=True)
    mediation_replay = mediation_sub.add_parser("replay", help="Replay mediation records from a ledger.")
    mediation_replay.add_argument("--ledger", required=True)

    supervise = subparsers.add_parser("supervise", help="Run process-group supervision checks.")
    supervise_sub = supervise.add_subparsers(dest="supervise_command", required=True)
    supervise_run = supervise_sub.add_parser("run", help="Run a command under process-group supervision.")
    supervise_run.add_argument("--target", default=None)
    supervise_run.add_argument("cmd", nargs=argparse.REMAINDER)

    runtime = subparsers.add_parser("runtime", help="Runtime audit helpers.")
    runtime_sub = runtime.add_subparsers(dest="runtime_command", required=True)
    analyze = runtime_sub.add_parser("analyze-event", help="Analyze a runtime event JSON payload.")
    analyze.add_argument("--event", required=True, help="JSON event payload.")
    analyze.add_argument("--session", default=None)
    analyze.add_argument("--ledger", default=None)
    analyze.add_argument("--review", choices=("off", "auto", "always", "required"), default="auto")
    analyze.add_argument("--policy-mode", choices=("audit", "advisory", "managed", "ci"), default="advisory")
    analyze.add_argument("--policy-profile", choices=("balanced", "strict", "audit"), default="balanced")
    analyze.add_argument("--reviewer", choices=("heuristic", "llm"), default="heuristic")
    add_profile_args(analyze)
    record = runtime_sub.add_parser("record-event", help="Append a runtime event to a v0.1 ledger.")
    record.add_argument("--event", required=True, help="JSON event payload.")
    record.add_argument("--session", default=None)
    record.add_argument("--ledger", "--log", default=".kappaski/session.jsonl", help="JSONL ledger path.")
    record.add_argument("--review", choices=("off", "auto", "always", "required"), default="auto")
    record.add_argument("--policy-mode", choices=("audit", "advisory", "managed", "ci"), default="advisory")
    record.add_argument("--policy-profile", choices=("balanced", "strict", "audit"), default="balanced")
    record.add_argument("--reviewer", choices=("heuristic", "llm"), default="heuristic")
    add_profile_args(record)
    shell = runtime_sub.add_parser("shell", help="Run a shell command with audit logging and policy decisions.")
    shell.add_argument("--session", default=None)
    shell.add_argument("--ledger", "--log", default=".kappaski/session.jsonl", help="JSONL ledger path.")
    shell.add_argument("--agent", default=None)
    shell.add_argument("--target", default=None)
    shell.add_argument("--review", choices=("off", "auto", "always", "required"), default="auto")
    shell.add_argument("--policy-mode", choices=("audit", "advisory", "managed", "ci"), default="advisory")
    shell.add_argument("--policy-profile", choices=("balanced", "strict", "audit"), default="balanced")
    shell.add_argument("--reviewer", choices=("heuristic", "llm"), default="heuristic")
    add_profile_args(shell)
    shell.add_argument("cmd", nargs=argparse.REMAINDER, help="Command to run after --.")
    approve = runtime_sub.add_parser("approve", help="Record approval evidence for a policy decision.")
    approve.add_argument("--ledger", required=True)
    approve.add_argument("--decision", required=True)
    approve.add_argument("--approver", default=None)
    approve.add_argument("--reason", default=None)
    reject = runtime_sub.add_parser("reject", help="Record rejection evidence for a policy decision.")
    reject.add_argument("--ledger", required=True)
    reject.add_argument("--decision", required=True)
    reject.add_argument("--approver", default=None)
    reject.add_argument("--reason", default=None)
    outcome = runtime_sub.add_parser("outcome", help="Record the observed execution outcome for a decision or invocation.")
    outcome.add_argument("--ledger", required=True)
    outcome.add_argument("--decision", default=None)
    outcome.add_argument("--invocation", default=None)
    outcome.add_argument("--status", choices=("executed", "blocked", "skipped", "overridden", "failed"), required=True)
    outcome.add_argument("--actor", default=None)
    outcome.add_argument("--reason", default=None)

    approval = subparsers.add_parser("approval", help="List and resolve approval inbox items.")
    approval_sub = approval.add_subparsers(dest="approval_command", required=True)
    approval_list = approval_sub.add_parser("list", help="List approval items from a ledger.")
    approval_list.add_argument("--ledger", required=True)
    approval_list.add_argument("--status", default=None)
    approval_approve = approval_sub.add_parser("approve", help="Approve one decision or all missing approvals.")
    approval_approve.add_argument("--ledger", required=True)
    approval_approve.add_argument("--decision", default=None)
    approval_approve.add_argument("--all", action="store_true")
    approval_approve.add_argument("--approver", default=None)
    approval_approve.add_argument("--reason", default=None)
    approval_reject = approval_sub.add_parser("reject", help="Reject one decision or all missing approvals.")
    approval_reject.add_argument("--ledger", required=True)
    approval_reject.add_argument("--decision", default=None)
    approval_reject.add_argument("--all", action="store_true")
    approval_reject.add_argument("--approver", default=None)
    approval_reject.add_argument("--reason", default=None)

    replay = subparsers.add_parser("replay", help="Export runtime replay reports.")
    replay_sub = replay.add_subparsers(dest="replay_command", required=True)
    replay_export = replay_sub.add_parser("export", help="Export a static HTML replay report.")
    replay_export.add_argument("--ledger", required=True)
    replay_export.add_argument("--out", required=True)
    replay_export.add_argument("--gate-mode", choices=("audit", "managed", "ci"), default="managed")
    replay_export.add_argument("--case", default=None)
    replay_export.add_argument("--no-raw", action="store_true")
    add_profile_args(replay_export)

    policy = subparsers.add_parser("policy", help="Inspect policy decisions and merged evaluations.")
    policy_sub = policy.add_subparsers(dest="policy_command", required=True)
    policy_validate = policy_sub.add_parser("validate", help="Validate a Kappaski-native policy-as-code profile.")
    policy_validate.add_argument("--profile", required=True)
    policy_test = policy_sub.add_parser("test", help="Run built-in product tests against a policy-as-code profile.")
    policy_test.add_argument("--profile", required=True)
    policy_explain = policy_sub.add_parser("explain", help="Explain a policy decision from the ledger.")
    policy_explain.add_argument("--ledger", required=True)
    policy_explain.add_argument("--decision", default=None)
    policy_explain.add_argument("--invocation", default=None)
    policy_check_path = policy_sub.add_parser("check-path", help="Evaluate path-aware policy over a ledger.")
    policy_check_path.add_argument("--ledger", required=True)
    policy_check_path.add_argument("--profile", default=None)
    policy_check_path.add_argument("--out", default=None)

    review = subparsers.add_parser("review", help="Inspect semantic review records.")
    review_sub = review.add_subparsers(dest="review_command", required=True)
    review_invocation = review_sub.add_parser("invocation", help="Show semantic review output for an invocation.")
    review_invocation.add_argument("--ledger", required=True)
    review_invocation.add_argument("--invocation", required=True)
    review_invocation.add_argument("--review", default=None)

    eval_parser = subparsers.add_parser("eval", help="Run Kappaski effectiveness benchmarks.")
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

    gate = subparsers.add_parser("gate", help="Consume proof and ledger artifacts as release/CI gates.")
    gate_sub = gate.add_subparsers(dest="gate_command", required=True)
    gate_verify = gate_sub.add_parser("verify", help="Evaluate proof/ledger artifacts against a gate mode.")
    gate_verify.add_argument("--proof", default=None)
    gate_verify.add_argument("--ledger", default=None)
    gate_verify.add_argument("--mode", choices=("audit", "managed", "ci"), default="managed")
    gate_verify.add_argument("--out", default=None)
    add_profile_args(gate_verify)

    proof = subparsers.add_parser("proof", help="Export or verify proof reports.")
    proof_sub = proof.add_subparsers(dest="proof_command", required=True)
    proof_export = proof_sub.add_parser("export", help="Export a proof JSON report.")
    proof_export.add_argument("--ledger", "--events", default=".kappaski/session.jsonl")
    proof_export.add_argument("--out", "--output", default=None)
    proof_verify = proof_sub.add_parser("verify", help="Verify a proof, a ledger, or both.")
    proof_verify.add_argument("--proof", default=None)
    proof_verify.add_argument("--ledger", "--events", default=None)

    evidence = subparsers.add_parser("evidence", help="Export and verify enterprise evidence bundles.")
    evidence_sub = evidence.add_subparsers(dest="evidence_command", required=True)
    evidence_export = evidence_sub.add_parser("export", help="Export a v0.27 evidence bundle from a ledger.")
    evidence_export.add_argument("--ledger", required=True)
    evidence_export.add_argument("--out-dir", required=True)
    evidence_export.add_argument("--profile", default=None)
    evidence_verify = evidence_sub.add_parser("verify", help="Verify an evidence bundle manifest.")
    evidence_verify.add_argument("--bundle", required=True)

    audit = subparsers.add_parser("audit", help="Generate audit reports from runtime evidence.")
    audit_sub = audit.add_subparsers(dest="audit_command", required=True)
    audit_report = audit_sub.add_parser("report", help="Export audit JSON/HTML through an evidence bundle.")
    audit_report.add_argument("--ledger", required=True)
    audit_report.add_argument("--out-dir", required=True)


    roadmap = subparsers.add_parser("roadmap", help="Inspect implementation coverage against the roadmap.")
    roadmap_sub = roadmap.add_subparsers(dest="roadmap_command", required=True)
    roadmap_status = roadmap_sub.add_parser("status", help="Show roadmap implementation coverage and gaps.")
    roadmap_status.add_argument("--require-full", action="store_true")
    roadmap_status.add_argument("--require-external-validation", action="store_true", help="Fail if optional external/live benchmark validation has not been run.")

    demo = subparsers.add_parser("demo", help="Generate packaged product demos and audit artifacts.")
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

    post = subparsers.add_parser("post-runtime", help="Summarize a JSONL runtime audit log.")
    post.add_argument("--events", default=".kappaski/session.jsonl", help="JSONL event log path.")

    for rc_name in ("release-candidate", "rc"):
        rc_parser = subparsers.add_parser(rc_name, help="Run the v0.40 release-candidate readiness gate.")
        rc_sub = rc_parser.add_subparsers(dest="rc_command", required=True)
        rc_verify = rc_sub.add_parser("verify", help="Verify pytest, roadmap, benchmarks, docs, and artifacts.")
        rc_verify.add_argument("--out-dir", required=True)
        rc_verify.add_argument("--skip-pytest", action="store_true")

    args = parser.parse_args(argv)
    if args.command == "corpus":
        return handle_corpus(args)
    if args.command == "identity":
        return handle_identity(args)
    if args.command == "daemon":
        return handle_daemon(args)
    if args.command == "pre-runtime":
        if args.save:
            preflight = save_preflight(Path(args.target), Path(args.preflight) if args.preflight else None, include_home=not args.no_home)
            return emit(preflight, args.output)
        report = scan_pre_runtime(Path(args.target), include_home=not args.no_home)
        return emit(report.to_dict(), args.output)
    if args.command == "session":
        return handle_session(args)
    if args.command == "run":
        args.session_command = "run"
        return handle_session(args)
    if args.command == "adapter":
        return handle_adapter(args)
    if args.command == "harness":
        return handle_harness(args)
    if args.command == "external-validation":
        return handle_external_validation(args)
    if args.command == "profile":
        return handle_profile(args)
    if args.command == "teamrun":
        return handle_teamrun(args)
    if args.command == "enforce":
        return handle_enforce(args)
    if args.command == "native":
        return handle_native(args)
    if args.command == "bridge":
        return handle_bridge(args)
    if args.command == "mcp":
        return handle_mcp(args)
    if args.command == "coverage":
        return handle_coverage(args)
    if args.command == "graph":
        return handle_graph(args)
    if args.command == "mediation":
        return handle_mediation(args)
    if args.command == "supervise":
        return handle_supervise(args)
    if args.command == "roadmap":
        return handle_roadmap(args)
    if args.command == "demo":
        return handle_demo(args)
    if args.command == "runtime":
        return handle_runtime(args)
    if args.command == "approval":
        return handle_approval(args)
    if args.command == "replay":
        return handle_replay(args)
    if args.command == "policy":
        return handle_policy(args)
    if args.command == "review":
        return handle_review(args)
    if args.command == "eval":
        return handle_eval(args)
    if args.command == "experiment":
        return handle_experiment(args)
    if args.command == "gate":
        return handle_gate(args)
    if args.command == "proof":
        return handle_proof(args)
    if args.command == "evidence":
        return handle_evidence(args)
    if args.command == "audit":
        return handle_audit(args)
    if args.command == "post-runtime":
        print(json.dumps(summarize_session(Path(args.events)), ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    if args.command in {"release-candidate", "rc"}:
        return handle_release_candidate(args)
    return 2




def add_profile_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--team-profile", default=None)
    parser.add_argument("--repo-profile", default=None)
    parser.add_argument("--session-profile", default=None)


def resolved_profile_from_args(args: argparse.Namespace) -> dict[str, Any] | None:
    return resolve_profile_from_paths(
        team=getattr(args, "team_profile", None),
        repo=getattr(args, "repo_profile", None),
        session=getattr(args, "session_profile", None),
    )


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
            Path(args.out).parent.mkdir(parents=True, exist_ok=True)
            Path(args.out).write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
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
                    "env": {
                        "KAPPASKI_SESSION_ID": session.session_id,
                        "KAPPASKI_LEDGER": session.ledger_path,
                    },
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
            print("kappaski session run requires a command after --", file=sys.stderr)
            return 2
        env = dict(os.environ)
        env["KAPPASKI_SESSION_ID"] = session.session_id
        env["KAPPASKI_LEDGER"] = session.ledger_path
        completed = subprocess.run(command, check=False, env=env)
        close_session(Path(session.ledger_path), status="closed" if completed.returncode == 0 else "aborted")
        return completed.returncode
    if args.session_command == "close":
        entry = close_session(Path(args.ledger), status=args.status)
        print(json.dumps({"closed": True, "entry": entry.to_dict()}, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    return 2


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
        from .profiles import create_profile_registry

        result = create_profile_registry(owner=args.owner, profiles=profiles)
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    if args.profile_command == "pin":
        from .profiles import pin_profile_bundle

        registry = json.loads(Path(args.registry).read_text(encoding="utf-8"))
        result = pin_profile_bundle(registry, scope=args.scope, profile_name=args.name, distributed_by=args.distributed_by)
        if args.out:
            Path(args.out).parent.mkdir(parents=True, exist_ok=True)
            Path(args.out).write_text(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    if args.profile_command == "verify":
        from .profiles import verify_profile_bundle

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
            print("kappaski runtime shell requires a command after --", file=sys.stderr)
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
            print("kappaski runtime outcome requires --decision or --invocation", file=sys.stderr)
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
            print("kappaski policy explain requires --decision or --invocation", file=sys.stderr)
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


def handle_eval(args: argparse.Namespace) -> int:
    if args.eval_command == "list":
        result = list_benchmark_suites()
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    if args.eval_command == "report":
        result = run_benchmark(args.suite)
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
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


def handle_gate(args: argparse.Namespace) -> int:
    if args.gate_command == "verify":
        if not args.proof and not args.ledger:
            print("kappaski gate verify requires --proof, --ledger, or both", file=sys.stderr)
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


def emit(payload: dict[str, object], output: str) -> int:
    if output == "json":
        print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    summary = payload.get("summary", {})
    print(f"target: {payload.get('target')}")
    print(f"findings: {summary.get('total_findings', 0)}")
    print(f"highest_severity: {summary.get('highest_severity', 'info')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
