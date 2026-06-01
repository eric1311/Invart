import json
import sys
from pathlib import Path

from kappaski.cli import main
from kappaski.ledger import load_ledger_entries, verify_ledger
from kappaski.models import RuntimeEvent
from kappaski.postruntime import export_proof_report, summarize_session, verify_proof_report
from kappaski.rules import analyze_command, analyze_runtime_event
from kappaski.preflight import save_preflight
from kappaski.runtime import append_event, close_session, explain_decision, inspect_invocation_review, record_action, record_approval, record_outcome, start_session
from kappaski.evidence import build_redacted_evidence
from kappaski.evals import run_benchmark
from kappaski.daemon import RuntimeAuthority
from kappaski.corpus import capability_events_from_corpus, run_capability_grant_benchmark, scan_corpus, run_real_surface_benchmark
from kappaski.review import LLMReviewer, StaticJSONProvider
from kappaski.harness import compare_harness_runs, run_official_swe_bench_full_validation, run_official_swe_bench_lite_check, run_swe_bench_lite_check
from kappaski.adapter_profiles import build_adapter_profile
from kappaski.claude_adapter import check_claude_code_environment, run_claude_code_adapter
from kappaski.profiles import resolve_profile
from kappaski.teamrun import create_handoff, create_teamrun, declare_agent_identity
from kappaski.enforcement import check_enforcement, run_file_write_intercepted, rust_shim_decision
from kappaski.roadmap import roadmap_capabilities, verify_roadmap_coverage
from kappaski.audit_demo import run_enterprise_audit_demo, run_enterprise_audit_live_adapter_demo
from kappaski.gate import verify_gate
from kappaski.adapter import run_adapter_command
from kappaski.approval import approve_items, list_approval_items
from kappaski.replay import export_replay_html
from kappaski.scanner import scan_pre_runtime
from kappaski.coverage import (
    COVERAGE_GRADES,
    CoverageRecord,
    coverage_meets_requirement,
    default_coverage_for_layer,
    merge_coverage_records,
)
from kappaski.native import install_native_integration, inventory_native_integrations
from kappaski.native_bridge import normalize_native_event, render_native_response
from kappaski.mcp_broker import summarize_mcp_message, transparent_broker_step
from kappaski.product_readiness import reviewer_quality_corpus, optional_provider_smoke
from kappaski.supervision import supervise_process_group
from kappaski.profiles import create_profile_distribution_bundle, record_break_glass_override, review_break_glass_override
from kappaski.teamrun import export_teamrun_timeline_html
from kappaski.enforcement import run_enforced_command
from kappaski.audit_demo import record_audit_signoff
from kappaski.native import native_conformance_report
from kappaski.native_bridge import bridge_conformance_matrix
from kappaski.mcp_broker import run_stdio_broker
from kappaski.coverage import export_coverage_html_report
from kappaski.identity import (
    bind_agent_identity,
    create_capability_grant,
    credential_inventory,
    declare_principal,
    record_identity_binding,
)
from kappaski.path_graph import build_execution_graph, export_execution_graph_html, query_execution_graph
from kappaski.path_policy import check_path_policy
from kappaski.mediation import mediate_event, replay_mediation, resolve_mediation
from kappaski.pre_v1 import run_pre_v1_control_plane_demo
from kappaski.profiles import apply_raw_content_policy, create_profile_registry, pin_profile_bundle, verify_profile_bundle

def test_v02_policy_profiles_change_noncritical_behavior(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.jsonl"
    session = start_session(tmp_path, ledger, agent="codex", goal="test")
    _action, decision, _taint = record_action(
        RuntimeEvent(type="network", session_id=session.session_id, url="http://example.com"),
        ledger,
        review_mode="off",
        policy_profile="strict",
    )
    entries, _warnings = load_ledger_entries(ledger)
    assert decision.effect == "ask"
    assert entries[-1].evaluation["approval_grade"] == "require_human"


def test_v03_authority_registers_sessions_and_records_events(tmp_path: Path) -> None:
    authority = RuntimeAuthority.for_target(tmp_path)
    session = authority.create_session(tmp_path, agent="codex", goal="authority test", session_id="ks_auth", create_preflight=False)
    assert session.status == "active"
    assert session.session_id == "ks_auth"

    result = authority.record_event("ks_auth", {"type": "file_read", "path": "/repo/.env"}, review_mode="auto")
    assert result["recorded"] is True
    assert result["decision"]["effect"] == "ask"

    registry = authority.get_session("ks_auth")
    assert registry.last_decision_id == result["decision"]["decision_id"]
    assert registry.last_invocation_id == result["event"]["invocation_id"]
    assert registry.pending_approvals == [result["decision"]["decision_id"]]


def test_v03_authority_lifecycle_blocks_paused_writes(tmp_path: Path) -> None:
    authority = RuntimeAuthority.for_target(tmp_path)
    authority.create_session(tmp_path, agent="codex", session_id="ks_pause", create_preflight=False)
    paused = authority.transition_session("ks_pause", "paused", reason="manual pause")
    assert paused.status == "paused"
    try:
        authority.record_event("ks_pause", {"type": "file_read", "path": "/repo/README.md"})
    except ValueError as exc:
        assert "not active" in str(exc)
    else:
        raise AssertionError("paused session accepted a runtime event")
    resumed = authority.transition_session("ks_pause", "active")
    assert resumed.status == "active"
    result = authority.record_event("ks_pause", {"type": "file_read", "path": "/repo/README.md"}, review_mode="off")
    assert result["decision"]["effect"] == "allow"


def test_v03_authority_approval_and_outcome_update_registry(tmp_path: Path) -> None:
    authority = RuntimeAuthority.for_target(tmp_path)
    authority.create_session(tmp_path, agent="codex", session_id="ks_approval", create_preflight=False)
    result = authority.record_event("ks_approval", {"type": "file_read", "path": "/repo/.env"})
    decision_id = result["decision"]["decision_id"]
    assert authority.get_session("ks_approval").pending_approvals == [decision_id]

    approval = authority.approve("ks_approval", decision_id, "approved", approver="tester", reason="ok")
    assert approval["approval"]["status"] == "approved"
    assert authority.get_session("ks_approval").pending_approvals == []

    outcome = authority.outcome("ks_approval", "executed", decision_id=decision_id, actor="tester")
    assert outcome["outcome"]["status"] == "executed"


def test_v03_cli_daemon_session_flow(tmp_path: Path) -> None:
    assert main(["daemon", "init", "--target", str(tmp_path)]) == 0
    assert main(["daemon", "session", "create", "--target", str(tmp_path), "--session-id", "ks_cli_auth", "--agent", "codex", "--no-preflight"]) == 0
    assert main(["daemon", "record-event", "--target", str(tmp_path), "--session", "ks_cli_auth", "--review", "off", "--event", '{"type":"file_read","path":"/repo/README.md"}']) == 0
    assert main(["daemon", "session", "pause", "--target", str(tmp_path), "--session", "ks_cli_auth"]) == 0
    assert main(["daemon", "session", "resume", "--target", str(tmp_path), "--session", "ks_cli_auth"]) == 0
    assert main(["daemon", "session", "list", "--target", str(tmp_path)]) == 0
    registry = RuntimeAuthority.for_target(tmp_path).get_session("ks_cli_auth")
    assert registry.status == "active"
    assert registry.last_effect == "allow"


def test_v10_claude_code_adapter_profile_redacts_env() -> None:
    profile = build_adapter_profile("claude-code", env={"OPENAI_API_KEY": "sk-secret-value", "PATH": "/bin:/usr/bin"})
    assert profile["claude_code"]["first_hardened_target"] is True
    items = {item["key"]: item for item in profile["environment"]["items"]}
    assert items["OPENAI_API_KEY"]["value"] == "[REDACTED]"
    assert items["OPENAI_API_KEY"]["secret_like_key"] is True


def test_v11_profile_resolution_precedence(tmp_path: Path) -> None:
    team = tmp_path / "team.toml"
    repo = tmp_path / "repo.toml"
    session = tmp_path / "session.toml"
    team.write_text('name = "team"\n[taint]\nhandoff_inheritance = "session-wide"\n', encoding="utf-8")
    repo.write_text('name = "repo"\n[replay]\nraw_content = "redacted"\n', encoding="utf-8")
    session.write_text('name = "session"\n[taint]\nhandoff_inheritance = "resource-reference"\n', encoding="utf-8")
    resolved = resolve_profile(team=team, repo=repo, session=session)
    assert resolved["name"] == "session"
    assert resolved["taint"]["handoff_inheritance"] == "resource-reference"
    assert resolved["replay"]["raw_content"] == "redacted"
    assert resolved["resolution"]["precedence"] == "session > repo > team"


def test_v12_teamrun_identity_and_handoff_taint_modes() -> None:
    teamrun = create_teamrun("security review", ["alice", "bob"])
    assert teamrun["schema_version"] == "kappaski.teamrun.v0.12"
    identity = declare_agent_identity("claude", "alice", {"agent_id": "codex"})
    assert identity["consistent"] is False
    resource_handoff = create_handoff("agent-a", "agent-b", [{"kind": "file", "value": ".env", "tainted": "true"}], taint_mode="resource-reference")
    session_handoff = create_handoff("agent-a", "agent-b", [], taint_mode="session-wide", session_tainted=True)
    assert resource_handoff["taint_inheritance"]["inherited"] is True
    assert session_handoff["taint_inheritance"]["inherited"] is True


def test_full_daemon_profile_injection_controls_policy_mode_and_approval(tmp_path: Path) -> None:
    profile = tmp_path / "enterprise.toml"
    profile.write_text(
        'mode = "managed"\n'
        '[policy]\n'
        'high_rule_effect = "require_approval"\n'
        '[approval]\n'
        'local_approval = false\n',
        encoding="utf-8",
    )
    authority = RuntimeAuthority.for_target(tmp_path)
    session = authority.create_session(
        tmp_path,
        agent="codex",
        goal="profile daemon",
        create_preflight=False,
        metadata={"policy_profile_config": resolve_profile(session=profile)},
    )
    result = authority.record_event(session.session_id, {"type": "file_read", "path": "/repo/.env"}, policy_mode="audit")
    assert result["decision"]["effect"] == "ask"
    stored = authority.get_session(session.session_id).to_dict()
    assert stored["metadata"]["policy_profile_config"]["mode"] == "managed"
    blocked = authority.approve(session.session_id, result["decision"]["decision_id"], "approved", approver="alice", reason="local override")
    assert blocked["approval_blocked"] is True
    assert blocked["session"]["pending_approvals"] == [result["decision"]["decision_id"]]


def test_full_teamrun_aggregate_merges_multiple_ledgers(tmp_path: Path) -> None:
    from kappaski.teamrun import export_teamrun_aggregate

    ledgers = []
    for index, user in enumerate(["alice", "bob"]):
        ledger = tmp_path / f"ledger-{index}.jsonl"
        session = start_session(tmp_path, ledger, session_id=f"ks_team_{index}", agent=f"agent-{index}", create_preflight=False)
        assert main(["teamrun", "create", "--ledger", str(ledger), "--name", "incident", "--user", user]) == 0
        assert main(["teamrun", "identity", "--ledger", str(ledger), "--agent", session.agent or f"agent-{index}", "--declared-by", user]) == 0
        ledgers.append(ledger)
    out = tmp_path / "aggregate.json"
    aggregate = export_teamrun_aggregate(ledgers, out)
    assert out.exists()
    assert aggregate["schema_version"] == "kappaski.teamrun_aggregate.v0.12"
    assert aggregate["summary"]["ledgers"] == 2
    assert aggregate["summary"]["teamruns"] == 2
    assert aggregate["summary"]["agent_identities"] == 2
    assert all(item["valid"] for item in aggregate["ledger_verification"])


def test_v11_profile_files_thread_into_runtime_replay_and_enforce(tmp_path: Path) -> None:
    profile = tmp_path / "session.toml"
    profile.write_text(
        'name = "enterprise"\n'
        'mode = "managed"\n'
        '[policy]\n'
        'high_rule_effect = "require_approval"\n'
        '[replay]\n'
        'raw_content = "hidden"\n'
        '[enforcement]\n'
        'fail_closed = true\n',
        encoding="utf-8",
    )
    ledger = tmp_path / "ledger.jsonl"
    replay = tmp_path / "replay.html"
    assert main(["session", "start", "--target", str(tmp_path), "--session-id", "ks_profile_full", "--ledger", str(ledger), "--no-preflight"]) == 0
    assert main([
        "runtime", "record-event",
        "--session", "ks_profile_full",
        "--ledger", str(ledger),
        "--session-profile", str(profile),
        "--event", '{"type":"file_read","path":"/repo/.env","content":"token=sk-secretvalue"}',
    ]) == 0
    entries, _warnings = load_ledger_entries(ledger)
    assert entries[-1].evaluation["policy_mode"] == "managed"
    assert entries[-1].evaluation["approval_grade"] == "require_human"
    assert main(["replay", "export", "--ledger", str(ledger), "--out", str(replay), "--session-profile", str(profile)]) == 0
    html = replay.read_text(encoding="utf-8")
    assert "Raw Proof" not in html
    assert main(["enforce", "check", "--session-profile", str(profile), "--domain", "file-write", "--event", '{"type":"shell","command":"echo safe"}']) == 0


def test_v11_break_glass_override_is_ledger_backed(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.jsonl"
    assert main(["session", "start", "--target", str(tmp_path), "--session-id", "ks_break_glass", "--ledger", str(ledger), "--no-preflight"]) == 0
    assert main([
        "profile", "break-glass",
        "--ledger", str(ledger),
        "--session", "ks_break_glass",
        "--actor", "security-admin",
        "--reason", "incident response",
        "--scope", "repo",
        "--expires-at", "2026-05-29T00:00:00Z",
    ]) == 0
    entries, _warnings = load_ledger_entries(ledger)
    assert entries[-1].entry_type == "profile_override"
    assert entries[-1].result["override_type"] == "break_glass"
    assert entries[-1].result["reason"] == "incident response"


def test_v11_gate_profile_can_require_closed_session(tmp_path: Path) -> None:
    profile = tmp_path / "session.toml"
    profile.write_text('[gate]\nrequire_closed_session = true\n', encoding="utf-8")
    ledger = tmp_path / "ledger.jsonl"
    assert main(["session", "start", "--target", str(tmp_path), "--session-id", "ks_gate_profile", "--ledger", str(ledger), "--no-preflight"]) == 0
    assert main(["runtime", "record-event", "--session", "ks_gate_profile", "--ledger", str(ledger), "--event", '{"type":"file_read","path":"/repo/README.md"}']) == 0
    assert main(["gate", "verify", "--ledger", str(ledger), "--mode", "managed", "--session-profile", str(profile)]) == 1
    assert main(["session", "close", "--ledger", str(ledger)]) == 0
    assert main(["gate", "verify", "--ledger", str(ledger), "--mode", "managed", "--session-profile", str(profile)]) == 0


def test_v12_teamrun_records_are_ledger_first_class_facts(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.jsonl"
    assert main(["session", "start", "--target", str(tmp_path), "--session-id", "ks_teamrun", "--ledger", str(ledger), "--no-preflight"]) == 0
    assert main(["teamrun", "create", "--ledger", str(ledger), "--name", "security review", "--user", "alice", "--user", "bob"]) == 0
    assert main(["teamrun", "identity", "--ledger", str(ledger), "--agent", "claude", "--declared-by", "alice", "--adapter-agent", "claude"]) == 0
    assert main(["teamrun", "blackboard", "--ledger", str(ledger), "--teamrun", "security review", "--author", "alice", "--content", "Investigate unsafe deletion risk", "--resource", "repo:main"]) == 0
    assert main(["teamrun", "handoff", "--ledger", str(ledger), "--source-agent", "claude", "--target-agent", "codex", "--resource", "tainted:.env", "--taint-mode", "resource-reference"]) == 0
    entries, _warnings = load_ledger_entries(ledger)
    types = [entry.entry_type for entry in entries]
    assert "teamrun" in types
    assert "agent_identity" in types
    assert "blackboard" in types
    assert "handoff" in types
    handoff = next(entry for entry in entries if entry.entry_type == "handoff")
    assert handoff.result["taint_inheritance"]["inherited"] is True


def test_v12_restrict_only_grant_delegation(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.jsonl"
    assert main(["session", "start", "--target", str(tmp_path), "--session-id", "ks_grant", "--ledger", str(ledger), "--no-preflight"]) == 0
    assert main([
        "teamrun", "delegate-grant",
        "--ledger", str(ledger),
        "--source-agent", "claude",
        "--target-agent", "codex",
        "--parent-scope", "repo:read,repo:write,network:localhost",
        "--delegate-scope", "repo:read",
    ]) == 0
    assert main([
        "teamrun", "delegate-grant",
        "--ledger", str(ledger),
        "--source-agent", "claude",
        "--target-agent", "codex",
        "--parent-scope", "repo:read",
        "--delegate-scope", "repo:read,network:external",
    ]) == 1
    entries, _warnings = load_ledger_entries(ledger)
    grants = [entry for entry in entries if entry.entry_type == "grant_delegation"]
    assert len(grants) == 1
    assert grants[0].result["restrict_only"] is True


def test_v12_teamrun_proof_exports_cross_session_facts(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.jsonl"
    proof = tmp_path / "teamrun-proof.json"
    assert main(["session", "start", "--target", str(tmp_path), "--session-id", "ks_teamrun_proof", "--ledger", str(ledger), "--no-preflight"]) == 0
    assert main(["teamrun", "create", "--ledger", str(ledger), "--name", "proof demo", "--user", "alice"]) == 0
    assert main(["teamrun", "blackboard", "--ledger", str(ledger), "--teamrun", "proof demo", "--author", "alice", "--content", "Shared finding"]) == 0
    assert main(["teamrun", "proof", "--ledger", str(ledger), "--out", str(proof)]) == 0
    payload = json.loads(proof.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "kappaski.teamrun_proof.v0.12"
    assert payload["summary"]["teamruns"] == 1
    assert payload["summary"]["blackboard_entries"] == 1


def test_v18_gate_profile_fails_when_required_coverage_is_missing(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.jsonl"
    session = start_session(tmp_path, ledger, agent="generic", goal="coverage gate", create_preflight=False)
    record_action(RuntimeEvent(type="shell", session_id=session.session_id, command="echo ok", metadata={"coverage_layer": "agent_log"}), ledger)
    close_session(ledger)
    proof_path = tmp_path / "proof.json"
    export_proof_report(ledger, proof_path)
    report = verify_gate(proof_path=proof_path, ledger_path=ledger, mode="ci", coverage_requirements={"runtime_enforcement": "mediated"})
    assert report["status"] == "fail"
    assert any("coverage" in finding["check_id"] for finding in report["findings"])


def test_v18_gate_cli_reads_coverage_requirement_from_profile(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.jsonl"
    session = start_session(tmp_path, ledger, agent="generic", goal="coverage gate profile", create_preflight=False)
    record_action(RuntimeEvent(type="shell", session_id=session.session_id, command="echo ok", metadata={"coverage_layer": "agent_log"}), ledger)
    close_session(ledger)
    proof_path = tmp_path / "proof.json"
    export_proof_report(ledger, proof_path)
    profile = tmp_path / "profile.json"
    profile.write_text(json.dumps({"gate": {"coverage_requirements": {"runtime_enforcement": "mediated"}}}), encoding="utf-8")
    assert main(["gate", "verify", "--proof", str(proof_path), "--ledger", str(ledger), "--mode", "ci", "--session-profile", str(profile)]) == 1


def test_full_v11_profile_review_and_distribution_bundle(tmp_path: Path) -> None:
    profile = {"name": "enterprise", "mode": "managed", "approval": {"local_approval": False}}
    bundle = create_profile_distribution_bundle(profile, scope="team", distributed_by="admin")
    assert bundle["schema_version"] == "kappaski.profile_distribution.v0.11"
    assert bundle["hash"].startswith("sha256:")
    ledger = tmp_path / "ledger.jsonl"
    session = start_session(tmp_path, ledger, session_id="ks_profile_review", create_preflight=False)
    override = record_break_glass_override(ledger, session_id=session.session_id, actor="alice", reason="incident", scope="repo")
    review = review_break_glass_override(
        ledger,
        override_id=override["override"]["override_id"],
        reviewer="security-admin",
        status="approved",
        reason="time-bounded incident response",
    )
    assert review["review"]["status"] == "approved"
    entries, _warnings = load_ledger_entries(ledger)
    assert entries[-1].entry_type == "profile_review"


def test_full_v12_teamrun_timeline_html_spans_multiple_ledgers(tmp_path: Path) -> None:
    ledger_a = tmp_path / "a.jsonl"
    ledger_b = tmp_path / "b.jsonl"
    start_session(tmp_path, ledger_a, session_id="ks_team_a", create_preflight=False)
    start_session(tmp_path, ledger_b, session_id="ks_team_b", create_preflight=False)
    append_a = create_teamrun("incident", ["alice"])
    append_b = create_handoff("claude", "codex", [{"kind": "file", "value": ".env", "tainted": "true"}])
    from kappaski.teamrun import append_teamrun_fact

    append_teamrun_fact(ledger_a, "teamrun", append_a)
    append_teamrun_fact(ledger_b, "handoff", append_b)
    out = tmp_path / "timeline.html"
    result = export_teamrun_timeline_html([ledger_a, ledger_b], out)
    html = out.read_text(encoding="utf-8")
    assert result["summary"]["ledgers"] == 2
    assert "TeamRun Timeline" in html
    assert "handoff" in html


def test_v019_identity_binding_is_proof_backed_and_daemon_rejects_mismatch(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.jsonl"
    session = start_session(tmp_path, ledger, agent="claude-code", goal="identity closure", create_preflight=False)
    principal = declare_principal("alice@example.com", display_name="Alice", source="local")
    agent_identity = bind_agent_identity("claude-code", declared_by=principal.principal_id, adapter_agent="claude-code")
    credentials = credential_inventory({"OPENAI_API_KEY": "sk-live-secret", "PATH": "/bin"}, owner=principal.principal_id)
    grant = create_capability_grant(
        principal_id=principal.principal_id,
        agent_id=agent_identity.agent_id,
        scopes=["file_read"],
        resources=["/repo/.env"],
        expires_at="2999-01-01T00:00:00Z",
    )
    record_identity_binding(ledger, session_id=session.session_id, principal=principal, agent_identity=agent_identity, credentials=credentials, grants=[grant])
    record_action(
        RuntimeEvent(type="file_read", session_id=session.session_id, path="/repo/.env", metadata={"capability_grant_id": grant.grant_id}),
        ledger,
    )
    proof = export_proof_report(ledger)
    assert proof["accountability"]["principal"]["principal_id"] == principal.principal_id
    assert proof["accountability"]["agent_identity"]["agent_id"] == agent_identity.agent_id
    assert proof["accountability"]["credential_boundary"]["redacted_values"] == 1
    assert proof["accountability"]["capability_grants"][0]["grant_id"] == grant.grant_id

    authority = RuntimeAuthority.for_target(tmp_path / "daemon")
    managed_profile = {"mode": "managed", "identity": {"required": True, "allowed_agents": ["claude-code"]}}
    try:
        authority.create_session(
            tmp_path,
            agent="codex",
            create_preflight=False,
            metadata={
                "policy_profile_config": managed_profile,
                "principal": principal.to_dict(),
                "agent_identity": agent_identity.to_dict(),
            },
        )
    except ValueError as exc:
        assert "agent identity mismatch" in str(exc)
    else:
        raise AssertionError("managed daemon session should reject declared agent mismatch")


def test_v023_profile_registry_pinning_and_raw_content_policy(tmp_path: Path) -> None:
    team_profile = {"schema_version": "kappaski.policy_profile.v0.23", "name": "team", "mode": "managed", "replay": {"raw_content": "hidden"}}
    repo_profile = {"schema_version": "kappaski.policy_profile.v0.23", "name": "repo", "mode": "managed", "replay": {"raw_content": "truncated", "max_raw_content_length": 8}}
    registry = create_profile_registry(owner="security-team", profiles=[("team", team_profile), ("repo", repo_profile)])
    pinned = pin_profile_bundle(registry, scope="repo", profile_name="repo", distributed_by="security-lead")
    verified = verify_profile_bundle(pinned, registry)
    assert verified["status"] == "pass"
    assert verified["profile"]["name"] == "repo"
    rendered = apply_raw_content_policy("0123456789abcdef", {"replay": {"raw_content": "truncated", "max_raw_content_length": 8}})
    assert rendered["display"] == "truncated"
    assert rendered["content"] == "01234567"
    hidden = apply_raw_content_policy("secret", {"replay": {"raw_content": "hidden"}})
    assert hidden["content"] == ""


def test_v019_to_v029_cli_and_roadmap_are_registered(tmp_path: Path) -> None:
    identity_path = tmp_path / "identity.json"
    assert main(["identity", "declare", "--principal", "alice@example.com", "--out", str(identity_path)]) == 0
    assert identity_path.exists()
    ledger = tmp_path / "ledger.jsonl"
    session = start_session(tmp_path, ledger, agent="codex", goal="cli", create_preflight=False)
    record_action(RuntimeEvent(type="file_read", session_id=session.session_id, path="/repo/.env"), ledger)
    record_action(RuntimeEvent(type="network", session_id=session.session_id, url="https://api.example.com/upload"), ledger)
    assert main(["graph", "export", "--ledger", str(ledger), "--out", str(tmp_path / "graph.json")]) == 0
    assert main(["graph", "html", "--ledger", str(ledger), "--out", str(tmp_path / "graph.html")]) == 0
    assert main(["policy", "check-path", "--ledger", str(ledger), "--out", str(tmp_path / "path-policy.json")]) == 1
    assert main(["mediation", "inspect", "--ledger", str(ledger)]) == 0
    assert main(["profile", "registry", "--owner", "security", "--profile", json.dumps({"name": "repo", "mode": "managed"})]) == 0
    assert main(["eval", "benchmark", "--suite", "pre-v1-control-plane"]) == 0
    report = verify_roadmap_coverage(require_full=True)
    assert report["passed"] is True
    assert report["summary"]["schema_version"] == "kappaski.roadmap_coverage.full_product.v0.40"
    versions = {item["version"] for item in report["capabilities"]}
    assert {"v0.19", "v0.20", "v0.21", "v0.22", "v0.23", "v0.24", "v0.25", "v0.26", "v0.27", "v0.28", "v0.29"}.issubset(versions)
    assert report["future_planned"]

