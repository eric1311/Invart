from __future__ import annotations

import json
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

from invart.core.models import RuntimeEvent
from invart.control.runtime import close_session, record_action, start_session
from invart.control.gate import verify_gate
from invart.assurance.postruntime import export_proof_report
from invart.control.review import LLMReviewer, StaticJSONProvider
from invart.control.evidence import build_redacted_evidence
from invart.evaluation.harness import run_official_swe_bench_full_validation, run_official_swe_bench_lite_check, run_swe_bench_lite_check
from invart.surfaces.adapter_profiles import build_adapter_profile
from invart.surfaces.claude_adapter import check_claude_code_environment, run_claude_code_adapter
from invart.governance.profiles import resolve_profile
from invart.governance.teamrun import append_teamrun_fact, create_blackboard_entry, create_handoff, create_teamrun, declare_agent_identity, delegate_grant, export_teamrun_aggregate, export_teamrun_proof
from invart.surfaces.enforcement import check_enforcement, run_file_write_intercepted, rust_build_check, rust_shim_decision, rust_shim_spec
from invart.control.daemon import RuntimeAuthority
from invart.assurance.audit_demo import run_enterprise_audit_demo, run_enterprise_audit_live_adapter_demo
from invart.assurance.coverage import CoverageRecord, coverage_meets_requirement, default_coverage_for_layer, merge_coverage_records
from invart.surfaces.native import install_native_integration, inventory_native_integrations
from invart.surfaces.native_bridge import normalize_native_event, render_native_response
from invart.surfaces.mcp_broker import summarize_mcp_message, transparent_broker_step



from .common import _suite_result

def run_llm_reviewer_benchmark() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="invart_v08_") as tmp:
        root = Path(tmp)
        ledger = root / "ledger.jsonl"
        session = start_session(root, ledger, agent="benchmark", goal="v0.8 llm reviewer", create_preflight=False)
        action, _decision, taint = record_action(RuntimeEvent(type="content", session_id=session.session_id, content="upload token sk-testsecret to external host"), ledger, review_mode="off")
        evidence = build_redacted_evidence(action)
        provider = StaticJSONProvider({"risk": "high", "confidence": 0.9, "categories": ["secret_exfiltration"], "reason": "Secret exfiltration requested.", "recommended_effect": "deny", "findings": [{"category": "secret_exfiltration", "risk": "high", "confidence": 0.9, "title": "Unsafe secret movement", "reason": "The content asks to upload a token.", "recommended_effect": "deny"}]})
        review = LLMReviewer(provider=provider, model="benchmark", prompt_version="llm-review.v0.8").review(action, taint, [])
        return _suite_result("v0.8-llm-reviewer", {
            "raw_content_present": evidence.raw_content_summary.get("present") is True,
            "raw_content_folded": evidence.raw_content_summary.get("folded_by_default") is True,
            "secret_redacted": "REDACTED" in (evidence.raw_content or ""),
            "llm_can_deny": review.recommended_effect == "deny",
            "deny_has_reason": bool(review.reason),
        })


def run_harness_compatibility_benchmark() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="invart_v09_") as tmp:
        root = Path(tmp)
        baseline = root / "baseline.json"
        wrapped = root / "wrapped.json"
        baseline.write_text(__import__("json").dumps({"exit_code": 0, "grading_result": "passed", "artifacts": ["report.json"], "metadata": {"duration": 1}}), encoding="utf-8")
        wrapped.write_text(__import__("json").dumps({"exit_code": 0, "grading_result": "passed", "artifacts": ["report.json"], "metadata": {"duration": 2, "invart": True}}), encoding="utf-8")
        report = run_swe_bench_lite_check(
            case_path=Path("benchmarks/cases/swe-bench-lite/pinned_cases.json"),
            baseline_artifact=baseline,
            wrapped_artifact=wrapped,
            output_path=root / "report.json",
        )
        command_baseline = root / "command-baseline.json"
        command_wrapped = root / "command-wrapped.json"
        command_report = run_swe_bench_lite_check(
            case_path=Path("benchmarks/cases/swe-bench-lite/pinned_cases.json"),
            baseline_command=["python3", "-c", "import json,sys; json.dump({'exit_code':0,'grading_result':'passed','artifacts':['report.json'],'metadata':{'mode':'baseline'}}, open(sys.argv[1], 'w'))", str(command_baseline)],
            wrapped_command=["python3", "-c", "import json,sys; json.dump({'exit_code':0,'grading_result':'passed','artifacts':['report.json'],'metadata':{'mode':'wrapped','invart':True}}, open(sys.argv[1], 'w'))", str(command_wrapped)],
            output_path=root / "command-report.json",
        )
        skipped = run_swe_bench_lite_check(
            case_path=Path("benchmarks/cases/swe-bench-lite/pinned_cases.json"),
            dependency="definitely_missing_swebench_binary_for_eval",
            skip_if_unavailable=True,
            output_path=root / "skipped.json",
        )
        fake_official = root / "fake_swebench.py"
        official_report_path = root / "gold.eval_official.json"
        fake_official.write_text(
            "import json, pathlib, sys\n"
            "path = pathlib.Path(sys.argv[1])\n"
            "path.write_text(json.dumps({\"total_instances\": 1, \"completed_instances\": 1, \"resolved_instances\": 1, \"error_instances\": 0, \"completed_ids\": [\"django__django-11001\"]}))\n",
            encoding="utf-8",
        )
        official = run_official_swe_bench_lite_check(
            command=[sys.executable, str(fake_official), str(official_report_path)],
            report_path=official_report_path,
            run_id="eval_official",
            work_dir=root,
            output_path=root / "official-report.json",
        )
        return _suite_result("v0.9-harness-compatibility", {
            "status_pass": report["status"] == "pass",
            "exit_code_same": report["checks"]["exit_code"],
            "artifacts_same": report["checks"]["artifacts"],
            "grading_same": report["checks"]["grading_result"],
            "metadata_diff_allowed": report["allowed_metadata_difference"] is True,
            "optional_runner_skips_cleanly": skipped["status"] == "skipped",
            "real_command_pair_runs": command_report["runner"]["mode"] == "command_pair" and command_report["status"] == "pass",
            "official_harness_command_contract": official["runner"]["mode"] == "official_swebench_harness" and official["status"] == "pass",
            "real_case_attached": report["case"].get("instance_id") == "django__django-11001",
        }, artifacts={"report": str(root / "report.json"), "command_report": str(root / "command-report.json"), "official_report": str(root / "official-report.json"), "skipped": str(root / "skipped.json")})


def run_swe_bench_full_validation_contract_benchmark() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="invart_v040_swebench_") as tmp:
        root = Path(tmp)
        fake = root / "fake_official_swebench.py"
        fake.write_text(
            "import json, pathlib\n"
            "results = pathlib.Path('results')\n"
            "run_dir = results / 'invart_contract'\n"
            "run_dir.mkdir(parents=True, exist_ok=True)\n"
            "payload = {\n"
            "  'total_instances': 4,\n"
            "  'submitted_instances': 4,\n"
            "  'completed_instances': 4,\n"
            "  'resolved_instances': 3,\n"
            "  'unresolved_instances': 1,\n"
            "  'error_instances': 0,\n"
            "  'completed_ids': ['repo__a-1', 'repo__b-2', 'repo__c-3', 'repo__d-4'],\n"
            "  'resolved_ids': ['repo__a-1', 'repo__b-2', 'repo__c-3'],\n"
            "  'error_ids': []\n"
            "}\n"
            "(results / 'invart_contract.json').write_text(json.dumps(payload))\n"
            "(run_dir / 'instance_results.jsonl').write_text('\\n'.join(json.dumps({'instance_id': item, 'resolved': item != 'repo__d-4'}) for item in payload['completed_ids']) + '\\n')\n",
            encoding="utf-8",
        )
        full = run_official_swe_bench_full_validation(
            command=[sys.executable, str(fake)],
            work_dir=root,
            run_id="invart_contract",
            expected_total_instances=4,
            output_path=root / "full-validation.json",
        )
        subset = run_official_swe_bench_full_validation(
            command=[sys.executable, str(fake)],
            work_dir=root,
            run_id="invart_contract",
            instance_ids=["repo__a-1"],
            expected_total_instances=4,
            output_path=root / "subset-validation.json",
        )
        return _suite_result(
            "v0.40-swe-bench-full-validation-contract",
            {
                "official_full_contract_passes": full["status"] == "pass",
                "official_report_found": full["checks"]["report_json_found"] is True,
                "instance_results_found": full["checks"]["instance_results_found"] is True,
                "all_instances_required": full["external_validation"]["all_instances_required"] is True,
                "subset_does_not_satisfy_full_validation": subset["status"] == "fail" and subset["checks"]["all_data_mode"] is False,
            },
            artifacts={"full_validation": str(root / "full-validation.json"), "subset_validation": str(root / "subset-validation.json")},
        )


def run_claude_adapter_profile_benchmark() -> dict[str, Any]:
    profile = build_adapter_profile("claude-code", env={"ANTHROPIC_API_KEY": "secret", "PATH": "/bin"})
    items = {item["key"]: item for item in profile["environment"]["items"]}
    with tempfile.TemporaryDirectory(prefix="invart_v10_") as tmp:
        root = Path(tmp)
        hooks = root / "hooks.jsonl"
        hooks.write_text('{"type":"file_read","path":"/repo/.env","metadata":{"source":"claude_code_hook"}}\n', encoding="utf-8")
        checked_binary = "claude" if shutil.which("claude") else "python3"
        env_check = check_claude_code_environment(binary=checked_binary)
        result = run_claude_code_adapter(
            target=root,
            command=["python3", "-c", "pass"],
            hook_events=hooks,
            out_dir=root / "artifacts",
            session_id="ks_eval_claude",
        )
        return _suite_result("v0.10-claude-adapter-profile", {
            "claude_target": profile["claude_code"]["first_hardened_target"] is True,
            "env_keys_recorded": "ANTHROPIC_API_KEY" in items,
            "secret_value_redacted": items["ANTHROPIC_API_KEY"]["value"] == "[REDACTED]",
            "degraded_mode_explicit": profile["process_supervision"]["degraded_mode_must_be_recorded"] is True,
            "hook_events_ingested": result["hook_events_ingested"] == 1,
            "child_command_ran": result["returncode"] == 0,
            "real_binary_environment_checked": env_check["available"] is True,
            "real_claude_binary_checked_when_available": (checked_binary != "claude") or (env_check["requested_binary"] == "claude" and env_check["available"] is True),
        }, artifacts={"ledger": result["ledger"], "proof": result["proof"], "environment_check": env_check})


def run_policy_profile_benchmark() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="invart_v11_") as tmp:
        root = Path(tmp)
        team = root / "team.toml"
        repo = root / "repo.toml"
        session = root / "session.toml"
        team.write_text('name = "team"\n[taint]\nhandoff_inheritance = "session-wide"\n', encoding="utf-8")
        repo.write_text('[replay]\nraw_content = "redacted"\n', encoding="utf-8")
        session.write_text('name = "session"\n[taint]\nhandoff_inheritance = "resource-reference"\n', encoding="utf-8")
        resolved = resolve_profile(team=team, repo=repo, session=session)
        from invart.governance.profiles import gate_requires_closed_session, include_raw_replay, record_break_glass_override
        ledger = root / "ledger.jsonl"
        session_obj = start_session(root, ledger, agent="benchmark", goal="v0.11 profile benchmark", create_preflight=False)
        override = record_break_glass_override(ledger, session_id=session_obj.session_id, actor="benchmark-admin", reason="benchmark", scope="repo")
        daemon_profile = root / "daemon.toml"
        daemon_profile.write_text('mode = "managed"\n[policy]\nhigh_rule_effect = "require_approval"\n[approval]\nlocal_approval = false\n', encoding="utf-8")
        authority = RuntimeAuthority.for_target(root / "daemon-target")
        daemon_session = authority.create_session(root, agent="benchmark", goal="daemon profile", create_preflight=False, metadata={"policy_profile_config": resolve_profile(session=daemon_profile)})
        daemon_event = authority.record_event(daemon_session.session_id, {"type": "file_read", "path": "/repo/.env"}, policy_mode="audit")
        daemon_approval = authority.approve(daemon_session.session_id, daemon_event["decision"]["decision_id"], "approved", approver="benchmark", reason="should be blocked by profile")
        return _suite_result("v0.11-policy-profiles", {
            "session_precedence": resolved["name"] == "session",
            "taint_resource_default": resolved["taint"]["handoff_inheritance"] == "resource-reference",
            "repo_replay_merged": resolved["replay"]["raw_content"] == "redacted",
            "override_disabled_default": resolved["enterprise"]["local_override"] is False,
            "replay_raw_profile_applied": include_raw_replay({"replay": {"raw_content": "hidden"}}) is False,
            "gate_profile_applied": gate_requires_closed_session({"gate": {"require_closed_session": True}}) is True,
            "break_glass_recorded": override["override"]["override_type"] == "break_glass",
            "daemon_profile_controls_policy": daemon_event["decision"]["effect"] == "ask",
            "daemon_profile_blocks_local_approval": daemon_approval.get("approval_blocked") is True,
        })


def run_teamrun_handoff_benchmark() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="invart_v12_") as tmp:
        root = Path(tmp)
        ledger = root / "ledger.jsonl"
        session = start_session(root, ledger, agent="benchmark", goal="v0.12 teamrun", create_preflight=False)
        teamrun = create_teamrun("benchmark", ["alice", "bob"])
        identity = declare_agent_identity("claude", "alice", {"agent_id": "codex"})
        handoff = create_handoff("a", "b", [{"kind": "file", "value": ".env", "tainted": "true"}], taint_mode="resource-reference")
        strict = create_handoff("a", "b", [], taint_mode="session-wide", session_tainted=True)
        grant = delegate_grant("a", "b", "repo:read,repo:write", "repo:read")
        append_teamrun_fact(ledger, "teamrun", teamrun)
        append_teamrun_fact(ledger, "agent_identity", identity)
        append_teamrun_fact(ledger, "blackboard", create_blackboard_entry("benchmark", "alice", "shared context"))
        append_teamrun_fact(ledger, "handoff", handoff)
        append_teamrun_fact(ledger, "grant_delegation", grant)
        proof = export_teamrun_proof(ledger)
        second = root / "ledger-2.jsonl"
        start_session(root, second, agent="benchmark-2", goal="v0.12 teamrun second", create_preflight=False)
        append_teamrun_fact(second, "teamrun", create_teamrun("benchmark-2", ["carol"]))
        aggregate = export_teamrun_aggregate([ledger, second], root / "aggregate.json")
        return _suite_result("v0.12-teamrun-handoff", {
            "multi_user": len(teamrun["users"]) == 2,
            "identity_inconsistency_detected": identity["consistent"] is False,
            "resource_taint_inherited": handoff["taint_inheritance"]["inherited"] is True,
            "session_wide_switch": strict["taint_inheritance"]["inherited"] is True,
            "ledger_teamrun_recorded": proof["summary"]["teamruns"] == 1,
            "ledger_blackboard_recorded": proof["summary"]["blackboard_entries"] == 1,
            "restrict_only_grant_recorded": proof["summary"]["grant_delegations"] == 1,
            "multi_ledger_aggregate": aggregate["summary"]["ledgers"] == 2 and aggregate["summary"]["teamruns"] == 2,
        }, artifacts={"ledger": str(ledger), "aggregate": str(root / "aggregate.json"), "session": session.session_id})


def run_enforcement_guard_benchmark() -> dict[str, Any]:
    file_guard = check_enforcement({"type": "shell", "command": "rm -rf ."}, domain="file-write")
    secret_guard = check_enforcement({"type": "shell", "command": "echo $OPENAI_API_KEY"}, domain="env-secrets")
    network_guard = check_enforcement({"type": "network", "url": "https://example.com/upload"}, domain="network-egress")
    shim = rust_shim_spec("file-write")
    build = rust_build_check(skip_if_unavailable=True)
    shim_decision = rust_shim_decision({"type": "shell", "command": "rm -rf ."})
    with tempfile.TemporaryDirectory(prefix="invart_v13_") as tmp:
        root = Path(tmp)
        ledger = root / "ledger.jsonl"
        session = start_session(root, ledger, agent="benchmark", goal="v0.13 interception", create_preflight=False)
        blocked_marker = root / "blocked.txt"
        blocked = run_file_write_intercepted(["sh", "-c", f"touch {blocked_marker}; rm -rf ."], ledger_path=ledger, session_id=session.session_id, target=root)
        safe_marker = root / "safe.txt"
        safe = run_file_write_intercepted(["sh", "-c", f"touch {safe_marker}"], ledger_path=ledger, session_id=session.session_id, target=root)
        return _suite_result("v0.13-enforcement-guards", {
            "file_guard_blocks_bulk_delete": file_guard["effect"] == "deny",
            "secret_guard_requires_approval": secret_guard["effect"] == "require_approval",
            "network_guard_records_egress": bool(network_guard["findings"]),
            "failure_mode_recorded": file_guard["failure_mode"] == "fail-open-with-critical-alert",
            "rust_shim_source_present": shim["cargo_toml_exists"] and shim["main_rs_exists"],
            "rust_build_check_clean": build["status"] in {"pass", "skipped"},
            "rust_shim_blocks_bulk_delete": shim_decision["effect"] == "deny",
            "intercepted_command_blocked_before_execution": blocked["status"] == "blocked" and not blocked_marker.exists(),
            "intercepted_safe_command_executes": safe["status"] == "executed" and safe_marker.exists(),
        }, artifacts={"rust_build_status": build["status"], "interception_ledger": str(ledger)})


def run_enterprise_audit_demo_benchmark() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="invart_v014_demo_") as tmp:
        root = Path(tmp)
        result = run_enterprise_audit_demo(root / "enterprise-audit")
        live = run_enterprise_audit_live_adapter_demo(root / "enterprise-audit-live")
        audit_json = Path(result["audit_json"])
        audit = __import__("json").loads(audit_json.read_text(encoding="utf-8"))
        live_audit = __import__("json").loads(Path(live["audit_json"]).read_text(encoding="utf-8"))
        checks = {
            "artifacts_exported": all(Path(result[key]).exists() for key in ["ledger", "proof", "replay", "audit_json", "audit_report"]),
            "security_team_audience": audit.get("audience") == "enterprise_security_team",
            "secret_leak_included": "secret_leak" in audit.get("risk_scenarios", []),
            "unsafe_deletion_included": "unsafe_deletion" in audit.get("risk_scenarios", []),
            "high_or_critical_findings": audit.get("summary", {}).get("critical_or_high_findings", 0) >= 2,
            "raw_evidence_folded": "<details" in Path(result["audit_report"]).read_text(encoding="utf-8"),
            "live_adapter_artifacts_exported": all(Path(live[key]).exists() for key in ["ledger", "proof", "replay", "audit_json", "audit_report"]),
            "live_adapter_enforcement_blocks_before_execution": live.get("summary", {}).get("blocked_before_execution") is True,
            "live_adapter_secret_leak_included": "secret_leak" in live_audit.get("risk_scenarios", []),
        }
        return _suite_result("v0.14-enterprise-audit-demo", checks, artifacts={"scripted": result, "live_adapter": live})


def run_native_integration_inventory_benchmark() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="invart_v015_") as tmp:
        root = Path(tmp)
        (root / ".claude").mkdir()
        (root / ".claude" / "settings.json").write_text(json.dumps({"hooks": {"PreToolUse": []}}), encoding="utf-8")
        (root / ".codex").mkdir()
        (root / ".codex" / "config.toml").write_text('[hooks]\npre_tool_use = "invart bridge"\n', encoding="utf-8")
        (root / ".gemini").mkdir()
        (root / ".gemini" / "settings.json").write_text(json.dumps({"mcpServers": {"fs": {"command": "node"}}}), encoding="utf-8")
        (root / ".cursor" / "rules").mkdir(parents=True)
        (root / ".cursor" / "rules" / "security.mdc").write_text("Never expose secrets", encoding="utf-8")
        (root / "opencode.json").write_text(json.dumps({"plugin": ["./plugin.js"]}), encoding="utf-8")
        report = inventory_native_integrations(root)
        install_preview = install_native_integration(root / "install", agent="claude-code", mode="preview")
        by_agent = {profile["agent"]: profile for profile in report["profiles"]}
        checks = {
            "claude_hooks_declared": by_agent["claude-code"]["surfaces"]["hooks"]["grade"] == "declared",
            "codex_hooks_declared": by_agent["codex"]["surfaces"]["hooks"]["grade"] == "declared",
            "gemini_mcp_declared": by_agent["gemini-cli"]["surfaces"]["mcp"]["grade"] == "declared",
            "cursor_rules_declared": by_agent["cursor"]["surfaces"]["rules"]["grade"] == "declared",
            "opencode_plugins_declared": by_agent["opencode"]["surfaces"]["plugins"]["grade"] == "declared",
            "openclaw_discovery_only": by_agent["openclaw"]["discovery_mode"] == "discovery_only",
            "preview_does_not_write": install_preview["mode"] == "preview" and not Path(install_preview["target_path"]).exists(),
        }
        return _suite_result("v0.15-native-integration-inventory", checks, artifacts={"target": str(root)})


def run_hook_plugin_bridge_benchmark() -> dict[str, Any]:
    claude = normalize_native_event("claude-code", {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "rm -rf ."}, "session_id": "bench"})
    codex_response = render_native_response("codex", {"effect": "deny", "reason": "benchmark block"})
    opencode_response = render_native_response("opencode", {"effect": "allow", "reason": "benchmark allow"})
    checks = {
        "claude_shell_normalized": claude.action_type == "shell" and claude.command == "rm -rf .",
        "coverage_layer_attached": claude.metadata.get("coverage_layer") == "native_hook",
        "codex_can_block": codex_response["allow"] is False,
        "opencode_can_allow": opencode_response["status"] == "allowed",
    }
    return _suite_result("v0.16-hook-plugin-bridge", checks)


def run_mcp_broker_benchmark() -> dict[str, Any]:
    tool_call = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "write_file", "arguments": {"path": ".env", "content": "SECRET=abc"}}}
    summary = summarize_mcp_message(tool_call, max_raw_length=16)
    forwarded, evidence = transparent_broker_step({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    checks = {
        "tool_call_summarized": summary["kind"] == "tool_call" and summary["tool_name"] == "write_file",
        "raw_content_folded": summary["raw_content_folded"] is True,
        "transparent_preserves_message": forwarded["method"] == "tools/list",
        "transparent_evidence_recorded": evidence["mode"] == "transparent",
    }
    return _suite_result("v0.17-mcp-broker", checks)


def run_coverage_aware_runtime_benchmark() -> dict[str, Any]:
    hook = default_coverage_for_layer("native_hook")
    shim = default_coverage_for_layer("rust_shim")
    merged = merge_coverage_records([hook, shim])
    with tempfile.TemporaryDirectory(prefix="invart_v018_") as tmp:
        root = Path(tmp)
        ledger = root / "ledger.jsonl"
        session = start_session(root, ledger, agent="benchmark", goal="v0.18 coverage", create_preflight=False)
        record_action(RuntimeEvent(type="shell", session_id=session.session_id, command="echo ok", metadata={"coverage_layer": "agent_log"}), ledger)
        close_session(ledger)
        proof_path = root / "proof.json"
        proof = export_proof_report(ledger, proof_path)
        gate = verify_gate(proof_path=proof_path, ledger_path=ledger, mode="ci", coverage_requirements={"runtime_enforcement": "mediated"})
        checks = {
            "coverage_merge_enforced": merged.runtime_enforcement == "enforced",
            "coverage_requirement_compares": coverage_meets_requirement(CoverageRecord(runtime_observation="mediated"), {"runtime_observation": "observed"}) is True,
            "proof_exports_coverage": proof["coverage"]["summary"]["runtime_observation"]["observed"] >= 1,
            "gate_fails_missing_coverage": gate["status"] == "fail",
        }
        return _suite_result("v0.18-coverage-aware-runtime", checks, artifacts={"ledger": str(ledger), "proof": str(proof_path)})




__all__ = [
    "run_claude_adapter_profile_benchmark",
    "run_coverage_aware_runtime_benchmark",
    "run_enforcement_guard_benchmark",
    "run_enterprise_audit_demo_benchmark",
    "run_harness_compatibility_benchmark",
    "run_hook_plugin_bridge_benchmark",
    "run_llm_reviewer_benchmark",
    "run_mcp_broker_benchmark",
    "run_native_integration_inventory_benchmark",
    "run_policy_profile_benchmark",
    "run_swe_bench_full_validation_contract_benchmark",
    "run_teamrun_handoff_benchmark",
]
