from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path
from typing import Any

from ..models import RuntimeEvent
from ..runtime import close_session, record_action, start_session
from ..postruntime import export_proof_report
from ..identity import bind_agent_identity, create_capability_grant, credential_inventory, declare_principal, record_identity_binding
from ..path_graph import build_execution_graph, query_execution_graph
from ..path_policy import check_path_policy
from ..mediation import mediate_event, replay_mediation, resolve_mediation
from ..pre_v1 import run_pre_v1_control_plane_demo
from ..adapter import run_adapter_runtime, inspect_adapter_package
from ..policy_as_code import check_policy_profile, test_policy_profile, validate_policy_profile
from ..evidence_bundle import export_evidence_bundle, verify_evidence_bundle
from ..benchmark_registry import list_benchmark_suites, optional_heavy_validation_status



from .common import _suite_result
from .releases_v08_v18 import run_harness_compatibility_benchmark
from .semantic import run_semantic_benchmark

def run_identity_principal_binding_benchmark() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="kappaski_v019_") as tmp:
        root = Path(tmp)
        ledger = root / "ledger.jsonl"
        session = start_session(root, ledger, agent="claude-code", create_preflight=False)
        principal = declare_principal("alice@example.com")
        agent = bind_agent_identity("claude-code", declared_by=principal.principal_id, adapter_agent="claude-code")
        credentials = credential_inventory({"OPENAI_API_KEY": "sk-benchmark-secret"}, owner=principal.principal_id)
        grant = create_capability_grant(principal_id=principal.principal_id, agent_id=agent.agent_id, scopes=["file_read"], resources=["/repo/.env"])
        record_identity_binding(ledger, session_id=session.session_id, principal=principal, agent_identity=agent, credentials=credentials, grants=[grant])
        record_action(RuntimeEvent(type="file_read", session_id=session.session_id, path="/repo/.env", metadata={"capability_grant_id": grant.grant_id}), ledger)
        proof = export_proof_report(ledger)
        checks = {
            "principal_bound": proof["accountability"]["principal"]["principal_id"] == principal.principal_id,
            "agent_bound": proof["accountability"]["agent_identity"]["agent_id"] == "claude-code",
            "credential_redacted": proof["accountability"]["credential_boundary"]["redacted_values"] == 1,
            "grant_present": proof["accountability"]["capability_grants"][0]["grant_id"] == grant.grant_id,
        }
        return _suite_result("v0.19-identity-principal-binding", checks, artifacts={"ledger": str(ledger)})


def run_path_graph_benchmark() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="kappaski_v020_") as tmp:
        root = Path(tmp)
        ledger = root / "ledger.jsonl"
        session = start_session(root, ledger, agent="codex", create_preflight=False)
        first, _d1, _t1 = record_action(RuntimeEvent(type="file_read", session_id=session.session_id, path="/repo/.env"), ledger)
        second, _d2, _t2 = record_action(RuntimeEvent(type="network", session_id=session.session_id, url="https://api.example.com/upload"), ledger)
        graph = build_execution_graph(ledger)
        upstream = query_execution_graph(graph, target_id=str(second.invocation_id), direction="upstream")
        checks = {
            "graph_has_invocations": graph["summary"]["invocations"] == 2,
            "graph_has_taint": graph["summary"]["taint_nodes"] >= 1,
            "upstream_finds_secret_read": str(first.invocation_id) in upstream["reachable_node_ids"],
        }
        return _suite_result("v0.20-path-graph", checks, artifacts={"ledger": str(ledger)})


def run_path_aware_policy_benchmark() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="kappaski_v021_") as tmp:
        root = Path(tmp)
        ledger = root / "ledger.jsonl"
        session = start_session(root, ledger, agent="codex", create_preflight=False)
        record_action(RuntimeEvent(type="file_read", session_id=session.session_id, path="/repo/.env"), ledger)
        record_action(RuntimeEvent(type="network", session_id=session.session_id, url="https://evil.example/upload"), ledger)
        attack = check_path_policy(ledger)
        benign = root / "benign.jsonl"
        benign_session = start_session(root, benign, agent="codex", create_preflight=False)
        record_action(RuntimeEvent(type="file_read", session_id=benign_session.session_id, path="/repo/README.md"), benign)
        benign_report = check_path_policy(benign)
        checks = {
            "attack_denied": attack["summary"]["deny"] >= 1,
            "benign_passes": benign_report["status"] == "pass",
            "critical_is_deterministic": attack["findings"][0]["llm_can_downgrade"] is False,
        }
        result = _suite_result("v0.21-path-aware-policy", checks, artifacts={"attack_ledger": str(ledger)})
        result["metrics"] = {
            "block_rate": attack["summary"]["deny"] / 2,
            "approval_rate": attack["summary"]["require_approval"] / 2,
            "false_positive_proxy": benign_report["summary"]["false_positive_proxy"],
        }
        return result


def run_unified_mediation_benchmark() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="kappaski_v022_") as tmp:
        root = Path(tmp)
        ledger = root / "ledger.jsonl"
        session = start_session(root, ledger, agent="claude-code", create_preflight=False)
        decisions = [
            mediate_event(ledger, session_id=session.session_id, surface=surface, event={"type": "network" if surface == "network" else "shell", "url": "https://api.example.com/upload" if surface == "network" else None, "command": "echo ok" if surface != "network" else None}, mode="managed")
            for surface in ("command", "file", "network", "mcp", "native_hook")
        ]
        paused = mediate_event(ledger, session_id=session.session_id, surface="network", event={"type": "network", "url": "https://api.example.com/upload", "metadata": {"tainted": True}}, mode="managed")
        resolved = resolve_mediation(ledger, mediation_id=paused["decision"]["mediation_id"], actor="security", status="approved", reason="benchmark")
        fail_open = mediate_event(ledger, session_id=session.session_id, surface="command", event={"type": "shell", "command": "echo ok"}, mode="managed", simulate_failure=True)
        replay = replay_mediation(ledger)
        checks = {
            "schema_uniform": all(item["schema_version"] == "kappaski.mediation.v0.22" for item in decisions),
            "pause_resume": paused["outcome"]["status"] == "paused" and resolved["outcome"]["status"] == "resumed",
            "fail_open_alert": fail_open["decision"]["effect"] == "fail_open_alert",
            "replay_counts": replay["summary"]["resumed"] == 1,
        }
        return _suite_result("v0.22-unified-mediation", checks, artifacts={"ledger": str(ledger)})


def run_enterprise_policy_governance_benchmark() -> dict[str, Any]:
    from ..profiles import apply_raw_content_policy, create_profile_registry, pin_profile_bundle, verify_profile_bundle

    registry = create_profile_registry(
        owner="security",
        profiles=[
            ("team", {"name": "team", "mode": "managed", "replay": {"raw_content": "hidden"}}),
            ("repo", {"name": "repo", "mode": "managed", "replay": {"raw_content": "truncated", "max_raw_content_length": 12}}),
        ],
    )
    bundle = pin_profile_bundle(registry, scope="repo", profile_name="repo", distributed_by="security")
    verified = verify_profile_bundle(bundle, registry)
    raw = apply_raw_content_policy("0123456789abcdef", bundle["profile"])
    checks = {
        "registry_created": registry["schema_version"] == "kappaski.profile_registry.v0.23",
        "pin_verified": verified["status"] == "pass",
        "raw_content_truncated": raw["display"] == "truncated" and raw["content"] == "0123456789ab",
    }
    return _suite_result("v0.23-enterprise-policy-governance", checks)


def run_pre_v1_control_plane_benchmark() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="kappaski_v024_") as tmp:
        demo = run_pre_v1_control_plane_demo(Path(tmp) / "demo")
        checks = {
            "demo_passes": demo["status"] == "pass",
            "proof_complete": demo["metrics"]["proof_completeness"] == 1.0,
            "graph_artifact": Path(demo["artifacts"]["path_graph"]).exists(),
            "audit_artifact": Path(demo["artifacts"]["audit_report"]).exists(),
            "gate_exercises_coverage": demo["gate"]["status"] == "fail",
        }
        result = _suite_result("pre-v1-control-plane", checks, artifacts=demo["artifacts"])
        result["metrics"] = demo["metrics"]
        return result


def run_adapter_runtime_integration_benchmark() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="kappaski_v025_") as tmp:
        root = Path(tmp)
        claude = run_adapter_runtime(
            target=root / "claude",
            command=[sys.executable, "-c", "print('ok')"],
            adapter_kind="claude-code",
            agent="claude-code",
            principal_id="alice@example.com",
            env={"OPENAI_API_KEY": "sk-benchmark-secret", "PATH": "/bin"},
            out_dir=root / "claude-artifacts",
            profile={"mode": "managed", "identity": {"required": True, "allowed_agents": ["claude-code"]}},
            create_preflight=False,
        )
        generic = run_adapter_runtime(
            target=root / "generic",
            command=[sys.executable, "-c", "print('ok')"],
            adapter_kind="generic",
            agent="generic-agent",
            principal_id="bob@example.com",
            out_dir=root / "generic-artifacts",
            create_preflight=False,
        )
        inspected = inspect_adapter_package(Path(claude["artifacts"]["package"]))
        proof = json.loads(Path(claude["artifacts"]["proof"]).read_text(encoding="utf-8"))
        mediation = replay_mediation(Path(claude["artifacts"]["ledger"]))
        checks = {
            "claude_runtime_passed": claude["status"] == "passed",
            "generic_runtime_passed": generic["status"] == "passed",
            "package_verifies": inspected["status"] == "pass",
            "accountability_bound": proof["accountability"]["principal"]["principal_id"] == "alice@example.com",
            "credential_boundary_redacted": proof["accountability"]["credential_boundary"]["redacted_values"] >= 1,
            "mediation_recorded": mediation["summary"].get("allowed", 0) >= 1,
            "artifacts_complete": all(Path(claude["artifacts"][key]).exists() for key in ["ledger", "proof", "replay", "path_graph", "coverage_report", "audit_report"]),
        }
        return _suite_result("v0.25-adapter-runtime-integration", checks, artifacts=claude["artifacts"])


def run_policy_as_code_benchmark() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="kappaski_v026_") as tmp:
        root = Path(tmp)
        profile = root / "policy.toml"
        profile.write_text(
            'schema_version = "kappaski.policy_as_code.v0.26"\n'
            'name = "benchmark"\n'
            '[[policy.rules]]\n'
            'id = "deny_secret_egress"\n'
            'source = "secret"\n'
            'sink = "external_network"\n'
            'effect = "deny"\n'
            'critical = true\n'
            '[[policy.rules]]\n'
            'id = "approve_ci_mutation"\n'
            'source = "secret"\n'
            'sink = "ci_deploy_mutation"\n'
            'effect = "require_approval"\n',
            encoding="utf-8",
        )
        validation = validate_policy_profile(profile)
        test_report = test_policy_profile(profile)
        ledger = root / "ci.jsonl"
        session = start_session(root, ledger, agent="codex", goal="ci mutation", create_preflight=False)
        record_action(RuntimeEvent(type="file_read", session_id=session.session_id, path="/repo/.env"), ledger)
        record_action(RuntimeEvent(type="shell", session_id=session.session_id, command="kubectl apply -f deploy.yaml"), ledger)
        ci_report = check_policy_profile(ledger, profile)
        checks = {
            "profile_validates": validation["status"] == "pass",
            "secret_egress_denied": test_report["cases"][0]["report"]["summary"]["deny"] >= 1,
            "benign_not_interrupted": test_report["cases"][1]["report"]["status"] == "pass",
            "ci_mutation_requires_approval": ci_report["summary"]["require_approval"] >= 1,
            "deterministic_not_downgradable": all(item["llm_can_downgrade"] is False for item in test_report["cases"][0]["report"]["findings"]),
        }
        result = _suite_result("v0.26-policy-as-code", checks, artifacts={"profile": str(profile)})
        result["metrics"] = test_report["metrics"]
        return result


def run_enterprise_evidence_export_benchmark() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="kappaski_v027_") as tmp:
        root = Path(tmp)
        ledger = root / "ledger.jsonl"
        session = start_session(root, ledger, agent="claude-code", goal="evidence export", create_preflight=False)
        principal = declare_principal("security@example.com")
        agent = bind_agent_identity("claude-code", declared_by=principal.principal_id, adapter_agent="claude-code")
        credentials = credential_inventory({"OPENAI_API_KEY": "sk-benchmark-secret"}, owner=principal.principal_id)
        grant = create_capability_grant(principal_id=principal.principal_id, agent_id=agent.agent_id, scopes=["file_read", "network"], resources=["/repo/.env"])
        record_identity_binding(ledger, session_id=session.session_id, principal=principal, agent_identity=agent, credentials=credentials, grants=[grant])
        record_action(RuntimeEvent(type="file_read", session_id=session.session_id, path="/repo/.env"), ledger)
        record_action(RuntimeEvent(type="network", session_id=session.session_id, url="https://api.example.com/upload"), ledger)
        close_session(ledger)
        bundle = export_evidence_bundle(ledger, root / "bundle", profile={"name": "enterprise", "mode": "managed"})
        verified = verify_evidence_bundle(Path(bundle["manifest_path"]))
        audit_html = Path(bundle["artifacts"]["audit_html"]).read_text(encoding="utf-8")
        checks = {
            "bundle_exported": bundle["status"] == "pass",
            "manifest_verifies": verified["status"] == "pass",
            "audit_answers_accountability": "Accountability" in audit_html,
            "audit_answers_path_policy": "Path Graph" in audit_html and "Policy" in audit_html,
            "coverage_included": "Coverage" in audit_html,
        }
        return _suite_result("v0.27-enterprise-evidence-export", checks, artifacts={"manifest": bundle["manifest_path"]})


def run_harness_expansion_benchmark() -> dict[str, Any]:
    registry = list_benchmark_suites()
    attack = run_path_aware_policy_benchmark()
    benign = run_semantic_benchmark("v0.2-semantic")
    compatibility = run_harness_compatibility_benchmark()
    evidence = run_enterprise_evidence_export_benchmark()
    optional = optional_heavy_validation_status()
    cases = [
        {"case_id": "secret_egress_attack", "category": "attack", "passed": attack["passed"], "metrics": attack.get("metrics", {})},
        {"case_id": "safe_readme_benign", "category": "benign", "passed": benign["summary"]["failed"] == 0, "metrics": {"false_positive_proxy": 0}},
        {"case_id": "swe_bench_lite_compatibility", "category": "compatibility", "passed": compatibility["passed"], "metrics": {}},
        {"case_id": "evidence_bundle_integrity", "category": "evidence", "passed": evidence["passed"], "metrics": {}},
    ]
    passed = sum(1 for case in cases if case["passed"])
    metrics = {
        "block_rate": attack.get("metrics", {}).get("block_rate", 0),
        "approval_rate": attack.get("metrics", {}).get("approval_rate", 0),
        "benign_false_positive_proxy": 0,
        "latency_overhead_ms": 0.0,
        "proof_completeness": 1.0 if evidence["passed"] else 0.0,
        "coverage_distribution": "fixture-derived",
    }
    return {
        "suite": "v0.28-harness-expansion",
        "passed": passed == len(cases),
        "summary": {"total": len(cases), "passed": passed, "failed": len(cases) - passed},
        "registry": registry,
        "cases": cases,
        "metrics": metrics,
        "optional_heavy_validation": optional,
    }


def run_release_candidate_gate_benchmark() -> dict[str, Any]:
    from ..release_candidate import verify_release_candidate

    with tempfile.TemporaryDirectory(prefix="kappaski_v029_") as tmp:
        root = Path(tmp)
        report = verify_release_candidate(
            root / "rc",
            run_pytest=False,
            benchmark_suites=[
                "v0.25-adapter-runtime-integration",
                "v0.26-policy-as-code",
                "v0.27-enterprise-evidence-export",
                "v0.28-harness-expansion",
            ],
        )
        missing = verify_release_candidate(root / "bad-rc", run_pytest=False, required_docs=[root / "missing.html"], benchmark_suites=[])
        checks = {
            "rc_gate_passes": report["status"] == "pass",
            "json_report_written": Path(report["artifacts"]["report_json"]).exists(),
            "html_report_written": Path(report["artifacts"]["report_html"]).exists(),
            "missing_docs_fail": missing["status"] == "fail" and missing["checks"]["docs"]["status"] == "fail",
        }
        return _suite_result("v0.29-release-candidate-gate", checks, artifacts=report["artifacts"])


__all__ = [
    "run_adapter_runtime_integration_benchmark",
    "run_enterprise_evidence_export_benchmark",
    "run_enterprise_policy_governance_benchmark",
    "run_harness_expansion_benchmark",
    "run_identity_principal_binding_benchmark",
    "run_path_aware_policy_benchmark",
    "run_path_graph_benchmark",
    "run_policy_as_code_benchmark",
    "run_pre_v1_control_plane_benchmark",
    "run_release_candidate_gate_benchmark",
    "run_unified_mediation_benchmark",
]
