from __future__ import annotations

import tempfile
import sys
from pathlib import Path

from .common import _suite_result
from invart.assurance.evidence_bundle import export_evidence_bundle, verify_evidence_bundle
from invart.assurance.evidence_workspace import inspect_evidence_workspace
from invart.assurance.layer_runtime import export_layer_runtime_workflow
from invart.core.ledger import load_ledger_entries
from invart.core.models import RuntimeEvent
from invart.control.runtime import close_session, record_action, start_session
from invart.evaluation.release_candidate import verify_release_candidate
from invart.evaluation.product_control_matrix import run_product_control_matrix
from invart.evaluation.real_agent_conformance import run_real_agent_conformance, validate_conformance_contract
from invart.surfaces.adapter import run_adapter_command
from invart.surfaces.claude_adapter import run_claude_code_adapter
from invart.surfaces.live_adapter import run_live_agent_adapter
from invart.surfaces.adapter_profiles import adapter_track_matrix, list_adapter_profiles, validate_adapter_profile_truthfulness
from invart.surfaces.vendor_evidence import import_gateway_server_evidence, import_vendor_native_evidence, validate_vendor_claim_boundary
from invart.surfaces.native import native_capability_matrix, unmanaged_agent_inventory
from invart.surfaces.native_bridge import bridge_conformance_matrix, normalize_native_event
from invart.governance.registration import export_agent_registry, unmanaged_registration_gaps, verify_registered_launch
from invart.surfaces.launcher import install_managed_launcher


def run_agent_adapter_contract_benchmark() -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="invart_v093_") as tmp:
        root = Path(tmp)
        fake = root / "fake-agent"
        fake.write_text("#!/usr/bin/env python3\nimport sys\nsys.exit(0)\n", encoding="utf-8")
        fake.chmod(0o755)
        profiles = list_adapter_profiles()
        validation = validate_adapter_profile_truthfulness(profiles)
        conformance = run_real_agent_conformance(
            out_dir=root / "conformance",
            agents=["claude-code", "codex"],
            binary_overrides={"claude-code": str(fake), "codex": str(fake)},
            require_live=True,
        )
        by_agent = {profile["agent_id"]: profile for profile in profiles}
        checks = {
            "profiles_truthful": validation.get("status") == "pass",
            "priority_agents_registered": {"claude-code", "codex", "hermes", "openclaw"}.issubset(by_agent),
            "cloud_import_not_mediated": by_agent.get("github-copilot-cloud-agent", {}).get("supports_mediation") is False,
            "claude_full_requires_evidence": {"ledger", "proof", "evidence_bundle"}.issubset(set(by_agent.get("claude-code", {}).get("required_artifacts", []))),
            "fixture_conformance_passed": conformance.get("status") == "pass",
            "strict_mode_records_managed_run": all(agent.get("managed_run", {}).get("status") == "pass" for agent in conformance.get("agents", [])),
        }
        return _suite_result(
            "v0.9.3-agent-adapter-contract",
            checks,
            artifacts=conformance.get("artifacts", {}),
        )


def run_claude_reference_adapter_benchmark() -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="invart_v094_") as tmp:
        root = Path(tmp)
        hooks = root / "hooks.jsonl"
        hooks.write_text(
            '{"type":"file_read","path":".env","metadata":{"source":"claude_code_hook"}}\n',
            encoding="utf-8",
        )
        package_run = run_claude_code_adapter(
            target=root,
            command=[sys.executable, "-c", "pass"],
            hook_events=hooks,
            out_dir=root / "package",
            session_id="ks_v094_benchmark_package",
            policy_mode="advisory",
        )
        managed_marker = root / "managed_should_not_exist.txt"
        managed_run = run_claude_code_adapter(
            target=root,
            command=["sh", "-c", f"touch {managed_marker}; rm -rf ."],
            out_dir=root / "managed",
            session_id="ks_v094_benchmark_managed",
            policy_mode="managed",
        )
        benign_marker = root / "benign.txt"
        benign_run = run_claude_code_adapter(
            target=root,
            command=[sys.executable, "-c", f"from pathlib import Path; Path({str(benign_marker)!r}).write_text('ok')"],
            out_dir=root / "benign",
            session_id="ks_v094_benchmark_benign",
            policy_mode="advisory",
        )
        entries, _warnings = load_ledger_entries(Path(package_run["ledger"]))
        mediation_surfaces = {
            entry.result.get("request", {}).get("surface")
            for entry in entries
            if entry.entry_type == "mediation" and isinstance(entry.result, dict)
        }
        verification = verify_evidence_bundle(Path(package_run["adapter_package"]["manifest_path"]))
        checks = {
            "hook_event_mediated": "file" in mediation_surfaces,
            "adapter_package_verified": verification.get("status") == "pass",
            "l5_artifacts_present": {
                "ledger",
                "proof",
                "replay",
                "path_graph_json",
                "path_graph_html",
                "coverage",
                "audit_html",
            }.issubset(set(package_run["adapter_package"]["artifacts"])),
            "managed_risk_stopped_before_side_effect": managed_run.get("returncode") == 126 and not managed_marker.exists(),
            "managed_status_is_explicit": managed_run.get("status") in {"blocked", "requires_approval"},
            "benign_advisory_kept_autonomy": benign_run.get("status") == "passed" and benign_marker.exists(),
            "supervision_truthful_degraded": package_run.get("supervision", {}).get("coverage_grade") == "mediated_without_process_tree",
        }
        return _suite_result(
            "v0.9.4-claude-reference-adapter",
            checks,
            artifacts={
                "package_manifest": package_run["adapter_package"]["manifest_path"],
                "package_ledger": package_run["ledger"],
                "managed_ledger": managed_run["ledger"],
                "benign_ledger": benign_run["ledger"],
            },
        )


def run_priority_agent_tracks_benchmark() -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="invart_v095_") as tmp:
        root = Path(tmp)
        profiles = list_adapter_profiles()
        by_agent = {profile["agent_id"]: profile for profile in profiles}
        validation = validate_adapter_profile_truthfulness(profiles)
        track_matrix = adapter_track_matrix()
        claude = run_claude_code_adapter(
            target=root,
            command=[sys.executable, "-c", "pass"],
            out_dir=root / "claude",
            session_id="ks_v095_benchmark_claude",
            policy_mode="advisory",
        )
        codex = run_adapter_command(
            target=root,
            command=[sys.executable, "-c", "pass"],
            agent="codex",
            goal="v0.9.5 priority track benchmark",
            session_id="ks_v095_benchmark_codex",
            out_dir=root / "codex",
            capabilities="audit",
            gate_mode="audit",
            create_preflight=False,
        )
        matrix = run_product_control_matrix(out_dir=root / "matrix")
        profile_rows = {row["agent_id"]: row for row in matrix["rows"] if row.get("source_kind") == "invart_adapter_profile"}
        checks = {
            "profiles_validate": validation.get("status") == "pass",
            "track_matrix_passes": track_matrix.get("status") == "pass",
            "priority_agents_have_tracks": all(
                by_agent[agent].get("integration_track") and by_agent[agent].get("control_position")
                for agent in ["claude-code", "codex", "gemini-cli", "cursor", "opencode", "openclaw", "hermes"]
            ),
            "vendor_import_not_mediated": all(
                profile.get("supports_mediation") is False and profile.get("control_position") == "vendor_owned_import"
                for profile in profiles
                if profile.get("integration_track") in {"vendor_evidence_import", "cloud_evidence_import", "framework_trace_import"}
            ),
            "claude_fixture_package_verifies": verify_evidence_bundle(Path(claude["adapter_package"]["manifest_path"])).get("status") == "pass",
            "codex_wrapper_package_exists": codex.package is not None and Path(codex.package).exists(),
            "product_matrix_uses_profile_rows": matrix.get("checks", {}).get("profile_rows_match_track_vocabulary") is True and "claude-code" in profile_rows,
            "profile_matrix_agrees_with_coverage_vocabulary": profile_rows.get("github-copilot-cloud-agent", {}).get("coverage_grade") == "vendor_owned",
        }
        return _suite_result(
            "v0.9.5-priority-agent-tracks",
            checks,
            artifacts={
                "claude_package": claude["adapter_package"]["manifest_path"],
                "codex_package": codex.package,
                "product_matrix": matrix["artifacts"]["matrix_json"],
            },
        )


def run_layer_runtime_workflow_benchmark() -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="invart_v096_") as tmp:
        root = Path(tmp)
        ledger = root / "ledger.jsonl"
        session = start_session(root, ledger, agent="claude-code", goal="v0.9.6 layer runtime benchmark", create_preflight=False)
        record_action(RuntimeEvent(type="file_read", session_id=session.session_id, path=str(root / ".env"), metadata={"coverage_layer": "native_hook"}), ledger)
        record_action(RuntimeEvent(type="network", session_id=session.session_id, url="https://example.com/upload", metadata={"coverage_layer": "native_hook"}), ledger)
        close_session(ledger)
        workflow = export_layer_runtime_workflow(ledger, root / "layers")
        checks = {
            "workflow_passes": workflow.get("status") == "pass",
            "matrix_has_all_stages": {item["stage"] for item in workflow["runtime_effect_matrix"]} == {"before-runtime", "during-runtime", "after-runtime"},
            "matrix_has_all_layers": {item["layer"] for item in workflow["runtime_effect_matrix"]} == {"L1", "L2", "L3", "L4", "L5"},
            "timeline_has_all_layers": {item["layer"] for item in workflow["layer_timeline"]} == {"L1", "L2", "L3", "L4", "L5"},
            "l5_artifacts_exist": all(Path(workflow["artifacts"][key]).exists() for key in ["proof", "replay", "path_graph_json", "path_graph_html", "coverage", "audit_html", "evidence_manifest", "workflow_json", "workflow_html"]),
            "operation_guide_has_cli": any("runtime layers" in item["command"] for item in workflow["operations"]),
        }
        return _suite_result(
            "v0.9.6-layer-runtime-workflow",
            checks,
            artifacts={
                "workflow_json": workflow["artifacts"]["workflow_json"],
                "workflow_html": workflow["artifacts"]["workflow_html"],
                "evidence_manifest": workflow["artifacts"]["evidence_manifest"],
            },
        )


def run_evidence_workspace_gate_benchmark() -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="invart_v097_") as tmp:
        root = Path(tmp)
        ledger = root / "ledger.jsonl"
        session = start_session(root, ledger, agent="claude-code", goal="v0.9.7 evidence workspace benchmark", create_preflight=False)
        record_action(RuntimeEvent(type="file_read", session_id=session.session_id, path=str(root / ".env"), metadata={"coverage_layer": "native_hook"}), ledger)
        record_action(RuntimeEvent(type="network", session_id=session.session_id, url="https://example.com/upload", metadata={"coverage_layer": "native_hook"}), ledger)
        close_session(ledger)

        workflow = export_layer_runtime_workflow(ledger, root / "layers")
        workspace = inspect_evidence_workspace(
            Path(workflow["artifacts"]["evidence_manifest"]),
            out_dir=root / "workspace",
            require_questions=True,
            require_layer_workflow=True,
        )

        tamper_bundle = export_evidence_bundle(ledger, root / "tamper-bundle", profile={"name": "tamper", "mode": "managed"})
        proof_path = Path(tamper_bundle["artifacts"]["proof"])
        proof_path.write_text(proof_path.read_text(encoding="utf-8") + "\n{\"tampered\": true}\n", encoding="utf-8")
        tampered = inspect_evidence_workspace(Path(tamper_bundle["manifest_path"]), out_dir=root / "tampered")

        claude = run_claude_code_adapter(
            target=root,
            command=[sys.executable, "-c", "pass"],
            out_dir=root / "claude",
            session_id="ks_v097_benchmark_claude",
            policy_mode="advisory",
        )
        adapter_workspace = inspect_evidence_workspace(
            Path(claude["adapter_package"]["manifest_path"]),
            out_dir=root / "adapter-workspace",
            require_adapter_package=True,
        )
        rc = verify_release_candidate(
            root / "rc",
            run_pytest=False,
            benchmark_suites=["v0.9.6-layer-runtime-workflow"],
            evidence_workspace_manifest=Path(workflow["artifacts"]["evidence_manifest"]),
            require_evidence_layer_workflow=True,
        )
        checks = {
            "workspace_answers_l5_questions": workspace.get("status") == "pass" and all(answer.get("answered") for answer in workspace.get("answers", {}).values()),
            "workspace_requires_layer_workflow": workspace.get("layer_workflow", {}).get("present") is True,
            "tamper_fails_workspace": tampered.get("status") == "fail" and any(item.get("check_id") == "artifact.hash_mismatch" for item in tampered.get("findings", [])),
            "adapter_package_requirement_passes": adapter_workspace.get("status") == "pass" and adapter_workspace.get("adapter_package", {}).get("present") is True,
            "rc_consumes_workspace_gate": rc.get("status") == "pass" and rc.get("checks", {}).get("evidence_workspace", {}).get("status") == "pass",
        }
        return _suite_result(
            "v0.9.7-evidence-workspace-gate",
            checks,
            artifacts={
                "workspace_json": workspace.get("artifacts", {}).get("workspace_json"),
                "workspace_html": workspace.get("artifacts", {}).get("workspace_html"),
                "layer_workflow": workflow["artifacts"]["workflow_json"],
                "adapter_workspace": adapter_workspace.get("artifacts", {}).get("workspace_json"),
                "rc_report": rc.get("artifacts", {}).get("report_json"),
            },
        )


def run_claude_full_live_adapter_benchmark() -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="invart_v098_") as tmp:
        root = Path(tmp)
        fake = root / "fake-claude"
        marker = root / "benign-marker.txt"
        fake.write_text(
            "#!/usr/bin/env python3\n"
            "import pathlib, sys\n"
            "if '--version' in sys.argv:\n"
            "    print('Claude Code fixture 0.9.8')\n"
            "    raise SystemExit(0)\n"
            "if '--write-marker' in sys.argv:\n"
            "    pathlib.Path(sys.argv[sys.argv.index('--write-marker') + 1]).write_text('ran')\n",
            encoding="utf-8",
        )
        fake.chmod(0o755)
        live = run_claude_code_adapter(
            target=root,
            command=[str(fake), "--write-marker", str(marker)],
            out_dir=root / "live",
            session_id="ks_v098_benchmark_live",
            policy_mode="advisory",
            binary=str(fake),
            require_live=True,
        )
        missing = run_claude_code_adapter(
            target=root,
            command=[sys.executable, "-c", "pass"],
            out_dir=root / "missing",
            session_id="ks_v098_benchmark_missing",
            binary=str(root / "missing-claude"),
            require_live=True,
        )
        risk_marker = root / "risk-marker.txt"
        risky = run_claude_code_adapter(
            target=root,
            command=[str(fake), "--write-marker", str(risk_marker), "rm -rf ."],
            out_dir=root / "risky",
            session_id="ks_v098_benchmark_risky",
            policy_mode="managed",
            binary=str(fake),
            require_live=True,
        )
        checks = {
            "strict_live_binary_backed": live.get("live_evidence", {}).get("binary", {}).get("status") == "found",
            "fixture_not_masquerading_as_unqualified_live": live.get("live_evidence", {}).get("evidence_level") == "binary_backed_live_or_fixture",
            "l5_package_present": live.get("adapter_package", {}).get("status") == "pass" and live.get("layer_runtime", {}).get("status") == "pass",
            "evidence_workspace_answers": live.get("evidence_workspace", {}).get("status") == "pass",
            "strict_missing_binary_fails": missing.get("status") == "blocked_missing_binary",
            "managed_risk_stopped_before_side_effect": risky.get("returncode") == 126 and not risk_marker.exists(),
            "benign_keeps_autonomy": live.get("status") == "passed" and marker.exists(),
            "coverage_degraded_is_truthful": live.get("supervision", {}).get("coverage_grade") == "mediated_without_process_tree",
        }
        return _suite_result(
            "v0.9.8-claude-full-live-adapter",
            checks,
            artifacts={
                "adapter_package": live.get("adapter_package", {}).get("manifest_path"),
                "layer_workflow": live.get("layer_runtime", {}).get("artifacts", {}).get("workflow_json"),
                "workspace": live.get("evidence_workspace", {}).get("artifacts", {}).get("workspace_json"),
            },
        )


def run_conformance_contract_v2_benchmark() -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="invart_v099_") as tmp:
        root = Path(tmp)
        fake = root / "fake-agent"
        fake.write_text("#!/usr/bin/env python3\nimport sys\nsys.exit(0)\n", encoding="utf-8")
        fake.chmod(0o755)
        report = run_real_agent_conformance(
            out_dir=root / "conformance",
            agents=["claude-code", "openclaw"],
            binary_overrides={"claude-code": str(fake), "openclaw": str(fake)},
            require_live=True,
        )
        by_agent = {row["agent"]: row for row in report["agents"]}
        inflated = dict(by_agent["openclaw"])
        inflated["contract"] = {**dict(inflated["contract"]), "claimable_coverage": "managed_wrapper"}
        inflated_gate = validate_conformance_contract([inflated])
        checks = {
            "contract_schema_present": report.get("conformance_contract", {}).get("schema_version") == "invart.adapter_conformance_contract.v0.9.9",
            "managed_wrapper_claim_has_artifacts": by_agent["claude-code"]["contract"]["artifact_completeness"]["status"] == "pass",
            "vendor_import_not_mediated": by_agent["openclaw"]["contract"]["claimable_coverage"] == "vendor_import",
            "vendor_cannot_claim_pre_side_effect_mediation": "invart_pre_side_effect_mediation" in by_agent["openclaw"]["contract"]["cannot_claim"],
            "claim_gate_passes_truthful_rows": report.get("conformance_contract", {}).get("claim_gate", {}).get("status") == "pass",
            "claim_gate_fails_inflated_row": inflated_gate.get("status") == "fail",
        }
        return _suite_result(
            "v0.9.9-conformance-contract-v2",
            checks,
            artifacts=report.get("artifacts", {}),
        )


def run_opencode_real_adapter_benchmark() -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="invart_v0910_") as tmp:
        root = Path(tmp)
        (root / "opencode.json").write_text('{"plugin":["demo"],"mcp":{"fs":{}}}\n', encoding="utf-8")
        fake = root / "fake-opencode"
        marker = root / "opencode-marker.txt"
        fake.write_text(
            "#!/usr/bin/env python3\n"
            "import pathlib, sys\n"
            "if '--version' in sys.argv:\n"
            "    raise SystemExit(0)\n"
            "if '--write-marker' in sys.argv:\n"
            "    pathlib.Path(sys.argv[sys.argv.index('--write-marker') + 1]).write_text('ran')\n",
            encoding="utf-8",
        )
        fake.chmod(0o755)
        run = run_live_agent_adapter(
            agent="opencode",
            target=root,
            out_dir=root / "opencode",
            command=[str(fake), "--write-marker", str(marker)],
            binary=str(fake),
            require_live=True,
            policy_mode="advisory",
        )
        risk_marker = root / "risk-marker.txt"
        risk = run_live_agent_adapter(
            agent="opencode",
            target=root,
            out_dir=root / "opencode-risk",
            command=[str(fake), "--write-marker", str(risk_marker), "rm -rf ."],
            binary=str(fake),
            require_live=True,
            policy_mode="managed",
        )
        inventory = [item for item in run.get("native_inventory", {}).get("profiles", []) if item.get("agent") == "opencode"][0]
        checks = {
            "live_binary_backed": run.get("live_evidence", {}).get("binary", {}).get("status") == "found",
            "managed_wrapper_artifacts": bool(run.get("managed_run", {}).get("ledger")) and bool(run.get("managed_run", {}).get("proof")) and bool(run.get("managed_run", {}).get("package")),
            "plugin_config_inventory": bool(inventory.get("surfaces", {}).get("plugins", {}).get("matches")),
            "mcp_config_inventory": bool(inventory.get("surfaces", {}).get("mcp", {}).get("matches")),
            "benign_keeps_autonomy": run.get("status") == "passed" and marker.exists(),
            "managed_risk_stopped_before_side_effect": risk.get("returncode") == 126 and not risk_marker.exists(),
            "l5_workspace_present": run.get("evidence_workspace", {}).get("status") == "pass",
        }
        return _suite_result(
            "v0.9.10-opencode-real-adapter",
            checks,
            artifacts=run.get("artifacts", {}),
        )


def run_terminal_agent_managed_wrappers_benchmark() -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="invart_v0911_") as tmp:
        root = Path(tmp)
        (root / ".gemini").mkdir()
        (root / ".gemini" / "settings.json").write_text('{"mcpServers":{"fs":{}}}\n', encoding="utf-8")
        (root / ".git").mkdir()
        (root / ".aider.conf.yml").write_text("auto-commits: false\n", encoding="utf-8")
        fake = root / "fake-terminal-agent"
        fake.write_text(
            "#!/usr/bin/env python3\n"
            "import pathlib, sys\n"
            "if '--version' in sys.argv:\n"
            "    raise SystemExit(0)\n"
            "if '--write-marker' in sys.argv:\n"
            "    pathlib.Path(sys.argv[sys.argv.index('--write-marker') + 1]).write_text('ran')\n",
            encoding="utf-8",
        )
        fake.chmod(0o755)
        runs: dict[str, dict[str, object]] = {}
        approval_counts: dict[str, int] = {}
        for agent in ("gemini-cli", "aider"):
            marker = root / f"{agent}.txt"
            run = run_live_agent_adapter(
                agent=agent,
                target=root,
                out_dir=root / agent,
                command=[str(fake), "--write-marker", str(marker)],
                binary=str(fake),
                require_live=True,
                policy_mode="advisory",
            )
            entries, _warnings = load_ledger_entries(Path(run["managed_run"]["ledger"]))
            approval_counts[agent] = sum(
                1
                for entry in entries
                if entry.entry_type == "action" and entry.decision and entry.decision.get("effect") == "require_approval"
            )
            run["marker_exists"] = marker.exists()
            runs[agent] = run
        gemini_inventory = [item for item in runs["gemini-cli"]["native_inventory"]["profiles"] if item["agent"] == "gemini-cli"][0]
        aider_inventory = [item for item in runs["aider"]["native_inventory"]["profiles"] if item["agent"] == "aider"][0]
        checks = {
            "gemini_managed_run_passed": runs["gemini-cli"].get("status") == "passed" and runs["gemini-cli"].get("marker_exists") is True,
            "aider_managed_run_passed": runs["aider"].get("status") == "passed" and runs["aider"].get("marker_exists") is True,
            "gemini_mcp_inventory": bool(gemini_inventory.get("surfaces", {}).get("mcp", {}).get("matches")),
            "aider_config_inventory": bool(aider_inventory.get("surfaces", {}).get("config", {}).get("matches")),
            "aider_repo_context_inventory": bool(aider_inventory.get("surfaces", {}).get("repo_map", {}).get("matches")),
            "approval_noise_zero": all(count == 0 for count in approval_counts.values()),
            "artifact_parity_present": all(bool(runs[agent].get("managed_run", {}).get("ledger")) and bool(runs[agent].get("managed_run", {}).get("proof")) for agent in runs),
        }
        return _suite_result(
            "v0.9.11-terminal-agent-managed-wrappers",
            checks,
            artifacts={agent: runs[agent].get("artifacts", {}).get("report_json") for agent in runs},
        )


def run_codex_boundary_benchmark() -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="invart_v0912_") as tmp:
        root = Path(tmp)
        source = root / "codex-native.json"
        source.write_text('{"sandbox":"workspace-write","approval":"on-request","network_policy":"restricted","credential_boundary":"redacted-env"}\n', encoding="utf-8")
        vendor = import_vendor_native_evidence(agent="codex", source_path=source, out_dir=root / "vendor")
        inflated = {**vendor, "coverage": {**vendor["coverage"], "invart_enforced": True}}
        inflated_check = validate_vendor_claim_boundary(inflated)
        fake = root / "fake-codex"
        marker = root / "codex-marker.txt"
        fake.write_text(
            "#!/usr/bin/env python3\n"
            "import pathlib, sys\n"
            "if '--version' in sys.argv:\n"
            "    raise SystemExit(0)\n"
            "if '--write-marker' in sys.argv:\n"
            "    pathlib.Path(sys.argv[sys.argv.index('--write-marker') + 1]).write_text('ran')\n",
            encoding="utf-8",
        )
        fake.chmod(0o755)
        run = run_live_agent_adapter(
            agent="codex",
            target=root,
            out_dir=root / "codex",
            command=[str(fake), "--write-marker", str(marker)],
            binary=str(fake),
            require_live=True,
            policy_mode="advisory",
        )
        entries, _warnings = load_ledger_entries(Path(run["managed_run"]["ledger"]))
        checks = {
            "vendor_native_imported": vendor.get("status") == "pass" and vendor.get("coverage", {}).get("control_position") == "vendor_owned_import",
            "vendor_not_invart_enforced": vendor.get("coverage", {}).get("invart_enforced") is False,
            "inflated_vendor_claim_fails": inflated_check.get("status") == "fail",
            "wrapper_run_is_invart_mediated": any(entry.entry_type == "action" and entry.decision for entry in entries),
            "wrapper_run_keeps_autonomy": run.get("status") == "passed" and marker.exists(),
            "boundary_text_present": "must not be counted" in vendor.get("claim_boundary", ""),
        }
        return _suite_result(
            "v0.9.12-codex-boundary",
            checks,
            artifacts={
                "vendor_evidence": vendor.get("artifacts", {}).get("report_json"),
                "managed_run": run.get("artifacts", {}).get("report_json"),
            },
        )


def run_ide_bridge_inventory_benchmark() -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="invart_v0913_") as tmp:
        root = Path(tmp)
        (root / ".cursor").mkdir()
        (root / ".cursor" / "mcp.json").write_text('{"mcpServers":{"fs":{}}}\n', encoding="utf-8")
        (root / ".cline").mkdir()
        (root / ".cline" / "settings.json").write_text('{"tools":["shell"]}\n', encoding="utf-8")
        (root / ".roo").mkdir()
        (root / ".roo" / "mcp.json").write_text('{"mcpServers":{"repo":{}}}\n', encoding="utf-8")
        matrix = native_capability_matrix(root)
        unmanaged = unmanaged_agent_inventory(root)
        by_agent = {item["agent"]: item for item in matrix["agents"]}
        bridge = bridge_conformance_matrix()
        action = normalize_native_event("cursor", {"tool": "shell", "arguments": {"command": "echo ok"}, "session_id": "bench"})
        checks = {
            "cursor_discovery_not_mediation": all(surface["coverage_state"] != "mediated" for surface in by_agent["cursor"]["surfaces"].values() if surface["source_evidence"]),
            "cline_discovery_not_mediation": all(surface["coverage_state"] != "mediated" for surface in by_agent["cline"]["surfaces"].values() if surface["source_evidence"]),
            "roo_discovery_not_mediation": all(surface["coverage_state"] != "mediated" for surface in by_agent["roo-code"]["surfaces"].values() if surface["source_evidence"]),
            "unmanaged_gaps_reported": {"cursor", "cline", "roo-code"}.issubset({item["agent"] for item in unmanaged["findings"]}),
            "bridge_conformance_includes_ide": bridge.get("status") == "pass" and {"cursor", "cline", "roo-code"}.issubset({item["agent"] for item in bridge["cases"]}),
            "imported_event_has_native_source": action.adapter == "native_hook:cursor" and action.metadata["coverage_layer"] == "native_hook",
        }
        return _suite_result(
            "v0.9.13-ide-bridge-inventory",
            checks,
            artifacts={},
        )


def run_gateway_server_evidence_benchmark() -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="invart_v0914_") as tmp:
        root = Path(tmp)
        hermes_source = root / "hermes-backend.json"
        hermes_source.write_text('{"timestamp":"2026-06-11T00:00:00Z","backend":"container","security_posture":{"credential_filter":"enabled"},"runtime_boundary":"vendor_owned"}\n', encoding="utf-8")
        hermes = import_gateway_server_evidence(agent="hermes", source_path=hermes_source, out_dir=root / "hermes")
        fake = root / "fake-openclaw"
        marker = root / "openclaw-marker.txt"
        fake.write_text(
            "#!/usr/bin/env python3\n"
            "import pathlib, sys\n"
            "if '--version' in sys.argv:\n"
            "    raise SystemExit(0)\n"
            "if '--write-marker' in sys.argv:\n"
            "    pathlib.Path(sys.argv[sys.argv.index('--write-marker') + 1]).write_text('ran')\n",
            encoding="utf-8",
        )
        fake.chmod(0o755)
        managed = run_live_agent_adapter(
            agent="openclaw",
            target=root,
            out_dir=root / "openclaw",
            command=[str(fake), "--write-marker", str(marker)],
            binary=str(fake),
            require_live=True,
            policy_mode="advisory",
        )
        checks = {
            "gateway_source_hash_recorded": bool(hermes.get("source", {}).get("sha256")),
            "gateway_source_timestamp_recorded": hermes.get("source", {}).get("source_timestamp") == "2026-06-11T00:00:00Z",
            "gateway_vendor_owned_not_mediated": hermes.get("coverage", {}).get("invart_mediated") is False and hermes.get("coverage", {}).get("coverage_grade") == "vendor_owned",
            "gateway_limitation_present": bool(hermes.get("limitation")),
            "managed_launcher_boundary_can_emit_ledger": managed.get("status") == "passed" and marker.exists() and bool(managed.get("managed_run", {}).get("ledger")),
            "claim_boundary_truthful": "cannot be counted as Invart-mediated" in hermes.get("claim_boundary", ""),
        }
        return _suite_result(
            "v0.9.14-gateway-server-evidence",
            checks,
            artifacts={
                "gateway_evidence": hermes.get("artifacts", {}).get("report_json"),
                "managed_run": managed.get("artifacts", {}).get("report_json"),
            },
        )


def run_enterprise_registration_authority_benchmark() -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="invart_v0915_") as tmp:
        root = Path(tmp)
        install_managed_launcher(root, agent="claude-code")
        (root / ".hermes").mkdir()
        (root / ".hermes" / "mcp.json").write_text('{"mcpServers":{"fs":{}}}\n', encoding="utf-8")
        registry = export_agent_registry(root, agents=["claude-code", "opencode"], owner="platform-security", scope="repo", output_path=root / "agent-registry.json")
        allowed = verify_registered_launch(
            registry,
            agent="claude-code",
            declared_agent="claude-code",
            principal_id="alice@example.com",
            profile={"mode": "enterprise", "registration": {"required": True, "require_managed_launcher": True}},
        )
        missing_launcher = verify_registered_launch(
            registry,
            agent="opencode",
            declared_agent="opencode",
            principal_id="alice@example.com",
            profile={"mode": "enterprise", "registration": {"required": True, "require_managed_launcher": True}},
        )
        mismatch = verify_registered_launch(
            registry,
            agent="claude-code",
            declared_agent="codex",
            principal_id="alice@example.com",
            profile={"mode": "enterprise", "registration": {"required": True}},
        )
        gaps = unmanaged_registration_gaps(root, registry)
        checks = {
            "registry_manifest_hashed": bool(registry.get("registry_hash")) and registry.get("schema_version") == "invart.enterprise_agent_registry.v0.9.15",
            "registered_managed_launch_passes": allowed.get("status") == "pass" and allowed.get("coverage", {}).get("runtime_enforcement") == "mediated",
            "registered_without_launcher_fails_enterprise": missing_launcher.get("status") == "fail" and any(item.get("check_id") == "registration.managed_launcher_missing" for item in missing_launcher.get("findings", [])),
            "declared_agent_mismatch_fails": mismatch.get("status") == "fail" and any(item.get("check_id") == "registration.agent_mismatch" for item in mismatch.get("findings", [])),
            "unregistered_native_gap_reported": any(item.get("agent") == "hermes" for item in gaps.get("findings", [])),
        }
        return _suite_result(
            "v0.9.15-enterprise-registration-authority",
            checks,
            artifacts={"registry": str(root / "agent-registry.json"), "gaps": gaps, "allowed": allowed, "missing_launcher": missing_launcher},
        )


__all__ = [
    "run_agent_adapter_contract_benchmark",
    "run_claude_full_live_adapter_benchmark",
    "run_claude_reference_adapter_benchmark",
    "run_conformance_contract_v2_benchmark",
    "run_codex_boundary_benchmark",
    "run_evidence_workspace_gate_benchmark",
    "run_enterprise_registration_authority_benchmark",
    "run_gateway_server_evidence_benchmark",
    "run_ide_bridge_inventory_benchmark",
    "run_opencode_real_adapter_benchmark",
    "run_terminal_agent_managed_wrappers_benchmark",
    "run_priority_agent_tracks_benchmark",
    "run_layer_runtime_workflow_benchmark",
]
