from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

from invart.core.models import RuntimeEvent
from invart.control.runtime import record_action, record_approval, start_session
from invart.surfaces.corpus import capability_events_from_corpus
from invart.control.gate import verify_gate
from invart.assurance.postruntime import export_proof_report
from invart.surfaces.adapter import run_adapter_command
from invart.control.approval import approve_items, list_approval_items
from invart.assurance.replay import export_replay_html




def run_gate_benchmark() -> dict[str, Any]:
    cases = [
        _gate_clean_case(),
        _gate_missing_approval_case(),
        _gate_approved_capability_case(),
        _gate_tampered_proof_case(),
    ]
    return {
        "suite": "v0.5-proof-gate",
        "summary": _gate_summary(cases),
        "results": cases,
    }


def _gate_clean_case() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="invart_gate_clean_") as tmp:
        root = Path(tmp)
        ledger = root / "ledger.jsonl"
        proof = root / "proof.json"
        session = start_session(root, ledger, agent="benchmark", goal="clean gate", create_preflight=False)
        record_action(RuntimeEvent(type="file_read", session_id=session.session_id, path="/repo/README.md"), ledger, review_mode="off")
        export_proof_report(ledger, proof)
        report = verify_gate(ledger_path=ledger, proof_path=proof, mode="ci")
        return _gate_case("clean_ci_passes", report, "pass")


def _gate_missing_approval_case() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="invart_gate_missing_") as tmp:
        root = Path(tmp)
        ledger = root / "ledger.jsonl"
        proof = root / "proof.json"
        session = start_session(root, ledger, agent="benchmark", goal="missing approval", create_preflight=False)
        record_action(RuntimeEvent(type="file_read", session_id=session.session_id, path="/repo/.env"), ledger)
        export_proof_report(ledger, proof)
        report = verify_gate(ledger_path=ledger, proof_path=proof, mode="managed")
        return _gate_case("missing_approval_fails", report, "fail")


def _gate_approved_capability_case() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="invart_gate_approved_cap_") as tmp:
        root = Path(tmp)
        ledger = root / "ledger.jsonl"
        proof = root / "proof.json"
        session = start_session(root, ledger, agent="benchmark", goal="approved grants", create_preflight=False)
        for event_payload in capability_events_from_corpus(Path("benchmarks/corpora"), session.session_id, adapter="benchmark-adapter"):
            _action, decision, _taint = record_action(RuntimeEvent.from_dict(event_payload), ledger, review_mode="off", policy_mode="managed")
            if decision.requires_approval:
                record_approval(ledger, decision.decision_id, "approved", approver="benchmark", reason="approved for eval")
        export_proof_report(ledger, proof)
        report = verify_gate(ledger_path=ledger, proof_path=proof, mode="managed")
        return _gate_case("approved_high_risk_capabilities_pass", report, "pass")


def _gate_tampered_proof_case() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="invart_gate_tampered_") as tmp:
        root = Path(tmp)
        ledger = root / "ledger.jsonl"
        proof = root / "proof.json"
        session = start_session(root, ledger, agent="benchmark", goal="tampered proof", create_preflight=False)
        record_action(RuntimeEvent(type="file_read", session_id=session.session_id, path="/repo/README.md"), ledger, review_mode="off")
        payload = export_proof_report(ledger, proof)
        payload["summary"]["total_actions"] = 999
        proof.write_text(__import__("json").dumps(payload, ensure_ascii=False, sort_keys=True), encoding="utf-8")
        report = verify_gate(ledger_path=ledger, proof_path=proof, mode="ci")
        return _gate_case("tampered_proof_fails", report, "fail")


def _gate_case(case_id: str, report: dict[str, Any], expected_status: str) -> dict[str, Any]:
    return {
        "case_id": case_id,
        "passed": report.get("status") == expected_status,
        "expected_status": expected_status,
        "actual_status": report.get("status"),
        "finding_ids": [finding.get("check_id") for finding in report.get("findings", [])],
    }


def _gate_summary(results: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(results)
    passed = sum(1 for item in results if item["passed"])
    return {
        "total": total,
        "passed": passed,
        "failed": total - passed,
        "pass_rate": passed / total if total else 0.0,
    }


def run_adapter_workflow_benchmark() -> dict[str, Any]:
    cases = [_adapter_audit_caps_pass_case(), _adapter_managed_caps_fail_case()]
    return {
        "suite": "v0.6-adapter-workflow",
        "summary": _gate_summary(cases),
        "results": cases,
    }


def _adapter_audit_caps_pass_case() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="invart_adapter_pass_") as tmp:
        root = Path(tmp)
        result = run_adapter_command(
            target=root,
            command=["python3", "-c", "pass"],
            agent="benchmark",
            goal="adapter audit capabilities",
            session_id="ks_eval_adapter_pass",
            out_dir=root / "artifacts",
            capabilities="audit",
            gate_mode="ci",
            create_preflight=False,
        )
        return {
            "case_id": "adapter_audit_capabilities_pass",
            "passed": result.status == "passed" and result.gate_status == "pass",
            "expected_status": "passed",
            "actual_status": result.status,
            "gate_status": result.gate_status,
        }


def _adapter_managed_caps_fail_case() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="invart_adapter_fail_") as tmp:
        root = Path(tmp)
        result = run_adapter_command(
            target=root,
            command=["python3", "-c", "pass"],
            agent="benchmark",
            goal="adapter managed capabilities",
            session_id="ks_eval_adapter_fail",
            out_dir=root / "artifacts",
            capabilities="managed",
            gate_mode="managed",
            create_preflight=False,
        )
        return {
            "case_id": "adapter_managed_capabilities_fail_gate",
            "passed": result.status == "failed" and result.gate_status == "fail",
            "expected_status": "failed",
            "actual_status": result.status,
            "gate_status": result.gate_status,
        }


def run_approval_replay_benchmark() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="invart_v07_") as tmp:
        root = Path(tmp)
        artifacts = root / "artifacts"
        case_path = Path("benchmarks/cases/swe-bench-lite/pinned_cases.json")
        result = run_adapter_command(
            target=root,
            command=["python3", "-c", "pass"],
            agent="benchmark",
            goal="SWE-Bench Lite django__django-11001 control-plane replay",
            session_id="ks_eval_v07",
            out_dir=artifacts,
            capabilities="managed",
            gate_mode="managed",
            create_preflight=False,
        )
        ledger = Path(result.ledger)
        proof = Path(result.proof)
        before_gate = verify_gate(ledger_path=ledger, proof_path=proof, mode="managed")
        inbox_before = list_approval_items(ledger, status="missing")
        approval = approve_items(ledger, all_missing=True, approver="benchmark", reason="approved v0.7 benchmark open mode")
        export_proof_report(ledger, proof)
        after_gate = verify_gate(ledger_path=ledger, proof_path=proof, mode="managed", output_path=artifacts / "gate-report.json")
        replay = export_replay_html(ledger, artifacts / "replay.html", gate_mode="managed", case_path=case_path)
        checks = {
            "initial_gate_failed": before_gate.get("status") == "fail",
            "missing_approvals_found": inbox_before["summary"]["by_status"].get("missing", 0) > 0,
            "bulk_approval_recorded": approval["resolved"] == inbox_before["summary"]["by_status"].get("missing", 0),
            "final_gate_passed": after_gate.get("status") == "pass",
            "replay_exported": Path(replay["replay"]).exists(),
            "real_case_attached": replay.get("case") == "django__django-11001",
        }
        return {
            "suite": "v0.7-approval-replay",
            "passed": all(checks.values()),
            "checks": checks,
            "artifacts": {"ledger": str(ledger), "proof": str(proof), "gate_report": str(artifacts / "gate-report.json"), "replay": str(artifacts / "replay.html"), "case": str(case_path)},
        }




__all__ = ["run_approval_replay_benchmark", "run_adapter_workflow_benchmark", "run_gate_benchmark"]
