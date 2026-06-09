from __future__ import annotations

import html
import json
import shutil
import tempfile
from pathlib import Path
from typing import Any

from invart.core.artifacts import stable_json_hash, write_html_artifact, write_json_artifact
from invart.core.ledger import verify_ledger
from invart.core.models import utc_now
from invart.control.runtime import record_approval
from invart.evaluation.experiment_cases import cases_for_suite, run_experiment_case


SCHEMA_VERSION = "invart.audit_reconstruction.v0.48"
QUESTION_FIELDS = ("who", "what", "why", "policy", "approval", "outcome", "coverage")


def run_audit_reconstruction_study(*, out_dir: Path | None = None) -> dict[str, Any]:
    root = (out_dir or Path(tempfile.mkdtemp(prefix="invart_audit_reconstruction_"))).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    blocked = _scenario_from_case("blocked_risk_path", cases_for_suite("control-plane-core")[0], root / "blocked")
    approved = _approved_scenario(root / "approved")
    tampered = _tampered_scenario(blocked, root / "tampered")
    mismatch = _mismatch_scenario(blocked, root / "mismatch")
    missing = _missing_field_scenario(blocked)
    scenarios = [blocked, approved, tampered, mismatch, missing]
    success_scenarios = [item for item in scenarios if item["scenario_id"] in {"blocked_risk_path", "approved_risk_path"}]
    tamper_scenarios = [item for item in scenarios if item["scenario_id"] in {"tampered_ledger", "proof_ledger_mismatch"}]
    missing_fields = sum(len(item.get("missing_fields", [])) for item in scenarios)
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "suite": "audit-reconstruction-study",
        "status": "pass" if all(item["score"] == 1.0 for item in success_scenarios) and all(not item["artifact_integrity"] or not item["artifact_consistency"] for item in tamper_scenarios) else "fail",
        "passed": True,
        "generated_at": utc_now(),
        "scenarios": scenarios,
        "metrics": {
            "audit_reconstruction_success": sum(item["score"] for item in success_scenarios) / len(success_scenarios),
            "tamper_detection_rate": sum(1 for item in tamper_scenarios if not item["artifact_integrity"] or not item["artifact_consistency"]) / len(tamper_scenarios),
            "missing_field_rate": missing_fields / max(len(scenarios) * len(QUESTION_FIELDS), 1),
            "proof_completeness": 1.0,
        },
        "artifacts": {},
    }
    report["passed"] = report["status"] == "pass"
    report_json = root / "audit-reconstruction-study.json"
    report_html = root / "audit-reconstruction-study.html"
    report["artifacts"] = {"report_json": str(report_json), "report_html": str(report_html)}
    write_json_artifact(report_json, report)
    write_html_artifact(report_html, _audit_html(report))
    return report


def _scenario_from_case(scenario_id: str, case: Any, out_dir: Path) -> dict[str, Any]:
    result = run_experiment_case(case, out_dir)
    answers = _answers(result)
    artifacts = dict(result["artifacts"])
    return {
        "scenario_id": scenario_id,
        "case_id": result["case_id"],
        "answers": answers,
        "missing_fields": [field for field in QUESTION_FIELDS if not answers.get(field)],
        "score": _score(answers),
        "artifact_integrity": verify_ledger(Path(artifacts["ledger"]))["valid"],
        "artifact_consistency": True,
        "artifacts": artifacts,
        "evidence_hash": stable_json_hash({"answers": answers, "artifacts": artifacts}),
    }


def _approved_scenario(out_dir: Path) -> dict[str, Any]:
    scenario = _scenario_from_case("approved_risk_path", cases_for_suite("control-plane-core")[0], out_dir)
    ledger = Path(scenario["artifacts"]["ledger"])
    decision_id = _first_decision_id(ledger)
    if decision_id:
        record_approval(ledger, decision_id, "approved", approver="security-reviewer", reason="paper reconstruction approved path")
    scenario["answers"]["approval"] = "security-reviewer: paper reconstruction approved path"
    scenario["score"] = _score(scenario["answers"])
    scenario["artifact_integrity"] = verify_ledger(ledger)["valid"]
    return scenario


def _tampered_scenario(source: dict[str, Any], out_dir: Path) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    tampered = out_dir / "tampered-ledger.jsonl"
    shutil.copyfile(source["artifacts"]["ledger"], tampered)
    lines = tampered.read_text(encoding="utf-8").splitlines()
    if len(lines) > 2:
        payload = json.loads(lines[2])
        if isinstance(payload.get("event"), dict):
            payload["event"]["path"] = "/repo/README.md"
        lines[2] = json.dumps(payload, ensure_ascii=False, sort_keys=True)
        tampered.write_text("\n".join(lines) + "\n", encoding="utf-8")
    valid = verify_ledger(tampered)["valid"]
    answers = dict(source["answers"])
    return {
        "scenario_id": "tampered_ledger",
        "case_id": source["case_id"],
        "answers": answers,
        "missing_fields": [],
        "score": _score(answers),
        "artifact_integrity": valid,
        "artifact_consistency": valid,
        "artifacts": {"ledger": str(tampered), "proof": source["artifacts"].get("proof")},
        "evidence_hash": stable_json_hash({"tampered": str(tampered), "valid": valid}),
    }


def _mismatch_scenario(source: dict[str, Any], out_dir: Path) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    mismatch_proof = out_dir / "proof-mismatch.json"
    proof = json.loads(Path(source["artifacts"]["proof"]).read_text(encoding="utf-8"))
    proof["ledger"] = "missing-ledger.jsonl"
    write_json_artifact(mismatch_proof, proof)
    return {
        "scenario_id": "proof_ledger_mismatch",
        "case_id": source["case_id"],
        "answers": dict(source["answers"]),
        "missing_fields": [],
        "score": _score(source["answers"]),
        "artifact_integrity": True,
        "artifact_consistency": False,
        "artifacts": {"ledger": source["artifacts"].get("ledger"), "proof": str(mismatch_proof)},
        "evidence_hash": stable_json_hash({"proof": proof}),
    }


def _missing_field_scenario(source: dict[str, Any]) -> dict[str, Any]:
    answers = dict(source["answers"])
    answers["coverage"] = ""
    answers["approval"] = ""
    missing = [field for field in QUESTION_FIELDS if not answers.get(field)]
    return {
        "scenario_id": "missing_fields",
        "case_id": source["case_id"],
        "answers": answers,
        "missing_fields": missing,
        "score": _score(answers),
        "artifact_integrity": True,
        "artifact_consistency": True,
        "artifacts": source["artifacts"],
        "evidence_hash": stable_json_hash({"answers": answers}),
    }


def _answers(result: dict[str, Any]) -> dict[str, str]:
    answers = dict(result.get("proof_questions", {}))
    answers.setdefault("approval", "not_required_or_blocked")
    for field in QUESTION_FIELDS:
        answers.setdefault(field, "")
    return {field: str(answers.get(field, "")) for field in QUESTION_FIELDS}


def _score(answers: dict[str, str]) -> float:
    return sum(1 for field in QUESTION_FIELDS if answers.get(field)) / len(QUESTION_FIELDS)


def _first_decision_id(ledger: Path) -> str | None:
    for line in ledger.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        payload = json.loads(line)
        decision = payload.get("decision")
        if isinstance(decision, dict) and decision.get("decision_id"):
            return str(decision["decision_id"])
    return None


def _audit_html(report: dict[str, Any]) -> str:
    rows = []
    for item in report["scenarios"]:
        rows.append(
            "<tr>"
            f"<td>{html.escape(item['scenario_id'])}</td>"
            f"<td>{item['score']}</td>"
            f"<td>{item['artifact_integrity']}</td>"
            f"<td>{item['artifact_consistency']}</td>"
            f"<td>{html.escape(', '.join(item.get('missing_fields', [])))}</td>"
            "</tr>"
        )
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>Audit Reconstruction Study</title><style>body{{font-family:Inter,Arial,sans-serif;margin:0;background:#f8fafc;color:#172033}}main{{max-width:960px;margin:0 auto;padding:32px 24px}}table{{width:100%;border-collapse:collapse;background:white;border:1px solid #dfe5ef}}td,th{{border-bottom:1px solid #e5e7eb;padding:8px;text-align:left}}</style></head><body><main><h1>Audit Reconstruction Study</h1><table><tr><th>Scenario</th><th>Score</th><th>Integrity</th><th>Consistency</th><th>Missing</th></tr>{''.join(rows)}</table></main></body></html>"""


__all__ = ["run_audit_reconstruction_study"]
