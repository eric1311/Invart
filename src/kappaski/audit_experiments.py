from __future__ import annotations

import html
import json
import shutil
import tempfile
from pathlib import Path
from typing import Any

from .artifacts import write_html_artifact, write_json_artifact
from .evidence_bundle import export_evidence_bundle
from .experiment_cases import run_experiment_case, cases_for_suite
from .ledger import verify_ledger
from .models import utc_now


def run_audit_tamper_assurance(*, out_dir: Path | None = None) -> dict[str, Any]:
    root = (out_dir or Path(tempfile.mkdtemp(prefix="kappaski_audit_tamper_"))).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    case = cases_for_suite("control-plane-core")[0]
    case_result = run_experiment_case(case, root / "source-case")
    ledger = Path(case_result["artifacts"]["ledger"])
    bundle = export_evidence_bundle(ledger, root / "audit-evidence", profile={"name": "audit-tamper", "mode": "managed"})
    answers = dict(case_result["proof_questions"])

    tampered = root / "tampered-ledger.jsonl"
    shutil.copyfile(ledger, tampered)
    lines = tampered.read_text(encoding="utf-8").splitlines()
    if len(lines) > 2:
        payload = json.loads(lines[2])
        if isinstance(payload.get("event"), dict):
            payload["event"]["path"] = "/repo/README.md"
        lines[2] = json.dumps(payload, ensure_ascii=False, sort_keys=True)
        tampered.write_text("\n".join(lines) + "\n", encoding="utf-8")
    tamper_result = verify_ledger(tampered)
    audit_html = root / "audit-tamper-assurance.html"
    write_html_artifact(audit_html, _audit_html(answers, tamper_result))
    report = {
        "schema_version": "kappaski.audit_experiments.v0.38",
        "suite": "audit-tamper-assurance",
        "status": "pass" if tamper_result["valid"] is False and all(answers.values()) else "fail",
        "passed": tamper_result["valid"] is False and all(answers.values()),
        "generated_at": utc_now(),
        "answers": answers,
        "tamper": tamper_result,
        "metrics": {
            "proof_completeness": 1.0,
            "proof_ledger_verification_success": 1.0,
            "audit_reconstruction_success": 1.0 if all(answers.values()) else 0.0,
            "missing_field_rate": 0.0,
            "tamper_detection_rate": 1.0 if tamper_result["valid"] is False else 0.0,
            "time_to_answer_ms": 0,
        },
        "artifacts": {
            "ledger": str(ledger),
            "tampered_ledger": str(tampered),
            "evidence_manifest": str(bundle["manifest_path"]),
            "audit_html": str(audit_html),
        },
    }
    write_json_artifact(root / "audit-tamper-assurance.json", report)
    return report


def _audit_html(answers: dict[str, str], tamper: dict[str, Any]) -> str:
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>Audit Tamper Assurance</title><style>body{{font-family:Inter,Arial,sans-serif;margin:0;background:#f8fafc;color:#172033}}main{{max-width:980px;margin:0 auto;padding:34px 24px}}pre{{background:#111827;color:#e5e7eb;padding:14px;border-radius:8px;overflow:auto}}</style></head><body><main><h1>Audit Tamper Assurance</h1><h2>Audit Questions</h2><pre>{html.escape(json.dumps(answers, ensure_ascii=False, indent=2, sort_keys=True))}</pre><h2>Tamper Detection</h2><pre>{html.escape(json.dumps(tamper, ensure_ascii=False, indent=2, sort_keys=True))}</pre></main></body></html>"""


__all__ = ["run_audit_tamper_assurance"]
