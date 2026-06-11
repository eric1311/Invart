from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

from invart.assurance.evidence_bundle import verify_evidence_bundle
from invart.core.artifacts import relative_href, write_html_artifact, write_json_artifact
from invart.core.models import utc_now


SCHEMA_VERSION = "invart.evidence_workspace.v0.9.7"
REQUIRED_ARTIFACTS = (
    "ledger",
    "proof",
    "replay",
    "path_graph_json",
    "path_graph_html",
    "path_policy",
    "coverage",
    "audit_json",
    "audit_html",
)
REVIEW_QUESTIONS = ("who", "what", "why", "policy", "approval", "outcome", "coverage")
EXPECTED_LAYERS = ("L1", "L2", "L3", "L4", "L5")
EXPECTED_STAGES = ("after-runtime", "before-runtime", "during-runtime")


def inspect_evidence_workspace(
    manifest_path: Path,
    *,
    out_dir: Path | None = None,
    require_questions: bool = True,
    require_layer_workflow: bool = False,
    require_adapter_package: bool = False,
) -> dict[str, Any]:
    manifest_path = manifest_path.expanduser().resolve()
    findings: list[dict[str, Any]] = []
    manifest, manifest_error = _load_json(manifest_path)
    if manifest_error:
        findings.append(_finding("manifest.unreadable", "fail", manifest_error, str(manifest_path)))
        report = _workspace_report(
            manifest_path,
            manifest={},
            verification={},
            findings=findings,
            answers=_empty_answers("manifest is unavailable"),
            layer_workflow=_layer_workflow_status(manifest_path),
            adapter_package=_adapter_package_status(manifest_path),
            out_dir=out_dir,
        )
        return _write_workspace(report, out_dir)

    verification = verify_evidence_bundle(manifest_path)
    findings.extend(_artifact_findings(verification, manifest))
    answers = _answer_review_questions(manifest)
    if require_questions:
        for question, answer in answers.items():
            if not answer.get("answered"):
                findings.append(_finding("question.unanswered", "fail", f"L5 review question is unanswered: {question}", question))

    layer_workflow = _layer_workflow_status(manifest_path)
    if require_layer_workflow and not layer_workflow["present"]:
        findings.append(_finding("workspace.layer_workflow_missing", "fail", "Layer runtime workflow JSON/HTML is required but was not found beside the evidence bundle.", str(manifest_path)))
    elif require_layer_workflow and (layer_workflow["layers"] != list(EXPECTED_LAYERS) or layer_workflow["stages"] != list(EXPECTED_STAGES)):
        findings.append(_finding("workspace.layer_workflow_invalid", "fail", "Layer runtime workflow is present but does not cover all expected stages and layers.", str(manifest_path)))

    adapter_package = _adapter_package_status(manifest_path)
    if require_adapter_package and not adapter_package["present"]:
        findings.append(_finding("workspace.adapter_package_missing", "fail", "Adapter package descriptor is required but was not found beside the evidence bundle.", str(manifest_path)))
    elif require_adapter_package and (adapter_package["status"] != "pass" or adapter_package["manifest_matches"] is not True):
        findings.append(_finding("workspace.adapter_package_invalid", "fail", "Adapter package descriptor is present but does not verify against this bundle manifest.", str(manifest_path)))

    report = _workspace_report(
        manifest_path,
        manifest=manifest,
        verification=verification,
        findings=findings,
        answers=answers,
        layer_workflow=layer_workflow,
        adapter_package=adapter_package,
        out_dir=out_dir,
    )
    return _write_workspace(report, out_dir)


def _workspace_report(
    manifest_path: Path,
    *,
    manifest: dict[str, Any],
    verification: dict[str, Any],
    findings: list[dict[str, Any]],
    answers: dict[str, dict[str, Any]],
    layer_workflow: dict[str, Any],
    adapter_package: dict[str, Any],
    out_dir: Path | None,
) -> dict[str, Any]:
    artifact_status = _artifact_completeness(manifest, verification)
    status = "pass" if not findings and artifact_status["status"] == "pass" else "fail"
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "status": status,
        "generated_at": utc_now(),
        "manifest_path": str(manifest_path),
        "ledger_is_fact_source": manifest.get("ledger_is_fact_source") is True,
        "proof_is_portable_summary": manifest.get("proof_is_portable_summary") is True,
        "artifact_completeness": artifact_status,
        "bundle_verification": _verification_summary(verification),
        "answers": answers,
        "layer_workflow": layer_workflow,
        "adapter_package": adapter_package,
        "findings": findings,
        "artifacts": {},
        "claim_boundary": "Evidence workspace is derived from the evidence bundle manifest and ledger-derived artifacts; it does not add runtime facts outside the ledger fact source.",
    }
    if out_dir:
        out = out_dir.expanduser().resolve()
        report["artifacts"] = {
            "workspace_json": str(out / "evidence-workspace.json"),
            "workspace_html": str(out / "evidence-workspace.html"),
        }
    return report


def _write_workspace(report: dict[str, Any], out_dir: Path | None) -> dict[str, Any]:
    if not out_dir:
        return report
    out = out_dir.expanduser().resolve()
    json_path = out / "evidence-workspace.json"
    html_path = out / "evidence-workspace.html"
    write_json_artifact(json_path, report)
    write_html_artifact(html_path, _render_workspace_html(report))
    return report


def _artifact_completeness(manifest: dict[str, Any], verification: dict[str, Any]) -> dict[str, Any]:
    artifacts = manifest.get("artifacts") if isinstance(manifest.get("artifacts"), dict) else {}
    missing_required = [name for name in REQUIRED_ARTIFACTS if name not in artifacts]
    failed = [
        item
        for item in verification.get("results", [])
        if isinstance(item, dict) and item.get("status") != "pass"
    ]
    return {
        "status": "pass" if not missing_required and not failed else "fail",
        "required": list(REQUIRED_ARTIFACTS),
        "missing_required": missing_required,
        "verified": verification.get("summary", {}).get("artifacts", 0),
        "failed": len(failed),
    }


def _verification_summary(verification: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": verification.get("schema_version"),
        "status": verification.get("status", "fail"),
        "summary": verification.get("summary", {}),
    }


def _artifact_findings(verification: dict[str, Any], manifest: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    artifacts = manifest.get("artifacts") if isinstance(manifest.get("artifacts"), dict) else {}
    for name in REQUIRED_ARTIFACTS:
        if name not in artifacts:
            findings.append(_finding("artifact.required_missing", "fail", f"Required evidence artifact is missing from manifest: {name}", name))
    for result in verification.get("results", []):
        if not isinstance(result, dict) or result.get("status") == "pass":
            continue
        check_id = "artifact.missing" if result.get("actual_sha256") is None else "artifact.hash_mismatch"
        findings.append(
            _finding(
                check_id,
                "fail",
                f"Evidence artifact verification failed for {result.get('artifact')}",
                str(result.get("path") or result.get("artifact") or ""),
                expected=result.get("expected_sha256"),
                actual=result.get("actual_sha256"),
            )
        )
    return findings


def _answer_review_questions(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    proof = _load_artifact(manifest, "proof")
    audit = _load_artifact(manifest, "audit_json")
    path_policy = _load_artifact(manifest, "path_policy")
    coverage_exists = _artifact_path(manifest, "coverage").exists() if _artifact_path(manifest, "coverage") else False

    session = proof.get("session", {}) if isinstance(proof.get("session"), dict) else {}
    summary = proof.get("summary", {}) if isinstance(proof.get("summary"), dict) else {}
    accountability = proof.get("accountability", {}) if isinstance(proof.get("accountability"), dict) else {}
    policy_decisions = proof.get("policy_decisions") if isinstance(proof.get("policy_decisions"), list) else []
    approvals = proof.get("approval_evidence") if isinstance(proof.get("approval_evidence"), list) else None
    outcomes = proof.get("execution_outcomes") if isinstance(proof.get("execution_outcomes"), list) else None
    coverage = proof.get("coverage") if isinstance(proof.get("coverage"), dict) else {}
    audit_policy = audit.get("policy") if isinstance(audit.get("policy"), dict) else {}

    return {
        "who": _answer(
            bool(session.get("session_id") or session.get("agent") or accountability),
            "Accountable session, agent, and principal boundary.",
            {
                "session_id": session.get("session_id"),
                "agent": session.get("agent"),
                "principal": accountability.get("principal") or accountability.get("accountable_principal"),
                "identity_source": "proof.accountability" if accountability else "proof.session",
            },
        ),
        "what": _answer(
            "total_actions" in summary or bool(proof.get("actions")),
            "Runtime actions and touched resources.",
            {"total_actions": summary.get("total_actions"), "action_types": summary.get("action_types", {})},
        ),
        "why": _answer(
            bool(path_policy or policy_decisions or proof.get("risk_statement")),
            "Policy, risk, and path explanation for the execution.",
            {
                "policy_decisions": len(policy_decisions),
                "path_policy_status": path_policy.get("status"),
                "risk_statement": proof.get("risk_statement"),
            },
        ),
        "policy": _answer(
            bool(audit_policy or path_policy),
            "Policy profile and path-aware decision evidence.",
            {"audit_policy_keys": sorted(audit_policy.keys()), "path_policy_schema": path_policy.get("schema_version")},
        ),
        "approval": _answer(
            approvals is not None,
            "Approval state, including the explicit absence of approvals.",
            {"approval_records": len(approvals or []), "summary": {key: summary.get(key) for key in ("missing_approvals", "approvals")}},
        ),
        "outcome": _answer(
            outcomes is not None or bool(session),
            "Execution outcome evidence, with session status as the fallback boundary.",
            {"outcome_records": len(outcomes or []), "session_status": session.get("status")},
        ),
        "coverage": _answer(
            bool(coverage) or coverage_exists,
            "Coverage evidence preserving observed, mediated, and enforced distinctions.",
            {"proof_coverage": bool(coverage), "coverage_artifact": str(_artifact_path(manifest, "coverage") or "")},
        ),
    }


def _answer(answered: bool, statement: str, evidence: dict[str, Any]) -> dict[str, Any]:
    return {"answered": bool(answered), "statement": statement, "evidence": evidence}


def _empty_answers(reason: str) -> dict[str, dict[str, Any]]:
    return {question: _answer(False, reason, {}) for question in REVIEW_QUESTIONS}


def _layer_workflow_status(manifest_path: Path) -> dict[str, Any]:
    json_path = _first_existing(
        [
            manifest_path.parent / "layer-runtime-workflow.json",
            manifest_path.parent.parent / "layer-runtime-workflow.json",
        ]
    )
    html_path = _first_existing(
        [
            manifest_path.parent / "layer-runtime-workflow.html",
            manifest_path.parent.parent / "layer-runtime-workflow.html",
        ]
    )
    payload = _load_json(json_path)[0] if json_path else {}
    present = json_path is not None and html_path is not None
    return {
        "present": present,
        "json": str(json_path) if json_path else None,
        "html": str(html_path) if html_path else None,
        "schema_version": payload.get("schema_version") if isinstance(payload, dict) else None,
        "layers": sorted({item.get("layer") for item in payload.get("runtime_effect_matrix", []) if isinstance(item, dict)}) if isinstance(payload, dict) else [],
        "stages": sorted({item.get("stage") for item in payload.get("runtime_effect_matrix", []) if isinstance(item, dict)}) if isinstance(payload, dict) else [],
    }


def _adapter_package_status(manifest_path: Path) -> dict[str, Any]:
    package_path = _first_existing(
        [
            manifest_path.parent / "adapter-package.json",
            manifest_path.parent.parent / "adapter-package.json",
        ]
    )
    payload, error = _load_json(package_path) if package_path else ({}, "adapter package not found")
    manifest_matches = False
    if isinstance(payload, dict):
        raw_manifest = payload.get("manifest_path")
        manifest_matches = Path(str(raw_manifest)).expanduser().resolve() == manifest_path if raw_manifest else False
    return {
        "present": package_path is not None,
        "path": str(package_path) if package_path else None,
        "status": payload.get("status") if isinstance(payload, dict) else None,
        "schema_version": payload.get("schema_version") if isinstance(payload, dict) else None,
        "manifest_matches": manifest_matches,
        "error": None if package_path else error,
    }


def _render_workspace_html(report: dict[str, Any]) -> str:
    base = Path(report["artifacts"]["workspace_html"]).parent if report.get("artifacts", {}).get("workspace_html") else Path.cwd()
    answer_rows = "".join(
        "<tr>"
        f"<td>{html.escape(question)}</td>"
        f"<td>{'yes' if answer.get('answered') else 'no'}</td>"
        f"<td>{html.escape(str(answer.get('statement', '')))}</td>"
        f"<td><pre>{html.escape(json.dumps(answer.get('evidence', {}), ensure_ascii=False, indent=2, sort_keys=True))}</pre></td>"
        "</tr>"
        for question, answer in report.get("answers", {}).items()
    )
    finding_rows = "".join(
        "<tr>"
        f"<td>{html.escape(str(item.get('check_id')))}</td>"
        f"<td>{html.escape(str(item.get('severity')))}</td>"
        f"<td>{html.escape(str(item.get('message')))}</td>"
        f"<td>{html.escape(str(item.get('artifact') or item.get('subject') or ''))}</td>"
        "</tr>"
        for item in report.get("findings", [])
    ) or "<tr><td colspan=\"4\">No findings.</td></tr>"
    links = []
    for section in ("layer_workflow", "adapter_package"):
        item = report.get(section, {})
        for key in ("json", "html", "path"):
            value = item.get(key) if isinstance(item, dict) else None
            if value:
                links.append(f"<li>{html.escape(section)} {html.escape(key)}: <a href=\"{relative_href(base, Path(value))}\">{html.escape(Path(value).name)}</a></li>")
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>Invart L5 Evidence Workspace</title><style>body{{font-family:Inter,Arial,sans-serif;margin:0;background:#f7f8fb;color:#172033}}header{{background:#0f172a;color:white;padding:34px 44px}}main{{max-width:1180px;margin:0 auto;padding:28px 24px}}section{{background:white;border:1px solid #dfe5ef;border-radius:8px;padding:18px;margin:16px 0}}table{{width:100%;border-collapse:collapse}}th,td{{border-bottom:1px solid #e5e7eb;padding:9px;text-align:left;vertical-align:top}}pre{{white-space:pre-wrap;background:#111827;color:#e5e7eb;padding:10px;border-radius:6px}}a{{color:#2563eb;text-decoration:none}}</style></head><body><header><h1>Invart L5 Evidence Workspace</h1><p>Status: <strong>{html.escape(str(report.get('status')))}</strong></p></header><main><section><h2>Review Questions</h2><table><tr><th>Question</th><th>Answered</th><th>Statement</th><th>Evidence</th></tr>{answer_rows}</table></section><section><h2>Artifact Completeness</h2><pre>{html.escape(json.dumps(report.get('artifact_completeness', {}), ensure_ascii=False, indent=2, sort_keys=True))}</pre></section><section><h2>Layer and Adapter Links</h2><ul>{''.join(links) or '<li>No linked layer workflow or adapter package.</li>'}</ul></section><section><h2>Findings</h2><table><tr><th>Check</th><th>Severity</th><th>Message</th><th>Subject</th></tr>{finding_rows}</table></section><section><h2>Claim Boundary</h2><p>{html.escape(str(report.get('claim_boundary')))}</p></section></main></body></html>"""


def _load_artifact(manifest: dict[str, Any], name: str) -> dict[str, Any]:
    path = _artifact_path(manifest, name)
    if not path:
        return {}
    payload, error = _load_json(path)
    return payload if not error else {}


def _artifact_path(manifest: dict[str, Any], name: str) -> Path | None:
    artifacts = manifest.get("artifacts") if isinstance(manifest.get("artifacts"), dict) else {}
    item = artifacts.get(name) if isinstance(artifacts.get(name), dict) else None
    raw = item.get("path") if item else None
    return Path(str(raw)).expanduser().resolve() if raw else None


def _load_json(path: Path | None) -> tuple[dict[str, Any], str | None]:
    if path is None:
        return {}, "path is missing"
    if not path.exists():
        return {}, f"file not found: {path}"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return {}, f"invalid JSON in {path}: {exc}"
    if not isinstance(payload, dict):
        return {}, f"JSON root is not an object: {path}"
    return payload, None


def _first_existing(paths: list[Path]) -> Path | None:
    for path in paths:
        if path.exists():
            return path.expanduser().resolve()
    return None


def _finding(check_id: str, severity: str, message: str, subject: str, **extra: Any) -> dict[str, Any]:
    return {"check_id": check_id, "severity": severity, "message": message, "subject": subject, **extra}


__all__ = ["inspect_evidence_workspace"]
