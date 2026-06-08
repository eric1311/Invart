from __future__ import annotations

import hashlib
import html
import json
from pathlib import Path
from typing import Any

from invart.core.artifacts import sha256_file, stable_json_hash, write_html_artifact, write_json_artifact
from invart.assurance.coverage import export_coverage_html_report
from invart.control.gate import verify_gate
from invart.assurance.path_graph import export_execution_graph_html, export_execution_graph_json
from invart.control.path_policy import check_path_policy
from invart.assurance.postruntime import export_proof_report
from invart.assurance.replay import export_replay_html
from invart.core.models import utc_now


EVIDENCE_BUNDLE_SCHEMA_VERSION = "invart.evidence_bundle.v0.27"


def export_evidence_bundle(ledger_path: Path, out_dir: Path, *, profile: dict[str, Any] | None = None) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    proof_path = out_dir / "proof.json"
    proof = export_proof_report(ledger_path, proof_path)
    replay = export_replay_html(ledger_path, out_dir / "replay.html", gate_mode="managed")
    graph_json = export_execution_graph_json(ledger_path, out_dir / "path-graph.json")
    graph_html = export_execution_graph_html(ledger_path, out_dir / "path-graph.html")
    path_policy = check_path_policy(ledger_path, profile=profile, output_path=out_dir / "path-policy.json")
    coverage = export_coverage_html_report(proof_path, out_dir / "coverage.html")
    gate = verify_gate(ledger_path=ledger_path, proof_path=proof_path, mode="managed")
    audit_json_path = out_dir / "audit.json"
    audit_html_path = out_dir / "audit.html"
    audit = _audit_payload(proof, path_policy, gate, profile)
    write_json_artifact(audit_json_path, audit)
    write_html_artifact(audit_html_path, _audit_html(audit))

    artifact_paths = {
        "ledger": ledger_path,
        "proof": proof_path,
        "replay": Path(replay["replay"]),
        "path_graph_json": Path(graph_json["output"]),
        "path_graph_html": Path(graph_html["output"]),
        "path_policy": out_dir / "path-policy.json",
        "coverage": Path(coverage["output"]),
        "audit_json": audit_json_path,
        "audit_html": audit_html_path,
    }
    manifest = {
        "schema_version": EVIDENCE_BUNDLE_SCHEMA_VERSION,
        "bundle_id": "evb_" + hashlib.sha256(f"{ledger_path}:{utc_now()}".encode("utf-8")).hexdigest()[:16],
        "created_at": utc_now(),
        "ledger_is_fact_source": True,
        "proof_is_portable_summary": True,
        "profile_hash": _hash_object(profile or {}),
        "coverage_summary": proof.get("coverage", {}).get("summary", {}),
        "policy_decision_summary": _policy_decision_summary(proof),
        "control_mapping": {
            "native": "invart.audit.v0.27",
            "siem_preview": {"event_type": "agent_runtime_audit", "status": gate.get("status")},
            "otel_preview": {"span_name": "invart.agent_runtime", "attributes": ["session_id", "principal", "coverage", "policy_effect"]},
        },
        "artifacts": {
            name: {"path": str(path), "sha256": sha256_file(path), "bytes": path.stat().st_size}
            for name, path in sorted(artifact_paths.items())
        },
    }
    manifest_path = out_dir / "manifest.json"
    write_json_artifact(manifest_path, manifest)
    return {
        "schema_version": EVIDENCE_BUNDLE_SCHEMA_VERSION,
        "status": "pass",
        "manifest_path": str(manifest_path),
        "artifacts": {name: str(path) for name, path in artifact_paths.items()},
        "summary": {"artifacts": len(artifact_paths), "gate_status": gate.get("status")},
    }


def verify_evidence_bundle(manifest_path: Path) -> dict[str, Any]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    results = []
    for name, item in manifest.get("artifacts", {}).items():
        path = Path(str(item.get("path", "")))
        exists = path.exists()
        actual = sha256_file(path) if exists else None
        expected = item.get("sha256")
        results.append(
            {
                "artifact": name,
                "path": str(path),
                "status": "pass" if exists and actual == expected else "fail",
                "expected_sha256": expected,
                "actual_sha256": actual,
            }
        )
    tampered = sum(1 for item in results if item["status"] != "pass")
    return {
        "schema_version": "invart.evidence_bundle_verify.v0.27",
        "status": "pass" if tampered == 0 else "fail",
        "manifest_path": str(manifest_path),
        "manifest": manifest,
        "results": results,
        "summary": {"artifacts": len(results), "tampered": tampered},
    }


def _audit_payload(proof: dict[str, Any], path_policy: dict[str, Any], gate: dict[str, Any], profile: dict[str, Any] | None) -> dict[str, Any]:
    return {
        "schema_version": "invart.enterprise_audit.v0.27",
        "generated_at": utc_now(),
        "audience": "enterprise_security_team",
        "accountability": proof.get("accountability", {}),
        "path_graph": proof.get("path_graph", {}),
        "policy": {"path_policy": path_policy, "profile": profile or {}},
        "approval": proof.get("approval_evidence", []),
        "outcome": proof.get("execution_outcomes", []),
        "coverage": proof.get("coverage", {}),
        "gate": gate,
        "summary": proof.get("summary", {}),
    }


def _audit_html(audit: dict[str, Any]) -> str:
    sections = [
        ("Accountability", audit.get("accountability", {})),
        ("Path Graph", audit.get("path_graph", {})),
        ("Policy", audit.get("policy", {})),
        ("Approval", audit.get("approval", [])),
        ("Outcome", audit.get("outcome", [])),
        ("Coverage", audit.get("coverage", {})),
        ("Gate", audit.get("gate", {})),
    ]
    rendered = "".join(
        f"<section><h2>{html.escape(title)}</h2><pre>{html.escape(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))}</pre></section>"
        for title, payload in sections
    )
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>Enterprise Evidence Bundle Audit</title><style>body{{font-family:Inter,Arial,sans-serif;margin:0;background:#f7f8fb;color:#152033}}main{{max-width:1120px;margin:0 auto;padding:34px 24px}}section{{background:#fff;border:1px solid #dce4ef;border-radius:8px;padding:16px;margin:14px 0}}pre{{background:#111827;color:#e5e7eb;padding:14px;border-radius:8px;overflow:auto}}</style></head><body><main><h1>Enterprise Evidence Bundle Audit</h1>{rendered}</main></body></html>"""


def _policy_decision_summary(proof: dict[str, Any]) -> dict[str, int]:
    summary: dict[str, int] = {}
    for decision in proof.get("policy_decisions", []):
        if not isinstance(decision, dict):
            continue
        effect = str(decision.get("effect", "unknown"))
        summary[effect] = summary.get(effect, 0) + 1
    return summary


def _hash_object(payload: dict[str, Any]) -> str:
    return stable_json_hash(payload)


__all__ = ["export_evidence_bundle", "verify_evidence_bundle"]
