from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from invart.core.artifacts import sha256_file, write_json_artifact
from invart.core.models import utc_now


def import_vendor_native_evidence(
    *,
    agent: str,
    source_path: Path,
    out_dir: Path,
    evidence_kind: str = "native_control",
) -> dict[str, Any]:
    source_path = source_path.expanduser().resolve()
    out_dir = out_dir.expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    payload = _load_source(source_path)
    controls = _controls_for_agent(agent, payload)
    report = {
        "schema_version": "invart.vendor_native_evidence.v0.9.12",
        "status": "pass" if source_path.exists() else "fail",
        "agent": agent,
        "evidence_kind": evidence_kind,
        "source": {
            "path": str(source_path),
            "exists": source_path.exists(),
            "sha256": sha256_file(source_path) if source_path.exists() and source_path.is_file() else None,
            "loaded_at": utc_now(),
        },
        "controls": controls,
        "coverage": {
            "coverage_grade": "vendor_owned",
            "control_position": "vendor_owned_import",
            "invart_mediated": False,
            "invart_enforced": False,
            "side_effect_timing": "vendor_native_or_after_the_fact",
        },
        "claim_boundary": "Vendor-native sandbox, approval, network, credential, or telemetry facts are imported audit evidence. They must not be counted as Invart-mediated or Invart-enforced coverage unless the action also enters an Invart mediation/enforcement surface.",
        "artifacts": {"report_json": str(out_dir / "vendor-native-evidence.json")},
    }
    write_json_artifact(out_dir / "vendor-native-evidence.json", report)
    return report


def validate_vendor_claim_boundary(report: dict[str, Any]) -> dict[str, Any]:
    findings = []
    coverage = report.get("coverage", {}) if isinstance(report.get("coverage"), dict) else {}
    if coverage.get("control_position") == "vendor_owned_import" and coverage.get("invart_enforced") is True:
        findings.append(_finding("vendor.enforcement_inflation", "Vendor-owned evidence cannot be labeled Invart-enforced."))
    if coverage.get("control_position") == "vendor_owned_import" and coverage.get("invart_mediated") is True:
        findings.append(_finding("vendor.mediation_inflation", "Vendor-owned evidence cannot be labeled Invart-mediated."))
    return {
        "schema_version": "invart.vendor_claim_boundary_check.v0.9.12",
        "status": "pass" if not findings else "fail",
        "findings": findings,
        "summary": {"findings": len(findings)},
    }


def import_gateway_server_evidence(
    *,
    agent: str,
    source_path: Path,
    out_dir: Path,
    source_timestamp: str | None = None,
    limitation: str | None = None,
) -> dict[str, Any]:
    report = import_vendor_native_evidence(
        agent=agent,
        source_path=source_path,
        out_dir=out_dir,
        evidence_kind="gateway_server",
    )
    payload = _load_source(source_path.expanduser().resolve())
    gateway = {
        "schema_version": "invart.gateway_server_evidence.v0.9.14",
        "status": report["status"],
        "agent": agent,
        "source": {
            **report["source"],
            "source_timestamp": source_timestamp or payload.get("timestamp") or payload.get("created_at") or report["source"]["loaded_at"],
        },
        "backend": payload.get("backend") or payload.get("container_backend") or "unknown",
        "security_posture": payload.get("security_posture") or payload.get("security") or {},
        "runtime_boundary": payload.get("runtime_boundary") or "vendor_owned",
        "coverage": report["coverage"],
        "limitation": limitation or "Gateway/server evidence is imported after or outside Invart-owned mediation unless a local launcher or backend bridge routes events through Invart before side effects.",
        "claim_boundary": "Gateway and server-agent logs can support audit reconstruction, but they are vendor-owned evidence and cannot be counted as Invart-mediated or Invart-enforced coverage without a managed launch, proxy, or bridge boundary.",
        "artifacts": {"report_json": str(out_dir.expanduser().resolve() / "gateway-server-evidence.json")},
    }
    write_json_artifact(Path(gateway["artifacts"]["report_json"]), gateway)
    return gateway


def _controls_for_agent(agent: str, payload: dict[str, Any]) -> list[dict[str, Any]]:
    if agent == "codex":
        return [
            _control("sandbox", payload.get("sandbox", "unknown"), "vendor_native"),
            _control("approval", payload.get("approval", "unknown"), "vendor_native"),
            _control("network_policy", payload.get("network_policy", "unknown"), "vendor_native"),
            _control("credential_boundary", payload.get("credential_boundary", "unknown"), "vendor_native"),
        ]
    return [_control(key, value, "vendor_native") for key, value in sorted(payload.items())]


def _control(name: str, value: Any, owner: str) -> dict[str, Any]:
    return {"name": name, "value": value, "owner": owner, "invart_owned": False}


def _load_source(path: Path) -> dict[str, Any]:
    if not path.exists() or not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {"raw_preview": path.read_text(encoding="utf-8")[:400]}
    return payload if isinstance(payload, dict) else {"value": payload}


def _finding(check_id: str, message: str) -> dict[str, Any]:
    return {"check_id": check_id, "severity": "high", "message": message}


__all__ = ["import_gateway_server_evidence", "import_vendor_native_evidence", "validate_vendor_claim_boundary"]
