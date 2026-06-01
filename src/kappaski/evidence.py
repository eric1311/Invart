from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from typing import Any

from .models import Finding, Invocation


SECRET_PATTERNS: tuple[tuple[str, str], ...] = (
    ("openai_key", r"sk-[A-Za-z0-9_-]{8,}"),
    ("github_token", r"gh[pousr]_[A-Za-z0-9_]{8,}"),
    ("aws_access_key", r"AKIA[0-9A-Z]{12,}"),
    ("bearer_token", r"Bearer\s+[A-Za-z0-9._~+/=-]{12,}"),
    ("generic_assignment_secret", r"(?i)(api[_-]?key|token|secret|password)\s*[=:]\s*[^\s]+"),
)


@dataclass
class RedactedEvidence:
    invocation_id: str
    operation: str | None
    actor: str | None
    source: str
    trust_level: str
    resource_refs: list[dict[str, str]] = field(default_factory=list)
    payload_summary: str | None = None
    command_summary: str | None = None
    path_summary: str | None = None
    url_summary: str | None = None
    taint_tags: list[str] = field(default_factory=list)
    rule_findings: list[dict[str, Any]] = field(default_factory=list)
    metadata_summary: dict[str, Any] = field(default_factory=dict)
    raw_content: str | None = None
    raw_content_summary: dict[str, Any] = field(default_factory=dict)
    redactions: list[dict[str, str]] = field(default_factory=list)
    input_hash: str = ""

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        if not payload["input_hash"]:
            payload["input_hash"] = hash_evidence(payload)
        return payload


def build_redacted_evidence(invocation: Invocation, findings: list[Finding] | None = None) -> RedactedEvidence:
    redactions: list[dict[str, str]] = []
    command_summary = redact_text(invocation.command, redactions)
    path_summary = redact_path(invocation.path, redactions)
    url_summary = redact_text(invocation.url, redactions)
    payload_summary = redact_text(invocation.payload_summary, redactions)
    metadata_summary = summarize_metadata(invocation.metadata, redactions)
    raw_content = _raw_content_from_invocation(invocation)
    summarized_raw = summarize_raw_content(raw_content, redactions)
    safe_findings = []
    for finding in findings or []:
        item = finding.to_dict()
        item["evidence"] = redact_text(item.get("evidence"), redactions)
        safe_findings.append(item)
    evidence = RedactedEvidence(
        invocation_id=invocation.invocation_id or invocation.event_id,
        operation=invocation.operation,
        actor=invocation.actor,
        source=invocation.source,
        trust_level=invocation.trust_level,
        resource_refs=[redact_ref(ref, redactions) for ref in invocation.resource_refs],
        payload_summary=payload_summary,
        command_summary=command_summary,
        path_summary=path_summary,
        url_summary=url_summary,
        taint_tags=list(invocation.taint_tags),
        rule_findings=safe_findings,
        metadata_summary=metadata_summary,
        raw_content=summarized_raw.get("display"),
        raw_content_summary={key: value for key, value in summarized_raw.items() if key != "display"},
        redactions=redactions,
    )
    evidence.input_hash = hash_evidence(evidence.to_dict() | {"input_hash": ""})
    return evidence


def summarize_raw_content(value: str | None, redactions: list[dict[str, str]], *, max_length: int = 1200) -> dict[str, Any]:
    if value is None:
        return {"present": False, "display": None}
    redacted = redact_text(value, redactions) or ""
    original_length = len(value)
    truncated = len(redacted) > max_length
    display = redacted[: max_length - 3] + "..." if truncated else redacted
    return {
        "present": True,
        "original_length": original_length,
        "display_length": len(display),
        "truncated": truncated,
        "folded_by_default": True,
        "content_note": _content_note(value),
        "display": display,
    }


def _raw_content_from_invocation(invocation: Invocation) -> str | None:
    raw = invocation.metadata.get("raw_content")
    if isinstance(raw, str):
        return raw
    return None


def _content_note(value: str) -> str:
    lowered = value.lower()
    if any(marker in lowered for marker in ("password", "secret", "api_key", "token", "sk-", "akia")):
        return "Raw content contains secret-like text and should remain folded unless profile permits review."
    if len(value) > 1200:
        return "Raw content is long and was truncated for reviewer/display safety."
    return "Raw content is included for semantic review and folded display."


def redact_ref(ref: dict[str, str], redactions: list[dict[str, str]]) -> dict[str, str]:
    safe = dict(ref)
    if "value" in safe:
        safe["value"] = redact_text(safe.get("value"), redactions) or ""
    return safe


def redact_path(path: str | None, redactions: list[dict[str, str]]) -> str | None:
    if path is None:
        return None
    lowered = path.lower()
    if any(marker in lowered for marker in (".env", "id_rsa", "id_ed25519", "credentials", "kubeconfig")):
        redactions.append({"kind": "sensitive_path", "replacement": "[REDACTED_PATH]"})
        parts = path.replace("\\", "/").split("/")
        return "/".join([*parts[:-1], "[REDACTED_PATH]"]) if len(parts) > 1 else "[REDACTED_PATH]"
    return redact_text(path, redactions)


def redact_text(value: str | None, redactions: list[dict[str, str]]) -> str | None:
    if value is None:
        return None
    result = value
    for kind, pattern in SECRET_PATTERNS:
        if re.search(pattern, result):
            result = re.sub(pattern, f"[{kind.upper()}_REDACTED]", result)
            redactions.append({"kind": kind, "replacement": f"[{kind.upper()}_REDACTED]"})
    if len(result) > 500:
        result = result[:497] + "..."
    return result


def summarize_metadata(metadata: dict[str, Any], redactions: list[dict[str, str]]) -> dict[str, Any]:
    allowed = {"source", "trust_level", "instruction", "skill_source", "repository", "operation", "actor"}
    summary: dict[str, Any] = {}
    for key, value in metadata.items():
        if key not in allowed:
            continue
        if isinstance(value, str):
            summary[key] = redact_text(value, redactions)
        elif isinstance(value, (int, float, bool)) or value is None:
            summary[key] = value
        else:
            summary[key] = redact_text(json.dumps(value, ensure_ascii=False, sort_keys=True), redactions)
    return summary


def hash_evidence(payload: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()
