from __future__ import annotations

import hashlib
import json
import os
import re
import uuid
import urllib.error
import urllib.request
from typing import Any, Protocol

from invart.control.evidence import build_redacted_evidence
from invart.core.models import Finding, Invocation, ReviewFinding, SemanticReview, TaintState, utc_now


REVIEW_MODES = {"off", "auto", "always", "required"}


class Reviewer(Protocol):
    name: str

    def review(self, invocation: Invocation, taint: TaintState, findings: list[Finding] | None = None) -> SemanticReview:
        ...


class LLMReviewProvider(Protocol):
    def complete_json(self, payload: dict[str, Any]) -> dict[str, Any]:
        ...


def should_review(invocation: Invocation, taint: TaintState, rule_risk: str, review_mode: str) -> bool:
    if review_mode == "off":
        return False
    if review_mode in {"always", "required"}:
        return True
    if taint.is_tainted:
        return True
    if rule_risk in {"high", "critical"}:
        return True
    if invocation.source in {"external_web", "issue_comment", "attachment", "skill_instruction", "mcp_result"}:
        return True
    if invocation.trust_level in {"untrusted", "unknown"} and invocation.operation in {"shell", "file_write", "network", "mcp_tool", "skill"}:
        return True
    if any(tag in invocation.taint_tags for tag in {"tainted_session", "sensitive_read", "external_instruction", "credential", "outbound"}):
        return True
    return False


class HeuristicReviewer:
    name = "heuristic"

    def review(self, invocation: Invocation, taint: TaintState, findings: list[Finding] | None = None) -> SemanticReview:
        text = " ".join(
            part
            for part in [
                invocation.operation or "",
                invocation.command or "",
                invocation.path or "",
                invocation.url or "",
                invocation.tool or "",
                invocation.skill or "",
                invocation.payload_summary or "",
                str(invocation.metadata.get("instruction", "")),
                str(invocation.metadata.get("skill_source", "")),
                " ".join(invocation.taint_tags),
            ]
            if part
        ).lower()
        findings: list[ReviewFinding] = []

        if _looks_like_archive_outbound(text):
            findings.append(
                ReviewFinding(
                    source="heuristic",
                    category="possible_exfiltration",
                    risk="high",
                    confidence=0.82,
                    title="Archive or encoded data appears to be sent outbound",
                    reason="The invocation combines archive/encoding behavior with an outbound destination.",
                    evidence_refs=invocation.evidence_refs,
                    recommended_effect="require_approval",
                )
            )
        if _looks_like_external_instruction(text):
            findings.append(
                ReviewFinding(
                    source="heuristic",
                    category="goal_hijack",
                    risk="high",
                    confidence=0.78,
                    title="External instruction appears to redirect the agent",
                    reason="The content contains phrases commonly used to override the current goal or instruction hierarchy.",
                    evidence_refs=invocation.evidence_refs,
                    recommended_effect="require_approval",
                )
            )
        if taint.is_tainted and invocation.operation in {"network", "file_write", "mcp_tool", "shell"}:
            findings.append(
                ReviewFinding(
                    source="heuristic",
                    category="tainted_action",
                    risk="medium",
                    confidence=0.7,
                    title="Tainted session performs write-like or outbound action",
                    reason="Sensitive or untrusted context was observed earlier in the session.",
                    evidence_refs=invocation.evidence_refs,
                    recommended_effect="require_approval",
                )
            )
        if invocation.operation in {"skill", "skill_load"} and _looks_like_external_instruction(text):
            findings.append(
                ReviewFinding(
                    source="heuristic",
                    category="skill_instruction_risk",
                    risk="high",
                    confidence=0.8,
                    title="Skill instruction appears to override the session goal",
                    reason="Skill-provided text includes instruction override or goal-hijack language.",
                    evidence_refs=invocation.evidence_refs,
                    recommended_effect="require_approval",
                )
            )
        if invocation.operation in {"file_read", "shell"} and not findings and not taint.is_tainted:
            findings.append(
                ReviewFinding(
                    source="heuristic",
                    category="low_semantic_risk",
                    risk="low",
                    confidence=0.66,
                    title="No semantic escalation detected",
                    reason="The invocation does not appear to cross a sensitive semantic boundary.",
                    evidence_refs=invocation.evidence_refs,
                    recommended_effect="allow",
                )
            )

        risk = _highest_review_risk(findings)
        recommended = _recommended_effect(findings)
        categories = sorted({finding.category for finding in findings})
        reason = findings[0].reason if findings else "No semantic review findings."
        return SemanticReview(
            review_id=f"rev_{uuid.uuid4().hex[:16]}",
            session_id=invocation.session_id,
            invocation_id=invocation.invocation_id or invocation.event_id,
            reviewer=self.name,
            model=None,
            prompt_version="heuristic.v0.2",
            input_refs=[invocation.invocation_id or invocation.event_id],
            input_hash=_input_hash(invocation),
            risk=risk,
            confidence=max((finding.confidence or 0.0 for finding in findings), default=0.0),
            categories=categories,
            reason=reason,
            recommended_effect=recommended,
            findings=findings,
            reviewed_at=utc_now(),
            warnings=[],
        )



class OpenAICompatibleProvider:
    def __init__(self, api_key: str, base_url: str, model: str, timeout: float = 30.0):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout

    @classmethod
    def from_env(cls) -> "OpenAICompatibleProvider | None":
        api_key = os.environ.get("INVART_LLM_API_KEY") or os.environ.get("KAPPASKI_LLM_API_KEY") or os.environ.get("OPENAI_API_KEY")
        model = os.environ.get("INVART_LLM_MODEL") or os.environ.get("KAPPASKI_LLM_MODEL")
        if not api_key or not model:
            return None
        base_url = os.environ.get("INVART_LLM_BASE_URL") or os.environ.get("KAPPASKI_LLM_BASE_URL") or "https://api.openai.com/v1"
        return cls(api_key=api_key, base_url=base_url, model=model)

    def complete_json(self, payload: dict[str, Any]) -> dict[str, Any]:
        request_payload = {
            "model": self.model,
            "temperature": 0,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": "You are Invart's semantic runtime reviewer. Return strict JSON only."},
                {"role": "user", "content": json.dumps(payload, ensure_ascii=False, sort_keys=True)},
            ],
        }
        data = json.dumps(request_payload, ensure_ascii=False).encode("utf-8")
        request = urllib.request.Request(
            self.base_url + "/chat/completions",
            data=data,
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                body = json.loads(response.read().decode("utf-8"))
        except urllib.error.URLError as exc:
            raise RuntimeError(f"OpenAI-compatible reviewer request failed: {exc}") from exc
        content = body.get("choices", [{}])[0].get("message", {}).get("content")
        if not isinstance(content, str):
            raise RuntimeError("OpenAI-compatible reviewer returned no message content")
        loaded = json.loads(content)
        if not isinstance(loaded, dict):
            raise RuntimeError("OpenAI-compatible reviewer JSON content must be an object")
        return loaded


class StaticJSONProvider:
    def __init__(self, payload: dict[str, Any]):
        self.payload = payload

    @classmethod
    def from_env(cls) -> "StaticJSONProvider | None":
        raw = os.environ.get("INVART_LLM_REVIEW_JSON") or os.environ.get("KAPPASKI_LLM_REVIEW_JSON")
        if not raw:
            return None
        loaded = json.loads(raw)
        if not isinstance(loaded, dict):
            raise ValueError("INVART_LLM_REVIEW_JSON must be a JSON object")
        return cls(loaded)

    def complete_json(self, payload: dict[str, Any]) -> dict[str, Any]:
        return dict(self.payload)


class LLMReviewer:
    name = "llm"

    def __init__(self, provider: LLMReviewProvider | None = None, model: str | None = None, prompt_version: str = "llm-review.v0.2"):
        self.provider = provider if provider is not None else StaticJSONProvider.from_env() or OpenAICompatibleProvider.from_env()
        self.model = model or os.environ.get("INVART_LLM_MODEL") or os.environ.get("KAPPASKI_LLM_MODEL")
        self.prompt_version = prompt_version

    def review(self, invocation: Invocation, taint: TaintState, findings: list[Finding] | None = None) -> SemanticReview:
        if self.provider is None:
            raise RuntimeError("LLM reviewer provider is not configured")
        evidence = build_redacted_evidence(invocation, findings)
        response = self.provider.complete_json({
            "schema": "invart.semantic_review.v0.8",
            "prompt_version": self.prompt_version,
            "evidence": evidence.to_dict(),
            "instructions": {
                "return_json_only": True,
                "allowed_risk": ["info", "low", "medium", "high", "critical"],
                "allowed_effect": ["allow", "audit_only", "require_approval", "deny"],
                "deny_requires_explanation": True,
                "raw_content_policy": "raw_content may be present, redacted, folded by default, and truncated; use raw_content_summary to explain risk without leaking secrets.",
            },
        })
        return semantic_review_from_llm_response(response, invocation, evidence.input_hash, self.model, self.prompt_version)


def semantic_review_from_llm_response(
    response: dict[str, Any],
    invocation: Invocation,
    input_hash: str,
    model: str | None,
    prompt_version: str,
) -> SemanticReview:
    risk = _safe_choice(str(response.get("risk", "medium")), {"info", "low", "medium", "high", "critical"}, "medium")
    recommended = _safe_choice(str(response.get("recommended_effect", "require_approval")), {"allow", "audit_only", "require_approval", "deny"}, "require_approval")
    categories = [str(item) for item in response.get("categories", []) if isinstance(item, str)]
    raw_findings = response.get("findings", [])
    findings: list[ReviewFinding] = []
    if isinstance(raw_findings, list):
        for item in raw_findings:
            if not isinstance(item, dict):
                continue
            findings.append(
                ReviewFinding(
                    source="llm",
                    category=str(item.get("category", "semantic_risk")),
                    risk=_safe_choice(str(item.get("risk", risk)), {"info", "low", "medium", "high", "critical"}, risk),
                    confidence=_safe_confidence(item.get("confidence")),
                    title=str(item.get("title", "LLM semantic finding")),
                    reason=str(item.get("reason", response.get("reason", ""))),
                    evidence_refs=[dict(ref) for ref in item.get("evidence_refs", []) if isinstance(ref, dict)],
                    recommended_effect=item.get("recommended_effect", recommended),
                )
            )
    if not categories:
        categories = sorted({finding.category for finding in findings})
    return SemanticReview(
        review_id=f"rev_{uuid.uuid4().hex[:16]}",
        session_id=invocation.session_id,
        invocation_id=invocation.invocation_id or invocation.event_id,
        reviewer="llm",
        model=model,
        prompt_version=prompt_version,
        input_refs=[invocation.invocation_id or invocation.event_id],
        input_hash=input_hash,
        risk=risk,
        confidence=_safe_confidence(response.get("confidence")) or 0.0,
        categories=categories,
        reason=str(response.get("reason", "LLM reviewer returned a semantic decision.")),
        recommended_effect=recommended,
        findings=findings,
        reviewed_at=utc_now(),
        warnings=[str(item) for item in response.get("warnings", []) if isinstance(item, str)],
    )


def make_reviewer(kind: str = "heuristic", provider: LLMReviewProvider | None = None) -> Reviewer:
    if kind == "llm":
        return LLMReviewer(provider=provider, prompt_version="llm-review.v0.8")
    if kind == "heuristic":
        return HeuristicReviewer()
    raise ValueError(f"unknown reviewer: {kind}")


def _safe_choice(value: str, allowed: set[str], default: str) -> str:
    return value if value in allowed else default


def _safe_confidence(value: Any) -> float | None:
    if value is None:
        return None
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        return None
    return max(0.0, min(1.0, numeric))

def _looks_like_archive_outbound(text: str) -> bool:
    archive = bool(re.search(r"\b(tar|zip|gzip|base64|openssl enc|xxd)\b", text))
    outbound = bool(re.search(r"\b(curl|wget|scp|rsync|post|upload)\b|https?://", text))
    sensitive = any(marker in text for marker in (".env", "credential", "secret", "token", "key", "config"))
    return archive and outbound and sensitive


def _looks_like_external_instruction(text: str) -> bool:
    patterns = (
        "ignore previous instructions",
        "ignore prior instructions",
        "your real task is",
        "new objective is",
        "updated objective is",
        "send secrets",
        "upload .env",
    )
    return any(pattern in text for pattern in patterns)


def _highest_review_risk(findings: list[ReviewFinding]) -> str:
    order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    risk = "low"
    for finding in findings:
        if order.get(finding.risk, 0) > order.get(risk, 0):
            risk = finding.risk
    return risk


def _recommended_effect(findings: list[ReviewFinding]) -> str:
    if any(finding.recommended_effect == "deny" for finding in findings):
        return "deny"
    if any(finding.recommended_effect == "require_approval" for finding in findings):
        return "require_approval"
    if any(finding.recommended_effect == "audit_only" for finding in findings):
        return "audit_only"
    return "allow"


def _input_hash(invocation: Invocation) -> str:
    payload = {
        "operation": invocation.operation,
        "resource_refs": invocation.resource_refs,
        "payload_summary": invocation.payload_summary,
        "source": invocation.source,
        "trust_level": invocation.trust_level,
        "taint_tags": invocation.taint_tags,
    }
    return hashlib.sha256(json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()
