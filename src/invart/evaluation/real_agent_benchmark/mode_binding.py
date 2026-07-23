from __future__ import annotations

from typing import Any

from invart.control.rules import analyze_command, evaluate_policy
from invart.core.models import ActionEvent, Finding, TaintState


MODE_BINDING_SCHEMA_VERSION = "invart.p0_mode_binding.v0.1"


def mode_binding_for_command(*, command: list[str], case_id: str, agent: str, mode: str) -> dict[str, Any]:
    command_text = " ".join(command)
    base = {
        "schema_version": MODE_BINDING_SCHEMA_VERSION,
        "case_id": case_id,
        "agent": agent,
        "mode": mode,
        "command_preview": command_text[:500],
        "claim_boundary": (
            "Mode binding records the control-plane semantics applied to this row. "
            "It does not replace official benchmark grading or independent side-effect evidence."
        ),
    }
    if mode == "baseline_agent":
        return {
            **base,
            "control_mode": "baseline_unmanaged_reference",
            "coverage_label": "observed_external_baseline",
            "pre_side_effect_gate": "not_applicable",
            "ledger_binding": "external_supervision_only",
            "mediation_status": "none",
            "enforcement_status": "none",
            "decision": _decision_payload(effect="allow", risk="info", reason="baseline row runs provider entrypoint without Invart mediation"),
        }
    if mode == "invart_observe_only":
        findings = [finding.to_dict() for finding in _findings_for_p0_command(command_text=command_text, case_id=case_id)]
        return {
            **base,
            "control_mode": "observe_only",
            "coverage_label": "observed",
            "pre_side_effect_gate": "observe_without_blocking",
            "ledger_binding": "runtime_supervision_and_side_effect_record",
            "mediation_status": "observation_only",
            "enforcement_status": "none",
            "decision": _decision_payload(
                effect="allow",
                risk=_highest_risk(findings),
                reason="observe-only rows record policy-relevant findings but do not enforce",
                findings=findings,
            ),
        }
    if mode == "invart_mediated":
        findings = _findings_for_p0_command(command_text=command_text, case_id=case_id)
        event = ActionEvent(
            event_id=f"p0_{_safe_id(case_id)}_{_safe_id(agent)}_{_safe_id(mode)}",
            session_id=f"p0_{_safe_id(case_id)}",
            timestamp="",
            sequence=1,
            action_type="shell",
            actor=agent,
            command=command_text,
            adapter="p0-real-agent",
            control_mode="mediated",
        )
        decision = evaluate_policy(event, findings, TaintState(session_id=event.session_id)).to_dict()
        return {
            **base,
            "control_mode": "mediated_pre_side_effect",
            "coverage_label": "mediated" if decision["effect"] in {"allow", "ask"} else "enforced",
            "pre_side_effect_gate": "active",
            "ledger_binding": "runtime_supervision_policy_decision_and_side_effect_record",
            "mediation_status": "active",
            "enforcement_status": "blocked" if decision["effect"] == "deny" else "not_triggered",
            "decision": decision,
        }
    return {
        **base,
        "control_mode": "unknown",
        "coverage_label": "unknown",
        "pre_side_effect_gate": "unknown",
        "ledger_binding": "unknown",
        "mediation_status": "unknown",
        "enforcement_status": "unknown",
        "decision": _decision_payload(effect="allow", risk="info", reason=f"unknown P0 mode: {mode}"),
    }


def should_block_for_mode(binding: dict[str, Any]) -> bool:
    decision = binding.get("decision")
    return isinstance(decision, dict) and decision.get("effect") == "deny" and binding.get("pre_side_effect_gate") == "active"


def _findings_for_p0_command(*, command_text: str, case_id: str) -> list[Finding]:
    findings = list(analyze_command(command_text, phase="runtime"))
    normalized_case = case_id.strip().lower()
    if normalized_case.startswith("skill_inject_malicious"):
        findings.append(
            Finding(
                rule_id="p0.skill_inject_malicious_runner",
                title="Skill-Inject malicious skill runner",
                severity="critical",
                phase="runtime",
                category="supply-chain-injection",
                evidence=command_text[:240],
                recommendation=(
                    "Do not execute the upstream agent sandbox for malicious skill-injection rows unless the run is "
                    "explicitly authorized as a benchmark experiment and bound to audit evidence."
                ),
            )
        )
    return findings


def _decision_payload(*, effect: str, risk: str, reason: str, findings: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    return {
        "effect": effect,
        "risk": risk,
        "reason": reason,
        "matched_rules": [str(item.get("rule_id")) for item in findings or [] if item.get("rule_id")],
        "findings": findings or [],
    }


def _highest_risk(findings: list[dict[str, Any]]) -> str:
    order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    highest = "info"
    for finding in findings:
        severity = str(finding.get("severity") or "info")
        if order.get(severity, 0) > order.get(highest, 0):
            highest = severity
    return highest


def _safe_id(value: str) -> str:
    return "".join(char if char.isalnum() else "_" for char in value).strip("_") or "unknown"
