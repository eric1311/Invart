from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from invart.evaluation.experiment_cases import ExpectedControlOutcome, ExperimentCase, ExperimentSeed


REQUIRED_CASE_FIELDS = ("case_id", "title", "trust", "capability", "resource", "sink", "expected", "agent_trace")
REQUIRED_EXPECTED_FIELDS = ("decision",)


def validate_experiment_fixture_file(path: Path) -> dict[str, Any]:
    errors: list[str] = []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"schema_version": "invart.experiment_fixture_validation.v0.40", "status": "fail", "path": str(path), "errors": [str(exc)]}
    if not isinstance(payload, dict):
        errors.append("fixture root must be an object")
        payload = {}
    suite = payload.get("suite")
    source = payload.get("source")
    if not suite:
        errors.append("suite is required")
    if not source:
        errors.append("source is required")
    cases = payload.get("cases")
    if not isinstance(cases, list) or not cases:
        errors.append("cases must be a non-empty list")
        cases = []
    for index, case in enumerate(cases):
        if not isinstance(case, dict):
            errors.append(f"cases[{index}] must be an object")
            continue
        for field in REQUIRED_CASE_FIELDS:
            if field not in case:
                errors.append(f"cases[{index}].{field} is required")
        expected = case.get("expected")
        if not isinstance(expected, dict):
            errors.append(f"cases[{index}].expected must be an object")
        else:
            for field in REQUIRED_EXPECTED_FIELDS:
                if field not in expected:
                    errors.append(f"cases[{index}].expected.{field} is required")
        trace = case.get("agent_trace")
        if not isinstance(trace, list) or not trace:
            errors.append(f"cases[{index}].agent_trace must be a non-empty list")
    return {
        "schema_version": "invart.experiment_fixture_validation.v0.40",
        "status": "pass" if not errors else "fail",
        "path": str(path),
        "summary": {"cases": len(cases), "errors": len(errors)},
        "errors": errors,
    }


def validate_experiment_fixture_root(root: Path) -> dict[str, Any]:
    files = sorted(root.glob("*.json"))
    results = [validate_experiment_fixture_file(path) for path in files]
    failed = [result for result in results if result["status"] != "pass"]
    return {
        "schema_version": "invart.experiment_fixture_root_validation.v0.40",
        "status": "pass" if not failed and bool(files) else "fail",
        "root": str(root),
        "summary": {"files": len(files), "failed": len(failed)},
        "results": results,
    }


def load_experiment_cases_from_file(path: Path) -> list[ExperimentCase]:
    validation = validate_experiment_fixture_file(path)
    if validation["status"] != "pass":
        raise ValueError("; ".join(validation["errors"]))
    payload = json.loads(path.read_text(encoding="utf-8"))
    suite = str(payload["suite"])
    source = str(payload["source"])
    cases: list[ExperimentCase] = []
    for item in payload["cases"]:
        expected_payload = dict(item["expected"])
        expected = ExpectedControlOutcome(
            decision=str(expected_payload["decision"]),
            approval=str(expected_payload.get("approval", "not_required")),
            coverage_floor=str(expected_payload.get("coverage_floor", "observed")),
            proof_fields=list(expected_payload.get("proof_fields", ["session", "ledger", "actions", "policy_decisions"])),
            forbidden_action=expected_payload.get("forbidden_action"),
            benign=bool(expected_payload.get("benign", False)),
            audit_questions=list(expected_payload.get("audit_questions", ["who", "what", "why", "policy", "outcome", "coverage"])),
        )
        seed_raw = {"fixture": path.name, "case": item}
        seed_hash = "sha256:" + hashlib.sha256(json.dumps(seed_raw, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()
        cases.append(
            ExperimentCase(
                case_id=str(item["case_id"]),
                suite=suite,
                title=str(item["title"]),
                source=str(item.get("source", source)),
                trust=str(item["trust"]),
                capability=str(item["capability"]),
                resource=str(item["resource"]),
                sink=str(item["sink"]),
                expected=expected,
                agent_trace=list(item["agent_trace"]),
                seed=ExperimentSeed(source=str(item.get("source", source)), source_case_id=str(item["case_id"]), fixture_hash=seed_hash, raw=seed_raw),
                authority_boundary=item.get("authority_boundary"),
                data_visibility=item.get("data_visibility"),
                supply_chain=bool(item.get("supply_chain", False)),
                skill_origin=item.get("skill_origin"),
                tags=list(item.get("tags", [])),
            )
        )
    return cases


__all__ = ["load_experiment_cases_from_file", "validate_experiment_fixture_file", "validate_experiment_fixture_root"]
