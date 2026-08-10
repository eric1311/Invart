from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any, Mapping

from invart.core.artifacts import (
    sha256_file,
    stable_json_dumps,
    stable_json_hash,
    write_json_artifact,
)

from .mediation_metrics import rate_with_completeness, security_effect_summary
from .provider_run_control import scan_provider_artifact_tree, secure_provider_artifact_tree


SCHEMA_VERSION = "invart.agentdojo_pilot_characterization.v0.1"


def build_agentdojo_pilot_characterization(
    *,
    manifest: Path,
    baseline_result: Path,
    mediated_result: Path,
    baseline_proxy: Path,
    mediated_proxy: Path,
) -> dict[str, Any]:
    source_paths = {
        "frozen_manifest": Path(manifest),
        "baseline_official_result": Path(baseline_result),
        "mediated_official_result": Path(mediated_result),
        "baseline_proxy_log": Path(baseline_proxy),
        "mediated_proxy_log": Path(mediated_proxy),
    }
    manifest_payload = _read_object(source_paths["frozen_manifest"])
    if manifest_payload.get("status") != "frozen":
        raise ValueError("AgentDojo pilot manifest must be frozen")
    benchmark = manifest_payload.get("benchmark")
    if not isinstance(benchmark, Mapping) or benchmark.get("family") != "agentdojo":
        raise ValueError("manifest must describe AgentDojo")

    baseline_payload = _read_object(source_paths["baseline_official_result"])
    mediated_payload = _read_object(source_paths["mediated_official_result"])
    baseline_job = _bind_job(manifest_payload, baseline_payload, expected_mode="baseline_agent")
    mediated_job = _bind_job(manifest_payload, mediated_payload, expected_mode="invart_mediated")
    _validate_comparable_jobs(baseline_job, mediated_job)

    expected = _expected_counts(baseline_job)
    mediated_expected = _expected_counts(mediated_job)
    if expected != mediated_expected:
        raise ValueError("baseline and mediated jobs have different frozen denominators")

    baseline_counts = _official_counts(baseline_payload)
    mediated_counts = _official_counts(mediated_payload)
    baseline_outcomes = _outcomes(baseline_payload)
    mediated_outcomes = _outcomes(mediated_payload)
    _validate_observed_counts(expected, baseline_counts, role="baseline")
    _validate_observed_counts(expected, mediated_counts, role="mediated")

    expected_attack_cells = expected["security"]
    expected_utility_cells = expected["paired_utility"]
    security = security_effect_summary(
        baseline_attack_successes=baseline_outcomes["attack_successes"],
        baseline_denominator=baseline_counts["security"],
        baseline_expected_denominator=expected_attack_cells,
        mediated_attack_successes=mediated_outcomes["attack_successes"],
        mediated_denominator=mediated_counts["security"],
        mediated_expected_denominator=expected_attack_cells,
    )
    baseline_utility = rate_with_completeness(
        successes=baseline_outcomes["paired_utility_successes"],
        observed=baseline_counts["paired_utility"],
        expected=expected_utility_cells,
    )
    mediated_utility = rate_with_completeness(
        successes=mediated_outcomes["paired_utility_successes"],
        observed=mediated_counts["paired_utility"],
        expected=expected_utility_cells,
    )
    utility_difference = (
        mediated_utility["rate"] - baseline_utility["rate"]
        if mediated_utility["rate"] is not None and baseline_utility["rate"] is not None
        else None
    )
    utility_retention = (
        mediated_utility["rate"] / baseline_utility["rate"]
        if baseline_utility["rate"] and mediated_utility["rate"] is not None
        else None
    )

    injection_expected = expected["injection_utility"]
    injection_utility = {
        "baseline": rate_with_completeness(
            successes=baseline_outcomes["injection_utility_successes"],
            observed=baseline_counts["injection_utility"],
            expected=injection_expected,
        ),
        "mediated": rate_with_completeness(
            successes=mediated_outcomes["injection_utility_successes"],
            observed=mediated_counts["injection_utility"],
            expected=injection_expected,
        ),
    }
    baseline_proxy_summary = _summarize_proxy_log(
        source_paths["baseline_proxy_log"], expected_mode="baseline_agent"
    )
    mediated_proxy_summary = _summarize_proxy_log(
        source_paths["mediated_proxy_log"], expected_mode="invart_mediated"
    )

    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "benchmark": {
            "family": "agentdojo",
            "version": benchmark.get("benchmark_version"),
            "suite": baseline_job.get("suite"),
            "scope": (manifest_payload.get("protocol") or {}).get("scope"),
            "attack": (manifest_payload.get("protocol") or {}).get("canonical_attack"),
        },
        "job_binding": {
            "baseline": {
                "job_id": baseline_payload["job_id"],
                "mode": "baseline_agent",
                "run_status": baseline_payload.get("run_status"),
                "timed_out": bool(baseline_payload.get("timed_out")),
            },
            "mediated": {
                "job_id": mediated_payload["job_id"],
                "mode": "invart_mediated",
                "run_status": mediated_payload.get("run_status"),
                "timed_out": bool(mediated_payload.get("timed_out")),
            },
        },
        "denominators": {
            "expected_attack_cells": expected_attack_cells,
            "expected_paired_utility_cells": expected_utility_cells,
            "expected_injection_utility_cells": injection_expected,
        },
        "official_metrics": {
            "security": security,
            "utility": {
                "baseline": baseline_utility,
                "mediated": mediated_utility,
                "observed_rate_difference": utility_difference,
                "observed_rate_retention": utility_retention,
                "claim_boundary": (
                    "The rate difference is descriptive, not a paired causal estimate: the baseline is "
                    "partial and the two jobs used independent runtime trajectories."
                ),
            },
            "injection_utility": injection_utility,
        },
        "proxy_observations": {
            "baseline": baseline_proxy_summary,
            "mediated": mediated_proxy_summary,
            "claim_boundary": (
                "Proxy decisions are intervention telemetry. Without benchmark-ground-truth adjudication, "
                "they do not establish that blocked calls were harmful or that allowed calls were benign."
            ),
        },
        "interpretation": {
            "security_improvement_demonstrated": False,
            "utility_degradation_observed": bool(utility_difference is not None and utility_difference < 0),
            "paired_effect_claimable": False,
            "policy_iteration_signal": bool(
                mediated_proxy_summary["known_capability_misclassifications"]
                ["add_user_to_channel_side_effect_false"]
            ),
            "experiment_decision": "iterate_policy_before_security_claim",
            "required_next_evidence": [
                "complete baseline attack denominator with an agent/model that exposes attack opportunity",
                "join every intervention to user-task and injection-task ground truth",
                "report harmful-block precision, harmful-block recall, benign false-block rate, and ambiguity",
                "rerun paired frozen cells with capability-aware Policy and bounded continuation",
            ],
        },
        "sources": [
            {
                "role": role,
                "name": path.name,
                "sha256": sha256_file(path, prefixed=True),
            }
            for role, path in sorted(source_paths.items())
        ],
        "claim_boundary": (
            "This pilot can report official AgentDojo outcome counts and observed mediation telemetry. "
            "Because the baseline recorded zero successful attacks and only 90/105 attack cells completed, "
            "it cannot demonstrate attack reduction. The utility drop is a valid warning signal, while the "
            "harmfulness of individual interventions remains unproven until ground-truth adjudication."
        ),
    }
    payload["artifact_hash"] = stable_json_hash(payload)
    return payload


def export_agentdojo_pilot_characterization(
    *,
    output_dir: Path,
    manifest: Path,
    baseline_result: Path,
    mediated_result: Path,
    baseline_proxy: Path,
    mediated_proxy: Path,
) -> dict[str, Any]:
    payload = build_agentdojo_pilot_characterization(
        manifest=manifest,
        baseline_result=baseline_result,
        mediated_result=mediated_result,
        baseline_proxy=baseline_proxy,
        mediated_proxy=mediated_proxy,
    )
    root = Path(output_dir)
    root.mkdir(parents=True, exist_ok=True)
    json_path = write_json_artifact(root / "agentdojo_pilot_characterization.json", payload)
    markdown_path = root / "agentdojo_pilot_characterization.md"
    markdown_path.write_text(_render_markdown(payload), encoding="utf-8")
    secure_provider_artifact_tree(root)
    scan = scan_provider_artifact_tree(root)
    if scan["status"] != "pass":
        raise RuntimeError("pilot characterization failed artifact safety scan")
    return {
        "status": "characterized",
        "artifact_hash": payload["artifact_hash"],
        "json": str(json_path),
        "markdown": str(markdown_path),
        "scan": scan,
    }


def _read_object(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid JSON source: {path.name}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"JSON source must be an object: {path.name}")
    return payload


def _bind_job(
    manifest: Mapping[str, Any], result: Mapping[str, Any], *, expected_mode: str
) -> Mapping[str, Any]:
    job_id = str(result.get("job_id") or "")
    jobs = manifest.get("jobs")
    if not isinstance(jobs, list):
        raise ValueError("manifest jobs must be a list")
    matches = [job for job in jobs if isinstance(job, Mapping) and job.get("job_id") == job_id]
    if len(matches) != 1 or matches[0].get("mode") != expected_mode:
        raise ValueError(f"result is not bound to frozen {expected_mode} job")
    job = matches[0]
    if job.get("condition") != "canonical_attack":
        raise ValueError(f"{expected_mode} result is not a canonical-attack job")
    return job


def _validate_comparable_jobs(baseline: Mapping[str, Any], mediated: Mapping[str, Any]) -> None:
    for key in ("suite", "condition"):
        if baseline.get(key) != mediated.get(key):
            raise ValueError(f"baseline and mediated jobs differ on {key}")


def _integer_map(payload: Mapping[str, Any], field: str, required: tuple[str, ...]) -> dict[str, int]:
    raw = payload.get(field)
    if not isinstance(raw, Mapping):
        raise ValueError(f"missing {field}")
    result: dict[str, int] = {}
    for key in required:
        value = raw.get(key)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f"invalid {field}.{key}")
        result[key] = value
    return result


def _expected_counts(job: Mapping[str, Any]) -> dict[str, int]:
    return _integer_map(
        job,
        "expected_results",
        ("injection_utility", "paired_utility", "security"),
    )


def _official_counts(result: Mapping[str, Any]) -> dict[str, int]:
    return _integer_map(
        result,
        "official_result_counts",
        ("injection_utility", "paired_utility", "security"),
    )


def _outcomes(result: Mapping[str, Any]) -> dict[str, int]:
    return _integer_map(
        result,
        "outcome_metrics",
        ("attack_successes", "injection_utility_successes", "paired_utility_successes"),
    )


def _validate_observed_counts(
    expected: Mapping[str, int], observed: Mapping[str, int], *, role: str
) -> None:
    for key, denominator in observed.items():
        if denominator > expected[key]:
            raise ValueError(f"{role} {key} exceeds frozen denominator")


def _summarize_proxy_log(path: Path, *, expected_mode: str) -> dict[str, Any]:
    rows = 0
    function_calls = 0
    blocked_calls = 0
    would_block_calls = 0
    rewritten_rows = 0
    decisions: Counter[str] = Counter()
    add_user_total = 0
    add_user_side_effect_false = 0
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid proxy JSONL at {path.name}:{line_number}") from exc
        if not isinstance(row, Mapping):
            raise ValueError(f"proxy row must be an object at {path.name}:{line_number}")
        mediation = row.get("tool_mediation")
        if not isinstance(mediation, Mapping):
            raise ValueError(f"proxy row lacks tool_mediation at {path.name}:{line_number}")
        mode = str(mediation.get("mode") or row.get("mode") or "")
        if mode != expected_mode:
            raise ValueError(f"proxy row mode {mode!r} does not match {expected_mode}")
        rows += 1
        function_calls += _nonnegative_int(mediation.get("function_calls"), "function_calls")
        blocked_calls += _nonnegative_int(mediation.get("blocked_calls"), "blocked_calls")
        would_block_calls += _nonnegative_int(
            mediation.get("would_block_calls"), "would_block_calls"
        )
        rewritten_rows += int(mediation.get("response_rewritten") is True)
        raw_decisions = mediation.get("decisions")
        if not isinstance(raw_decisions, list):
            raise ValueError("proxy decisions must be a list")
        for decision in raw_decisions:
            if not isinstance(decision, Mapping):
                raise ValueError("proxy decision must be an object")
            effect = str(decision.get("decision_effect") or "missing")
            decisions[effect] += 1
            if decision.get("tool") == "add_user_to_channel":
                add_user_total += 1
                if decision.get("side_effect") is False:
                    add_user_side_effect_false += 1
    return {
        "rows": rows,
        "function_calls": function_calls,
        "blocked_calls": blocked_calls,
        "would_block_calls": would_block_calls,
        "response_rewritten_rows": rewritten_rows,
        "decision_counts": dict(sorted(decisions.items())),
        "add_user_to_channel_calls": add_user_total,
        "known_capability_misclassifications": {
            "add_user_to_channel_side_effect_false": add_user_side_effect_false
        },
    }


def _nonnegative_int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"invalid proxy {field}")
    return value


def _render_markdown(payload: Mapping[str, Any]) -> str:
    security = payload["official_metrics"]["security"]
    utility = payload["official_metrics"]["utility"]
    baseline_security = security["baseline"]
    mediated_security = security["mediated"]
    baseline_utility = utility["baseline"]
    mediated_utility = utility["mediated"]
    baseline_proxy = payload["proxy_observations"]["baseline"]
    mediated_proxy = payload["proxy_observations"]["mediated"]
    return "\n".join(
        [
            "# AgentDojo Slack Pilot Characterization",
            "",
            f"Artifact hash: `{payload['artifact_hash']}`",
            "",
            "## Outcome",
            "",
            (
                f"- Official attack successes: baseline {baseline_security['successes']}/"
                f"{baseline_security['observed_denominator']} of "
                f"{baseline_security['expected_denominator']} expected; mediated "
                f"{mediated_security['successes']}/{mediated_security['observed_denominator']} of "
                f"{mediated_security['expected_denominator']} expected."
            ),
            (
                f"- Official paired utility successes: baseline {baseline_utility['successes']}/"
                f"{baseline_utility['observed_denominator']}; mediated "
                f"{mediated_utility['successes']}/{mediated_utility['observed_denominator']}."
            ),
            (
                f"- Baseline zero-event one-sided 95% upper bound: "
                f"{security['baseline_zero_event_upper_95']:.6f}."
            ),
            "",
            "The zero-success baseline cannot demonstrate attack reduction. The observed utility change is "
            "descriptive because the baseline is partial and the trajectories are not paired.",
            "",
            "## Mediation telemetry",
            "",
            f"- Baseline would-block calls: {baseline_proxy['would_block_calls']} (not enforced).",
            (
                f"- Mediated blocked calls: {mediated_proxy['blocked_calls']}; rewritten response rows: "
                f"{mediated_proxy['response_rewritten_rows']}."
            ),
            (
                "- Historical capability gap (`add_user_to_channel` marked `side_effect=false`): "
                f"{mediated_proxy['known_capability_misclassifications']['add_user_to_channel_side_effect_false']} "
                "mediated calls."
            ),
            "",
            "Proxy telemetry alone cannot determine whether each intervention was harmful or benign; that "
            "requires benchmark-ground-truth adjudication.",
            "",
            "## Claim boundary",
            "",
            str(payload["claim_boundary"]),
            "",
        ]
    )


__all__ = [
    "build_agentdojo_pilot_characterization",
    "export_agentdojo_pilot_characterization",
]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Freeze an evidence-bounded characterization of an AgentDojo pilot."
    )
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--baseline-result", type=Path, required=True)
    parser.add_argument("--mediated-result", type=Path, required=True)
    parser.add_argument("--baseline-proxy", type=Path, required=True)
    parser.add_argument("--mediated-proxy", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    result = export_agentdojo_pilot_characterization(
        output_dir=args.output_dir,
        manifest=args.manifest,
        baseline_result=args.baseline_result,
        mediated_result=args.mediated_result,
        baseline_proxy=args.baseline_proxy,
        mediated_proxy=args.mediated_proxy,
    )
    print(stable_json_dumps(result), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
