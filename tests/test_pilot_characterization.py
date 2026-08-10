from __future__ import annotations

import json
from pathlib import Path

import pytest

from invart.evaluation.real_agent_benchmark.pilot_characterization import (
    build_agentdojo_pilot_characterization,
    export_agentdojo_pilot_characterization,
)


def _write_json(path: Path, payload: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _write_jsonl(path: Path, rows: list[dict[str, object]]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    return path


def _manifest() -> dict[str, object]:
    expected = {"injection_utility": 5, "paired_utility": 105, "security": 105}
    return {
        "schema_version": "invart.agentdojo_full_manifest.v0.1",
        "status": "frozen",
        "benchmark": {"family": "agentdojo", "benchmark_version": "v1.2.2"},
        "protocol": {"scope": "pilot", "canonical_attack": "tool_knowledge"},
        "jobs": [
            {
                "job_id": "baseline-job",
                "mode": "baseline_agent",
                "condition": "canonical_attack",
                "suite": "slack",
                "expected_results": expected,
            },
            {
                "job_id": "mediated-job",
                "mode": "invart_mediated",
                "condition": "canonical_attack",
                "suite": "slack",
                "expected_results": expected,
            },
        ],
    }


def _result(job_id: str, *, observed: int, utility: int, timed_out: bool) -> dict[str, object]:
    return {
        "schema_version": "invart.agentdojo_full_run_record.v0.1",
        "job_id": job_id,
        "run_status": "timeout" if timed_out else "graded",
        "timed_out": timed_out,
        "official_result_status": "graded",
        "official_result_counts": {
            "injection_utility": 5,
            "paired_utility": observed,
            "security": observed,
        },
        "outcome_metrics": {
            "attack_successes": 0,
            "injection_utility_successes": 5,
            "paired_utility_successes": utility,
            "secure_outcomes": observed,
        },
    }


def _proxy_row(*, mode: str, blocked: int, add_user_misclassified: bool) -> dict[str, object]:
    decisions: list[dict[str, object]] = [
        {
            "tool": "send_direct_message",
            "decision_effect": "deny" if blocked else "allow",
            "side_effect": True,
        }
    ]
    if add_user_misclassified:
        decisions.append(
            {
                "tool": "add_user_to_channel",
                "decision_effect": "allow",
                "side_effect": False,
            }
        )
    return {
        "mode": mode,
        "tool_mediation": {
            "mode": mode,
            "function_calls": len(decisions),
            "blocked_calls": blocked,
            "would_block_calls": blocked,
            "response_rewritten": bool(blocked),
            "decisions": decisions,
        },
    }


def _fixture_paths(tmp_path: Path) -> dict[str, Path]:
    return {
        "manifest": _write_json(tmp_path / "manifest.json", _manifest()),
        "baseline_result": _write_json(
            tmp_path / "baseline" / "job_result.json",
            _result("baseline-job", observed=90, utility=76, timed_out=True),
        ),
        "mediated_result": _write_json(
            tmp_path / "mediated" / "job_result.json",
            _result("mediated-job", observed=105, utility=9, timed_out=False),
        ),
        "baseline_proxy": _write_jsonl(
            tmp_path / "baseline" / "proxy.jsonl",
            [_proxy_row(mode="baseline_agent", blocked=0, add_user_misclassified=True)],
        ),
        "mediated_proxy": _write_jsonl(
            tmp_path / "mediated" / "proxy.jsonl",
            [_proxy_row(mode="invart_mediated", blocked=1, add_user_misclassified=True)],
        ),
    }


def test_characterization_keeps_zero_asr_and_utility_collapse_claims_separate(tmp_path: Path) -> None:
    paths = _fixture_paths(tmp_path)
    payload = build_agentdojo_pilot_characterization(**paths)

    assert payload["denominators"]["expected_attack_cells"] == 105
    assert payload["official_metrics"]["security"]["baseline"]["status"] == "partial"
    assert payload["official_metrics"]["security"]["baseline_zero_event_upper_95"] == pytest.approx(
        1 - 0.05 ** (1 / 90)
    )
    assert payload["official_metrics"]["security"]["claimable_security_improvement"] is False
    assert payload["official_metrics"]["utility"]["baseline"]["rate"] == pytest.approx(76 / 90)
    assert payload["official_metrics"]["utility"]["mediated"]["rate"] == pytest.approx(9 / 105)
    assert payload["interpretation"]["utility_degradation_observed"] is True
    assert payload["interpretation"]["paired_effect_claimable"] is False
    assert payload["proxy_observations"]["mediated"]["blocked_calls"] == 1
    assert payload["proxy_observations"]["mediated"]["known_capability_misclassifications"] == {
        "add_user_to_channel_side_effect_false": 1
    }
    assert all("/" not in source["name"] for source in payload["sources"])
    assert payload["artifact_hash"].startswith("sha256:")


def test_characterization_rejects_result_not_bound_to_frozen_mode(tmp_path: Path) -> None:
    paths = _fixture_paths(tmp_path)
    paths["mediated_result"] = _write_json(
        tmp_path / "wrong.json", _result("baseline-job", observed=105, utility=9, timed_out=False)
    )

    with pytest.raises(ValueError, match="invart_mediated"):
        build_agentdojo_pilot_characterization(**paths)


def test_export_is_owner_only_and_contains_no_absolute_source_paths(tmp_path: Path) -> None:
    paths = _fixture_paths(tmp_path)
    output = tmp_path / "artifact"
    result = export_agentdojo_pilot_characterization(output_dir=output, **paths)

    payload = json.loads((output / "agentdojo_pilot_characterization.json").read_text())
    assert result["scan"]["status"] == "pass"
    assert not any(str(tmp_path) in json.dumps(source) for source in payload["sources"])
    assert (output.stat().st_mode & 0o077) == 0
    assert all((path.stat().st_mode & 0o077) == 0 for path in output.iterdir())
    markdown = (output / "agentdojo_pilot_characterization.md").read_text()
    assert "cannot demonstrate attack reduction" in markdown
    assert "76/90" in markdown
    assert "9/105" in markdown
