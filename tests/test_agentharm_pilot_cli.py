from __future__ import annotations

import json
from pathlib import Path

import pytest

from invart.evaluation.real_agent_benchmark.agentharm_pilot_cli import main
from tests.test_agentharm_source import (
    _patch_fingerprints,
    _write_dataset,
    _write_runner,
)


def test_agentharm_pilot_cli_builds_request_without_approval_or_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    dataset_root, fingerprints = _write_dataset(tmp_path / "AgentHarm")
    _patch_fingerprints(monkeypatch, fingerprints)
    runner_root = _write_runner(tmp_path / "inspect_evals", monkeypatch)
    output = tmp_path / "control" / "request.json"

    result = main(
        [
            "--dataset-root",
            str(dataset_root),
            "--runner-root",
            str(runner_root),
            "--output-request",
            str(output),
            "--harmful-case-id",
            "2-1",
            "--benign-case-id",
            "2-2",
            "--variant",
            "V0",
            "--maximum-calls-per-sample",
            "2",
            "--maximum-tokens-per-call",
            "256",
            "--maximum-usd",
            "0.25",
            "--profile-state-hash",
            "sha256:cli-fixture",
        ]
    )

    summary = json.loads(capsys.readouterr().out)
    request = json.loads(output.read_text(encoding="utf-8"))
    assert result == 0
    assert summary["status"] == "approval_required"
    assert summary["ready_to_execute"] is False
    assert summary["reasons"] == ["provider_approval_missing"]
    assert request["approved"] is False
    assert request["variants"] == ["V0"]
    assert request["approval_scope_hash"] == summary["approval_scope_hash"]
