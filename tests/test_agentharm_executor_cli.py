from __future__ import annotations

from pathlib import Path

import pytest

from invart.evaluation.real_agent_benchmark import agentharm_executor_cli
from invart.evaluation.real_agent_benchmark.agentharm_executor_cli import main
from invart.evaluation.real_agent_benchmark.provider_run_control import (
    write_provider_approval_packet,
)
from tests.test_agentharm_executor import _prepared_package


def test_executor_cli_requires_exact_request_hash_before_provider_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (
        dataset_root,
        runner_root,
        _manifest,
        _request,
        approval,
        package_dir,
        _package,
    ) = _prepared_package(tmp_path, monkeypatch)
    approval_path = write_provider_approval_packet(
        tmp_path / "approval.json",
        approval,
    )
    executed = False

    def fail_if_executed(**_kwargs):
        nonlocal executed
        executed = True
        raise AssertionError("executor must not run")

    monkeypatch.setattr(
        agentharm_executor_cli,
        "execute_agentharm_launch_package",
        fail_if_executed,
    )

    status = main(
        [
            "--launch-package",
            str(package_dir),
            "--execution-dir",
            str(tmp_path / "execution"),
            "--approval",
            str(approval_path),
            "--dataset-root",
            str(dataset_root),
            "--runner-root",
            str(runner_root),
            "--confirm-request-hash",
            "sha256:wrong-request",
            "--confirm-approval-hash",
            approval.approval_hash,
        ]
    )

    assert status == 2
    assert executed is False


def test_executor_cli_requires_exact_approval_hash_before_provider_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (
        dataset_root,
        runner_root,
        _manifest,
        request,
        approval,
        package_dir,
        _package,
    ) = _prepared_package(tmp_path, monkeypatch)
    approval_path = write_provider_approval_packet(
        tmp_path / "approval.json",
        approval,
    )
    executed = False

    def fail_if_executed(**_kwargs):
        nonlocal executed
        executed = True
        raise AssertionError("executor must not run")

    monkeypatch.setattr(
        agentharm_executor_cli,
        "execute_agentharm_launch_package",
        fail_if_executed,
    )

    status = main(
        [
            "--launch-package",
            str(package_dir),
            "--execution-dir",
            str(tmp_path / "execution"),
            "--approval",
            str(approval_path),
            "--dataset-root",
            str(dataset_root),
            "--runner-root",
            str(runner_root),
            "--confirm-request-hash",
            request["request_hash"],
            "--confirm-approval-hash",
            "sha256:wrong-approval",
        ]
    )

    assert status == 2
    assert executed is False
