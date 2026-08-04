from __future__ import annotations

import json
from pathlib import Path

import pytest

from invart.core.artifacts import sha256_file, stable_json_hash
from invart.evaluation.real_agent_benchmark.agentharm_executor import (
    execute_agentharm_launch_package,
)
from invart.evaluation.real_agent_benchmark.agentharm_scored_package import (
    finalize_agentharm_scored_package,
)
from invart.evaluation.real_agent_benchmark.provider_budget_gateway import (
    GatewayUpstreamResponse,
)
from tests.test_agentharm_adapter import _inspect_payload
from tests.test_agentharm_executor import _prepared_package


def _run_unscored(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    response: bytes = b'{"choices":[{"message":{"role":"assistant","content":"fixture-ok"}}]}',
):
    (
        dataset_root,
        runner_root,
        _manifest,
        request,
        approval,
        package_dir,
        package,
    ) = _prepared_package(tmp_path, monkeypatch)
    execution_dir = tmp_path / "execution"
    execution = execute_agentharm_launch_package(
        package_dir=package_dir,
        output_dir=execution_dir,
        approval=approval,
        dataset_root=dataset_root,
        runner_root=runner_root,
        provider_environment={"DASHSCOPE_TP_API_KEY": "fixture-provider-secret"},
        budget_state_root=tmp_path / "budget-state",
        gateway_transport=lambda **_kwargs: GatewayUpstreamResponse(
            200,
            "application/json",
            (response,),
        ),
        runtime_attestor=lambda **_kwargs: dict(package["runtime_attestation"]),
        client_token_factory=lambda: "fixture-loopback-client-token-32-bytes",
    )
    assert execution["status"] == "completed_unscored"
    return (
        dataset_root,
        runner_root,
        request,
        approval,
        package_dir,
        package,
        execution_dir,
    )


def _dump_payload(
    path: Path,
    *,
    inspect_executable: Path,
    benign_score: float = 1.0,
):
    benign = "000" in path.name
    case_id = "2-2" if benign else "2-1"
    payload = _inspect_payload(
        task="inspect_evals/agentharm_benign" if benign else "inspect_evals/agentharm",
        score=benign_score if benign else 0.5,
    )
    payload["eval"]["model"] = "openai/deepseek-v4-pro"
    payload["eval"]["task_args"]["refusal_judge"] = "openai/deepseek-v4-pro"
    payload["eval"]["task_args"]["semantic_judge"] = "openai/deepseek-v4-pro"
    payload["samples"][0]["id"] = case_id
    payload["samples"][0]["metadata"]["id"] = case_id
    return {
        "payload": payload,
        "upstream_artifact_hash": sha256_file(path, prefixed=True),
        "inspect_executable": str(inspect_executable),
    }


def test_finalizer_replays_official_scores_and_builds_v0_condition_gate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (
        dataset_root,
        runner_root,
        request,
        approval,
        package_dir,
        package,
        execution_dir,
    ) = _run_unscored(tmp_path, monkeypatch)
    monkeypatch.setattr(
        "invart.evaluation.real_agent_benchmark.official_runners.dump_agentharm_inspect_eval",
        _dump_payload,
    )

    result = finalize_agentharm_scored_package(
        package_dir=package_dir,
        execution_dir=execution_dir,
        approval=approval,
        dataset_root=dataset_root,
        runner_root=runner_root,
        runtime_attestor=lambda **_kwargs: dict(package["runtime_attestation"]),
        inspect_dumper=_dump_payload,
    )

    assert result["status"] == "scored_condition_only"
    assert result["request_hash"] == request["request_hash"]
    assert result["official_package_validation"]["status"] == "pass"
    assert result["technical_evidence"]["status"] == "valid"
    assert result["pilot_gate"]["technical_valid"] is True
    assert result["pilot_gate"]["eligibility_status"] == "opportunity_qualified"
    assert result["pilot_gate"]["security_effect_eligible"] is False
    assert result["denominator"]["benign_scored_cases"] == 1
    assert result["denominator"]["harmful_scored_cases"] == 1
    assert result["denominator"]["paired_security_effect_cases"] == 0
    assert result["runtime_execution_proof"]["proof_hash"].startswith("sha256:")
    assert result["runtime_execution_proof"]["native_artifact_sha256"] == sha256_file(
        execution_dir
        / "scored"
        / "native"
        / "native_artifact_manifest.json",
        prefixed=True,
    )
    assert len(
        list((execution_dir / "scored" / "native").glob("*.eval"))
    ) == 2
    assert len(
        list(
            (execution_dir / "scored" / "native").glob(
                "*.agentharm-bound.json"
            )
        )
    ) == 1


def test_finalizer_rejects_empty_assistant_receipt_even_with_successful_commands(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (
        dataset_root,
        runner_root,
        _request,
        approval,
        package_dir,
        package,
        execution_dir,
    ) = _run_unscored(tmp_path, monkeypatch, response=b"{}")

    with pytest.raises(ValueError, match="assistant response"):
        finalize_agentharm_scored_package(
            package_dir=package_dir,
            execution_dir=execution_dir,
            approval=approval,
            dataset_root=dataset_root,
            runner_root=runner_root,
            runtime_attestor=lambda **_kwargs: dict(package["runtime_attestation"]),
            inspect_dumper=_dump_payload,
        )


def test_finalizer_rejects_ambiguous_extra_eval_archive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (
        dataset_root,
        runner_root,
        _request,
        approval,
        package_dir,
        package,
        execution_dir,
    ) = _run_unscored(tmp_path, monkeypatch)
    command = package["commands"][0]["command_spec"]["command"]
    log_dir = Path(command[command.index("--log-dir") + 1])
    extra = log_dir / "ambiguous.eval"
    extra.write_bytes(b"unexpected second archive")
    extra.chmod(0o600)

    with pytest.raises(ValueError, match="exactly one Inspect Eval archive"):
        finalize_agentharm_scored_package(
            package_dir=package_dir,
            execution_dir=execution_dir,
            approval=approval,
            dataset_root=dataset_root,
            runner_root=runner_root,
            runtime_attestor=lambda **_kwargs: dict(package["runtime_attestation"]),
            inspect_dumper=_dump_payload,
        )


def test_finalizer_cleans_staging_and_can_retry_after_dump_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (
        dataset_root,
        runner_root,
        _request,
        approval,
        package_dir,
        package,
        execution_dir,
    ) = _run_unscored(tmp_path, monkeypatch)
    monkeypatch.setattr(
        "invart.evaluation.real_agent_benchmark.official_runners.dump_agentharm_inspect_eval",
        _dump_payload,
    )
    calls = 0

    def fail_once(path: Path, *, inspect_executable: Path):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("synthetic dump failure")
        return _dump_payload(path, inspect_executable=inspect_executable)

    with pytest.raises(RuntimeError, match="synthetic dump failure"):
        finalize_agentharm_scored_package(
            package_dir=package_dir,
            execution_dir=execution_dir,
            approval=approval,
            dataset_root=dataset_root,
            runner_root=runner_root,
            runtime_attestor=lambda **_kwargs: dict(package["runtime_attestation"]),
            inspect_dumper=fail_once,
        )

    assert not (execution_dir / "scored").exists()
    assert not list(execution_dir.glob(".agentharm-finalize-*"))

    result = finalize_agentharm_scored_package(
        package_dir=package_dir,
        execution_dir=execution_dir,
        approval=approval,
        dataset_root=dataset_root,
        runner_root=runner_root,
        runtime_attestor=lambda **_kwargs: dict(package["runtime_attestation"]),
        inspect_dumper=fail_once,
    )

    assert result["status"] == "scored_condition_only"


def test_finalizer_rejects_gateway_log_changed_after_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (
        dataset_root,
        runner_root,
        _request,
        approval,
        package_dir,
        package,
        execution_dir,
    ) = _run_unscored(tmp_path, monkeypatch)
    gateway_log = execution_dir / "provider_gateway_requests.jsonl"
    gateway_log.write_text(
        gateway_log.read_text(encoding="utf-8") + "{}\n",
        encoding="utf-8",
    )
    gateway_log.chmod(0o600)

    with pytest.raises(ValueError, match="gateway log hash"):
        finalize_agentharm_scored_package(
            package_dir=package_dir,
            execution_dir=execution_dir,
            approval=approval,
            dataset_root=dataset_root,
            runner_root=runner_root,
            runtime_attestor=lambda **_kwargs: dict(package["runtime_attestation"]),
            inspect_dumper=_dump_payload,
        )


@pytest.mark.parametrize(
    ("field_name", "replacement"),
    [
        ("approval_hash", "sha256:substituted-approval"),
        ("runtime_manifest_hash", "sha256:substituted-manifest"),
        ("status", "execution_failed"),
        ("command_count", 99),
    ],
)
def test_finalizer_rejects_rehashed_execution_record_tampering(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field_name: str,
    replacement: object,
) -> None:
    (
        dataset_root,
        runner_root,
        _request,
        approval,
        package_dir,
        package,
        execution_dir,
    ) = _run_unscored(tmp_path, monkeypatch)
    execution_record_path = execution_dir / "execution_record.json"
    execution_record = json.loads(
        execution_record_path.read_text(encoding="utf-8")
    )
    execution_record[field_name] = replacement
    execution_record["execution_record_hash"] = stable_json_hash(
        {
            key: value
            for key, value in execution_record.items()
            if key != "execution_record_hash"
        }
    )
    execution_record_path.write_text(
        json.dumps(execution_record, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    execution_record_path.chmod(0o600)

    with pytest.raises(ValueError, match="does not match launch package"):
        finalize_agentharm_scored_package(
            package_dir=package_dir,
            execution_dir=execution_dir,
            approval=approval,
            dataset_root=dataset_root,
            runner_root=runner_root,
            runtime_attestor=lambda **_kwargs: dict(package["runtime_attestation"]),
            inspect_dumper=_dump_payload,
        )


def test_finalizer_rejects_rehashed_gateway_scope_substitution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (
        dataset_root,
        runner_root,
        _request,
        approval,
        package_dir,
        package,
        execution_dir,
    ) = _run_unscored(tmp_path, monkeypatch)
    gateway_log = execution_dir / "provider_gateway_requests.jsonl"
    rows = [
        json.loads(line)
        for line in gateway_log.read_text(encoding="utf-8").splitlines()
    ]
    rows[0]["provider"] = "substituted-provider"
    gateway_log.write_text(
        "".join(
            json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n"
            for row in rows
        ),
        encoding="utf-8",
    )
    gateway_log.chmod(0o600)
    execution_record_path = execution_dir / "execution_record.json"
    execution_record = json.loads(
        execution_record_path.read_text(encoding="utf-8")
    )
    execution_record["gateway_log_sha256"] = sha256_file(
        gateway_log,
        prefixed=True,
    )
    execution_record["execution_record_hash"] = stable_json_hash(
        {
            key: value
            for key, value in execution_record.items()
            if key != "execution_record_hash"
        }
    )
    execution_record_path.write_text(
        json.dumps(execution_record, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    execution_record_path.chmod(0o600)

    with pytest.raises(ValueError, match="receipt scope"):
        finalize_agentharm_scored_package(
            package_dir=package_dir,
            execution_dir=execution_dir,
            approval=approval,
            dataset_root=dataset_root,
            runner_root=runner_root,
            runtime_attestor=lambda **_kwargs: dict(package["runtime_attestation"]),
            inspect_dumper=_dump_payload,
        )


def test_finalizer_rejects_failed_capability_control(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (
        dataset_root,
        runner_root,
        _request,
        approval,
        package_dir,
        package,
        execution_dir,
    ) = _run_unscored(tmp_path, monkeypatch)

    def low_capability_dump(path: Path, *, inspect_executable: Path):
        return _dump_payload(
            path,
            inspect_executable=inspect_executable,
            benign_score=0.0,
        )

    monkeypatch.setattr(
        "invart.evaluation.real_agent_benchmark.official_runners.dump_agentharm_inspect_eval",
        low_capability_dump,
    )

    result = finalize_agentharm_scored_package(
        package_dir=package_dir,
        execution_dir=execution_dir,
        approval=approval,
        dataset_root=dataset_root,
        runner_root=runner_root,
        runtime_attestor=lambda **_kwargs: dict(package["runtime_attestation"]),
        inspect_dumper=low_capability_dump,
    )

    assert result["pilot_gate"]["eligibility_status"] != "opportunity_qualified"
    assert result["pilot_gate"]["security_effect_eligible"] is False
