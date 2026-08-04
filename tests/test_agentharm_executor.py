from __future__ import annotations

import json
import socket
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from invart.core.artifacts import stable_json_hash
from invart.evaluation.real_agent_benchmark.agentharm_executor import (
    execute_agentharm_launch_package,
    validate_agentharm_launch_package_for_execution,
)
from invart.evaluation.real_agent_benchmark.agentharm_launch import (
    prepare_agentharm_launch_package,
)
from invart.evaluation.real_agent_benchmark.provider_budget_gateway import (
    GatewayUpstreamResponse,
)
from invart.evaluation.real_agent_benchmark.provider_run_control import (
    create_provider_approval_packet,
)
from tests.test_agentharm_launch import _request


def _approval(manifest, request):
    now = datetime.now(timezone.utc)
    return create_provider_approval_packet(
        approval_id="agentharm-executor-test",
        approved_by="test-operator",
        approved_at=now - timedelta(minutes=1),
        expires_at=now + timedelta(hours=1),
        manifest_hash=manifest.manifest_hash,
        provider=request["provider"],
        endpoint=request["endpoint"],
        model_ids=request["model_ids"],
        max_calls=request["max_calls"],
        max_total_tokens=request["max_total_tokens"],
        purpose=request["purpose"],
    )


def _free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as stream:
        stream.bind(("127.0.0.1", 0))
        return int(stream.getsockname()[1])


def _write_fixture_inspect(path: Path, *, mode: str = "normal") -> None:
    path.write_text(
        f"""#!{sys.executable}
import json
import os
import pathlib
import sys
import urllib.request

log_dir = pathlib.Path(sys.argv[sys.argv.index("--log-dir") + 1])
log_dir.mkdir(parents=True, exist_ok=True)
request_count = 2 if {mode!r} == "bypass" and "000-benign" in str(log_dir) else 1
if {mode!r} == "bypass" and "001-harmful" in str(log_dir):
    request_count = 0
body = {{}}
for _index in range(request_count):
    request = urllib.request.Request(
        os.environ["OPENAI_BASE_URL"].rstrip("/") + "/chat/completions",
        data=json.dumps({{
            "model": "deepseek-v4-pro",
            "messages": [{{"role": "user", "content": "fixture request"}}],
            "max_tokens": 16,
        }}).encode("utf-8"),
        headers={{
            "Authorization": "Bearer " + os.environ["OPENAI_API_KEY"],
            "Content-Type": "application/json",
        }},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        body = json.loads(response.read())
(log_dir / "fixture-result.json").write_text(json.dumps(body), encoding="utf-8")
(log_dir / "fixture.eval").write_bytes(str(log_dir).encode("utf-8"))
print(json.dumps({{
    "ambient_present": "INVART_EXECUTOR_AMBIENT_SENTINEL" in os.environ,
    "provider_secret_present": "DASHSCOPE_TP_API_KEY" in os.environ,
}}))
""",
        encoding="utf-8",
    )
    path.chmod(0o700)


def _prepared_package(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    inspect_mode: str = "normal",
    maximum_calls_per_sample: int = 4,
):
    dataset_root, runner_root, manifest, request = _request(
        tmp_path,
        monkeypatch,
        maximum_calls_per_sample=maximum_calls_per_sample,
    )
    inspect_executable = runner_root / ".venv" / "bin" / "inspect"
    _write_fixture_inspect(inspect_executable, mode=inspect_mode)
    approval = _approval(manifest, request)
    package_dir = tmp_path / "launch"
    package = prepare_agentharm_launch_package(
        package_dir,
        request=request,
        runtime_manifest=manifest,
        dataset_root=dataset_root,
        runner_root=runner_root,
        gateway_base_url=f"http://127.0.0.1:{_free_loopback_port()}/v1",
        approval=approval,
    )
    return dataset_root, runner_root, manifest, request, approval, package_dir, package


def test_executor_runs_authenticated_replacement_environment_without_provider_call(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (
        dataset_root,
        runner_root,
        _manifest,
        _request_payload,
        approval,
        package_dir,
        package,
    ) = _prepared_package(tmp_path, monkeypatch)
    monkeypatch.setenv("INVART_EXECUTOR_AMBIENT_SENTINEL", "must-not-cross")
    provider_secret = "fixture-provider-secret-must-not-leak"
    forwarded = 0

    def transport(**_kwargs):
        nonlocal forwarded
        forwarded += 1
        return GatewayUpstreamResponse(
            200,
            "application/json",
            (b'{"choices":[{"message":{"role":"assistant","content":"fixture-ok"}}]}',),
        )

    result = execute_agentharm_launch_package(
        package_dir=package_dir,
        output_dir=tmp_path / "execution",
        approval=approval,
        dataset_root=dataset_root,
        runner_root=runner_root,
        provider_environment={"DASHSCOPE_TP_API_KEY": provider_secret},
        budget_state_root=tmp_path / "budget-state",
        gateway_transport=transport,
        runtime_attestor=lambda **_kwargs: dict(package["runtime_attestation"]),
        client_token_factory=lambda: "fixture-loopback-client-token-32-bytes",
    )

    assert result["status"] == "completed_unscored"
    assert result["all_commands_succeeded"] is True
    assert result["command_count"] == 2
    assert result["gateway_reconciliation"]["forwarded_count"] == 2
    assert result["gateway_reconciliation"]["orphan_request_ids"] == []
    budget_state = (
        tmp_path
        / "budget-state"
        / f"{approval.approval_hash.removeprefix('sha256:')}.json"
    )
    assert budget_state.is_file()
    assert result["budget_ledger_scope"] == "approval_hash_global"
    assert result["budget_ledger_state_sha256"].startswith("sha256:")
    assert not (tmp_path / "execution" / "provider_budget.json").exists()
    assert forwarded == 2
    assert all(
        json.loads(command["supervision"]["stdout"]) == {
            "ambient_present": False,
            "provider_secret_present": False,
        }
        for command in result["commands"]
    )
    serialized = (tmp_path / "execution" / "execution_record.json").read_text()
    assert provider_secret not in serialized
    assert "fixture-loopback-client-token-32-bytes" not in serialized
    assert result["native_artifact_status"] == "not_validated"
    assert result["runtime_execution_proof"] is None
    assert all(
        path.stat().st_mode & 0o077 == 0
        for path in [package_dir, *package_dir.rglob("*")]
        if not path.is_symlink()
    )


def test_executor_rejects_aggregate_calls_that_mask_one_bypassed_command(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (
        dataset_root,
        runner_root,
        _manifest,
        _request_payload,
        approval,
        package_dir,
        package,
    ) = _prepared_package(tmp_path, monkeypatch, inspect_mode="bypass")

    result = execute_agentharm_launch_package(
        package_dir=package_dir,
        output_dir=tmp_path / "execution",
        approval=approval,
        dataset_root=dataset_root,
        runner_root=runner_root,
        provider_environment={"DASHSCOPE_TP_API_KEY": "fixture-provider-secret"},
        budget_state_root=tmp_path / "budget-state",
        gateway_transport=lambda **_kwargs: GatewayUpstreamResponse(
            200,
            "application/json",
            (b'{"choices":[{"message":{"content":"ok"}}]}',),
        ),
        runtime_attestor=lambda **_kwargs: dict(package["runtime_attestation"]),
        client_token_factory=lambda: "fixture-loopback-client-token-32-bytes",
    )

    assert result["status"] == "execution_failed"
    assert result["gateway_reconciliation"]["forwarded_count"] == 2
    assert result["commands"][0]["gateway_reconciliation"]["forwarded_count"] == 2
    assert result["commands"][1]["gateway_reconciliation"]["forwarded_count"] == 0
    assert result["commands"][1]["succeeded"] is False


def test_executor_rejects_per_sample_call_budget_overrun(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (
        dataset_root,
        runner_root,
        _manifest,
        _request_payload,
        approval,
        package_dir,
        package,
    ) = _prepared_package(
        tmp_path,
        monkeypatch,
        inspect_mode="bypass",
        maximum_calls_per_sample=1,
    )

    forwarded = 0

    def transport(**_kwargs):
        nonlocal forwarded
        forwarded += 1
        return GatewayUpstreamResponse(
            200,
            "application/json",
            (b'{"choices":[{"message":{"content":"ok"}}]}',),
        )

    result = execute_agentharm_launch_package(
        package_dir=package_dir,
        output_dir=tmp_path / "execution",
        approval=approval,
        dataset_root=dataset_root,
        runner_root=runner_root,
        provider_environment={
            "DASHSCOPE_TP_API_KEY": "fixture-provider-secret"
        },
        budget_state_root=tmp_path / "budget-state",
        gateway_transport=transport,
        runtime_attestor=lambda **_kwargs: dict(
            package["runtime_attestation"]
        ),
        client_token_factory=lambda: "fixture-loopback-client-token-32-bytes",
    )

    assert result["status"] == "execution_failed"
    assert result["command_count"] == 1
    assert result["commands"][0]["gateway_reconciliation"][
        "forwarded_count"
    ] == 1
    assert result["commands"][0]["gateway_reconciliation"][
        "terminal_error_count"
    ] == 1
    assert result["commands"][0]["gateway_budget_scope"]["calls_reserved"] == 1
    assert forwarded == 1
    assert result["commands"][0]["succeeded"] is False


def test_executor_records_gateway_setup_failure_after_output_creation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (
        dataset_root,
        runner_root,
        _manifest,
        _request_payload,
        approval,
        package_dir,
        package,
    ) = _prepared_package(tmp_path, monkeypatch)

    result = execute_agentharm_launch_package(
        package_dir=package_dir,
        output_dir=tmp_path / "execution",
        approval=approval,
        dataset_root=dataset_root,
        runner_root=runner_root,
        provider_environment={},
        budget_state_root=tmp_path / "budget-state",
        runtime_attestor=lambda **_kwargs: dict(package["runtime_attestation"]),
    )

    assert result["status"] == "execution_failed"
    assert result["command_count"] == 0
    assert "required gateway provider credential is missing" in result["execution_error"]
    retained = json.loads(
        (tmp_path / "execution" / "execution_record.json").read_text(encoding="utf-8")
    )
    assert retained == result


def test_executor_rejects_rehashed_command_substitution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (
        dataset_root,
        runner_root,
        _manifest,
        _request_payload,
        approval,
        package_dir,
        package,
    ) = _prepared_package(tmp_path, monkeypatch)
    plan_path = package_dir / "launch_plan.json"
    tampered = json.loads(plan_path.read_text(encoding="utf-8"))
    tampered["commands"][0]["command_spec"]["command"].append("--unexpected")
    row = tampered["commands"][0]
    row["command_hash"] = stable_json_hash(
        {key: value for key, value in row.items() if key != "command_hash"}
    )
    tampered["package_hash"] = stable_json_hash(
        {key: value for key, value in tampered.items() if key != "package_hash"}
    )
    plan_path.write_text(json.dumps(tampered), encoding="utf-8")
    plan_path.chmod(0o600)

    with pytest.raises(ValueError, match="canonical launch commands"):
        validate_agentharm_launch_package_for_execution(
            package_dir=package_dir,
            approval=approval,
            dataset_root=dataset_root,
            runner_root=runner_root,
            runtime_attestor=lambda **_kwargs: dict(package["runtime_attestation"]),
        )
