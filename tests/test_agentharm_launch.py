from __future__ import annotations

import json
import os
import shutil
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from invart.core.artifacts import stable_json_hash
from invart.evaluation.real_agent_benchmark import agentharm_launch
from invart.evaluation.real_agent_benchmark.agent_runtime_manifest import (
    runtime_manifest_from_dict,
)
from invart.evaluation.real_agent_benchmark.agentharm_launch import (
    attest_agentharm_inspect_runtime,
    prepare_agentharm_launch_package,
)
from invart.evaluation.real_agent_benchmark.agentharm_launch_cli import main as launch_main
from invart.evaluation.real_agent_benchmark.agentharm_pilot import (
    build_agentharm_pilot_request_from_source,
    load_agentharm_pilot_request,
    write_agentharm_pilot_request,
)
from invart.evaluation.real_agent_benchmark.provider_run_control import (
    create_provider_approval_packet,
)
from tests.test_agentharm_pilot import _manifest
from tests.test_agentharm_source import (
    _patch_fingerprints,
    _write_dataset,
    _write_runner,
)


def _write_canonical_runtime(runner_root: Path) -> tuple[Path, Path]:
    executable_dir = "Scripts" if os.name == "nt" else "bin"
    inspect_name = "inspect.exe" if os.name == "nt" else "inspect"
    python_name = "python.exe" if os.name == "nt" else "python"
    runtime_dir = runner_root / ".venv" / executable_dir
    runtime_dir.mkdir(parents=True)
    inspect_executable = runtime_dir / inspect_name
    python_executable = runtime_dir / python_name
    python_executable.write_bytes(b"synthetic canonical python\n")
    inspect_executable.write_text(
        (
            "synthetic canonical inspect\n"
            if os.name == "nt"
            else f"#!{python_executable}\nsynthetic canonical inspect\n"
        ),
        encoding="utf-8",
    )
    inspect_executable.chmod(0o700)
    python_executable.chmod(0o700)
    return inspect_executable, python_executable


def _request(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    variants: tuple[str, ...] = ("V0",),
):
    dataset_root, fingerprints = _write_dataset(tmp_path / "AgentHarm")
    _patch_fingerprints(monkeypatch, fingerprints)
    runner_root = _write_runner(tmp_path / "inspect_evals", monkeypatch)
    _write_canonical_runtime(runner_root)
    (runner_root / ".git" / "info" / "exclude").write_text(
        ".venv/\n",
        encoding="utf-8",
    )
    manifest = _manifest()
    request = build_agentharm_pilot_request_from_source(
        runtime_manifest=manifest,
        dataset_root=dataset_root,
        runner_root=runner_root,
        split="validation",
        primary_model="deepseek-v4-pro",
        refusal_judge="deepseek-v4-pro",
        semantic_judge="deepseek-v4-pro",
        harmful_case_ids=("2-1",),
        benign_case_ids=("2-2",),
        variants=variants,
        epochs=1,
        maximum_calls_per_sample=4,
        maximum_tokens_per_call=512,
        maximum_usd=1.0,
        timeout_seconds=90,
    )
    monkeypatch.setattr(
        agentharm_launch,
        "attest_agentharm_inspect_runtime",
        lambda **_kwargs: {
            "schema_version": "invart.agentharm_inspect_runtime_attestation.v0.1",
            "status": "valid",
            "inspect_ai_revision": "fixture",
            "inspect_ai_version": "fixture",
            "attestation_hash": "sha256:fixture",
        },
    )
    return dataset_root, runner_root, manifest, request


def test_launch_package_stages_exact_source_and_requires_approval(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DASHSCOPE_TP_API_KEY", "must-not-leak")
    monkeypatch.setenv("PYTHONPATH", "/tmp/must-not-load")
    dataset_root, runner_root, manifest, request = _request(tmp_path, monkeypatch)
    output = tmp_path / "launch"
    gateway_base_url = "http://127.0.0.1:43123/v1"

    package = prepare_agentharm_launch_package(
        output,
        request=request,
        runtime_manifest=manifest,
        dataset_root=dataset_root,
        runner_root=runner_root,
        gateway_base_url=gateway_base_url,
    )

    assert package["status"] == "approval_required"
    assert package["ready_to_execute"] is False
    assert package["provider_execution_performed"] is False
    assert package["observed_command_count"] == 2
    assert [row["role"] for row in package["commands"]] == ["benign", "harmful"]
    assert not list(dataset_root.rglob("*.jsonl"))
    for staged in package["staged_dataset_files"]:
        staged_path = output / staged["relative_path"]
        assert staged_path.is_file()
        assert staged_path.read_bytes() == (
            dataset_root / Path(staged["relative_path"]).relative_to(
                "runtime-home/.cache/inspect_evals/agentharm_dataset/AgentHarm"
            )
        ).read_bytes()
    serialized = (output / "launch_plan.json").read_text(encoding="utf-8")
    assert "must-not-leak" not in serialized
    assert "invart-local-loopback-non-secret" in serialized
    for row in package["commands"]:
        spec = row["command_spec"]
        environment = spec["environment_overrides"]
        assert "--model-base-url" in spec["command"]
        assert spec["environment_mode"] == "replace"
        assert "DASHSCOPE_TP_API_KEY" in spec["forbidden_environment_names"]
        assert "DASHSCOPE_TP_API_KEY" not in environment
        assert "PYTHONPATH" not in environment
        assert environment["OPENAI_BASE_URL"] == gateway_base_url
        assert environment["OPENAI_API_KEY"] == "invart-local-loopback-non-secret"
        assert environment["VIRTUAL_ENV"] == str(runner_root / ".venv")
        assert environment["PATH"].split(os.pathsep)[0] == str(
            runner_root / ".venv" / ("Scripts" if os.name == "nt" else "bin")
        )
        assert environment["XDG_CACHE_HOME"].startswith(str(output))
        assert "source_checked_at" not in spec
    assert (output / "launch_plan.json").stat().st_mode & 0o077 == 0
    assert all(
        path.stat().st_mode & 0o077 == 0
        for path in [output, *output.rglob("*")]
    )


def test_launch_package_requires_executor_with_exact_active_approval(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dataset_root, runner_root, manifest, request = _request(tmp_path, monkeypatch)
    now = datetime.now(timezone.utc)
    approval = create_provider_approval_packet(
        approval_id="agentharm-launch-test",
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

    package = prepare_agentharm_launch_package(
        tmp_path / "approved-launch",
        request=request,
        runtime_manifest=manifest,
        dataset_root=dataset_root,
        runner_root=runner_root,
        gateway_base_url="http://127.0.0.1:43123/v1",
        approval=approval,
    )

    assert package["status"] == "executor_required"
    assert package["ready_to_execute"] is False
    assert package["preflight"]["status"] == "approved_inputs_validated"
    assert package["preflight"]["ready_to_execute"] is False
    assert package["preflight"]["approved_inputs_validated"] is True
    assert package["approval_hash"] == approval.approval_hash


def test_launch_package_blocks_nonbaseline_variant_before_commands(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dataset_root, runner_root, manifest, request = _request(
        tmp_path,
        monkeypatch,
        variants=("V5",),
    )

    package = prepare_agentharm_launch_package(
        tmp_path / "blocked-launch",
        request=request,
        runtime_manifest=manifest,
        dataset_root=dataset_root,
        runner_root=runner_root,
        gateway_base_url="http://127.0.0.1:43123/v1",
    )

    assert package["status"] == "blocked_unsupported_variant"
    assert package["commands"] == []
    assert package["staged_dataset_files"] == []


@pytest.mark.parametrize(
    ("gateway_base_url", "expected_status"),
    [
        ("https://api.example.invalid/v1", "blocked_gateway_configuration"),
        ("http://localhost:43123/v1", "blocked_gateway_configuration"),
    ],
)
def test_launch_package_blocks_invalid_gateway_without_materializing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    gateway_base_url: str,
    expected_status: str,
) -> None:
    dataset_root, runner_root, manifest, request = _request(tmp_path, monkeypatch)

    package = prepare_agentharm_launch_package(
        tmp_path / "blocked-gateway",
        request=request,
        runtime_manifest=manifest,
        dataset_root=dataset_root,
        runner_root=runner_root,
        gateway_base_url=gateway_base_url,
    )

    assert package["status"] == expected_status
    assert package["commands"] == []
    assert package["staged_dataset_files"] == []


def test_launch_package_blocks_failed_runtime_attestation_without_materializing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dataset_root, runner_root, manifest, request = _request(tmp_path, monkeypatch)

    def fail_attestation(**_kwargs: object) -> dict[str, object]:
        raise RuntimeError("synthetic attestation failure")

    monkeypatch.setattr(
        agentharm_launch,
        "attest_agentharm_inspect_runtime",
        fail_attestation,
    )

    package = prepare_agentharm_launch_package(
        tmp_path / "blocked-attestation",
        request=request,
        runtime_manifest=manifest,
        dataset_root=dataset_root,
        runner_root=runner_root,
        gateway_base_url="http://127.0.0.1:43123/v1",
    )

    assert package["status"] == "blocked_runtime_attestation"
    assert package["commands"] == []
    assert package["staged_dataset_files"] == []


def _runtime_metadata(runner_root: Path) -> dict[str, object]:
    agentharm_module = runner_root / "src" / "inspect_evals" / "agentharm" / "__init__.py"
    inspect_module = runner_root / "synthetic-site" / "inspect_ai" / "__init__.py"
    openai_module = runner_root / "synthetic-site" / "openai" / "__init__.py"
    for module in (agentharm_module, inspect_module, openai_module):
        module.parent.mkdir(parents=True, exist_ok=True)
        module.write_text("# synthetic runtime module\n", encoding="utf-8")
    return {
        "direct_url": {
            "vcs_info": {"commit_id": agentharm_launch.AGENTHARM_INSPECT_AI_REVISION}
        },
        "inspect_ai": {
            "version": "0.3.test",
            "distribution_path": str(inspect_module.parent),
            "module_file": str(inspect_module),
        },
        "inspect_evals_agentharm": {
            "version": "0.3.test",
            "distribution_path": str(agentharm_module.parent),
            "module_file": str(agentharm_module),
        },
        "openai": {
            "version": "1.test",
            "distribution_path": str(openai_module.parent),
            "module_file": str(openai_module),
        },
    }


def test_runtime_attestation_binds_canonical_runtime_and_component_hashes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner_root = tmp_path / "inspect_evals"
    inspect_executable, python_executable = _write_canonical_runtime(runner_root)
    metadata = _runtime_metadata(runner_root)
    monkeypatch.setattr(
        agentharm_launch.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=json.dumps(metadata),
            stderr="",
        ),
    )

    attestation = attest_agentharm_inspect_runtime(runner_root=runner_root)

    assert attestation["status"] == "valid"
    assert attestation["inspect_executable"] == str(inspect_executable)
    assert attestation["python_executable"] == str(python_executable)
    assert all(
        component["module_file_sha256"].startswith("sha256:")
        for component in attestation["components"].values()
    )


@pytest.mark.parametrize(
    ("returncode", "stdout", "match"),
    [
        (1, "", "metadata probe failed"),
        (0, "{", "metadata is invalid"),
    ],
)
def test_runtime_attestation_rejects_failed_or_malformed_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    returncode: int,
    stdout: str,
    match: str,
) -> None:
    runner_root = tmp_path / "inspect_evals"
    _write_canonical_runtime(runner_root)
    monkeypatch.setattr(
        agentharm_launch.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            args=[],
            returncode=returncode,
            stdout=stdout,
            stderr="synthetic failure",
        ),
    )

    with pytest.raises((RuntimeError, ValueError), match=match):
        attest_agentharm_inspect_runtime(runner_root=runner_root)


def test_runtime_attestation_rejects_wrong_revision_and_noncanonical_executable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner_root = tmp_path / "inspect_evals"
    _write_canonical_runtime(runner_root)
    metadata = _runtime_metadata(runner_root)
    metadata["direct_url"] = {"vcs_info": {"commit_id": "wrong-revision"}}
    monkeypatch.setattr(
        agentharm_launch.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=json.dumps(metadata),
            stderr="",
        ),
    )

    with pytest.raises(ValueError, match="revision"):
        attest_agentharm_inspect_runtime(runner_root=runner_root)

    noncanonical = tmp_path / "inspect"
    noncanonical.write_text("# synthetic noncanonical executable\n", encoding="utf-8")
    noncanonical.chmod(0o700)
    with pytest.raises(ValueError, match="canonical runner executable"):
        attest_agentharm_inspect_runtime(
            runner_root=runner_root,
            inspect_executable=noncanonical,
        )


def test_embedded_runtime_manifest_round_trips_and_tampering_fails() -> None:
    manifest = _manifest()
    payload = manifest.to_dict()

    assert runtime_manifest_from_dict(payload) == manifest
    payload["runtime_version"] = "tampered"

    with pytest.raises(ValueError, match="inconsistent"):
        runtime_manifest_from_dict(payload)


def test_request_binds_runtime_artifact_and_execution_limits(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dataset_root, runner_root, manifest, request = _request(tmp_path, monkeypatch)

    assert request["runtime_manifest"] == manifest.to_dict()
    assert request["execution_limits"] == {
        "timeout_seconds": 90,
        "max_connections": 1,
        "max_retries": 0,
    }
    assert request["approval_scope"]["timeout_seconds"] == 90
    request["execution_limits"]["timeout_seconds"] = 91
    request["request_hash"] = stable_json_hash(
        {key: value for key, value in request.items() if key != "request_hash"}
    )

    package = prepare_agentharm_launch_package(
        tmp_path / "tampered-launch",
        request=request,
        runtime_manifest=manifest,
        dataset_root=dataset_root,
        runner_root=runner_root,
        gateway_base_url="http://127.0.0.1:43123/v1",
    )
    assert package["status"] == "preflight_invalid"
    assert "request_approval_scope_mismatch" in package["reasons"]
    assert package["commands"] == []


def test_request_loader_rejects_unsafe_or_invalid_requests(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _dataset_root, _runner_root, _manifest_value, request = _request(
        tmp_path,
        monkeypatch,
    )

    readable = write_agentharm_pilot_request(tmp_path / "readable.json", request)
    readable.chmod(0o640)
    with pytest.raises(ValueError, match="owner-only"):
        load_agentharm_pilot_request(readable)

    invalid_json = tmp_path / "invalid.json"
    invalid_json.write_text("{", encoding="utf-8")
    invalid_json.chmod(0o600)
    with pytest.raises(ValueError, match="invalid JSON"):
        load_agentharm_pilot_request(invalid_json)

    tampered = write_agentharm_pilot_request(tmp_path / "tampered.json", request)
    tampered_payload = json.loads(tampered.read_text(encoding="utf-8"))
    tampered_payload["purpose"] = "tampered"
    tampered.write_text(json.dumps(tampered_payload), encoding="utf-8")
    with pytest.raises(ValueError, match="hash mismatch"):
        load_agentharm_pilot_request(tampered)

    unsupported_payload = dict(request)
    unsupported_payload["schema_version"] = "invart.agentharm_pilot_request.v999"
    unsupported_payload["request_hash"] = stable_json_hash(
        {
            key: value
            for key, value in unsupported_payload.items()
            if key != "request_hash"
        }
    )
    unsupported = write_agentharm_pilot_request(
        tmp_path / "unsupported.json",
        unsupported_payload,
    )
    with pytest.raises(ValueError, match="schema is unsupported"):
        load_agentharm_pilot_request(unsupported)

    symlink = tmp_path / "request-link.json"
    try:
        symlink.symlink_to(unsupported)
    except (NotImplementedError, OSError):
        pytest.skip("symlinks are not supported on this platform")
    with pytest.raises(ValueError):
        load_agentharm_pilot_request(symlink)


def test_launch_package_hashes_are_repeatable_at_same_output_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dataset_root, runner_root, manifest, request = _request(tmp_path, monkeypatch)
    output = tmp_path / "repeatable-launch"

    first = prepare_agentharm_launch_package(
        output,
        request=request,
        runtime_manifest=manifest,
        dataset_root=dataset_root,
        runner_root=runner_root,
        gateway_base_url="http://127.0.0.1:43123/v1",
    )
    shutil.rmtree(output)
    second = prepare_agentharm_launch_package(
        output,
        request=request,
        runtime_manifest=manifest,
        dataset_root=dataset_root,
        runner_root=runner_root,
        gateway_base_url="http://127.0.0.1:43123/v1",
    )

    assert [row["command_hash"] for row in first["commands"]] == [
        row["command_hash"] for row in second["commands"]
    ]
    assert first["package_hash"] == second["package_hash"]


def test_launch_cli_rebuilds_embedded_manifest_without_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    dataset_root, runner_root, _manifest_value, request = _request(tmp_path, monkeypatch)
    request_path = write_agentharm_pilot_request(tmp_path / "request.json", request)

    result = launch_main(
        [
            "--request",
            str(request_path),
            "--dataset-root",
            str(dataset_root),
            "--runner-root",
            str(runner_root),
            "--output-dir",
            str(tmp_path / "cli-launch"),
        ]
    )

    summary = json.loads(capsys.readouterr().out)
    assert result == 0
    assert summary["status"] == "approval_required"
    assert summary["provider_execution_performed"] is False
    assert summary["command_count"] == 2
