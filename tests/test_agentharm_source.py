from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

import pytest

from invart.core.artifacts import stable_json_hash
from invart.evaluation.real_agent_benchmark import agentharm_source
from invart.evaluation.real_agent_benchmark.agent_runtime_manifest import (
    ClaimKind,
    QWENCLOUD_TOKEN_PLAN,
    RuntimeRequest,
    build_runtime_manifest,
)
from invart.evaluation.real_agent_benchmark.agentharm_pilot import (
    build_agentharm_pilot_request_from_source,
    validate_agentharm_pilot_preflight,
)
from invart.evaluation.real_agent_benchmark.agentharm_source import (
    AGENTHARM_SOURCE_ATTESTATION_SCHEMA_VERSION,
    build_agentharm_validation_case_manifest,
    build_agentharm_validation_source_attestation,
    validate_agentharm_validation_case_manifest,
    write_agentharm_source_package,
)


def _write_dataset(root: Path) -> tuple[Path, dict[str, dict[str, str]]]:
    benchmark = root / "benchmark"
    metadata = root / ".cache" / "huggingface" / "download" / "benchmark"
    benchmark.mkdir(parents=True)
    metadata.mkdir(parents=True)
    fingerprints: dict[str, dict[str, str]] = {}
    for kind in ("harmful", "benign"):
        name = f"{kind}_behaviors_validation.json"
        payload = {
            "canary_guid": "fixture-canary",
            "behaviors": [
                {"id": "2-2", "prompt": f"{kind} two"},
                {"id": "2-1", "prompt": f"{kind} one"},
            ],
        }
        encoded = json.dumps(payload, sort_keys=True).encode("utf-8")
        path = benchmark / name
        path.write_bytes(encoded)
        digest = hashlib.sha256(encoded).hexdigest()
        etag = hashlib.sha1(encoded).hexdigest()
        (metadata / f"{name}.metadata").write_text(
            f"{agentharm_source.AGENTHARM_DATASET_REVISION}\n{etag}\n0\n",
            encoding="utf-8",
        )
        fingerprints[name] = {"sha256": digest, "etag": etag, "count": "2"}
    return root, fingerprints


def _patch_fingerprints(
    monkeypatch: pytest.MonkeyPatch,
    fingerprints: dict[str, dict[str, str]],
) -> None:
    monkeypatch.setattr(agentharm_source, "AGENTHARM_VALIDATION_FILES", fingerprints)
    monkeypatch.setattr(
        agentharm_source,
        "AGENTHARM_VALIDATION_CASE_ID_HASHES",
        {
            "benign": stable_json_hash(["2-1", "2-2"]),
            "harmful": stable_json_hash(["2-1", "2-2"]),
        },
    )


def _write_runner(root: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    file_hashes: dict[str, str] = {}
    for index, relative_path in enumerate(agentharm_source.AGENTHARM_RUNNER_FILES):
        path = root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        encoded = f"fixture runner file {index}\n".encode("utf-8")
        path.write_bytes(encoded)
        file_hashes[relative_path] = hashlib.sha256(encoded).hexdigest()
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    subprocess.run(["git", "-C", str(root), "add", "."], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "-c",
            "user.name=Invart Test",
            "-c",
            "user.email=invart-test@example.invalid",
            "commit",
            "-qm",
            "fixture",
        ],
        check=True,
    )
    revision = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    monkeypatch.setattr(agentharm_source, "AGENTHARM_RUNNER_REVISION", revision)
    monkeypatch.setattr(agentharm_source, "AGENTHARM_RUNNER_FILES", file_hashes)
    return root


def test_source_attestation_binds_revision_fingerprints_and_counts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dataset_root, fingerprints = _write_dataset(tmp_path / "AgentHarm")
    _patch_fingerprints(monkeypatch, fingerprints)
    runner_root = _write_runner(tmp_path / "inspect_evals", monkeypatch)

    attestation = build_agentharm_validation_source_attestation(
        dataset_root,
        runner_root=runner_root,
    )

    assert attestation["schema_version"] == AGENTHARM_SOURCE_ATTESTATION_SCHEMA_VERSION
    assert attestation["status"] == "valid"
    assert attestation["dataset_revision"] == agentharm_source.AGENTHARM_DATASET_REVISION
    assert attestation["case_counts"] == {"benign": 2, "harmful": 2}
    assert [row["role"] for row in attestation["files"]] == ["benign", "harmful"]
    assert attestation["attestation_hash"] == stable_json_hash(
        {key: value for key, value in attestation.items() if key != "attestation_hash"}
    )
    assert str(dataset_root) not in json.dumps(attestation)


def test_source_attestation_rejects_wrong_revision_or_content(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dataset_root, fingerprints = _write_dataset(tmp_path / "AgentHarm")
    _patch_fingerprints(monkeypatch, fingerprints)
    runner_root = _write_runner(tmp_path / "inspect_evals", monkeypatch)
    metadata = (
        dataset_root
        / ".cache"
        / "huggingface"
        / "download"
        / "benchmark"
        / "harmful_behaviors_validation.json.metadata"
    )
    metadata.write_text("wrong-revision\netag\n0\n", encoding="utf-8")
    with pytest.raises(ValueError, match="revision"):
        build_agentharm_validation_source_attestation(
            dataset_root,
            runner_root=runner_root,
        )

    dataset_root, fingerprints = _write_dataset(tmp_path / "second" / "AgentHarm")
    _patch_fingerprints(monkeypatch, fingerprints)
    target = dataset_root / "benchmark" / "harmful_behaviors_validation.json"
    target.write_text(target.read_text(encoding="utf-8") + " ", encoding="utf-8")
    with pytest.raises(ValueError, match="fingerprint"):
        build_agentharm_validation_source_attestation(
            dataset_root,
            runner_root=runner_root,
        )


def test_source_attestation_rejects_dirty_runner_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dataset_root, fingerprints = _write_dataset(tmp_path / "AgentHarm")
    _patch_fingerprints(monkeypatch, fingerprints)
    runner_root = _write_runner(tmp_path / "inspect_evals", monkeypatch)
    runner_file = runner_root / sorted(agentharm_source.AGENTHARM_RUNNER_FILES)[0]
    runner_file.write_text("modified\n", encoding="utf-8")

    with pytest.raises(ValueError, match="dirty"):
        build_agentharm_validation_source_attestation(
            dataset_root,
            runner_root=runner_root,
        )


def test_source_attestation_rejects_untracked_runner_content(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dataset_root, fingerprints = _write_dataset(tmp_path / "AgentHarm")
    _patch_fingerprints(monkeypatch, fingerprints)
    runner_root = _write_runner(tmp_path / "inspect_evals", monkeypatch)
    (runner_root / "untracked_runtime_override.py").write_text("enabled = True\n", encoding="utf-8")

    with pytest.raises(ValueError, match="checkout is dirty"):
        build_agentharm_validation_source_attestation(
            dataset_root,
            runner_root=runner_root,
        )


def test_source_attestation_ignores_ambient_git_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dataset_root, fingerprints = _write_dataset(tmp_path / "AgentHarm")
    _patch_fingerprints(monkeypatch, fingerprints)
    runner_root = _write_runner(tmp_path / "inspect_evals", monkeypatch)
    hostile = _write_runner(tmp_path / "hostile_checkout", monkeypatch)
    expected_revision = subprocess.run(
        ["git", "-C", str(runner_root), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    monkeypatch.setattr(agentharm_source, "AGENTHARM_RUNNER_REVISION", expected_revision)
    monkeypatch.setenv("GIT_DIR", str(hostile / ".git"))

    attestation = build_agentharm_validation_source_attestation(
        dataset_root,
        runner_root=runner_root,
    )

    assert attestation["runner_source"]["revision"] == expected_revision
    assert attestation["runner_source"]["checkout_clean"] is True


def test_case_manifest_is_derived_from_attested_files_and_revalidated(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dataset_root, fingerprints = _write_dataset(tmp_path / "AgentHarm")
    _patch_fingerprints(monkeypatch, fingerprints)
    runner_root = _write_runner(tmp_path / "inspect_evals", monkeypatch)

    manifest = build_agentharm_validation_case_manifest(
        dataset_root,
        runner_root=runner_root,
    )
    validation = validate_agentharm_validation_case_manifest(
        manifest,
        dataset_root=dataset_root,
        runner_root=runner_root,
    )

    assert manifest["harmful_case_ids"] == ["2-1", "2-2"]
    assert manifest["benign_case_ids"] == ["2-1", "2-2"]
    assert manifest["case_counts"] == {"benign": 2, "harmful": 2}
    assert manifest["case_id_hashes"] == {
        "benign": stable_json_hash(["2-1", "2-2"]),
        "harmful": stable_json_hash(["2-1", "2-2"]),
    }
    assert validation["status"] == "valid"
    assert validation["manifest_hash"] == manifest["manifest_hash"]

    tampered = dict(manifest)
    tampered["harmful_case_ids"] = ["fabricated"]
    tampered["manifest_hash"] = stable_json_hash(
        {key: value for key, value in tampered.items() if key != "manifest_hash"}
    )
    with pytest.raises(ValueError, match="case universe"):
        validate_agentharm_validation_case_manifest(
            tampered,
            dataset_root=dataset_root,
            runner_root=runner_root,
        )


def test_case_manifest_rejects_rehashed_top_level_source_substitution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dataset_root, fingerprints = _write_dataset(tmp_path / "AgentHarm")
    _patch_fingerprints(monkeypatch, fingerprints)
    runner_root = _write_runner(tmp_path / "inspect_evals", monkeypatch)
    manifest = build_agentharm_validation_case_manifest(
        dataset_root,
        runner_root=runner_root,
    )
    substituted = dict(manifest)
    substituted["source_attestation_hash"] = "sha256:" + ("0" * 64)
    substituted["manifest_hash"] = stable_json_hash(
        {key: value for key, value in substituted.items() if key != "manifest_hash"}
    )

    with pytest.raises(ValueError, match="source attestation binding"):
        validate_agentharm_validation_case_manifest(
            substituted,
            dataset_root=dataset_root,
            runner_root=runner_root,
        )


def test_source_package_writer_is_owner_only_and_refuses_overwrite(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dataset_root, fingerprints = _write_dataset(tmp_path / "AgentHarm")
    _patch_fingerprints(monkeypatch, fingerprints)
    runner_root = _write_runner(tmp_path / "inspect_evals", monkeypatch)

    package = write_agentharm_source_package(
        tmp_path / "out",
        dataset_root=dataset_root,
        runner_root=runner_root,
    )

    assert set(package) == {"source_attestation", "case_manifest"}
    for path in package.values():
        assert path.stat().st_mode & 0o077 == 0
    with pytest.raises(FileExistsError):
        write_agentharm_source_package(
            tmp_path / "out",
            dataset_root=dataset_root,
            runner_root=runner_root,
        )


def test_pilot_request_from_source_carries_attested_case_universe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dataset_root, fingerprints = _write_dataset(tmp_path / "AgentHarm")
    _patch_fingerprints(monkeypatch, fingerprints)
    runner_root = _write_runner(tmp_path / "inspect_evals", monkeypatch)
    runtime_manifest = build_runtime_manifest(
        request=RuntimeRequest(
            requested_provider=QWENCLOUD_TOKEN_PLAN.profile_id,
            requested_model="deepseek-v4-pro",
            agent_product="inspect-evals-agentharm",
            low_level_runtime="inspect-ai",
            execution_contract="completion_backend",
            evidence_kind=ClaimKind.COMPLETION_BACKEND,
        ),
        provider_profile=QWENCLOUD_TOKEN_PLAN,
        profile_state_hash="sha256:agentharm-source-test",
    )

    request = build_agentharm_pilot_request_from_source(
        runtime_manifest=runtime_manifest,
        dataset_root=dataset_root,
        runner_root=runner_root,
        split="validation",
        primary_model="deepseek-v4-pro",
        refusal_judge="deepseek-v4-pro",
        semantic_judge="deepseek-v4-pro",
        harmful_case_ids=("2-1",),
        benign_case_ids=("2-2",),
        variants=("V0",),
        epochs=1,
        maximum_calls_per_sample=2,
        maximum_tokens_per_call=256,
        maximum_usd=0.25,
    )

    assert request["case_manifest"]["case_counts"] == {"benign": 2, "harmful": 2}
    assert request["source_attestation_hash"] == request["case_manifest"]["source_attestation_hash"]
    assert request["request_hash"] == stable_json_hash(
        {key: value for key, value in request.items() if key != "request_hash"}
    )


def test_live_preflight_rejects_source_changed_after_request_build(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dataset_root, fingerprints = _write_dataset(tmp_path / "AgentHarm")
    _patch_fingerprints(monkeypatch, fingerprints)
    runner_root = _write_runner(tmp_path / "inspect_evals", monkeypatch)
    runtime_manifest = build_runtime_manifest(
        request=RuntimeRequest(
            requested_provider=QWENCLOUD_TOKEN_PLAN.profile_id,
            requested_model="deepseek-v4-pro",
            agent_product="inspect-evals-agentharm",
            low_level_runtime="inspect-ai",
            execution_contract="completion_backend",
            evidence_kind=ClaimKind.COMPLETION_BACKEND,
        ),
        provider_profile=QWENCLOUD_TOKEN_PLAN,
        profile_state_hash="sha256:agentharm-source-test",
    )
    request = build_agentharm_pilot_request_from_source(
        runtime_manifest=runtime_manifest,
        dataset_root=dataset_root,
        runner_root=runner_root,
        split="validation",
        primary_model="deepseek-v4-pro",
        refusal_judge="deepseek-v4-pro",
        semantic_judge="deepseek-v4-pro",
        harmful_case_ids=("2-1",),
        benign_case_ids=("2-2",),
        variants=("V0",),
        epochs=1,
        maximum_calls_per_sample=2,
        maximum_tokens_per_call=256,
        maximum_usd=0.25,
    )
    target = dataset_root / "benchmark" / "harmful_behaviors_validation.json"
    target.write_text(target.read_text(encoding="utf-8") + " ", encoding="utf-8")

    preflight = validate_agentharm_pilot_preflight(
        request,
        runtime_manifest=runtime_manifest,
        dataset_root=dataset_root,
        runner_root=runner_root,
    )

    assert preflight["status"] == "preflight_invalid"
    assert "live_source_validation_failed" in preflight["reasons"]
