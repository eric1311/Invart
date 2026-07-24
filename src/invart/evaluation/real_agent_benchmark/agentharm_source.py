from __future__ import annotations

import argparse
import json
import os
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Mapping

from invart.core.artifacts import sha256_file, stable_json_dumps, stable_json_hash

from .benchmark_adapters.agentharm import (
    AGENTHARM_DATASET_REVISION,
    AGENTHARM_DATASET_URL,
    AGENTHARM_INSPECT_AI_REVISION,
    AGENTHARM_RUNNER_REVISION,
)


AGENTHARM_SOURCE_ATTESTATION_SCHEMA_VERSION = "invart.agentharm_source_attestation.v0.2"
AGENTHARM_CASE_MANIFEST_SCHEMA_VERSION = "invart.agentharm_case_manifest.v0.2"
AGENTHARM_LICENSE = "MIT-with-safety-and-security-use-clause"
AGENTHARM_LICENSE_CONTRACT_SHA256 = (
    "04bc888d42b38203bff65c3fedda56fe623d2176422a12fa96d302ab57b1d82b"
)
AGENTHARM_VALIDATION_FILES: Mapping[str, Mapping[str, Any]] = {
    "benign_behaviors_validation.json": {
        "sha256": "b74ffb781ce54182775a8b2843ea341ab2fb4cfea5743bfa89a368e52a76c27a",
        "etag": "df3b27f77dcde3aad2b9a8c6f5687f0c5fd90c2f",
        "count": 32,
    },
    "harmful_behaviors_validation.json": {
        "sha256": "40cd099915258b41142acfc88a9f2b4e15cd631c5490ad02a0dce0cf2b9c175e",
        "etag": "82da7dae24aaa3cb707dc78566d020d239a01003",
        "count": 32,
    },
}
AGENTHARM_VALIDATION_CASE_ID_HASHES: Mapping[str, str] = {
    "benign": "sha256:74cbfc47d9dc344490e9717482c558f9de1e3e99e8955f6da9e77da2f69de2f4",
    "harmful": "sha256:74cbfc47d9dc344490e9717482c558f9de1e3e99e8955f6da9e77da2f69de2f4",
}
AGENTHARM_RUNNER_URL = "https://github.com/UKGovernmentBEIS/inspect_evals"
AGENTHARM_RUNNER_FILES: Mapping[str, str] = {
    "src/inspect_evals/agentharm/LICENSE": (
        "04bc888d42b38203bff65c3fedda56fe623d2176422a12fa96d302ab57b1d82b"
    ),
    "src/inspect_evals/agentharm/agentharm.py": (
        "8b6de106e783f1d761cd015bd42f8346720c3c5ce60a7f32febe03c9ad0ee158"
    ),
    "src/inspect_evals/agentharm/scorer.py": (
        "a49f279ae724a7cf7643ff859a70f44e708d1b89d79d810aa5c0b3e74d5f7847"
    ),
    "src/inspect_evals/agentharm/utils.py": (
        "5453e15000831066968f8bbb83abcc7f242c5b32172c03a388d323205ab5cbc2"
    ),
}


def build_agentharm_validation_source_attestation(
    dataset_root: Path,
    *,
    runner_root: Path,
) -> dict[str, Any]:
    """Attest the exact pinned AgentHarm validation files without embedding local paths."""

    root = _regular_directory(dataset_root, field_name="AgentHarm dataset root")
    file_rows: list[dict[str, Any]] = []
    case_counts: dict[str, int] = {}
    canary_hashes: set[str] = set()
    for filename, expected in sorted(AGENTHARM_VALIDATION_FILES.items()):
        role = filename.split("_", 1)[0]
        source_path = _regular_file(
            root / "benchmark" / filename,
            field_name=f"AgentHarm {role} validation file",
        )
        observed_sha256 = sha256_file(source_path)
        expected_sha256 = str(expected.get("sha256") or "")
        if observed_sha256 != expected_sha256:
            raise ValueError(f"AgentHarm {role} validation fingerprint mismatch")
        metadata_path = _regular_file(
            root
            / ".cache"
            / "huggingface"
            / "download"
            / "benchmark"
            / f"{filename}.metadata",
            field_name=f"AgentHarm {role} Hugging Face metadata",
        )
        metadata_lines = metadata_path.read_text(encoding="utf-8").splitlines()
        if len(metadata_lines) < 2 or metadata_lines[0].strip() != AGENTHARM_DATASET_REVISION:
            raise ValueError(f"AgentHarm {role} metadata revision mismatch")
        expected_etag = str(expected.get("etag") or "")
        if metadata_lines[1].strip() != expected_etag:
            raise ValueError(f"AgentHarm {role} metadata etag mismatch")
        behaviors, canary_hash = _load_behavior_rows(source_path, role=role)
        expected_count = int(expected.get("count") or 0)
        if len(behaviors) != expected_count:
            raise ValueError(f"AgentHarm {role} validation case count mismatch")
        canary_hashes.add(canary_hash)
        case_counts[role] = len(behaviors)
        file_rows.append(
            {
                "role": role,
                "relative_path": f"benchmark/{filename}",
                "sha256": f"sha256:{observed_sha256}",
                "huggingface_revision": metadata_lines[0].strip(),
                "huggingface_etag": metadata_lines[1].strip(),
                "case_count": len(behaviors),
            }
        )
    if len(canary_hashes) != 1:
        raise ValueError("AgentHarm validation files have inconsistent canary GUIDs")
    runner_source = _build_runner_attestation(runner_root)
    payload = {
        "schema_version": AGENTHARM_SOURCE_ATTESTATION_SCHEMA_VERSION,
        "status": "valid",
        "source_url": AGENTHARM_DATASET_URL,
        "dataset_revision": AGENTHARM_DATASET_REVISION,
        "split": "validation",
        "license": AGENTHARM_LICENSE,
        "license_contract_sha256": f"sha256:{AGENTHARM_LICENSE_CONTRACT_SHA256}",
        "runner_revision": AGENTHARM_RUNNER_REVISION,
        "inspect_ai_revision": AGENTHARM_INSPECT_AI_REVISION,
        "runner_source": runner_source,
        "files": file_rows,
        "case_counts": dict(sorted(case_counts.items())),
        "canary_guid_hash": next(iter(canary_hashes)),
        "claim_boundary": (
            "This attests exact local bytes for the pinned public validation JSON files and their "
            "Hugging Face download metadata. It is source provenance, not execution or score evidence."
        ),
    }
    payload["attestation_hash"] = stable_json_hash(payload)
    return payload


def build_agentharm_validation_case_manifest(
    dataset_root: Path,
    *,
    runner_root: Path,
) -> dict[str, Any]:
    """Derive the complete validation case IDs from the attested source bytes."""

    root = _regular_directory(dataset_root, field_name="AgentHarm dataset root")
    attestation = build_agentharm_validation_source_attestation(
        root,
        runner_root=runner_root,
    )
    role_ids: dict[str, list[str]] = {}
    for filename in sorted(AGENTHARM_VALIDATION_FILES):
        role = filename.split("_", 1)[0]
        behaviors, _ = _load_behavior_rows(
            _regular_file(
                root / "benchmark" / filename,
                field_name=f"AgentHarm {role} validation file",
            ),
            role=role,
        )
        case_ids = sorted(str(row["id"]).strip() for row in behaviors)
        if not case_ids or len(case_ids) != len(set(case_ids)):
            raise ValueError(f"AgentHarm {role} validation case IDs must be unique and nonempty")
        role_ids[role] = case_ids
    payload = {
        "schema_version": AGENTHARM_CASE_MANIFEST_SCHEMA_VERSION,
        "dataset_revision": AGENTHARM_DATASET_REVISION,
        "split": "validation",
        "harmful_case_ids": role_ids["harmful"],
        "benign_case_ids": role_ids["benign"],
        "case_counts": {
            "benign": len(role_ids["benign"]),
            "harmful": len(role_ids["harmful"]),
        },
        "case_id_hashes": {
            role: stable_json_hash(case_ids)
            for role, case_ids in sorted(role_ids.items())
        },
        "source_attestation": attestation,
        "source_attestation_hash": attestation["attestation_hash"],
        "claim_boundary": (
            "Case membership is derived from the complete attested validation files. This manifest "
            "does not select a pilot subset or authorize provider execution."
        ),
    }
    payload["manifest_hash"] = stable_json_hash(payload)
    validate_agentharm_case_manifest_contract(payload)
    return payload


def validate_agentharm_source_attestation_contract(
    attestation: Mapping[str, Any],
) -> dict[str, Any]:
    materialized = _verified_mapping_hash(
        attestation,
        hash_field="attestation_hash",
        field_name="AgentHarm source attestation",
    )
    expected_scalars = {
        "schema_version": AGENTHARM_SOURCE_ATTESTATION_SCHEMA_VERSION,
        "status": "valid",
        "source_url": AGENTHARM_DATASET_URL,
        "dataset_revision": AGENTHARM_DATASET_REVISION,
        "split": "validation",
        "license": AGENTHARM_LICENSE,
        "license_contract_sha256": f"sha256:{AGENTHARM_LICENSE_CONTRACT_SHA256}",
        "runner_revision": AGENTHARM_RUNNER_REVISION,
        "inspect_ai_revision": AGENTHARM_INSPECT_AI_REVISION,
    }
    if any(materialized.get(key) != value for key, value in expected_scalars.items()):
        raise ValueError("AgentHarm source attestation freeze mismatch")
    expected_files: list[dict[str, Any]] = []
    expected_counts: dict[str, int] = {}
    for filename, expected in sorted(AGENTHARM_VALIDATION_FILES.items()):
        role = filename.split("_", 1)[0]
        count = int(expected["count"])
        expected_counts[role] = count
        expected_files.append(
            {
                "role": role,
                "relative_path": f"benchmark/{filename}",
                "sha256": f"sha256:{expected['sha256']}",
                "huggingface_revision": AGENTHARM_DATASET_REVISION,
                "huggingface_etag": expected["etag"],
                "case_count": count,
            }
        )
    if materialized.get("files") != expected_files or materialized.get("case_counts") != dict(
        sorted(expected_counts.items())
    ):
        raise ValueError("AgentHarm source attestation file contract mismatch")
    expected_runner_files = [
        {
            "relative_path": relative_path,
            "sha256": f"sha256:{digest}",
        }
        for relative_path, digest in sorted(AGENTHARM_RUNNER_FILES.items())
    ]
    if materialized.get("runner_source") != {
        "source_url": AGENTHARM_RUNNER_URL,
        "revision": AGENTHARM_RUNNER_REVISION,
        "checkout_clean": True,
        "files": expected_runner_files,
    }:
        raise ValueError("AgentHarm runner source attestation mismatch")
    if not str(materialized.get("canary_guid_hash") or "").startswith("sha256:"):
        raise ValueError("AgentHarm source attestation canary hash is missing")
    return materialized


def validate_agentharm_case_manifest_contract(
    manifest: Mapping[str, Any],
) -> dict[str, Any]:
    materialized = _verified_mapping_hash(
        manifest,
        hash_field="manifest_hash",
        field_name="AgentHarm case manifest",
    )
    if (
        materialized.get("schema_version") != AGENTHARM_CASE_MANIFEST_SCHEMA_VERSION
        or materialized.get("dataset_revision") != AGENTHARM_DATASET_REVISION
        or materialized.get("split") != "validation"
    ):
        raise ValueError("AgentHarm case manifest freeze mismatch")
    role_ids: dict[str, list[str]] = {}
    for role in ("benign", "harmful"):
        values = materialized.get(f"{role}_case_ids")
        if not isinstance(values, list):
            raise ValueError("AgentHarm case manifest IDs must be lists")
        normalized = sorted({str(value).strip() for value in values if str(value).strip()})
        if values != normalized or len(values) != len(normalized):
            raise ValueError("AgentHarm case manifest IDs must be sorted, unique, and nonempty")
        role_ids[role] = normalized
    expected_counts = {role: len(values) for role, values in sorted(role_ids.items())}
    observed_hashes = {
        role: stable_json_hash(values)
        for role, values in sorted(role_ids.items())
    }
    if (
        materialized.get("case_counts") != expected_counts
        or materialized.get("case_id_hashes") != observed_hashes
        or observed_hashes != dict(AGENTHARM_VALIDATION_CASE_ID_HASHES)
    ):
        raise ValueError("AgentHarm case manifest case universe mismatch")
    source = materialized.get("source_attestation")
    if not isinstance(source, Mapping):
        raise ValueError("AgentHarm case manifest source attestation is missing")
    validated_source = validate_agentharm_source_attestation_contract(source)
    if materialized.get("source_attestation_hash") != validated_source["attestation_hash"]:
        raise ValueError("AgentHarm case manifest source attestation binding mismatch")
    return materialized


def validate_agentharm_validation_case_manifest(
    manifest: Mapping[str, Any],
    *,
    dataset_root: Path,
    runner_root: Path,
) -> dict[str, Any]:
    materialized = validate_agentharm_case_manifest_contract(manifest)
    observed_hash = materialized["manifest_hash"]
    expected = build_agentharm_validation_case_manifest(
        dataset_root,
        runner_root=runner_root,
    )
    if materialized != expected:
        raise ValueError("AgentHarm case manifest does not match the attested dataset")
    return {
        "schema_version": "invart.agentharm_case_manifest_validation.v0.1",
        "status": "valid",
        "manifest_hash": observed_hash,
        "source_attestation_hash": expected["source_attestation_hash"],
        "case_counts": expected["case_counts"],
    }


def _verified_mapping_hash(
    payload: Mapping[str, Any],
    *,
    hash_field: str,
    field_name: str,
) -> dict[str, Any]:
    materialized = dict(payload)
    observed_hash = str(materialized.get(hash_field) or "")
    expected_hash = stable_json_hash(
        {key: value for key, value in materialized.items() if key != hash_field}
    )
    if observed_hash != expected_hash:
        raise ValueError(f"{field_name} hash mismatch")
    return materialized


def write_agentharm_source_package(
    output_dir: Path,
    *,
    dataset_root: Path,
    runner_root: Path,
) -> dict[str, Path]:
    root = _path_without_symlink_ancestors(
        output_dir,
        field_name="AgentHarm source package directory",
    )
    if root.exists():
        raise FileExistsError(root)
    root.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    manifest = build_agentharm_validation_case_manifest(
        dataset_root,
        runner_root=runner_root,
    )
    attestation = manifest["source_attestation"]
    temporary = Path(
        tempfile.mkdtemp(
            prefix=f".{root.name}.",
            dir=root.parent,
        )
    )
    temporary.chmod(0o700)
    try:
        _write_owner_only_json(
            temporary / "agentharm_source_attestation.json",
            attestation,
        )
        _write_owner_only_json(
            temporary / "agentharm_case_manifest.json",
            manifest,
        )
        temporary.rename(root)
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return {
        "source_attestation": root / "agentharm_source_attestation.json",
        "case_manifest": root / "agentharm_case_manifest.json",
    }


def _load_behavior_rows(path: Path, *, role: str) -> tuple[list[Mapping[str, Any]], str]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"AgentHarm {role} validation file is invalid JSON") from exc
    if not isinstance(payload, Mapping) or not isinstance(payload.get("behaviors"), list):
        raise ValueError(f"AgentHarm {role} validation file has invalid structure")
    rows = payload["behaviors"]
    if any(not isinstance(row, Mapping) or not str(row.get("id") or "").strip() for row in rows):
        raise ValueError(f"AgentHarm {role} validation behavior has an invalid ID")
    canary = str(payload.get("canary_guid") or "").strip()
    if not canary:
        raise ValueError(f"AgentHarm {role} validation canary GUID is missing")
    return list(rows), stable_json_hash({"canary_guid": canary})


def _build_runner_attestation(runner_root: Path) -> dict[str, Any]:
    root = _regular_directory(runner_root, field_name="AgentHarm runner root")
    checkout_root = Path(_git_output(root, "rev-parse", "--show-toplevel")).resolve(strict=True)
    if checkout_root != root.resolve(strict=True):
        raise ValueError("AgentHarm runner root does not match the Git checkout root")
    revision = _git_output(root, "rev-parse", "HEAD")
    if revision != AGENTHARM_RUNNER_REVISION:
        raise ValueError("AgentHarm runner revision mismatch")
    dirty = _git_output(root, "status", "--porcelain=v1")
    if dirty:
        raise ValueError("AgentHarm runner checkout is dirty")
    files: list[dict[str, str]] = []
    for relative_path, expected_hash in sorted(AGENTHARM_RUNNER_FILES.items()):
        path = _regular_file(
            root / relative_path,
            field_name=f"AgentHarm runner file {relative_path}",
        )
        if sha256_file(path) != expected_hash:
            raise ValueError(f"AgentHarm runner file fingerprint mismatch: {relative_path}")
        files.append(
            {
                "relative_path": relative_path,
                "sha256": f"sha256:{expected_hash}",
            }
        )
    return {
        "source_url": AGENTHARM_RUNNER_URL,
        "revision": revision,
        "checkout_clean": True,
        "files": files,
    }


def _git_output(root: Path, *args: str) -> str:
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("GIT_")
    }
    git = shutil.which("git", path=environment.get("PATH"))
    if git is None:
        raise ValueError("Git executable is unavailable")
    try:
        return subprocess.run(
            [git, "-C", str(root), *args],
            check=True,
            capture_output=True,
            text=True,
            env=environment,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ValueError("AgentHarm runner root is not a readable Git checkout") from exc


def _regular_directory(path: Path, *, field_name: str) -> Path:
    candidate = _path_without_symlink_ancestors(path, field_name=field_name)
    if not candidate.is_dir():
        raise ValueError(f"{field_name} must be a regular non-symlink directory")
    if candidate.resolve(strict=True) != candidate:
        raise ValueError(f"{field_name} must not traverse symlinks")
    return candidate


def _regular_file(path: Path, *, field_name: str) -> Path:
    candidate = _path_without_symlink_ancestors(path, field_name=field_name)
    if not candidate.is_file():
        raise ValueError(f"{field_name} must be a regular non-symlink file")
    if candidate.resolve(strict=True) != candidate:
        raise ValueError(f"{field_name} must not traverse symlinks")
    if not stat.S_ISREG(candidate.stat().st_mode):
        raise ValueError(f"{field_name} must be a regular non-symlink file")
    return candidate


def _path_without_symlink_ancestors(path: Path, *, field_name: str) -> Path:
    candidate = Path(path).expanduser().absolute()
    current = Path(candidate.anchor)
    for part in candidate.parts[1:]:
        current /= part
        try:
            mode = os.lstat(current).st_mode
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(mode):
            raise ValueError(f"{field_name} must not traverse symlinks")
    return candidate


def _write_owner_only_json(path: Path, payload: Mapping[str, Any]) -> Path:
    target = _path_without_symlink_ancestors(
        path,
        field_name="AgentHarm source artifact",
    )
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(target, flags, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        os.fchmod(descriptor, 0o600)
        stream.write(stable_json_dumps(payload))
        stream.flush()
        os.fsync(descriptor)
    return target


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build a hash-bound AgentHarm validation source and case package."
    )
    parser.add_argument("--dataset-root", type=Path, required=True)
    parser.add_argument("--runner-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        paths = write_agentharm_source_package(
            args.output_dir,
            dataset_root=args.dataset_root,
            runner_root=args.runner_root,
        )
    except Exception as exc:
        print(
            json.dumps(
                {
                    "status": "blocked",
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                },
                ensure_ascii=False,
                sort_keys=True,
            )
        )
        return 2
    print(
        json.dumps(
            {
                "status": "valid",
                "artifacts": {name: str(path) for name, path in paths.items()},
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())


__all__ = [
    "AGENTHARM_CASE_MANIFEST_SCHEMA_VERSION",
    "AGENTHARM_SOURCE_ATTESTATION_SCHEMA_VERSION",
    "build_agentharm_validation_case_manifest",
    "build_agentharm_validation_source_attestation",
    "validate_agentharm_case_manifest_contract",
    "validate_agentharm_source_attestation_contract",
    "validate_agentharm_validation_case_manifest",
    "write_agentharm_source_package",
]
