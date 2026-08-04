from __future__ import annotations

import ctypes
import errno
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlparse

from invart.core.artifacts import sha256_file, stable_json_hash

from .agent_runtime_manifest import RuntimeManifest
from .agentharm_pilot import validate_agentharm_pilot_preflight
from .benchmark_adapters.agentharm import AGENTHARM_INSPECT_AI_REVISION
from .official_runners import build_agentharm_command
from .provider_credentials import (
    build_scoped_provider_environment,
    loopback_no_proxy_environment,
)
from .provider_run_control import ProviderApprovalPacket
from .provider_run_control import secure_provider_artifact_tree, write_owner_only_json


AGENTHARM_LAUNCH_PACKAGE_SCHEMA_VERSION = "invart.agentharm_launch_package.v0.1"
_LOCAL_LOOPBACK_API_KEY = "invart-local-loopback-non-secret"


def prepare_agentharm_launch_package(
    output_dir: Path,
    *,
    request: Mapping[str, Any],
    runtime_manifest: RuntimeManifest,
    dataset_root: Path,
    runner_root: Path,
    gateway_base_url: str,
    approval: ProviderApprovalPacket | None = None,
    inspect_executable: Path | None = None,
) -> dict[str, Any]:
    """Materialize a no-secret launch package without starting a provider call."""

    root = _safe_output_directory(output_dir)
    preflight = validate_agentharm_pilot_preflight(
        request,
        runtime_manifest=runtime_manifest,
        dataset_root=dataset_root,
        runner_root=runner_root,
        approval=approval,
    )
    status = str(preflight["status"])
    reasons = list(preflight["reasons"])
    variants = request.get("variants")
    if variants != ["V0"]:
        status = "blocked_unsupported_variant"
        reasons.append("Phase B0 launch supports only canonical V0")
    if request.get("epochs") != 1:
        status = "blocked_unsupported_epochs"
        reasons.append("Phase B0 launch supports exactly one epoch")

    try:
        normalized_gateway_url = _validated_loopback_base_url(gateway_base_url)
    except ValueError:
        normalized_gateway_url = None
        status = "blocked_gateway_configuration"
        reasons.append("gateway_base_url_must_be_loopback_http_v1")

    may_materialize = (
        preflight["status"] in {"approval_required", "approved_inputs_validated"}
        and status
        not in {
            "blocked_unsupported_variant",
            "blocked_unsupported_epochs",
            "blocked_gateway_configuration",
        }
    )
    runtime_attestation: dict[str, Any] | None = None
    if may_materialize:
        try:
            runtime_attestation = attest_agentharm_inspect_runtime(
                runner_root=runner_root,
                inspect_executable=inspect_executable,
            )
        except (OSError, RuntimeError, ValueError):
            status = "blocked_runtime_attestation"
            reasons.append("inspect_runtime_attestation_failed")
            may_materialize = False

    root.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = Path(tempfile.mkdtemp(prefix=f".{root.name}.", dir=root.parent))
    temporary.chmod(0o700)
    try:
        write_owner_only_json(temporary / "request.json", request)
        write_owner_only_json(
            temporary / "runtime_manifest.json",
            runtime_manifest.to_dict(),
        )
        staged_files: list[dict[str, Any]] = []
        command_rows: list[dict[str, Any]] = []
        if may_materialize and normalized_gateway_url is not None:
            staged_files = _stage_validation_dataset(
                temporary_root=temporary,
                final_root=root,
                dataset_root=dataset_root,
                request=request,
            )
            command_rows = _build_launch_commands(
                root=root,
                request=request,
                runner_root=runner_root,
                inspect_executable=inspect_executable,
                gateway_base_url=normalized_gateway_url,
            )
            if len(command_rows) != request.get("sample_executions"):
                status = "blocked_command_denominator_mismatch"
                reasons.append("launch_command_count_does_not_match_request")
                command_rows = []
            elif status == "approved_inputs_validated":
                status = "executor_required"

        package = {
            "schema_version": AGENTHARM_LAUNCH_PACKAGE_SCHEMA_VERSION,
            "status": status,
            "ready_to_execute": False,
            "provider_execution_performed": False,
            "reasons": sorted(set(reasons)),
            "request_hash": request.get("request_hash"),
            "approval_hash": approval.approval_hash if approval else None,
            "runtime_manifest_hash": runtime_manifest.manifest_hash,
            "preflight": preflight,
            "gateway": {
                "base_url": normalized_gateway_url,
                "bind_address": "127.0.0.1",
                "provider_credential_exposed_to_child": False,
                "child_provider_credential": "absent",
                "child_api_key_kind": "non_secret_loopback",
                "client_authentication": "deferred_to_executor",
            },
            "runtime_attestation": runtime_attestation,
            "staged_dataset_files": staged_files,
            "commands": command_rows,
            "expected_command_count": request.get("sample_executions"),
            "observed_command_count": len(command_rows),
            "execution_order": "benign_before_harmful",
            "claim_boundary": (
                "This package binds source, runtime, approval preflight, and official command inputs. "
                "It performs no provider call and is not scored benchmark evidence."
            ),
        }
        package["package_hash"] = stable_json_hash(package)
        write_owner_only_json(temporary / "launch_plan.json", package)
        secure_provider_artifact_tree(temporary)
        _publish_directory_without_replacement(temporary, root)
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return package


def attest_agentharm_inspect_runtime(
    *,
    runner_root: Path,
    inspect_executable: Path | None = None,
) -> dict[str, Any]:
    """Bind the installed Inspect package to the revision frozen by the runner lock."""

    runner, executable, python = _canonical_inspect_runtime(
        runner_root=runner_root,
        inspect_executable=inspect_executable,
    )
    if os.name != "nt":
        _verify_inspect_shebang(executable, python)
    probe_code = (
        "import importlib,importlib.metadata as m,json\n"
        "def component(distribution_name,module_name):\n"
        " d=m.distribution(distribution_name)\n"
        " module=importlib.import_module(module_name)\n"
        " return {'version':d.version,'distribution_path':str(d.locate_file('')),"
        "'module_file':str(module.__file__)}\n"
        "inspect_distribution=m.distribution('inspect-ai')\n"
        "direct_url=json.loads(inspect_distribution.read_text('direct_url.json') or '{}')\n"
        "print(json.dumps({'direct_url':direct_url,"
        "'inspect_ai':component('inspect-ai','inspect_ai'),"
        "'inspect_evals_agentharm':component('inspect-evals','inspect_evals.agentharm'),"
        "'openai':component('openai','openai')},sort_keys=True))"
    )
    environment = {
        "LANG": os.environ.get("LANG", "C.UTF-8"),
        "PATH": os.environ.get("PATH", ""),
        "PYTHONNOUSERSITE": "1",
    }
    completed = subprocess.run(
        [str(python), "-c", probe_code],
        cwd=runner,
        env=environment,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError("Inspect runtime metadata probe failed")
    try:
        metadata = json.loads(completed.stdout)
        observed_revision = metadata["direct_url"]["vcs_info"]["commit_id"]
        components = {
            name: _attested_runtime_component(metadata[name])
            for name in ("inspect_ai", "inspect_evals_agentharm", "openai")
        }
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise ValueError("Inspect runtime metadata is invalid") from exc
    if observed_revision != AGENTHARM_INSPECT_AI_REVISION:
        raise ValueError("Inspect runtime revision does not match the frozen runner lock")
    expected_agentharm_root = (
        runner / "src" / "inspect_evals" / "agentharm"
    ).resolve(strict=True)
    agentharm_module = Path(
        components["inspect_evals_agentharm"]["module_file"]
    ).resolve(strict=True)
    try:
        agentharm_module.relative_to(expected_agentharm_root)
    except ValueError as exc:
        raise ValueError("AgentHarm module is not loaded from the canonical runner source") from exc
    payload = {
        "schema_version": "invart.agentharm_inspect_runtime_attestation.v0.1",
        "status": "valid",
        "inspect_ai_revision": observed_revision,
        "inspect_ai_version": components["inspect_ai"]["version"],
        "inspect_executable": str(executable),
        "inspect_executable_sha256": sha256_file(executable, prefixed=True),
        "python_executable": str(python),
        "python_executable_sha256": sha256_file(python, prefixed=True),
        "components": components,
    }
    payload["attestation_hash"] = stable_json_hash(payload)
    return payload


def _build_launch_commands(
    *,
    root: Path,
    request: Mapping[str, Any],
    runner_root: Path,
    inspect_executable: Path | None,
    gateway_base_url: str,
) -> list[dict[str, Any]]:
    runner, canonical_inspect, _python = _canonical_inspect_runtime(
        runner_root=runner_root,
        inspect_executable=inspect_executable,
    )
    models = request["models"]
    limits = request["execution_limits"]
    model = _inspect_model_name(str(models["primary"]))
    refusal_judge = _inspect_model_name(str(models["refusal_judge"]))
    semantic_judge = _inspect_model_name(str(models["semantic_judge"]))
    per_command_cost = float(request["maximum_usd"]) / int(request["sample_executions"])
    rows: list[dict[str, Any]] = []
    for role, split in (("benign", "validation_benign"), ("harmful", "validation")):
        for case_id in request[f"{role}_case_ids"]:
            for epoch in range(1, int(request["epochs"]) + 1):
                index = len(rows)
                log_dir = root / "logs" / f"{index:03d}-{role}"
                spec = build_agentharm_command(
                    repository_root=str(runner_root),
                    inspect_executable=str(canonical_inspect),
                    split=split,
                    model_name=model,
                    prompt_template_name="empty",
                    refusal_judge=refusal_judge,
                    semantic_judge=semantic_judge,
                    behavior_ids=[str(case_id)],
                    log_dir=str(log_dir),
                    epochs=1,
                    max_connections=int(limits["max_connections"]),
                    max_retries=int(limits["max_retries"]),
                    timeout=int(limits["timeout_seconds"]),
                    max_tokens=int(request["maximum_tokens_per_call"]),
                    token_limit=(
                        int(request["maximum_calls_per_sample"])
                        * int(request["maximum_tokens_per_call"])
                    ),
                    cost_limit=per_command_cost,
                    runtime_home=str(root / "runtime-home"),
                    model_base_url=gateway_base_url,
                )
                spec.pop("source_checked_at", None)
                environment = build_scoped_provider_environment(
                    provider=None,
                    agent="inspect-evals-agentharm",
                    base_env=os.environ,
                    include_provider_credentials=False,
                )
                environment.pop("PYTHONPATH", None)
                environment.update(spec["environment_overrides"] or {})
                environment.update(
                    {
                        "OPENAI_API_KEY": _LOCAL_LOOPBACK_API_KEY,
                        "OPENAI_BASE_URL": gateway_base_url,
                        "PATH": os.pathsep.join(
                            filter(
                                None,
                                (
                                    str(canonical_inspect.parent),
                                    environment.get("PATH"),
                                ),
                            )
                        ),
                        "PYTHONNOUSERSITE": "1",
                        "VIRTUAL_ENV": str(runner / ".venv"),
                    }
                )
                environment.update(loopback_no_proxy_environment())
                credential_env_name = str(request["credential_env_name"])
                environment.pop(credential_env_name, None)
                spec["environment_overrides"] = environment
                spec["environment_mode"] = "replace"
                spec["forbidden_environment_names"] = [credential_env_name]
                row = {
                    "command_id": f"agentharm-v0-{index:03d}",
                    "variant": "V0",
                    "role": role,
                    "case_id": str(case_id),
                    "epoch": epoch,
                    "command_spec": spec,
                }
                row["command_hash"] = stable_json_hash(row)
                rows.append(row)
    return rows


def _canonical_inspect_runtime(
    *,
    runner_root: Path,
    inspect_executable: Path | None,
) -> tuple[Path, Path, Path]:
    runner = runner_root.expanduser().resolve(strict=True)
    executable_dir = "Scripts" if os.name == "nt" else "bin"
    executable_name = "inspect.exe" if os.name == "nt" else "inspect"
    python_name = "python.exe" if os.name == "nt" else "python"
    canonical_executable = runner / ".venv" / executable_dir / executable_name
    canonical_python = runner / ".venv" / executable_dir / python_name
    resolved_executable = canonical_executable.resolve(strict=True)
    if inspect_executable is not None:
        supplied = inspect_executable.expanduser().resolve(strict=True)
        if supplied != resolved_executable:
            raise ValueError("Inspect executable must be the canonical runner executable")
    if not canonical_executable.is_file() or not os.access(canonical_executable, os.X_OK):
        raise ValueError("Inspect executable is missing or not executable")
    if not canonical_python.is_file() or not os.access(canonical_python, os.X_OK):
        raise ValueError("Inspect Python executable is missing or not executable")
    return runner, canonical_executable, canonical_python


def _verify_inspect_shebang(executable: Path, python: Path) -> None:
    with executable.open("rb") as stream:
        first_line = stream.readline(4096)
    if not first_line.startswith(b"#!"):
        raise ValueError("Inspect executable has no shebang")
    try:
        interpreter = first_line[2:].decode("utf-8").strip().split(maxsplit=1)[0]
        resolved_interpreter = Path(interpreter).expanduser().resolve(strict=True)
    except (IndexError, OSError, UnicodeDecodeError) as exc:
        raise ValueError("Inspect executable shebang is invalid") from exc
    if resolved_interpreter != python.resolve(strict=True):
        raise ValueError("Inspect executable shebang does not use the canonical runner Python")


def _attested_runtime_component(payload: Mapping[str, Any]) -> dict[str, str]:
    version = str(payload["version"]).strip()
    distribution_path = Path(str(payload["distribution_path"])).resolve(strict=True)
    module_file = Path(str(payload["module_file"])).resolve(strict=True)
    if not version or not module_file.is_file():
        raise ValueError("Inspect runtime component metadata is invalid")
    return {
        "version": version,
        "distribution_path": str(distribution_path),
        "module_file": str(module_file),
        "module_file_sha256": sha256_file(module_file, prefixed=True),
    }


def _stage_validation_dataset(
    *,
    temporary_root: Path,
    final_root: Path,
    dataset_root: Path,
    request: Mapping[str, Any],
) -> list[dict[str, Any]]:
    source_root = dataset_root.expanduser().resolve(strict=True)
    relative_cache_root = (
        Path("runtime-home")
        / ".cache"
        / "inspect_evals"
        / "agentharm_dataset"
        / "AgentHarm"
    )
    rows: list[dict[str, Any]] = []
    files = request["case_manifest"]["source_attestation"]["files"]
    for item in files:
        relative_path = Path(str(item["relative_path"]))
        if relative_path.is_absolute() or ".." in relative_path.parts:
            raise ValueError("AgentHarm staged source path is unsafe")
        source = source_root / relative_path
        expected_hash = str(item["sha256"])
        target = temporary_root / relative_cache_root / relative_path
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        _copy_verified_owner_only(
            source,
            target,
            expected_hash=expected_hash,
        )
        rows.append(
            {
                "role": item["role"],
                "relative_path": str(relative_cache_root / relative_path),
                "runtime_path": str(final_root / relative_cache_root / relative_path),
                "sha256": expected_hash,
            }
        )
    return rows


def _validated_loopback_base_url(value: str) -> str:
    parsed = urlparse(str(value).strip())
    if (
        parsed.scheme != "http"
        or parsed.hostname != "127.0.0.1"
        or parsed.port is None
        or parsed.port <= 0
        or parsed.path.rstrip("/") != "/v1"
        or parsed.username
        or parsed.password
        or parsed.params
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("AgentHarm gateway URL must be loopback HTTP with a fixed port and /v1")
    return f"http://127.0.0.1:{parsed.port}/v1"


def _inspect_model_name(model: str) -> str:
    normalized = str(model).strip()
    if not normalized or "/" in normalized:
        raise ValueError("AgentHarm gateway models must be unqualified model IDs")
    return f"openai/{normalized}"


def _safe_output_directory(path: Path) -> Path:
    candidate = path.expanduser().absolute()
    current = Path(candidate.anchor)
    for part in candidate.parts[1:]:
        current /= part
        try:
            mode = os.lstat(current).st_mode
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(mode):
            raise ValueError("AgentHarm launch package path must not traverse symlinks")
    if candidate.exists():
        raise FileExistsError(candidate)
    return candidate


def _copy_verified_owner_only(
    source: Path,
    target: Path,
    *,
    expected_hash: str,
) -> None:
    source_flags = os.O_RDONLY
    target_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        source_flags |= os.O_NOFOLLOW
        target_flags |= os.O_NOFOLLOW
    source_descriptor = os.open(source, source_flags)
    target_descriptor: int | None = None
    digest = hashlib.sha256()
    try:
        if not stat.S_ISREG(os.fstat(source_descriptor).st_mode):
            raise ValueError("AgentHarm staged source must be a regular file")
        target_descriptor = os.open(target, target_flags, 0o600)
        if not stat.S_ISREG(os.fstat(target_descriptor).st_mode):
            raise ValueError("AgentHarm staged target must be a regular file")
        os.fchmod(target_descriptor, 0o600)
        while chunk := os.read(source_descriptor, 1024 * 1024):
            digest.update(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(target_descriptor, view)
                view = view[written:]
        os.fsync(target_descriptor)
    except Exception:
        if target_descriptor is not None:
            os.close(target_descriptor)
            target_descriptor = None
        target.unlink(missing_ok=True)
        raise
    finally:
        os.close(source_descriptor)
        if target_descriptor is not None:
            os.close(target_descriptor)
    if f"sha256:{digest.hexdigest()}" != expected_hash:
        target.unlink(missing_ok=True)
        raise ValueError("AgentHarm staged source hash changed after preflight")


def _publish_directory_without_replacement(source: Path, target: Path) -> None:
    if sys.platform == "darwin":
        libc = ctypes.CDLL(None, use_errno=True)
        function = libc.renamex_np
        function.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
        result = function(os.fsencode(source), os.fsencode(target), 0x00000004)
    elif sys.platform.startswith("linux"):
        libc = ctypes.CDLL(None, use_errno=True)
        function = libc.renameat2
        function.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        result = function(-100, os.fsencode(source), -100, os.fsencode(target), 0x1)
    elif os.name == "nt":
        os.rename(source, target)
        return
    else:
        raise RuntimeError("atomic no-replace directory publication is unsupported")
    if result == 0:
        return
    error_number = ctypes.get_errno()
    if error_number in {errno.EEXIST, errno.ENOTEMPTY}:
        raise FileExistsError(target)
    raise OSError(error_number, os.strerror(error_number), str(target))


__all__ = [
    "AGENTHARM_LAUNCH_PACKAGE_SCHEMA_VERSION",
    "attest_agentharm_inspect_runtime",
    "prepare_agentharm_launch_package",
]
