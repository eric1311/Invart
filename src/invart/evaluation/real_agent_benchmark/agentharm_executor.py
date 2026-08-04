from __future__ import annotations

import json
import os
import stat
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.parse import urlparse

from invart.core.artifacts import sha256_file, stable_json_hash

from invart.surfaces.supervision import supervise_process_group

from .agent_runtime_manifest import (
    RuntimeManifest,
    build_runtime_receipt,
    runtime_manifest_from_dict,
)
from .agentharm_launch import (
    AGENTHARM_LAUNCH_PACKAGE_SCHEMA_VERSION,
    _build_launch_commands,
    attest_agentharm_inspect_runtime,
)
from .agentharm_pilot import (
    load_agentharm_pilot_request,
    validate_agentharm_pilot_preflight,
)
from .provider_budget_gateway import (
    GatewayTransport,
    ProviderBudgetGateway,
    reconcile_gateway_records,
    start_provider_budget_gateway,
)
from .provider_credentials import redact_provider_secrets
from .provider_run_control import (
    ProviderApprovalPacket,
    ProviderBudgetLedger,
    read_owner_only_json,
    require_owner_only_directory,
    secure_provider_artifact_tree,
    write_owner_only_json,
)


AGENTHARM_EXECUTION_RECORD_SCHEMA_VERSION = "invart.agentharm_execution_record.v0.1"
RuntimeAttestor = Callable[..., dict[str, Any]]
ClientTokenFactory = Callable[[], str]


def validate_agentharm_launch_package_for_execution(
    *,
    package_dir: Path,
    approval: ProviderApprovalPacket,
    dataset_root: Path,
    runner_root: Path,
    runtime_attestor: RuntimeAttestor = attest_agentharm_inspect_runtime,
    approval_validation_at: datetime | None = None,
) -> dict[str, Any]:
    root = require_owner_only_directory(package_dir, field_name="launch package")
    package = read_owner_only_json(root / "launch_plan.json", field_name="launch plan")
    if package.get("schema_version") != AGENTHARM_LAUNCH_PACKAGE_SCHEMA_VERSION:
        raise ValueError("AgentHarm launch package schema mismatch")
    package_hash = str(package.get("package_hash") or "")
    if package_hash != stable_json_hash(
        {key: value for key, value in package.items() if key != "package_hash"}
    ):
        raise ValueError("AgentHarm launch package hash mismatch")
    if package.get("status") != "executor_required":
        raise ValueError("AgentHarm launch package is not approved for executor handoff")
    if package.get("ready_to_execute") is not False:
        raise ValueError("AgentHarm launch package readiness boundary is invalid")
    if package.get("provider_execution_performed") is not False:
        raise ValueError("AgentHarm launch package already claims provider execution")
    if package.get("approval_hash") != approval.approval_hash:
        raise ValueError("AgentHarm launch package approval hash mismatch")

    request = load_agentharm_pilot_request(root / "request.json")
    manifest_payload = read_owner_only_json(
        root / "runtime_manifest.json",
        field_name="runtime manifest",
    )
    manifest = runtime_manifest_from_dict(manifest_payload)
    if package.get("request_hash") != request.get("request_hash"):
        raise ValueError("AgentHarm launch package request hash mismatch")
    if package.get("runtime_manifest_hash") != manifest.manifest_hash:
        raise ValueError("AgentHarm launch package runtime manifest hash mismatch")

    preflight = validate_agentharm_pilot_preflight(
        request,
        runtime_manifest=manifest,
        dataset_root=dataset_root,
        runner_root=runner_root,
        approval=approval,
        at=approval_validation_at,
    )
    if preflight.get("status") != "approved_inputs_validated":
        raise RuntimeError("AgentHarm launch approval or live source preflight is no longer valid")

    runtime_attestation = runtime_attestor(runner_root=runner_root)
    if runtime_attestation != package.get("runtime_attestation"):
        raise ValueError("AgentHarm runtime attestation changed after package creation")

    gateway = package.get("gateway")
    if not isinstance(gateway, Mapping):
        raise ValueError("AgentHarm launch package gateway contract is missing")
    gateway_base_url = str(gateway.get("base_url") or "")
    _gateway_port(gateway_base_url)
    expected_commands = _build_launch_commands(
        root=root,
        request=request,
        runner_root=runner_root,
        inspect_executable=None,
        gateway_base_url=gateway_base_url,
    )
    commands = package.get("commands")
    if commands != expected_commands:
        raise ValueError("AgentHarm launch commands do not match canonical launch commands")
    if int(package.get("observed_command_count") or -1) != len(expected_commands):
        raise ValueError("AgentHarm launch package command count mismatch")
    if int(package.get("expected_command_count") or -1) != len(expected_commands):
        raise ValueError("AgentHarm launch package expected command count mismatch")
    for row in expected_commands:
        command_hash = str(row.get("command_hash") or "")
        if command_hash != stable_json_hash(
            {key: value for key, value in row.items() if key != "command_hash"}
        ):
            raise ValueError("AgentHarm launch command hash mismatch")

    staged_files = package.get("staged_dataset_files")
    if not isinstance(staged_files, list) or not staged_files:
        raise ValueError("AgentHarm launch package staged dataset is missing")
    for item in staged_files:
        if not isinstance(item, Mapping):
            raise ValueError("AgentHarm staged dataset record is invalid")
        relative_path = _safe_relative_path(item.get("relative_path"))
        staged_path = root / relative_path
        if staged_path.is_symlink() or not staged_path.is_file():
            raise ValueError("AgentHarm staged dataset file is missing")
        if sha256_file(staged_path, prefixed=True) != item.get("sha256"):
            raise ValueError("AgentHarm staged dataset file hash mismatch")
        if str(staged_path) != str(item.get("runtime_path")):
            raise ValueError("AgentHarm staged dataset runtime path mismatch")

    return {
        "package_dir": root,
        "package": package,
        "request": request,
        "runtime_manifest": manifest,
        "approval_scope": preflight,
        "runtime_attestation": runtime_attestation,
        "gateway_base_url": gateway_base_url,
        "commands": expected_commands,
    }


def execute_agentharm_launch_package(
    *,
    package_dir: Path,
    output_dir: Path,
    approval: ProviderApprovalPacket,
    dataset_root: Path,
    runner_root: Path,
    provider_environment: Mapping[str, str],
    budget_state_root: Path | None = None,
    gateway_transport: GatewayTransport | None = None,
    runtime_attestor: RuntimeAttestor = attest_agentharm_inspect_runtime,
    client_token_factory: ClientTokenFactory | None = None,
) -> dict[str, Any]:
    context = validate_agentharm_launch_package_for_execution(
        package_dir=package_dir,
        approval=approval,
        dataset_root=dataset_root,
        runner_root=runner_root,
        runtime_attestor=runtime_attestor,
    )
    output = _create_owner_only_directory(output_dir)
    manifest: RuntimeManifest = context["runtime_manifest"]
    request: Mapping[str, Any] = context["request"]
    credential_name = str(request["credential_env_name"])
    provider_secret = str(provider_environment.get(credential_name) or "")
    provider_secret_values = (provider_secret,) if provider_secret else ()
    gateway_log_path = output / "provider_gateway_requests.jsonl"
    budget_state_path = _approval_budget_state_path(
        approval,
        root=budget_state_root,
    )
    client_token: str | None = None
    gateway: ProviderBudgetGateway | None = None
    server = None
    thread = None
    command_records: list[dict[str, Any]] = []
    execution_error: str | None = None
    try:
        client_token = (
            client_token_factory()
            if client_token_factory is not None
            else _random_client_token()
        )
        ledger = ProviderBudgetLedger(
            approval=approval,
            state_path=budget_state_path,
            maximum_calls=int(request["max_calls"]),
            maximum_total_tokens=int(request["max_total_tokens"]),
        )
        gateway = ProviderBudgetGateway(
            manifest=manifest,
            budget_ledger=ledger,
            environment=provider_environment,
            log_path=gateway_log_path,
            maximum_tokens_per_call=int(request["maximum_tokens_per_call"]),
            timeout=float(request["execution_limits"]["timeout_seconds"]),
            transport=gateway_transport,
            require_command_scope=True,
        )
        server, thread, actual_port = start_provider_budget_gateway(
            gateway=gateway,
            client_bearer_token=client_token,
            port=_gateway_port(context["gateway_base_url"]),
        )
        if actual_port != _gateway_port(context["gateway_base_url"]):
            raise RuntimeError("AgentHarm gateway bound an unexpected port")
        for row in context["commands"]:
            before_record_count = len(_read_jsonl(gateway_log_path))
            command_id = str(row["command_id"])
            maximum_calls_per_sample = int(request["maximum_calls_per_sample"])
            maximum_tokens_per_call = int(request["maximum_tokens_per_call"])
            gateway.begin_command_scope(
                command_id=command_id,
                maximum_calls=maximum_calls_per_sample,
                maximum_total_tokens=(
                    maximum_calls_per_sample * maximum_tokens_per_call
                ),
            )
            try:
                record = _execute_command(
                    row,
                    client_token=client_token,
                    provider_credential_name=credential_name,
                    provider_secret_values=provider_secret_values,
                )
            finally:
                command_budget_scope = gateway.end_command_scope(
                    command_id=command_id
                )
            command_gateway_records = _read_jsonl(gateway_log_path)[
                before_record_count:
            ]
            command_reconciliation = reconcile_gateway_records(
                command_gateway_records
            )
            command_gateway_complete = (
                command_reconciliation["forwarded_count"] >= 1
                and command_reconciliation["terminal_error_count"] == 0
                and not command_reconciliation["orphan_request_ids"]
                and _gateway_records_within_sample_budget(
                    command_gateway_records,
                    maximum_calls=maximum_calls_per_sample,
                    maximum_tokens_per_call=maximum_tokens_per_call,
                )
            )
            record["gateway_reconciliation"] = command_reconciliation
            record["gateway_budget_scope"] = command_budget_scope
            record["succeeded"] = (
                record["succeeded"] and command_gateway_complete
            )
            command_records.append(record)
            if not record["succeeded"]:
                execution_error = f"command_failed:{row['command_id']}"
                break
    except Exception as exc:
        execution_error = redact_provider_secrets(
            f"{type(exc).__name__}:{str(exc)}",
            secret_values=(
                *provider_secret_values,
                *((client_token,) if client_token else ()),
            ),
        )
    finally:
        if server is not None:
            server.shutdown()
            server.server_close()
        if thread is not None:
            thread.join(timeout=5)

    gateway_records = _read_jsonl(gateway_log_path)
    reconciliation = reconcile_gateway_records(gateway_records)
    gateway_log_sha256 = (
        sha256_file(gateway_log_path, prefixed=True)
        if gateway_log_path.is_file()
        else None
    )
    secure_provider_artifact_tree(context["package_dir"])
    all_commands_succeeded = (
        execution_error is None
        and len(command_records) == len(context["commands"])
        and all(record["succeeded"] for record in command_records)
    )
    gateway_complete = (
        not reconciliation["orphan_request_ids"]
        and reconciliation["terminal_error_count"] == 0
        and reconciliation["forwarded_count"] >= len(command_records)
    )
    status = (
        "completed_unscored"
        if all_commands_succeeded and gateway_complete
        else "execution_failed"
    )
    runtime_receipt = build_runtime_receipt(
        resolved_provider=manifest.request.requested_provider,
        resolved_model=manifest.request.requested_model,
        resolved_agent_product=manifest.request.agent_product,
        resolved_low_level_runtime=manifest.request.low_level_runtime,
        resolved_profile_state_hash=manifest.profile_state_hash,
    )
    result = {
        "schema_version": AGENTHARM_EXECUTION_RECORD_SCHEMA_VERSION,
        "status": status,
        "package_hash": context["package"]["package_hash"],
        "request_hash": request["request_hash"],
        "approval_hash": approval.approval_hash,
        "runtime_manifest_hash": manifest.manifest_hash,
        "runtime_attestation_hash": context["runtime_attestation"]["attestation_hash"],
        "command_count": len(command_records),
        "expected_command_count": len(context["commands"]),
        "all_commands_succeeded": all_commands_succeeded,
        "execution_error": execution_error,
        "commands": command_records,
        "gateway_reconciliation": reconciliation,
        "gateway_log_sha256": gateway_log_sha256,
        "budget_ledger_scope": "approval_hash_global",
        "budget_ledger_state_sha256": (
            sha256_file(budget_state_path, prefixed=True)
            if budget_state_path.is_file()
            else None
        ),
        "runtime_receipt": runtime_receipt.to_dict(),
        "native_artifact_status": "not_validated",
        "runtime_execution_proof": None,
        "claim_boundary": (
            "This record proves bounded executor and gateway lifecycle evidence only. "
            "It is not an official AgentHarm score or security-effect result."
        ),
    }
    result["execution_record_hash"] = stable_json_hash(result)
    write_owner_only_json(
        output / "execution_record.json",
        result,
        field_name="AgentHarm execution record",
    )
    secure_provider_artifact_tree(output)
    return result


def _execute_command(
    row: Mapping[str, Any],
    *,
    client_token: str,
    provider_credential_name: str,
    provider_secret_values: tuple[str, ...],
) -> dict[str, Any]:
    spec = row.get("command_spec")
    if not isinstance(spec, Mapping) or spec.get("environment_mode") != "replace":
        raise ValueError("AgentHarm command requires replacement environment")
    environment_payload = spec.get("environment_overrides")
    if not isinstance(environment_payload, Mapping):
        raise ValueError("AgentHarm command replacement environment is invalid")
    environment = {str(key): str(value) for key, value in environment_payload.items()}
    if provider_credential_name in environment:
        raise ValueError("AgentHarm child environment contains provider credential")
    environment["OPENAI_API_KEY"] = client_token
    command = [str(value) for value in spec.get("command") or ()]
    supervision = supervise_process_group(
        command,
        cwd=Path(str(spec["working_directory"])),
        timeout=float(_command_timeout(command)),
        env=environment,
        redactions=(*provider_secret_values, client_token),
    )
    succeeded = (
        supervision["returncode"] == 0
        and not supervision["timed_out"]
        and not supervision["lifecycle_violation"]
    )
    return {
        "command_id": row["command_id"],
        "command_hash": row["command_hash"],
        "role": row["role"],
        "case_id": row["case_id"],
        "epoch": row["epoch"],
        "succeeded": succeeded,
        "supervision": supervision,
    }


def _command_timeout(command: list[str]) -> int:
    try:
        timeout = int(command[command.index("--timeout") + 1])
    except (ValueError, IndexError) as exc:
        raise ValueError("AgentHarm command timeout is missing") from exc
    if timeout <= 0:
        raise ValueError("AgentHarm command timeout is invalid")
    return timeout + 15


def _gateway_port(base_url: str) -> int:
    parsed = urlparse(str(base_url))
    if (
        parsed.scheme != "http"
        or parsed.hostname != "127.0.0.1"
        or parsed.port is None
        or parsed.path.rstrip("/") != "/v1"
    ):
        raise ValueError("AgentHarm executor gateway must be fixed loopback HTTP /v1")
    return int(parsed.port)


def _gateway_records_within_sample_budget(
    records: list[dict[str, Any]],
    *,
    maximum_calls: int,
    maximum_tokens_per_call: int,
) -> bool:
    reservations = [
        record.get("budget_reservation")
        for record in records
        if record.get("status") == "reserved_pending"
    ]
    if len(reservations) > maximum_calls:
        return False
    reserved_tokens = sum(
        int(reservation.get("tokens_reserved") or 0)
        for reservation in reservations
        if isinstance(reservation, Mapping)
    )
    return (
        len(reservations)
        == sum(isinstance(reservation, Mapping) for reservation in reservations)
        and reserved_tokens <= maximum_calls * maximum_tokens_per_call
    )


def _random_client_token() -> str:
    import secrets

    return secrets.token_urlsafe(32)


def _approval_budget_state_path(
    approval: ProviderApprovalPacket,
    *,
    root: Path | None,
) -> Path:
    if root is None:
        state_home = Path(
            os.environ.get("XDG_STATE_HOME")
            or (Path.home() / ".local" / "state")
        )
        candidate = state_home / "invart" / "provider-budgets"
    else:
        candidate = root
    resolved = candidate.expanduser().absolute()
    current = Path(resolved.anchor)
    for part in resolved.parts[1:]:
        current /= part
        try:
            mode = os.lstat(current).st_mode
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(mode):
            raise ValueError("provider budget state root must not traverse symlinks")
    resolved.mkdir(parents=True, exist_ok=True, mode=0o700)
    resolved.chmod(0o700)
    key = approval.approval_hash.removeprefix("sha256:")
    if not key or any(character not in "0123456789abcdef" for character in key):
        raise ValueError("provider approval hash is not a canonical SHA-256")
    return resolved / f"{key}.json"


def _create_owner_only_directory(path: Path) -> Path:
    candidate = path.expanduser().absolute()
    candidate.mkdir(parents=True, mode=0o700, exist_ok=False)
    candidate.chmod(0o700)
    return candidate


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return []
    records: list[dict[str, Any]] = []
    for line in lines:
        payload = json.loads(line)
        if not isinstance(payload, dict):
            raise ValueError("gateway record must be an object")
        records.append(payload)
    return records


def _safe_relative_path(value: Any) -> Path:
    path = Path(str(value))
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise ValueError("AgentHarm staged dataset relative path is unsafe")
    return path


__all__ = [
    "AGENTHARM_EXECUTION_RECORD_SCHEMA_VERSION",
    "execute_agentharm_launch_package",
    "validate_agentharm_launch_package_for_execution",
]
