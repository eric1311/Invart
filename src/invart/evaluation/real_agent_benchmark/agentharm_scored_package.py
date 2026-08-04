from __future__ import annotations

import json
import os
import shutil
import stat
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Mapping

from invart.core.artifacts import sha256_file, stable_json_hash

from .agent_runtime_manifest import (
    build_runtime_execution_proof,
    build_runtime_receipt,
)
from .agentharm_effect_gate import build_agentharm_treatment_binding
from .agentharm_executor import (
    AGENTHARM_EXECUTION_RECORD_SCHEMA_VERSION,
    validate_agentharm_launch_package_for_execution,
)
from .agentharm_launch import attest_agentharm_inspect_runtime
from .agentharm_pilot import build_agentharm_pilot_gate
from .benchmark_adapters.agentharm import (
    bind_agentharm_capability_control,
    build_agentharm_capability_control,
    dump_agentharm_inspect_eval,
    extract_agentharm_inspect_rows,
)
from .official_runners import validate_agentharm_execution_package
from .provider_budget_gateway import GATEWAY_RECORD_SCHEMA_VERSION
from .provider_run_control import (
    ProviderApprovalPacket,
    read_owner_only_json,
    require_owner_only_directory,
    secure_provider_artifact_tree,
    write_owner_only_json,
)


AGENTHARM_SCORE_RECORD_SCHEMA_VERSION = "invart.agentharm_score_record.v0.1"
AGENTHARM_TECHNICAL_EVIDENCE_SCHEMA_VERSION = (
    "invart.agentharm_technical_evidence.v0.1"
)
AGENTHARM_NATIVE_MANIFEST_SCHEMA_VERSION = (
    "invart.agentharm_native_artifact_manifest.v0.1"
)
InspectDumper = Callable[..., dict[str, Any]]
RuntimeAttestor = Callable[..., dict[str, Any]]
PackageValidator = Callable[..., dict[str, Any]]


def finalize_agentharm_scored_package(
    *,
    package_dir: Path,
    execution_dir: Path,
    approval: ProviderApprovalPacket,
    dataset_root: Path,
    runner_root: Path,
    runtime_attestor: RuntimeAttestor = attest_agentharm_inspect_runtime,
    inspect_dumper: InspectDumper = dump_agentharm_inspect_eval,
    package_validator: PackageValidator = validate_agentharm_execution_package,
) -> dict[str, Any]:
    """Convert one completed V0 executor run into replayable condition evidence."""

    context = validate_agentharm_launch_package_for_execution(
        package_dir=package_dir,
        approval=approval,
        dataset_root=dataset_root,
        runner_root=runner_root,
        runtime_attestor=runtime_attestor,
        approval_validation_at=approval.approved_at,
    )
    output = require_owner_only_directory(
        execution_dir,
        field_name="execution directory",
    )
    execution = _validated_execution_record(
        output / "execution_record.json",
        context=context,
        approval=approval,
    )
    gateway_receipts = _strict_gateway_receipts(
        output / "provider_gateway_requests.jsonl",
        context=context,
        execution=execution,
        approval=approval,
    )

    scored_dir = output / "scored"
    if scored_dir.exists():
        raise ValueError("AgentHarm scored package output already exists")
    staging_root = Path(
        tempfile.mkdtemp(prefix=".agentharm-finalize-", dir=output)
    )
    staging_root.chmod(0o700)
    staging_native = staging_root / "native"
    staging_native.mkdir(mode=0o700)
    staged_score_record = staging_root / "agentharm_score_record.json"
    try:
        score_record = _build_staged_scored_package(
            context=context,
            execution=execution,
            gateway_receipts=gateway_receipts,
            approval=approval,
            runner_root=runner_root,
            native_dir=staging_native,
            inspect_dumper=inspect_dumper,
            package_validator=package_validator,
        )
        write_owner_only_json(
            staged_score_record,
            score_record,
            field_name="AgentHarm score record",
        )
        secure_provider_artifact_tree(staging_root)
        _publish_scored_package(
            staging_root=staging_root,
            scored_dir=scored_dir,
        )
    except Exception:
        shutil.rmtree(staging_root, ignore_errors=True)
        raise

    return score_record


def _build_staged_scored_package(
    *,
    context: Mapping[str, Any],
    execution: Mapping[str, Any],
    gateway_receipts: list[dict[str, Any]],
    approval: ProviderApprovalPacket,
    runner_root: Path,
    native_dir: Path,
    inspect_dumper: InspectDumper,
    package_validator: PackageValidator,
) -> dict[str, Any]:
    inspect_executable = (
        runner_root.expanduser().resolve(strict=True)
        / ".venv"
        / ("Scripts" if os.name == "nt" else "bin")
        / ("inspect.exe" if os.name == "nt" else "inspect")
    ).resolve(strict=True)
    benign_rows: list[dict[str, Any]] = []
    harmful_rows: list[dict[str, Any]] = []
    retained_archives: list[Path] = []
    for command in context["commands"]:
        source = _single_command_eval_archive(command)
        retained = native_dir / f"{command['command_id']}.eval"
        _copy_owner_only_file(source, retained)
        retained_archives.append(retained)
        dumped = inspect_dumper(
            retained,
            inspect_executable=inspect_executable,
        )
        role = str(command["role"])
        split = "validation_benign" if role == "benign" else "validation"
        rows = extract_agentharm_inspect_rows(
            dumped["payload"],
            split=split,
            upstream_artifact_hash=str(dumped["upstream_artifact_hash"]),
        )
        if len(rows) != 1:
            raise ValueError("AgentHarm command must produce exactly one scored sample")
        row = rows[0]
        _validate_row_against_command(row, command=command, request=context["request"])
        (benign_rows if role == "benign" else harmful_rows).append(row)

    capability_gate = context["request"]["capability_gate"]
    capability_control = build_agentharm_capability_control(
        benign_rows,
        minimum_scored_cases=int(capability_gate["minimum_scored_cases"]),
        minimum_mean_functional_grader=float(
            capability_gate["minimum_mean_functional_grader"]
        ),
        minimum_tool_use_rate=float(capability_gate["minimum_tool_use_rate"]),
    )
    write_owner_only_json(
        native_dir / "capability_control.json",
        capability_control,
        field_name="AgentHarm capability control",
    )
    harmful_artifacts: list[dict[str, Any]] = []
    for row in harmful_rows:
        artifact = bind_agentharm_capability_control(row, capability_control)
        harmful_artifacts.append(artifact)
        write_owner_only_json(
            native_dir
            / f"{_safe_filename(str(row['case_id']))}-e{int(row['epoch'])}.agentharm-bound.json",
            artifact,
            field_name="AgentHarm bound artifact",
        )

    official_validation = package_validator(
        package_dir=native_dir,
        inspect_executable=inspect_executable,
        expected_harmful_case_ids=list(context["request"]["harmful_case_ids"]),
        minimum_scored_cases=int(capability_gate["minimum_scored_cases"]),
        minimum_mean_functional_grader=float(
            capability_gate["minimum_mean_functional_grader"]
        ),
        minimum_tool_use_rate=float(capability_gate["minimum_tool_use_rate"]),
    )
    if official_validation.get("status") != "pass":
        raise ValueError("AgentHarm official package replay validation failed")

    harmful_hashes = sorted(
        str(artifact["artifact_hash"]) for artifact in harmful_artifacts
    )
    technical_evidence = _build_technical_evidence(
        gateway_receipts,
        request_hash=str(context["request"]["request_hash"]),
        execution_record_hash=str(execution["execution_record_hash"]),
        gateway_log_sha256=str(execution["gateway_log_sha256"]),
        harmful_artifact_hashes=harmful_hashes,
        official_artifact_status=str(
            official_validation["official_artifact_status"]
        ),
    )
    treatment_binding = build_agentharm_treatment_binding(
        policy_variant="V0",
        expected_request_hash=str(context["request"]["request_hash"]),
        technical_evidence_hash=str(technical_evidence["evidence_hash"]),
        harmful_artifact_hashes=harmful_hashes,
    )
    pilot_gate = build_agentharm_pilot_gate(
        harmful_artifacts,
        capability_control=capability_control,
        technical_validity=technical_evidence,
        official_package_validation=official_validation,
        expected_request_hash=str(context["request"]["request_hash"]),
        expected_harmful_case_ids=context["request"]["harmful_case_ids"],
        treatment_binding=treatment_binding,
    )

    evidence_files = {
        "official_package_validation.json": official_validation,
        "technical_evidence.json": technical_evidence,
        "treatment_binding.json": treatment_binding,
        "pilot_gate.json": pilot_gate,
    }
    for filename, payload in evidence_files.items():
        write_owner_only_json(
            native_dir / filename,
            payload,
            field_name=f"AgentHarm {filename}",
        )
    native_manifest = _build_native_manifest(native_dir)
    write_owner_only_json(
        native_dir / "native_artifact_manifest.json",
        native_manifest,
        field_name="AgentHarm native artifact manifest",
    )
    native_manifest_sha256 = sha256_file(
        native_dir / "native_artifact_manifest.json",
        prefixed=True,
    )

    receipt_payload = execution["runtime_receipt"]
    runtime_receipt = build_runtime_receipt(
        resolved_provider=str(receipt_payload["resolved_provider"]),
        resolved_model=str(receipt_payload["resolved_model"]),
        resolved_agent_product=str(receipt_payload["resolved_agent_product"]),
        resolved_low_level_runtime=str(receipt_payload["resolved_low_level_runtime"]),
        fallback_used=bool(receipt_payload.get("fallback_used")),
        fallback_id=receipt_payload.get("fallback_id"),
        resolved_profile_state_hash=receipt_payload.get(
            "resolved_profile_state_hash"
        ),
    )
    runtime_proof = build_runtime_execution_proof(
        runtime_manifest=context["runtime_manifest"],
        runtime_receipt=runtime_receipt,
        native_artifact_sha256=native_manifest_sha256,
        execution_record_hash=str(execution["execution_record_hash"]),
    ).to_dict()
    score_record = {
        "schema_version": AGENTHARM_SCORE_RECORD_SCHEMA_VERSION,
        "status": "scored_condition_only",
        "policy_variant": "V0",
        "package_hash": context["package"]["package_hash"],
        "request_hash": context["request"]["request_hash"],
        "approval_hash": approval.approval_hash,
        "runtime_manifest_hash": context["runtime_manifest"].manifest_hash,
        "execution_record_hash": execution["execution_record_hash"],
        "native_artifact_manifest": native_manifest,
        "runtime_execution_proof": runtime_proof,
        "official_package_validation": official_validation,
        "technical_evidence": technical_evidence,
        "pilot_gate": pilot_gate,
        "denominator": {
            "expected_commands": len(context["commands"]),
            "retained_eval_archives": len(retained_archives),
            "benign_scored_cases": len(benign_rows),
            "harmful_scored_cases": len(harmful_rows),
            "paired_security_effect_cases": 0,
        },
        "claim_boundary": (
            "This package establishes replayable V0 capability and attack-opportunity "
            "evidence only. It does not estimate an Invart security effect because no "
            "paired V5 condition has been executed."
        ),
    }
    score_record["score_record_hash"] = stable_json_hash(score_record)
    return score_record


def _publish_scored_package(
    *,
    staging_root: Path,
    scored_dir: Path,
) -> None:
    os.rename(staging_root, scored_dir)


def _validated_execution_record(
    path: Path,
    *,
    context: Mapping[str, Any],
    approval: ProviderApprovalPacket,
) -> dict[str, Any]:
    record = read_owner_only_json(
        path,
        field_name="AgentHarm execution record",
    )
    observed_hash = str(record.get("execution_record_hash") or "")
    expected_hash = stable_json_hash(
        {key: value for key, value in record.items() if key != "execution_record_hash"}
    )
    if observed_hash != expected_hash:
        raise ValueError("AgentHarm execution record hash mismatch")
    expected_commands = context["commands"]
    command_records = record.get("commands")
    expected_bindings = [
        (item["command_id"], item["command_hash"]) for item in expected_commands
    ]
    observed_bindings = (
        [(item.get("command_id"), item.get("command_hash")) for item in command_records]
        if isinstance(command_records, list)
        and all(isinstance(item, Mapping) for item in command_records)
        else []
    )
    if (
        record.get("schema_version") != AGENTHARM_EXECUTION_RECORD_SCHEMA_VERSION
        or record.get("status") != "completed_unscored"
        or record.get("all_commands_succeeded") is not True
        or record.get("native_artifact_status") != "not_validated"
        or record.get("runtime_execution_proof") is not None
        or record.get("package_hash") != context["package"]["package_hash"]
        or record.get("request_hash") != context["request"]["request_hash"]
        or record.get("approval_hash") != approval.approval_hash
        or record.get("runtime_manifest_hash")
        != context["runtime_manifest"].manifest_hash
        or int(record.get("command_count") or -1) != len(expected_commands)
        or int(record.get("expected_command_count") or -1) != len(expected_commands)
        or observed_bindings != expected_bindings
        or not str(record.get("gateway_log_sha256") or "").startswith(
            "sha256:"
        )
        or record.get("budget_ledger_scope") != "approval_hash_global"
        or not str(record.get("budget_ledger_state_sha256") or "").startswith(
            "sha256:"
        )
    ):
        raise ValueError("AgentHarm execution record does not match launch package")
    return record


def _strict_gateway_receipts(
    path: Path,
    *,
    context: Mapping[str, Any],
    execution: Mapping[str, Any],
    approval: ProviderApprovalPacket,
) -> list[dict[str, Any]]:
    records = _owner_only_jsonl(path, field_name="AgentHarm gateway log")
    if sha256_file(path, prefixed=True) != execution["gateway_log_sha256"]:
        raise ValueError("AgentHarm gateway log hash does not match execution record")
    pending: dict[str, dict[str, Any]] = {}
    terminal: dict[str, dict[str, Any]] = {}
    for record in records:
        status = record.get("status")
        request_id = str(record.get("gateway_request_id") or "")
        if status == "reserved_pending":
            if not request_id or request_id in pending:
                raise ValueError("AgentHarm gateway reservations are not unique")
            pending[request_id] = record
        elif status == "forwarded":
            if not request_id or request_id in terminal:
                raise ValueError("AgentHarm gateway terminal records are not unique")
            terminal[request_id] = record
        else:
            raise ValueError("AgentHarm gateway log contains a non-success state")
    if not pending or set(pending) != set(terminal):
        raise ValueError("AgentHarm gateway reservation and terminal sets differ")
    request_command_bindings = _execution_gateway_request_bindings(execution)
    if set(pending) != set(request_command_bindings):
        raise ValueError("AgentHarm gateway request IDs do not match execution record")

    receipts: list[dict[str, Any]] = []
    runtime_manifest = context["runtime_manifest"]
    provider_profile = runtime_manifest.provider_profile
    if provider_profile is None:
        raise ValueError("AgentHarm runtime manifest provider profile is missing")
    expected_provider = provider_profile.profile_id
    expected_model = str(context["request"]["models"]["primary"])
    expected_manifest_hash = runtime_manifest.manifest_hash
    reserved_tokens = 0
    command_calls: dict[str, int] = {}
    command_tokens: dict[str, int] = {}
    for request_id in sorted(pending):
        ingress = pending[request_id]
        forwarded = terminal[request_id]
        if (
            ingress.get("schema_version") != GATEWAY_RECORD_SCHEMA_VERSION
            or forwarded.get("schema_version") != GATEWAY_RECORD_SCHEMA_VERSION
            or ingress.get("provider") != expected_provider
            or ingress.get("model") != expected_model
            or ingress.get("manifest_hash") != expected_manifest_hash
        ):
            raise ValueError("AgentHarm gateway receipt scope does not match execution")
        if any(
            ingress.get(field_name) != forwarded.get(field_name)
            for field_name in (
                "provider",
                "model",
                "manifest_hash",
                "request_hash",
                "forwarded_request_hash",
                "budget_reservation",
            )
        ):
            raise ValueError("AgentHarm gateway terminal does not match reservation")
        if not 200 <= int(forwarded.get("upstream_status") or 0) < 300:
            raise ValueError("AgentHarm gateway upstream response was not successful")
        if (
            forwarded.get("assistant_message_observed") is not True
            or forwarded.get("assistant_nonempty") is not True
            or not str(forwarded.get("assistant_message_hash") or "").startswith(
                "sha256:"
            )
        ):
            raise ValueError("AgentHarm gateway assistant response is missing or empty")
        reservation = ingress.get("budget_reservation")
        if not isinstance(reservation, Mapping):
            raise ValueError("AgentHarm gateway budget reservation is missing")
        if (
            reservation.get("approval_hash") != execution["approval_hash"]
            or reservation.get("manifest_hash") != expected_manifest_hash
            or reservation.get("request_id") != request_id
        ):
            raise ValueError("AgentHarm gateway reservation scope is invalid")
        try:
            reserved_at = datetime.fromisoformat(str(reservation["reserved_at"]))
        except (KeyError, ValueError) as exc:
            raise ValueError("AgentHarm gateway reservation time is invalid") from exc
        if (
            reserved_at.tzinfo is None
            or reserved_at.utcoffset() is None
            or not approval.approved_at <= reserved_at < approval.expires_at
        ):
            raise ValueError("AgentHarm gateway reservation was outside approval")
        reservation_tokens = int(reservation.get("tokens_reserved") or 0)
        reserved_tokens += reservation_tokens
        command_id = request_command_bindings[request_id]
        command_calls[command_id] = command_calls.get(command_id, 0) + 1
        command_tokens[command_id] = (
            command_tokens.get(command_id, 0) + reservation_tokens
        )
        receipt = {
            "request_id": request_id,
            "reservation_hash": stable_json_hash(dict(reservation)),
            "ingress_hash": stable_json_hash(ingress),
            "forwarded_hash": str(forwarded["forwarded_request_hash"]),
            "terminal_hash": stable_json_hash(forwarded),
            "terminal_status": "success",
            "assistant_nonempty": True,
            "assistant_message_hash": str(forwarded["assistant_message_hash"]),
        }
        receipt["receipt_hash"] = stable_json_hash(receipt)
        receipts.append(receipt)
    request = context["request"]
    if (
        len(receipts) > int(request["max_calls"])
        or reserved_tokens > int(request["max_total_tokens"])
    ):
        raise ValueError("AgentHarm gateway receipts exceed frozen request budget")
    maximum_calls_per_sample = int(request["maximum_calls_per_sample"])
    maximum_tokens_per_call = int(request["maximum_tokens_per_call"])
    if any(
        calls > maximum_calls_per_sample
        or command_tokens.get(command_id, 0)
        > maximum_calls_per_sample * maximum_tokens_per_call
        for command_id, calls in command_calls.items()
    ):
        raise ValueError("AgentHarm command receipts exceed frozen sample budget")
    return receipts


def _execution_gateway_request_bindings(
    execution: Mapping[str, Any],
) -> dict[str, str]:
    reconciliation = execution.get("gateway_reconciliation")
    if not isinstance(reconciliation, Mapping):
        raise ValueError("AgentHarm execution gateway reconciliation is missing")
    pending = {
        str(item)
        for item in reconciliation.get("pending_request_ids") or ()
        if str(item)
    }
    terminal = {
        str(item)
        for item in reconciliation.get("terminal_request_ids") or ()
        if str(item)
    }
    if not pending or pending != terminal:
        raise ValueError("AgentHarm execution gateway request sets are incomplete")
    request_bindings: dict[str, str] = {}
    for command in execution.get("commands") or ():
        if not isinstance(command, Mapping):
            raise ValueError("AgentHarm execution command record is invalid")
        command_reconciliation = command.get("gateway_reconciliation")
        if not isinstance(command_reconciliation, Mapping):
            raise ValueError("AgentHarm command gateway reconciliation is missing")
        command_pending = {
            str(item)
            for item in command_reconciliation.get("pending_request_ids") or ()
            if str(item)
        }
        command_terminal = {
            str(item)
            for item in command_reconciliation.get("terminal_request_ids") or ()
            if str(item)
        }
        if not command_pending or command_pending != command_terminal:
            raise ValueError("AgentHarm command gateway request sets are incomplete")
        if set(request_bindings) & command_pending:
            raise ValueError("AgentHarm gateway request ID is shared across commands")
        command_id = str(command.get("command_id") or "")
        if not command_id:
            raise ValueError("AgentHarm execution command ID is missing")
        request_bindings.update(
            {request_id: command_id for request_id in command_pending}
        )
    if set(request_bindings) != pending:
        raise ValueError("AgentHarm command gateway requests do not match execution")
    return request_bindings


def _build_technical_evidence(
    receipts: list[dict[str, Any]],
    *,
    request_hash: str,
    execution_record_hash: str,
    gateway_log_sha256: str,
    harmful_artifact_hashes: list[str],
    official_artifact_status: str,
) -> dict[str, Any]:
    evidence = {
        "schema_version": AGENTHARM_TECHNICAL_EVIDENCE_SCHEMA_VERSION,
        "status": "valid",
        "provider_ingress_count": len(receipts),
        "provider_forwarded_count": len(receipts),
        "provider_terminal_success_count": len(receipts),
        "provider_terminal_error_count": 0,
        "reservation_count": len(receipts),
        "assistant_message_count": len(receipts),
        "nonempty_assistant_message_count": len(receipts),
        "orphan_request_ids": [],
        "official_artifact_status": official_artifact_status,
        "request_hash": request_hash,
        "execution_record_hash": execution_record_hash,
        "gateway_log_sha256": gateway_log_sha256,
        "harmful_artifact_hashes": harmful_artifact_hashes,
        "receipt_records": receipts,
    }
    evidence["evidence_hash"] = stable_json_hash(evidence)
    return evidence


def _single_command_eval_archive(command: Mapping[str, Any]) -> Path:
    spec = command.get("command_spec")
    argv = list(spec.get("command") or ()) if isinstance(spec, Mapping) else []
    try:
        log_dir = Path(str(argv[argv.index("--log-dir") + 1]))
    except (ValueError, IndexError) as exc:
        raise ValueError("AgentHarm command log directory is missing") from exc
    root = require_owner_only_directory(
        log_dir,
        field_name="AgentHarm command log",
    )
    archives = [
        item
        for item in root.rglob("*.eval")
        if item.is_file() and not item.is_symlink()
    ]
    if len(archives) != 1:
        raise ValueError("AgentHarm command must retain exactly one Inspect Eval archive")
    return archives[0]


def _validate_row_against_command(
    row: Mapping[str, Any],
    *,
    command: Mapping[str, Any],
    request: Mapping[str, Any],
) -> None:
    expected_model = f"openai/{request['models']['primary']}"
    expected_judges = {
        "refusal": f"openai/{request['models']['refusal_judge']}",
        "semantic": f"openai/{request['models']['semantic_judge']}",
    }
    expected_kind = "benign" if command["role"] == "benign" else "harmful"
    if (
        row.get("case_id") != command.get("case_id")
        or row.get("epoch") != command.get("epoch")
        or row.get("task_kind") != expected_kind
        or row.get("model") != expected_model
        or row.get("judge_models") != expected_judges
    ):
        raise ValueError("AgentHarm scored row does not match its launch command")


def _build_native_manifest(root: Path) -> dict[str, Any]:
    files = [
        {
            "relative_path": str(path.relative_to(root)),
            "sha256": sha256_file(path, prefixed=True),
            "bytes": path.stat().st_size,
        }
        for path in sorted(root.iterdir())
        if path.is_file() and not path.is_symlink()
    ]
    manifest = {
        "schema_version": AGENTHARM_NATIVE_MANIFEST_SCHEMA_VERSION,
        "files": files,
    }
    manifest["manifest_hash"] = stable_json_hash(manifest)
    return manifest


def _owner_only_jsonl(path: Path, *, field_name: str) -> list[dict[str, Any]]:
    candidate = path.expanduser().absolute()
    if candidate.is_symlink() or not candidate.is_file():
        raise ValueError(f"{field_name} must be a regular non-symlink file")
    if candidate.stat().st_mode & 0o077:
        raise ValueError(f"{field_name} must be owner-only")
    rows: list[dict[str, Any]] = []
    for line in candidate.read_text(encoding="utf-8").splitlines():
        try:
            payload = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{field_name} is invalid JSONL") from exc
        if not isinstance(payload, dict):
            raise ValueError(f"{field_name} rows must be objects")
        rows.append(payload)
    return rows


def _copy_owner_only_file(source: Path, destination: Path) -> None:
    source_path = source.expanduser().absolute()
    if source_path.is_symlink() or not source_path.is_file():
        raise ValueError("AgentHarm source archive must be a regular non-symlink file")
    source_descriptor = os.open(source_path, os.O_RDONLY)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    destination_descriptor = os.open(destination, flags, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(source_descriptor).st_mode):
            raise ValueError("AgentHarm source archive must be regular")
        while True:
            chunk = os.read(source_descriptor, 1024 * 1024)
            if not chunk:
                break
            _write_all(destination_descriptor, chunk)
        os.fchmod(destination_descriptor, 0o600)
        os.fsync(destination_descriptor)
    finally:
        os.close(source_descriptor)
        os.close(destination_descriptor)


def _write_all(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("AgentHarm artifact write made no progress")
        view = view[written:]


def _safe_filename(value: str) -> str:
    if not value or any(character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-" for character in value):
        raise ValueError("AgentHarm case ID is unsafe for artifact naming")
    return value


__all__ = [
    "AGENTHARM_SCORE_RECORD_SCHEMA_VERSION",
    "finalize_agentharm_scored_package",
]
