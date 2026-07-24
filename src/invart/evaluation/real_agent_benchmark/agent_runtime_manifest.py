from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Iterable, Optional

from invart.core.artifacts import sha256_file, stable_json_hash


RUNTIME_MANIFEST_SCHEMA_VERSION = "invart.agent_runtime_manifest.v0.1"
RUNTIME_EXECUTION_PROOF_SCHEMA_VERSION = "invart.runtime_execution_proof.v0.1"


class ExecutionContract(str, Enum):
    COMPLETION_BACKEND = "completion_backend"
    NATIVE_RUNTIME = "native_runtime"


class ClaimKind(str, Enum):
    COMPLETION_BACKEND = "completion_backend"
    NATIVE_RUNTIME = "native_runtime"
    NATIVE_CONTROL = "native_control"
    OBSERVE_ONLY = "observe_only"


EvidenceKind = ClaimKind


def _is_prefixed_sha256(value: str) -> bool:
    prefix, separator, digest = value.partition(":")
    return (
        prefix == "sha256"
        and separator == ":"
        and len(digest) == 64
        and all(character in "0123456789abcdef" for character in digest)
    )


def _freeze_nonempty_string(instance: object, field_name: str) -> None:
    value = str(getattr(instance, field_name) or "").strip()
    if not value:
        raise ValueError(f"{field_name} must be nonempty")
    object.__setattr__(instance, field_name, value)


def _frozen_string_set(values: Iterable[str], *, field_name: str) -> tuple[str, ...]:
    source = tuple(values)
    normalized = tuple(sorted({str(value).strip() for value in source if str(value).strip()}))
    if len(normalized) != len(source):
        raise ValueError(f"{field_name} must contain unique nonempty values")
    return normalized


@dataclass(frozen=True)
class ProviderProfile:
    profile_id: str
    base_url: str
    credential_env_name: str
    preferred_model: str
    hosted: bool
    checkpoint_verifiable: bool
    attribution_scope: str

    def __post_init__(self) -> None:
        for field_name in (
            "profile_id",
            "base_url",
            "credential_env_name",
            "preferred_model",
            "attribution_scope",
        ):
            _freeze_nonempty_string(self, field_name)
        if self.hosted and self.checkpoint_verifiable and self.attribution_scope == "hosted_deployment_stack":
            raise ValueError("hosted_deployment_stack attribution cannot claim checkpoint verification")

    def to_dict(self) -> dict[str, Any]:
        return {
            "profile_id": self.profile_id,
            "base_url": self.base_url,
            "credential_env_name": self.credential_env_name,
            "preferred_model": self.preferred_model,
            "hosted": self.hosted,
            "checkpoint_verifiable": self.checkpoint_verifiable,
            "attribution_scope": self.attribution_scope,
        }


QWENCLOUD_TOKEN_PLAN = ProviderProfile(
    profile_id="qwencloud-token-plan",
    base_url="https://token-plan.cn-beijing.maas.aliyuncs.com/compatible-mode/v1",
    credential_env_name="DASHSCOPE_TP_API_KEY",
    preferred_model="deepseek-v4-pro",
    hosted=True,
    checkpoint_verifiable=False,
    attribution_scope="hosted_deployment_stack",
)


def provider_profile_for_id(profile_id: str) -> Optional[ProviderProfile]:
    if str(profile_id or "").strip() == QWENCLOUD_TOKEN_PLAN.profile_id:
        return QWENCLOUD_TOKEN_PLAN
    return None


def hash_runtime_state_tree(root: Path) -> str:
    """Hash names, types, modes, and contents without serializing local absolute paths."""

    resolved = root.expanduser().resolve()
    if not resolved.exists() or not resolved.is_dir():
        raise ValueError("runtime state root must be an existing directory")
    entries: list[dict[str, Any]] = []
    for item in sorted(resolved.rglob("*")):
        relative = str(item.relative_to(resolved))
        if item.is_symlink():
            raise ValueError(f"runtime state cannot contain symlinks: {relative}")
        if item.is_dir():
            entries.append({"path": relative, "kind": "directory"})
        elif item.is_file():
            entries.append(
                {
                    "path": relative,
                    "kind": "file",
                    "sha256": sha256_file(item, prefixed=True),
                    "owner_executable": bool(item.stat().st_mode & 0o100),
                }
            )
        else:
            raise ValueError(f"unsupported runtime state entry: {relative}")
    return stable_json_hash({"schema_version": "invart.runtime_state_tree.v0.1", "entries": entries})


@dataclass(frozen=True)
class RuntimeRequest:
    requested_provider: str
    requested_model: str
    agent_product: str
    low_level_runtime: str
    execution_contract: ExecutionContract
    evidence_kind: ClaimKind

    def __post_init__(self) -> None:
        for field_name in (
            "requested_provider",
            "requested_model",
            "agent_product",
            "low_level_runtime",
        ):
            _freeze_nonempty_string(self, field_name)
        execution_contract = ExecutionContract(self.execution_contract)
        evidence_kind = ClaimKind(self.evidence_kind)
        object.__setattr__(self, "execution_contract", execution_contract)
        object.__setattr__(self, "evidence_kind", evidence_kind)
        if execution_contract is ExecutionContract.COMPLETION_BACKEND and evidence_kind in {
            ClaimKind.NATIVE_RUNTIME,
            ClaimKind.NATIVE_CONTROL,
        }:
            raise ValueError(
                f"completion_backend execution cannot emit {evidence_kind.value} evidence"
            )
        if execution_contract is ExecutionContract.NATIVE_RUNTIME and evidence_kind is ClaimKind.COMPLETION_BACKEND:
            raise ValueError("native_runtime execution cannot emit completion_backend evidence")

    def to_dict(self) -> dict[str, str]:
        return {
            "requested_provider": self.requested_provider,
            "requested_model": self.requested_model,
            "agent_product": self.agent_product,
            "low_level_runtime": self.low_level_runtime,
            "execution_contract": self.execution_contract.value,
            "evidence_kind": self.evidence_kind.value,
        }


def completion_backend_request(
    *,
    requested_provider: str,
    requested_model: str,
    agent_product: str,
    low_level_runtime: str,
    evidence_kind: ClaimKind = ClaimKind.COMPLETION_BACKEND,
) -> RuntimeRequest:
    return RuntimeRequest(
        requested_provider=requested_provider,
        requested_model=requested_model,
        agent_product=agent_product,
        low_level_runtime=low_level_runtime,
        execution_contract=ExecutionContract.COMPLETION_BACKEND,
        evidence_kind=evidence_kind,
    )


def native_runtime_request(
    *,
    requested_provider: str,
    requested_model: str,
    agent_product: str,
    low_level_runtime: str,
    evidence_kind: ClaimKind = ClaimKind.NATIVE_RUNTIME,
) -> RuntimeRequest:
    return RuntimeRequest(
        requested_provider=requested_provider,
        requested_model=requested_model,
        agent_product=agent_product,
        low_level_runtime=low_level_runtime,
        execution_contract=ExecutionContract.NATIVE_RUNTIME,
        evidence_kind=evidence_kind,
    )


@dataclass(frozen=True)
class RuntimeManifest:
    request: RuntimeRequest
    provider_profile: Optional[ProviderProfile] = None
    profile_name: str = "comparable-clean"
    agent_version: str = "unknown"
    runtime_version: str = "unknown"
    tool_allowlist: tuple[str, ...] = ()
    memory_hashes: tuple[str, ...] = ()
    skill_hashes: tuple[str, ...] = ()
    declared_fallbacks: tuple[str, ...] = ()
    profile_state_hash: Optional[str] = None
    schema_version: str = RUNTIME_MANIFEST_SCHEMA_VERSION
    manifest_hash: str = field(init=False)

    def __post_init__(self) -> None:
        for field_name in ("profile_name", "agent_version", "runtime_version", "schema_version"):
            _freeze_nonempty_string(self, field_name)
        if self.provider_profile is not None and self.provider_profile.profile_id != self.request.requested_provider:
            raise ValueError("provider profile does not match requested_provider")
        for field_name in ("tool_allowlist", "memory_hashes", "skill_hashes", "declared_fallbacks"):
            values = _frozen_string_set(getattr(self, field_name), field_name=field_name)
            object.__setattr__(self, field_name, values)
        profile_state_hash = str(self.profile_state_hash or "").strip() or None
        object.__setattr__(self, "profile_state_hash", profile_state_hash)
        if self.profile_name == "comparable-clean" and (self.memory_hashes or self.skill_hashes):
            raise ValueError("comparable-clean profiles cannot declare memory or skill state")
        object.__setattr__(self, "manifest_hash", stable_json_hash(self.to_dict(include_hash=False)))

    @property
    def checkpoint_model_family_claimable(self) -> bool:
        return bool(self.provider_profile and self.provider_profile.checkpoint_verifiable)

    @property
    def attribution_scope(self) -> str:
        if self.provider_profile is None:
            return "unverified_runtime_resolution"
        return self.provider_profile.attribution_scope

    def to_dict(self, *, include_hash: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema_version": self.schema_version,
            "request": self.request.to_dict(),
            "provider_profile": self.provider_profile.to_dict() if self.provider_profile else None,
            "profile_name": self.profile_name,
            "agent_version": self.agent_version,
            "runtime_version": self.runtime_version,
            "tool_allowlist": list(self.tool_allowlist),
            "memory_hashes": list(self.memory_hashes),
            "skill_hashes": list(self.skill_hashes),
            "declared_fallbacks": list(self.declared_fallbacks),
            "profile_state_hash": self.profile_state_hash,
            "checkpoint_model_family_claimable": self.checkpoint_model_family_claimable,
            "attribution_scope": self.attribution_scope,
        }
        if include_hash:
            payload["manifest_hash"] = self.manifest_hash
        return payload


def build_runtime_manifest(
    *,
    request: RuntimeRequest,
    provider_profile: Optional[ProviderProfile] = None,
    profile_name: str = "comparable-clean",
    agent_version: str = "unknown",
    runtime_version: str = "unknown",
    tool_allowlist: Iterable[str] = (),
    memory_hashes: Iterable[str] = (),
    skill_hashes: Iterable[str] = (),
    declared_fallbacks: Iterable[str] = (),
    profile_state_hash: Optional[str] = None,
) -> RuntimeManifest:
    return RuntimeManifest(
        request=request,
        provider_profile=provider_profile,
        profile_name=profile_name,
        agent_version=agent_version,
        runtime_version=runtime_version,
        tool_allowlist=tuple(tool_allowlist),
        memory_hashes=tuple(memory_hashes),
        skill_hashes=tuple(skill_hashes),
        declared_fallbacks=tuple(declared_fallbacks),
        profile_state_hash=profile_state_hash,
    )


@dataclass(frozen=True)
class RuntimeReceipt:
    resolved_provider: str
    resolved_model: str
    resolved_agent_product: str
    resolved_low_level_runtime: str
    fallback_used: bool = False
    fallback_id: Optional[str] = None
    resolved_profile_state_hash: Optional[str] = None

    def __post_init__(self) -> None:
        for field_name in (
            "resolved_provider",
            "resolved_model",
            "resolved_agent_product",
            "resolved_low_level_runtime",
        ):
            _freeze_nonempty_string(self, field_name)
        fallback_id = str(self.fallback_id or "").strip() or None
        object.__setattr__(self, "fallback_id", fallback_id)
        state_hash = str(self.resolved_profile_state_hash or "").strip() or None
        object.__setattr__(self, "resolved_profile_state_hash", state_hash)
        if fallback_id and not self.fallback_used:
            raise ValueError("fallback_id requires fallback_used=True")

    def to_dict(self) -> dict[str, Any]:
        return {
            "resolved_provider": self.resolved_provider,
            "resolved_model": self.resolved_model,
            "resolved_agent_product": self.resolved_agent_product,
            "resolved_low_level_runtime": self.resolved_low_level_runtime,
            "fallback_used": self.fallback_used,
            "fallback_id": self.fallback_id,
            "resolved_profile_state_hash": self.resolved_profile_state_hash,
        }


def build_runtime_receipt(
    *,
    resolved_provider: str,
    resolved_model: str,
    resolved_agent_product: str,
    resolved_low_level_runtime: str,
    fallback_used: bool = False,
    fallback_id: Optional[str] = None,
    resolved_profile_state_hash: Optional[str] = None,
) -> RuntimeReceipt:
    return RuntimeReceipt(
        resolved_provider=resolved_provider,
        resolved_model=resolved_model,
        resolved_agent_product=resolved_agent_product,
        resolved_low_level_runtime=resolved_low_level_runtime,
        fallback_used=fallback_used,
        fallback_id=fallback_id,
        resolved_profile_state_hash=resolved_profile_state_hash,
    )


@dataclass(frozen=True)
class RuntimeReceiptValidation:
    valid: bool
    status: str
    reasons: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {"valid": self.valid, "status": self.status, "reasons": list(self.reasons)}


def validate_runtime_receipt(
    manifest: RuntimeManifest,
    receipt: RuntimeReceipt,
) -> RuntimeReceiptValidation:
    request = manifest.request
    reasons: list[str] = []
    if receipt.resolved_provider != request.requested_provider:
        reasons.append("provider_mismatch")
    if receipt.resolved_model != request.requested_model:
        reasons.append("model_mismatch")
    if receipt.resolved_agent_product != request.agent_product:
        reasons.append("agent_product_mismatch")
    if receipt.resolved_low_level_runtime != request.low_level_runtime:
        reasons.append("low_level_runtime_mismatch")
    if receipt.fallback_used and (
        receipt.fallback_id is None or receipt.fallback_id not in manifest.declared_fallbacks
    ):
        reasons.append("undeclared_fallback")
    if manifest.profile_state_hash and not receipt.resolved_profile_state_hash:
        reasons.append("profile_state_receipt_missing")
    elif (
        manifest.profile_state_hash
        and receipt.resolved_profile_state_hash != manifest.profile_state_hash
    ):
        reasons.append("profile_state_mismatch")
    valid = not reasons
    return RuntimeReceiptValidation(
        valid=valid,
        status="valid_runtime_resolution" if valid else "invalid_runtime_resolution",
        reasons=tuple(reasons),
    )


@dataclass(frozen=True)
class RuntimeExecutionProof:
    runtime_manifest_hash: str
    runtime_receipt: RuntimeReceipt
    native_artifact_sha256: str
    execution_record_hash: str
    proof_hash: str
    schema_version: str = RUNTIME_EXECUTION_PROOF_SCHEMA_VERSION

    def __post_init__(self) -> None:
        for field_name in (
            "runtime_manifest_hash",
            "native_artifact_sha256",
            "execution_record_hash",
            "proof_hash",
            "schema_version",
        ):
            _freeze_nonempty_string(self, field_name)
        if not isinstance(self.runtime_receipt, RuntimeReceipt):
            raise TypeError("runtime_receipt must be a RuntimeReceipt")
        for field_name in (
            "runtime_manifest_hash",
            "native_artifact_sha256",
            "execution_record_hash",
            "proof_hash",
        ):
            if not _is_prefixed_sha256(getattr(self, field_name)):
                raise ValueError(f"{field_name} must be a prefixed sha256 digest")

    def to_dict(self, *, include_hash: bool = True) -> dict[str, Any]:
        payload = _runtime_execution_proof_material(
            schema_version=self.schema_version,
            runtime_manifest_hash=self.runtime_manifest_hash,
            runtime_receipt=self.runtime_receipt,
            native_artifact_sha256=self.native_artifact_sha256,
            execution_record_hash=self.execution_record_hash,
        )
        if include_hash:
            payload["proof_hash"] = self.proof_hash
        return payload


def _runtime_execution_proof_material(
    *,
    schema_version: str,
    runtime_manifest_hash: str,
    runtime_receipt: RuntimeReceipt,
    native_artifact_sha256: str,
    execution_record_hash: str,
) -> dict[str, Any]:
    return {
        "schema_version": schema_version,
        "runtime_manifest_hash": runtime_manifest_hash,
        "runtime_receipt": runtime_receipt.to_dict(),
        "native_artifact_sha256": native_artifact_sha256,
        "execution_record_hash": execution_record_hash,
    }


def build_runtime_execution_proof(
    *,
    runtime_manifest: RuntimeManifest,
    runtime_receipt: RuntimeReceipt,
    native_artifact_sha256: str,
    execution_record_hash: str,
) -> RuntimeExecutionProof:
    observed_manifest_hash = stable_json_hash(runtime_manifest.to_dict(include_hash=False))
    if runtime_manifest.manifest_hash != observed_manifest_hash:
        raise ValueError("runtime manifest hash does not match manifest contents")
    receipt_validation = validate_runtime_receipt(runtime_manifest, runtime_receipt)
    if not receipt_validation.valid:
        raise ValueError(
            "runtime receipt does not match runtime manifest: "
            + ", ".join(receipt_validation.reasons)
        )
    material = _runtime_execution_proof_material(
        schema_version=RUNTIME_EXECUTION_PROOF_SCHEMA_VERSION,
        runtime_manifest_hash=observed_manifest_hash,
        runtime_receipt=runtime_receipt,
        native_artifact_sha256=str(native_artifact_sha256 or "").strip(),
        execution_record_hash=str(execution_record_hash or "").strip(),
    )
    return RuntimeExecutionProof(
        runtime_manifest_hash=observed_manifest_hash,
        runtime_receipt=runtime_receipt,
        native_artifact_sha256=material["native_artifact_sha256"],
        execution_record_hash=material["execution_record_hash"],
        proof_hash=stable_json_hash(material),
    )


@dataclass(frozen=True)
class RuntimeExecutionProofValidation:
    valid: bool
    status: str
    reasons: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {"valid": self.valid, "status": self.status, "reasons": list(self.reasons)}


def validate_runtime_execution_proof(
    runtime_manifest: RuntimeManifest,
    proof: RuntimeExecutionProof,
    *,
    native_artifact_sha256: str,
) -> RuntimeExecutionProofValidation:
    reasons: list[str] = []
    observed_manifest_hash = stable_json_hash(runtime_manifest.to_dict(include_hash=False))
    if runtime_manifest.manifest_hash != observed_manifest_hash:
        reasons.append("runtime_manifest_hash_invalid")
    if proof.schema_version != RUNTIME_EXECUTION_PROOF_SCHEMA_VERSION:
        reasons.append("schema_version_mismatch")
    if proof.runtime_manifest_hash != observed_manifest_hash:
        reasons.append("runtime_manifest_hash_mismatch")
    receipt_validation = validate_runtime_receipt(runtime_manifest, proof.runtime_receipt)
    reasons.extend(receipt_validation.reasons)
    if proof.native_artifact_sha256 != str(native_artifact_sha256 or "").strip():
        reasons.append("native_artifact_sha256_mismatch")
    if not str(proof.execution_record_hash or "").strip():
        reasons.append("execution_record_hash_missing")
    expected_proof_hash = stable_json_hash(proof.to_dict(include_hash=False))
    if proof.proof_hash != expected_proof_hash:
        reasons.append("proof_hash_mismatch")
    valid = not reasons
    return RuntimeExecutionProofValidation(
        valid=valid,
        status=(
            "valid_runtime_execution_proof"
            if valid
            else "invalid_runtime_execution_proof"
        ),
        reasons=tuple(reasons),
    )


__all__ = [
    "ClaimKind",
    "EvidenceKind",
    "ExecutionContract",
    "ProviderProfile",
    "QWENCLOUD_TOKEN_PLAN",
    "RUNTIME_EXECUTION_PROOF_SCHEMA_VERSION",
    "RUNTIME_MANIFEST_SCHEMA_VERSION",
    "RuntimeExecutionProof",
    "RuntimeExecutionProofValidation",
    "RuntimeManifest",
    "RuntimeReceipt",
    "RuntimeReceiptValidation",
    "RuntimeRequest",
    "build_runtime_execution_proof",
    "build_runtime_manifest",
    "build_runtime_receipt",
    "completion_backend_request",
    "hash_runtime_state_tree",
    "native_runtime_request",
    "provider_profile_for_id",
    "validate_runtime_execution_proof",
    "validate_runtime_receipt",
]
