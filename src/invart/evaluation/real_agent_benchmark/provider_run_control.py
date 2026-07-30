from __future__ import annotations

import fcntl
import json
import os
import re
import stat
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from invart.core.artifacts import stable_json_dumps, stable_json_hash

from .agent_runtime_manifest import RuntimeManifest


PROVIDER_APPROVAL_SCHEMA_VERSION = "invart.provider_run_approval.v0.1"
_AUTHORIZATION_BEARER_RE = re.compile(r"(?i)Authorization\s*:\s*Bearer\s+[^\s\"']+")
_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b[A-Z][A-Z0-9_]*(?:API_KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)[A-Z0-9_]*"
    r"\s*=\s*[^\s\"']+"
)


def _utc(value: datetime, *, field_name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")
    return value.astimezone(timezone.utc)


@dataclass(frozen=True)
class ProviderApprovalPacket:
    approval_id: str
    approved_by: str
    approved_at: datetime
    expires_at: datetime
    manifest_hash: str
    provider: str
    endpoint: str
    model_ids: tuple[str, ...]
    max_calls: int
    max_total_tokens: int
    purpose: str
    schema_version: str = PROVIDER_APPROVAL_SCHEMA_VERSION
    approval_hash: str = field(init=False)

    def __post_init__(self) -> None:
        for name in (
            "approval_id",
            "approved_by",
            "manifest_hash",
            "provider",
            "endpoint",
            "purpose",
            "schema_version",
        ):
            value = str(getattr(self, name) or "").strip()
            if not value:
                raise ValueError(f"{name} must be nonempty")
            object.__setattr__(self, name, value)
        approved_at = _utc(self.approved_at, field_name="approved_at")
        expires_at = _utc(self.expires_at, field_name="expires_at")
        if expires_at <= approved_at:
            raise ValueError("expires_at must be later than approved_at")
        object.__setattr__(self, "approved_at", approved_at)
        object.__setattr__(self, "expires_at", expires_at)
        models = tuple(sorted({str(model).strip() for model in self.model_ids if str(model).strip()}))
        if not models:
            raise ValueError("model_ids must be nonempty")
        object.__setattr__(self, "model_ids", models)
        for name in ("max_calls", "max_total_tokens"):
            value = int(getattr(self, name))
            if value <= 0:
                raise ValueError(f"{name} must be positive")
            object.__setattr__(self, name, value)
        object.__setattr__(self, "approval_hash", stable_json_hash(self.to_dict(include_hash=False)))

    def to_dict(self, *, include_hash: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema_version": self.schema_version,
            "approval_id": self.approval_id,
            "approved_by": self.approved_by,
            "approved_at": self.approved_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "manifest_hash": self.manifest_hash,
            "provider": self.provider,
            "endpoint": self.endpoint,
            "model_ids": list(self.model_ids),
            "max_calls": self.max_calls,
            "max_total_tokens": self.max_total_tokens,
            "purpose": self.purpose,
            "claim_boundary": (
                "This packet authorizes only the bound provider execution budget. It is not benchmark "
                "evidence and does not authorize a different manifest, endpoint, model, or purpose."
            ),
        }
        if include_hash:
            payload["approval_hash"] = self.approval_hash
        return payload


def create_provider_approval_packet(
    *,
    approval_id: str,
    approved_by: str,
    approved_at: datetime,
    expires_at: datetime,
    manifest_hash: str,
    provider: str,
    endpoint: str,
    model_ids: Iterable[str],
    max_calls: int,
    max_total_tokens: int,
    purpose: str,
) -> ProviderApprovalPacket:
    return ProviderApprovalPacket(
        approval_id=approval_id,
        approved_by=approved_by,
        approved_at=approved_at,
        expires_at=expires_at,
        manifest_hash=manifest_hash,
        provider=provider,
        endpoint=endpoint,
        model_ids=tuple(model_ids),
        max_calls=max_calls,
        max_total_tokens=max_total_tokens,
        purpose=purpose,
    )


def load_provider_approval_packet(path: Path) -> ProviderApprovalPacket:
    resolved = path.expanduser().absolute()
    if resolved.is_symlink() or not resolved.is_file():
        raise ValueError("provider approval must be a regular non-symlink file")
    if resolved.stat().st_mode & 0o077:
        raise ValueError("provider approval must be owner-only")
    try:
        payload = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("provider approval is invalid JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError("provider approval must be an object")
    try:
        approval = ProviderApprovalPacket(
            approval_id=payload["approval_id"],
            approved_by=payload["approved_by"],
            approved_at=datetime.fromisoformat(payload["approved_at"]),
            expires_at=datetime.fromisoformat(payload["expires_at"]),
            manifest_hash=payload["manifest_hash"],
            provider=payload["provider"],
            endpoint=payload["endpoint"],
            model_ids=tuple(payload["model_ids"]),
            max_calls=payload["max_calls"],
            max_total_tokens=payload["max_total_tokens"],
            purpose=payload["purpose"],
            schema_version=payload.get("schema_version", PROVIDER_APPROVAL_SCHEMA_VERSION),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("provider approval has invalid fields") from exc
    if payload.get("approval_hash") != approval.approval_hash:
        raise ValueError("provider approval hash mismatch")
    return approval


def write_provider_approval_packet(
    path: Path,
    approval: ProviderApprovalPacket,
) -> Path:
    target = path.expanduser().absolute()
    if target.is_symlink():
        raise ValueError("provider approval output must not be a symlink")
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    target.parent.chmod(0o700)
    descriptor = os.open(
        target,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600,
    )
    try:
        os.fchmod(descriptor, 0o600)
        encoded = json.dumps(approval.to_dict(), ensure_ascii=False, indent=2, sort_keys=True)
        os.write(descriptor, (encoded + "\n").encode("utf-8"))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return target


def write_owner_only_json(
    path: Path,
    payload: Mapping[str, Any],
    *,
    field_name: str = "provider artifact",
) -> Path:
    target = path.expanduser().absolute()
    current = Path(target.anchor)
    for part in target.parts[1:]:
        current /= part
        try:
            mode = os.lstat(current).st_mode
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(mode):
            raise ValueError(f"{field_name} path must not traverse symlinks")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(target, flags, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError(f"{field_name} must be a regular file")
        with os.fdopen(descriptor, "w", encoding="utf-8", closefd=False) as stream:
            os.fchmod(descriptor, 0o600)
            stream.write(stable_json_dumps(payload))
            stream.flush()
            os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return target


class ProviderBudgetLedger:
    """Crash-persistent, process-safe reservation ledger for one approval packet."""

    def __init__(self, *, approval: ProviderApprovalPacket, state_path: Path) -> None:
        self.approval = approval
        self.state_path = state_path.expanduser().absolute()
        self._validate_state_path()

    def reserve(
        self,
        *,
        manifest: RuntimeManifest,
        maximum_tokens: int,
        at: datetime | None = None,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        requested_tokens = int(maximum_tokens)
        if requested_tokens <= 0:
            raise ValueError("maximum_tokens must be positive")
        now = _utc(at or datetime.now(timezone.utc), field_name="at")
        self.validate_scope(manifest=manifest, at=now)
        normalized_request_id = str(request_id or "").strip() or None

        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        self.state_path.parent.chmod(0o700)
        self._validate_state_path()
        flags = os.O_RDWR | os.O_CREAT
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(self.state_path, flags, 0o600)
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise RuntimeError("budget ledger state must be a regular file")
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "r+", encoding="utf-8", closefd=False) as handle:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
                raw = handle.read().strip()
                state = json.loads(raw) if raw else self._empty_state()
                if state.get("approval_hash") != self.approval.approval_hash:
                    raise RuntimeError("budget ledger approval hash mismatch")
                calls = int(state.get("calls_reserved") or 0)
                tokens = int(state.get("tokens_reserved") or 0)
                reservations = state.get("reservations")
                if not isinstance(reservations, list):
                    reservations = []
                if normalized_request_id and any(
                    item.get("request_id") == normalized_request_id
                    for item in reservations
                    if isinstance(item, dict)
                ):
                    raise RuntimeError("provider request ID was already reserved")
                if calls >= self.approval.max_calls:
                    raise RuntimeError("provider call budget exhausted")
                if tokens + requested_tokens > self.approval.max_total_tokens:
                    raise RuntimeError("provider token budget exhausted")
                calls += 1
                tokens += requested_tokens
                state.update(
                    {
                        "calls_reserved": calls,
                        "tokens_reserved": tokens,
                        "reservations": [
                            *reservations,
                            {
                                "request_id": normalized_request_id,
                                "call_index": calls,
                                "tokens_reserved": requested_tokens,
                                "manifest_hash": manifest.manifest_hash,
                                "reserved_at": now.isoformat(),
                            },
                        ],
                        "updated_at": now.isoformat(),
                    }
                )
                handle.seek(0)
                handle.truncate()
                json.dump(state, handle, ensure_ascii=False, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        finally:
            os.close(descriptor)
        return {
            "schema_version": "invart.provider_budget_reservation.v0.1",
            "approval_hash": self.approval.approval_hash,
            "manifest_hash": manifest.manifest_hash,
            "call_index": calls,
            "tokens_reserved": requested_tokens,
            "request_id": normalized_request_id,
            "remaining_calls": self.approval.max_calls - calls,
            "remaining_tokens": self.approval.max_total_tokens - tokens,
        }

    def validate_scope(
        self,
        *,
        manifest: RuntimeManifest,
        at: datetime | None = None,
    ) -> dict[str, Any]:
        """Validate an approval binding without reserving calls or tokens."""

        now = _utc(at or datetime.now(timezone.utc), field_name="at")
        self._validate_scope(manifest=manifest, at=now)
        return {
            "schema_version": "invart.provider_approval_scope_validation.v0.1",
            "status": "valid_provider_approval_scope",
            "approval_hash": self.approval.approval_hash,
            "manifest_hash": manifest.manifest_hash,
            "validated_at": now.isoformat(),
        }

    def _validate_scope(self, *, manifest: RuntimeManifest, at: datetime) -> None:
        approval = self.approval
        if at < approval.approved_at:
            raise RuntimeError("approval is not active yet")
        if at >= approval.expires_at:
            raise RuntimeError("approval expired")
        if manifest.manifest_hash != approval.manifest_hash:
            raise RuntimeError("provider approval manifest hash mismatch")
        profile = manifest.provider_profile
        if profile is None:
            raise RuntimeError("provider approval requires a resolved provider profile")
        if profile.profile_id != approval.provider:
            raise RuntimeError("provider approval provider mismatch")
        if profile.base_url.rstrip("/") != approval.endpoint.rstrip("/"):
            raise RuntimeError("provider approval endpoint mismatch")
        if manifest.request.requested_model not in approval.model_ids:
            raise RuntimeError("provider approval model mismatch")

    def _empty_state(self) -> dict[str, Any]:
        return {
            "schema_version": "invart.provider_budget_ledger.v0.1",
            "approval_hash": self.approval.approval_hash,
            "calls_reserved": 0,
            "tokens_reserved": 0,
            "reservations": [],
        }

    def _validate_state_path(self) -> None:
        if self.state_path.is_symlink():
            raise ValueError("budget ledger state must not be a symlink")
        if self.state_path.exists():
            if not self.state_path.is_file():
                raise ValueError("budget ledger state must be a regular file")
            if self.state_path.stat().st_mode & 0o077:
                raise ValueError("budget ledger state must be owner-only")


def secure_provider_artifact_tree(root: Path) -> None:
    resolved = root.expanduser().resolve()
    if not resolved.exists() or not resolved.is_dir():
        raise ValueError("artifact root must be an existing directory")
    for path in sorted((item for item in resolved.rglob("*") if not item.is_symlink()), reverse=True):
        if path.is_file():
            owner_executable = bool(path.stat().st_mode & stat.S_IXUSR)
            path.chmod(0o700 if owner_executable else 0o600)
        elif path.is_dir():
            path.chmod(0o700)
    resolved.chmod(0o700)


def scan_provider_artifact_tree(
    root: Path,
    *,
    secret_values: Sequence[str] = (),
    require_owner_only: bool = True,
    maximum_file_bytes: int = 10 * 1024 * 1024,
) -> dict[str, Any]:
    resolved = root.expanduser().resolve()
    if not resolved.exists() or not resolved.is_dir():
        raise ValueError("artifact root must be an existing directory")
    secrets = tuple(sorted({str(value) for value in secret_values if str(value)}, key=len, reverse=True))
    secret_matches: list[dict[str, str]] = []
    permission_violations: list[dict[str, str]] = []
    symlinks: list[str] = []
    scan_errors: list[dict[str, str]] = []
    scanned_files = 0

    paths = [resolved, *sorted(resolved.rglob("*"))]
    for path in paths:
        relative = "." if path == resolved else str(path.relative_to(resolved))
        if path.is_symlink():
            symlinks.append(relative)
            continue
        if require_owner_only and path.stat().st_mode & 0o077:
            permission_violations.append(
                {"file": relative, "mode": oct(path.stat().st_mode & 0o777)}
            )
        if not path.is_file():
            continue
        if path.stat().st_size > maximum_file_bytes:
            scan_errors.append({"file": relative, "reason": "file_exceeds_scan_limit"})
            continue
        try:
            content = path.read_bytes()
        except OSError:
            scan_errors.append({"file": relative, "reason": "file_unreadable"})
            continue
        scanned_files += 1
        for secret in secrets:
            if secret.encode("utf-8") in content:
                secret_matches.append({"file": relative, "kind": "exact_secret_value"})
                break
        text = content.decode("utf-8", errors="replace")
        if _AUTHORIZATION_BEARER_RE.search(text):
            secret_matches.append({"file": relative, "kind": "authorization_bearer"})
        if _SECRET_ASSIGNMENT_RE.search(text):
            secret_matches.append({"file": relative, "kind": "secret_assignment"})

    status = "pass"
    if secret_matches or permission_violations or symlinks or scan_errors:
        status = "fail"
    return {
        "schema_version": "invart.provider_artifact_tree_scan.v0.1",
        "status": status,
        "root_name": resolved.name,
        "scanned_files": scanned_files,
        "secret_matches": secret_matches,
        "permission_violations": permission_violations,
        "symlinks": symlinks,
        "scan_errors": scan_errors,
    }
