from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from invart.core.ledger import append_ledger_entry, load_ledger_entries
from invart.core.models import LedgerEntry, utc_now


IDENTITY_SCHEMA_VERSION = "invart.identity.v0.19"


@dataclass(frozen=True)
class Principal:
    principal_id: str
    display_name: str | None = None
    source: str = "local"
    declared_at: str = field(default_factory=utc_now)
    local_signature: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class AgentIdentity:
    agent_id: str
    declared_by: str
    adapter_agent: str | None = None
    identity_source: str = "user_declared"
    declared_at: str = field(default_factory=utc_now)
    validation_status: str = "validated"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class CredentialBinding:
    binding_id: str
    owner_principal_id: str
    env_keys: list[dict[str, Any]]
    redacted_values: int
    recorded_at: str = field(default_factory=utc_now)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class CapabilityGrant:
    grant_id: str
    principal_id: str
    agent_id: str
    scopes: list[str]
    resources: list[str]
    issued_at: str = field(default_factory=utc_now)
    expires_at: str | None = None
    status: str = "active"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def declare_principal(principal_id: str, *, display_name: str | None = None, source: str = "local") -> Principal:
    if not principal_id:
        raise ValueError("principal_id is required")
    material = json.dumps({"principal_id": principal_id, "source": source}, sort_keys=True)
    signature = "local-sha256:" + hashlib.sha256(material.encode("utf-8")).hexdigest()
    return Principal(principal_id=principal_id, display_name=display_name, source=source, local_signature=signature)


def bind_agent_identity(agent_id: str, *, declared_by: str, adapter_agent: str | None = None) -> AgentIdentity:
    if not agent_id:
        raise ValueError("agent_id is required")
    if not declared_by:
        raise ValueError("declared_by is required")
    status = "validated" if adapter_agent is None or adapter_agent == agent_id else "mismatch"
    return AgentIdentity(agent_id=agent_id, declared_by=declared_by, adapter_agent=adapter_agent, validation_status=status)


def credential_inventory(env: dict[str, str], *, owner: str) -> CredentialBinding:
    keys: list[dict[str, Any]] = []
    redacted = 0
    for key in sorted(env):
        value = env[key]
        sensitive = _is_sensitive_key(key) or _looks_like_secret(value)
        if sensitive:
            redacted += 1
        keys.append(
            {
                "key": key,
                "value": "[REDACTED]" if sensitive else _fold_value(value),
                "redacted": sensitive,
                "sha256": hashlib.sha256(value.encode("utf-8")).hexdigest() if sensitive else None,
            }
        )
    return CredentialBinding(binding_id="cred_" + uuid.uuid4().hex[:16], owner_principal_id=owner, env_keys=keys, redacted_values=redacted)


def create_capability_grant(
    *,
    principal_id: str,
    agent_id: str,
    scopes: list[str],
    resources: list[str],
    expires_at: str | None = None,
) -> CapabilityGrant:
    if not principal_id or not agent_id:
        raise ValueError("capability grant requires principal_id and agent_id")
    if not scopes:
        raise ValueError("capability grant requires at least one scope")
    return CapabilityGrant(
        grant_id="grant_" + uuid.uuid4().hex[:16],
        principal_id=principal_id,
        agent_id=agent_id,
        scopes=list(scopes),
        resources=list(resources),
        expires_at=expires_at,
    )


def record_identity_binding(
    ledger_path: Path,
    *,
    session_id: str,
    principal: Principal,
    agent_identity: AgentIdentity,
    credentials: CredentialBinding | None = None,
    grants: list[CapabilityGrant] | None = None,
) -> dict[str, Any]:
    payload = {
        "schema_version": IDENTITY_SCHEMA_VERSION,
        "type": "identity_binding",
        "session_id": session_id,
        "principal": principal.to_dict(),
        "agent_identity": agent_identity.to_dict(),
        "credential_boundary": credentials.to_dict() if credentials else None,
        "capability_grants": [grant.to_dict() for grant in grants or []],
        "recorded_at": utc_now(),
    }
    entry = LedgerEntry(
        sequence=0,
        entry_id="led_" + uuid.uuid4().hex[:16],
        session_id=session_id,
        timestamp=payload["recorded_at"],
        entry_type="identity",
        event=payload,
        result={"status": "bound", "principal_id": principal.principal_id, "agent_id": agent_identity.agent_id},
    )
    appended = append_ledger_entry(entry, ledger_path)
    return {"binding": payload, "entry": appended.to_dict()}


def accountability_from_ledger(ledger_path: Path) -> dict[str, Any]:
    entries, _warnings = load_ledger_entries(ledger_path)
    result: dict[str, Any] = {
        "schema_version": IDENTITY_SCHEMA_VERSION,
        "principal": None,
        "agent_identity": None,
        "credential_boundary": {"env_keys": [], "redacted_values": 0},
        "capability_grants": [],
    }
    for entry in entries:
        if entry.entry_type != "identity" or not entry.event:
            continue
        event = entry.event
        if event.get("principal"):
            result["principal"] = dict(event["principal"])
        if event.get("agent_identity"):
            result["agent_identity"] = dict(event["agent_identity"])
        if isinstance(event.get("credential_boundary"), dict):
            result["credential_boundary"] = dict(event["credential_boundary"])
        if isinstance(event.get("capability_grants"), list):
            result["capability_grants"].extend(dict(item) for item in event["capability_grants"] if isinstance(item, dict))
    return result


def validate_session_identity(agent: str | None, metadata: dict[str, Any] | None) -> None:
    metadata = metadata or {}
    profile = metadata.get("policy_profile_config") if isinstance(metadata.get("policy_profile_config"), dict) else {}
    identity_policy = profile.get("identity") if isinstance(profile.get("identity"), dict) else {}
    required = bool(identity_policy.get("required"))
    principal = metadata.get("principal") if isinstance(metadata.get("principal"), dict) else None
    agent_identity = metadata.get("agent_identity") if isinstance(metadata.get("agent_identity"), dict) else None
    if required and not principal:
        raise ValueError("managed identity policy requires principal")
    if required and not agent_identity:
        raise ValueError("managed identity policy requires agent identity")
    if agent_identity:
        declared = str(agent_identity.get("agent_id") or "")
        adapter_agent = str(agent_identity.get("adapter_agent") or declared)
        if agent and declared and agent != declared:
            raise ValueError("agent identity mismatch: session agent differs from declared agent identity")
        if declared and adapter_agent and declared != adapter_agent:
            raise ValueError("agent identity mismatch: adapter agent differs from declared agent identity")
    allowed = identity_policy.get("allowed_agents") if isinstance(identity_policy.get("allowed_agents"), list) else []
    if allowed and agent and agent not in {str(item) for item in allowed}:
        raise ValueError("agent identity mismatch: session agent is not allowed by profile")


def _is_sensitive_key(key: str) -> bool:
    lowered = key.lower()
    return any(marker in lowered for marker in ("key", "token", "secret", "password", "credential"))


def _looks_like_secret(value: str) -> bool:
    lowered = value.lower()
    return lowered.startswith(("sk-", "akia")) or "secret" in lowered or len(value) > 80


def _fold_value(value: str, limit: int = 64) -> str:
    return value if len(value) <= limit else value[:limit] + "..."


__all__ = [
    "AgentIdentity",
    "CapabilityGrant",
    "CredentialBinding",
    "Principal",
    "accountability_from_ledger",
    "bind_agent_identity",
    "create_capability_grant",
    "credential_inventory",
    "declare_principal",
    "record_identity_binding",
    "validate_session_identity",
]
