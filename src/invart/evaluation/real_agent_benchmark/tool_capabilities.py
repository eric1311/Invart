from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import urlparse

from invart.core.artifacts import stable_json_hash


CAPABILITY_REGISTRY_SCHEMA_VERSION = "invart.tool_capability_registry.v0.1"
_BLINDING_FORBIDDEN_TOKENS = (
    "task_id",
    "user_task",
    "injection",
    "attack",
    "outcome",
    "security",
    "utility",
    "label",
    "ground_truth",
)


class Capability(str, Enum):
    READ = "read"
    WRITE = "write"
    COMMUNICATION = "communication"
    EXTERNAL_NETWORK = "external_network"
    DATA_EGRESS = "data_egress"
    FINANCIAL = "financial"
    DESTRUCTIVE = "destructive"
    ACCOUNT_MEMBERSHIP_ADMIN = "account_membership_admin"
    APPROVAL_REQUIRED = "approval_required"
    ATTACK_TARGET = "attack_target"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class ToolCapability:
    tool_name: str
    capabilities: frozenset[Capability]
    target_argument_keys: tuple[str, ...] = ()
    content_argument_keys: tuple[str, ...] = ()
    source: str = "schema_and_public_documentation"

    def __post_init__(self) -> None:
        name = str(self.tool_name or "").strip()
        if not name:
            raise ValueError("tool_name must be nonempty")
        object.__setattr__(self, "tool_name", name)
        capabilities = frozenset(Capability(value) for value in self.capabilities)
        if not capabilities:
            raise ValueError("capabilities must be nonempty")
        object.__setattr__(self, "capabilities", capabilities)
        for field_name in ("target_argument_keys", "content_argument_keys"):
            values = tuple(sorted({str(value).strip() for value in getattr(self, field_name) if str(value).strip()}))
            object.__setattr__(self, field_name, values)
        source = str(self.source or "").strip()
        if not source:
            raise ValueError("source must be nonempty")
        object.__setattr__(self, "source", source)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "capabilities": sorted(item.value for item in self.capabilities),
            "target_argument_keys": list(self.target_argument_keys),
            "content_argument_keys": list(self.content_argument_keys),
            "source": self.source,
        }


@dataclass(frozen=True)
class CapabilityRegistry:
    suite: str
    benchmark_version: str
    tools: tuple[ToolCapability, ...]
    schema_source_hash: str
    schema_version: str = CAPABILITY_REGISTRY_SCHEMA_VERSION
    registry_hash: str = field(init=False)

    def __post_init__(self) -> None:
        for field_name in ("suite", "benchmark_version", "schema_source_hash", "schema_version"):
            value = str(getattr(self, field_name) or "").strip()
            if not value:
                raise ValueError(f"{field_name} must be nonempty")
            object.__setattr__(self, field_name, value)
        ordered = tuple(sorted(self.tools, key=lambda item: item.tool_name))
        if len({item.tool_name for item in ordered}) != len(ordered):
            raise ValueError("tool capability entries must be unique")
        object.__setattr__(self, "tools", ordered)
        object.__setattr__(self, "registry_hash", stable_json_hash(self.to_dict(include_hash=False)))

    def resolve(self, tool_name: str) -> ToolCapability | None:
        normalized = str(tool_name or "").strip()
        return next((item for item in self.tools if item.tool_name == normalized), None)

    def to_dict(self, *, include_hash: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema_version": self.schema_version,
            "suite": self.suite,
            "benchmark_version": self.benchmark_version,
            "schema_source_hash": self.schema_source_hash,
            "tools": [item.to_dict() for item in self.tools],
            "unknown_tool_behavior": "ask",
            "claim_boundary": (
                "Capability mappings describe tool effects from schemas and public documentation. "
                "They do not encode task, injection, or benchmark outcome labels."
            ),
        }
        if include_hash:
            payload["registry_hash"] = self.registry_hash
        return payload


@dataclass(frozen=True)
class ToolCallAssessment:
    tool_name: str
    known_tool: bool
    capabilities: frozenset[Capability]
    target_argument_keys: tuple[str, ...]
    target_values: tuple[str, ...]
    dynamic_reason_codes: tuple[str, ...]
    registry_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "known_tool": self.known_tool,
            "capabilities": sorted(item.value for item in self.capabilities),
            "target_argument_keys": list(self.target_argument_keys),
            "target_values": list(self.target_values),
            "dynamic_reason_codes": list(self.dynamic_reason_codes),
            "registry_hash": self.registry_hash,
        }


def build_agentdojo_slack_registry() -> CapabilityRegistry:
    entries = (
        ToolCapability("get_channels", frozenset({Capability.READ})),
        ToolCapability(
            "add_user_to_channel",
            frozenset(
                {
                    Capability.WRITE,
                    Capability.ACCOUNT_MEMBERSHIP_ADMIN,
                    Capability.APPROVAL_REQUIRED,
                }
            ),
            target_argument_keys=("user", "channel"),
        ),
        ToolCapability(
            "read_channel_messages",
            frozenset({Capability.READ}),
            target_argument_keys=("channel",),
        ),
        ToolCapability("read_inbox", frozenset({Capability.READ}), target_argument_keys=("user",)),
        ToolCapability(
            "send_direct_message",
            frozenset({Capability.WRITE, Capability.COMMUNICATION, Capability.DATA_EGRESS}),
            target_argument_keys=("recipient",),
            content_argument_keys=("body",),
        ),
        ToolCapability(
            "send_channel_message",
            frozenset({Capability.WRITE, Capability.COMMUNICATION, Capability.DATA_EGRESS}),
            target_argument_keys=("channel",),
            content_argument_keys=("body",),
        ),
        ToolCapability(
            "get_users_in_channel",
            frozenset({Capability.READ}),
            target_argument_keys=("channel",),
        ),
        ToolCapability(
            "invite_user_to_slack",
            frozenset(
                {
                    Capability.WRITE,
                    Capability.COMMUNICATION,
                    Capability.EXTERNAL_NETWORK,
                    Capability.ACCOUNT_MEMBERSHIP_ADMIN,
                    Capability.APPROVAL_REQUIRED,
                }
            ),
            target_argument_keys=("user", "user_email"),
        ),
        ToolCapability(
            "remove_user_from_slack",
            frozenset(
                {
                    Capability.WRITE,
                    Capability.DESTRUCTIVE,
                    Capability.ACCOUNT_MEMBERSHIP_ADMIN,
                    Capability.APPROVAL_REQUIRED,
                }
            ),
            target_argument_keys=("user",),
        ),
        ToolCapability(
            "get_webpage",
            frozenset({Capability.READ, Capability.EXTERNAL_NETWORK}),
            target_argument_keys=("url",),
        ),
        ToolCapability(
            "post_webpage",
            frozenset({Capability.WRITE, Capability.EXTERNAL_NETWORK, Capability.DATA_EGRESS}),
            target_argument_keys=("url",),
            content_argument_keys=("content",),
        ),
    )
    schema_projection = [entry.to_dict() for entry in entries]
    return CapabilityRegistry(
        suite="agentdojo-slack",
        benchmark_version="v1.2.2-compatible-tools",
        tools=entries,
        schema_source_hash=stable_json_hash(schema_projection),
    )


def classify_tool_call(
    *,
    registry: CapabilityRegistry,
    tool_name: str,
    arguments: Mapping[str, Any],
    unauthorized_targets: Sequence[str] = (),
) -> ToolCallAssessment:
    name = str(tool_name or "").strip()
    entry = registry.resolve(name)
    if entry is None:
        return ToolCallAssessment(
            tool_name=name,
            known_tool=False,
            capabilities=frozenset({Capability.UNKNOWN}),
            target_argument_keys=(),
            target_values=(),
            dynamic_reason_codes=("unknown_tool",),
            registry_hash=registry.registry_hash,
        )
    values = tuple(
        str(arguments[key])
        for key in entry.target_argument_keys
        if key in arguments and isinstance(arguments[key], (str, int, float, bool))
    )
    capabilities = set(entry.capabilities)
    reasons: list[str] = []
    blocked_targets = {_normalize_target(value) for value in unauthorized_targets}
    if blocked_targets and any(_normalize_target(value) in blocked_targets for value in values):
        capabilities.add(Capability.ATTACK_TARGET)
        reasons.append("known_unauthorized_target")
    return ToolCallAssessment(
        tool_name=name,
        known_tool=True,
        capabilities=frozenset(capabilities),
        target_argument_keys=entry.target_argument_keys,
        target_values=values,
        dynamic_reason_codes=tuple(reasons),
        registry_hash=registry.registry_hash,
    )


def build_blinded_registry(
    *,
    suite: str,
    benchmark_version: str,
    tools: Sequence[Mapping[str, Any]],
    mappings: Mapping[str, Iterable[Capability]],
) -> CapabilityRegistry:
    allowed_schema_fields = {"name", "description", "parameters"}
    entries: list[ToolCapability] = []
    schema_projection: list[dict[str, Any]] = []
    for schema in tools:
        fields = {str(key) for key in schema}
        forbidden = sorted(
            field for field in fields if any(token in field.lower() for token in _BLINDING_FORBIDDEN_TOKENS)
        )
        if forbidden:
            raise ValueError(f"blinding-forbidden fields: {forbidden}")
        unknown = fields - allowed_schema_fields
        if unknown:
            raise ValueError(f"unsupported schema-only fields: {sorted(unknown)}")
        name = str(schema.get("name") or "").strip()
        if name not in mappings:
            raise ValueError(f"missing capability mapping for tool: {name}")
        entries.append(ToolCapability(name, frozenset(mappings[name]), source="blinded_schema_only"))
        schema_projection.append({key: schema.get(key) for key in sorted(fields)})
    if set(mappings) != {entry.tool_name for entry in entries}:
        raise ValueError("capability mappings contain undeclared tools")
    return CapabilityRegistry(
        suite=suite,
        benchmark_version=benchmark_version,
        tools=tuple(entries),
        schema_source_hash=stable_json_hash(schema_projection),
    )


def load_trusted_capability_registry(
    *,
    path: Path,
    expected_hash: str,
    workspace_root: Path,
) -> CapabilityRegistry:
    resolved = path.expanduser().resolve()
    workspace = workspace_root.expanduser().resolve()
    if resolved.is_relative_to(workspace):
        raise ValueError("trusted capability registry must be outside the agent workspace")
    if resolved.is_symlink() or not resolved.is_file():
        raise ValueError("trusted capability registry must be a regular non-symlink file")
    if resolved.stat().st_mode & 0o222:
        raise ValueError("trusted capability registry must be read-only")
    payload = json.loads(resolved.read_text(encoding="utf-8"))
    tools = tuple(
        ToolCapability(
            tool_name=item["tool_name"],
            capabilities=frozenset(Capability(value) for value in item["capabilities"]),
            target_argument_keys=tuple(item.get("target_argument_keys", ())),
            content_argument_keys=tuple(item.get("content_argument_keys", ())),
            source=str(item.get("source") or "schema_and_public_documentation"),
        )
        for item in payload.get("tools", [])
    )
    registry = CapabilityRegistry(
        suite=payload["suite"],
        benchmark_version=payload["benchmark_version"],
        tools=tools,
        schema_source_hash=payload["schema_source_hash"],
        schema_version=payload.get("schema_version", CAPABILITY_REGISTRY_SCHEMA_VERSION),
    )
    if registry.registry_hash != expected_hash or payload.get("registry_hash") != expected_hash:
        raise ValueError("trusted capability registry hash mismatch")
    return registry


def _normalize_target(value: str) -> str:
    rendered = str(value or "").strip().lower()
    parsed = urlparse(rendered if "://" in rendered else f"https://{rendered}")
    return (parsed.hostname or rendered).rstrip(".")


__all__ = [
    "Capability",
    "CapabilityRegistry",
    "ToolCallAssessment",
    "ToolCapability",
    "build_agentdojo_slack_registry",
    "build_blinded_registry",
    "classify_tool_call",
    "load_trusted_capability_registry",
]
