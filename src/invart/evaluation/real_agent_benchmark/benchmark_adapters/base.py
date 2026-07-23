from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any, Mapping, Protocol, Sequence

from invart.core.artifacts import stable_json_hash


ADAPTER_SCHEMA_VERSION = "invart.benchmark_adapter.v0.1"
_RUNTIME_POLICY_FORBIDDEN = (
    "task_id",
    "case_id",
    "injection",
    "attack",
    "outcome",
    "security",
    "utility",
    "label",
    "ground_truth",
    "rubric",
    "judge",
    "expected",
    "answer",
)


class CaseRole(str, Enum):
    CLEAN = "clean"
    ATTACK = "attack"
    CAPABILITY = "capability"


class EffectState(str, Enum):
    PROPOSED = "proposed"
    ATTEMPTED = "attempted"
    PREVENTED = "prevented"
    EXECUTED = "executed"
    FAILED = "failed"


class EvidenceKind(str, Enum):
    NATIVE_RUNTIME = "native_runtime"
    ADAPTER_COMPARABLE = "adapter_comparable"
    DETERMINISTIC_ORACLE = "deterministic_oracle"
    JUDGE = "judge"
    SIDE_EFFECT = "side_effect"


class ProvenanceSurface(str, Enum):
    USER_OBJECTIVE = "user_objective"
    TOOL_NAME = "tool_name"
    TOOL_DESCRIPTION = "tool_description"
    TOOL_SCHEMA = "tool_schema"
    TOOL_ARGUMENTS = "tool_arguments"
    TOOL_RESULT = "tool_result"
    SERVER = "server"


@dataclass(frozen=True)
class BenchmarkSourceFreeze:
    benchmark_id: str
    source_url: str
    revision: str
    license: str
    split: str
    allowed_network_destinations: tuple[str, ...] = ()
    companion_sources: tuple[Mapping[str, str], ...] = ()
    source_hash: str = field(init=False)

    def __post_init__(self) -> None:
        for name in ("benchmark_id", "source_url", "revision", "license", "split"):
            value = str(getattr(self, name) or "").strip()
            if not value:
                raise ValueError(f"{name} must be nonempty")
            object.__setattr__(self, name, value)
        if not self.source_url.startswith("https://"):
            raise ValueError("source_url must use https")
        destinations = tuple(sorted({str(item).strip().lower() for item in self.allowed_network_destinations if str(item).strip()}))
        object.__setattr__(self, "allowed_network_destinations", destinations)
        object.__setattr__(self, "companion_sources", tuple(_freeze(item) for item in self.companion_sources))
        object.__setattr__(self, "source_hash", stable_json_hash(self.to_dict(include_hash=False)))

    def to_dict(self, *, include_hash: bool = True) -> dict[str, Any]:
        payload = {
            "benchmark_id": self.benchmark_id,
            "source_url": self.source_url,
            "revision": self.revision,
            "license": self.license,
            "split": self.split,
            "allowed_network_destinations": list(self.allowed_network_destinations),
            "companion_sources": [_thaw(item) for item in self.companion_sources],
        }
        if include_hash:
            payload["source_hash"] = self.source_hash
        return payload


@dataclass(frozen=True)
class BenchmarkCase:
    benchmark_id: str
    case_id: str
    role: CaseRole
    comparison_key: str | None
    user_objective: str
    tool_schemas: tuple[Mapping[str, Any], ...]
    capability_profile: Mapping[str, Sequence[str]]
    adapter_metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for name in ("benchmark_id", "case_id", "user_objective"):
            value = str(getattr(self, name) or "").strip()
            if not value:
                raise ValueError(f"{name} must be nonempty")
            object.__setattr__(self, name, value)
        object.__setattr__(self, "role", CaseRole(self.role))
        key = str(self.comparison_key).strip() if self.comparison_key is not None else None
        object.__setattr__(self, "comparison_key", key or None)
        schemas = tuple(_freeze(item) for item in self.tool_schemas)
        _reject_runtime_forbidden(schemas)
        object.__setattr__(self, "tool_schemas", schemas)
        profile = _freeze({
            str(name): tuple(sorted({str(value) for value in values}))
            for name, values in self.capability_profile.items()
        })
        _reject_runtime_forbidden(profile)
        object.__setattr__(self, "capability_profile", profile)
        object.__setattr__(self, "adapter_metadata", _freeze(self.adapter_metadata))

    def runtime_policy_projection(self) -> dict[str, Any]:
        payload = {
            "user_objective": self.user_objective,
            "tool_schemas": [_thaw(item) for item in self.tool_schemas],
            "capability_profile": _thaw(self.capability_profile),
        }
        _reject_runtime_forbidden(payload)
        return payload


@dataclass(frozen=True)
class NativeBenchmarkOutcome:
    benchmark_id: str
    case_id: str
    artifact_sha256: str
    validator_id: str
    native_metrics: Mapping[str, Any]
    source_hash: str

    def __post_init__(self) -> None:
        for name in ("benchmark_id", "case_id", "artifact_sha256", "validator_id", "source_hash"):
            value = str(getattr(self, name) or "").strip()
            if not value:
                raise ValueError(f"{name} must be nonempty")
            object.__setattr__(self, name, value)
        if not self.artifact_sha256.startswith("sha256:"):
            raise ValueError("artifact_sha256 must be prefixed")
        if not self.source_hash.startswith("sha256:"):
            raise ValueError("source_hash must be prefixed")
        object.__setattr__(self, "native_metrics", _freeze(self.native_metrics))


@dataclass(frozen=True)
class CommonActionEvent:
    benchmark_id: str
    case_id: str
    action_id: str
    tool_name: str
    effect: EffectState
    provenance_surface: ProvenanceSurface
    evidence_kind: EvidenceKind
    authorization_evidence_refs: tuple[str, ...] = ()
    side_effect_evidence_refs: tuple[str, ...] = ()
    native_event_ref: str | None = None

    def __post_init__(self) -> None:
        for name in ("benchmark_id", "case_id", "action_id", "tool_name"):
            value = str(getattr(self, name) or "").strip()
            if not value:
                raise ValueError(f"{name} must be nonempty")
            object.__setattr__(self, name, value)
        object.__setattr__(self, "effect", EffectState(self.effect))
        object.__setattr__(self, "provenance_surface", ProvenanceSurface(self.provenance_surface))
        object.__setattr__(self, "evidence_kind", EvidenceKind(self.evidence_kind))
        for name in ("authorization_evidence_refs", "side_effect_evidence_refs"):
            refs = tuple(sorted({str(item).strip() for item in getattr(self, name) if str(item).strip()}))
            object.__setattr__(self, name, refs)

    def to_dict(self) -> dict[str, Any]:
        return {
            "benchmark_id": self.benchmark_id,
            "case_id": self.case_id,
            "action_id": self.action_id,
            "tool_name": self.tool_name,
            "effect": self.effect.value,
            "provenance_surface": self.provenance_surface.value,
            "evidence_kind": self.evidence_kind.value,
            "authorization_evidence_refs": list(self.authorization_evidence_refs),
            "side_effect_evidence_refs": list(self.side_effect_evidence_refs),
            "native_event_ref": self.native_event_ref,
        }


class BenchmarkAdapter(Protocol):
    benchmark_id: str

    def source_freeze(self) -> BenchmarkSourceFreeze: ...
    def enumerate_cases(self, payload: Mapping[str, Any]) -> tuple[BenchmarkCase, ...]: ...
    def validate_native_result(self, *, case: BenchmarkCase, artifact: Any) -> NativeBenchmarkOutcome: ...
    def join_events(self, *, case: BenchmarkCase, records: Sequence[Mapping[str, Any]]) -> tuple[CommonActionEvent, ...]: ...


def _reject_runtime_forbidden(
    value: Any,
    *,
    path: str = "root",
    schema_property_names: bool = False,
) -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            rendered = str(key).lower()
            if not schema_property_names and any(token in rendered for token in _RUNTIME_POLICY_FORBIDDEN):
                raise ValueError(f"runtime-policy-forbidden field at {path}.{key}")
            _reject_runtime_forbidden(
                child,
                path=f"{path}.{key}",
                schema_property_names=rendered == "properties",
            )
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            _reject_runtime_forbidden(child, path=f"{path}[{index}]")


def normalize_effect_state(value: Any) -> EffectState:
    rendered = str(value or "").strip().lower()
    if rendered == "blocked":
        rendered = EffectState.PREVENTED.value
    return EffectState(rendered)


def thaw_payload(value: Any) -> Any:
    return _thaw(value)


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({str(key): _freeze(child) for key, child in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(child) for child in value)
    if isinstance(value, (set, frozenset)):
        return tuple(sorted((_freeze(child) for child in value), key=str))
    return value


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _thaw(child) for key, child in value.items()}
    if isinstance(value, (list, tuple)):
        return [_thaw(child) for child in value]
    return value


__all__ = [
    "ADAPTER_SCHEMA_VERSION",
    "BenchmarkAdapter",
    "BenchmarkCase",
    "BenchmarkSourceFreeze",
    "CaseRole",
    "CommonActionEvent",
    "EffectState",
    "EvidenceKind",
    "NativeBenchmarkOutcome",
    "ProvenanceSurface",
    "normalize_effect_state",
    "thaw_payload",
]
