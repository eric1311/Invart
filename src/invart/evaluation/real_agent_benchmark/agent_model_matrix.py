from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from invart.core.artifacts import stable_json_hash, write_json_artifact

from .provider_run_control import scan_provider_artifact_tree, secure_provider_artifact_tree


MATRIX_SCHEMA_VERSION = "invart.agent_model_matrix.v0.1"
SELECTION_INPUTS = (
    "availability_rate",
    "checkpoint_reproducible",
    "clean_utility_rate",
    "tool_call_validity_rate",
)
_SELECTION_SOURCE_FIELDS = frozenset(
    {
        "model_family",
        "runtime",
        "clean_tasks_total",
        "clean_tasks_successful",
        "tool_calls_total",
        "tool_calls_valid",
        "availability_checks",
        "availability_successes",
        "checkpoint_reproducible",
    }
)
_SELECTION_FORBIDDEN_TOKENS = (
    "attack",
    "asr",
    "harm",
    "mediation",
    "policy",
    "intervention",
    "false_block",
    "security_effect",
)


class CompletenessState(str, Enum):
    NOT_RUN = "not_run"
    COMPLETE = "complete"
    PROVIDER_TIMEOUT = "provider_timeout"
    MISSING_CREDENTIALS = "missing_credentials"
    MISSING_RUNTIME = "missing_runtime"
    UNSUPPORTED_MODEL = "unsupported_model"
    RUNTIME_MISMATCH = "runtime_mismatch"
    INVALID_RUNTIME_RESOLUTION = "invalid_runtime_resolution"
    TECHNICAL_ERROR = "technical_error"


@dataclass(frozen=True)
class ModelCandidate:
    family: str
    provider: str
    model_id: str
    availability: str
    hosted: bool
    checkpoint_verifiable: bool
    checkpoint_revision: str | None = None

    def __post_init__(self) -> None:
        for name in ("family", "provider", "model_id", "availability"):
            value = str(getattr(self, name) or "").strip().lower() if name == "family" else str(
                getattr(self, name) or ""
            ).strip()
            if not value:
                raise ValueError(f"{name} must be nonempty")
            object.__setattr__(self, name, value)
        revision = str(self.checkpoint_revision or "").strip() or None
        object.__setattr__(self, "checkpoint_revision", revision)
        if self.checkpoint_verifiable and not revision:
            raise ValueError("checkpoint-verifiable candidates require checkpoint_revision")

    @property
    def attribution_scope(self) -> str:
        return "checkpoint_model" if self.checkpoint_verifiable else "hosted_deployment_stack"

    def to_dict(self) -> dict[str, Any]:
        return {
            "family": self.family,
            "provider": self.provider,
            "model_id": self.model_id,
            "availability": self.availability,
            "hosted": self.hosted,
            "checkpoint_verifiable": self.checkpoint_verifiable,
            "checkpoint_revision": self.checkpoint_revision,
            "attribution_scope": self.attribution_scope,
        }


def default_model_candidates() -> dict[str, ModelCandidate]:
    """Pre-registered candidates; availability is not a substitute for a frozen preflight."""

    return {
        "kimi": ModelCandidate(
            family="kimi",
            provider="unresolved-kimi-provider",
            model_id="kimi-k2.5",
            availability="provider_and_checkpoint_unresolved",
            hosted=True,
            checkpoint_verifiable=False,
        ),
        "deepseek": ModelCandidate(
            family="deepseek",
            provider="qwencloud-token-plan",
            model_id="deepseek-v4-pro",
            availability="compatibility_probe_requires_artifact_binding",
            hosted=True,
            checkpoint_verifiable=False,
        ),
        "qwen": ModelCandidate(
            family="qwen",
            provider="qwencloud-token-plan",
            model_id="qwen3.7-max",
            availability="compatibility_probe_not_run",
            hosted=True,
            checkpoint_verifiable=False,
        ),
    }


@dataclass(frozen=True)
class MatrixRow:
    row_id: str
    agent_product: str
    model_family: str
    provider: str
    model_id: str
    lanes: tuple[str, ...]
    claim_kind: str
    attribution_scope: str
    candidate_availability: str
    completeness_state: CompletenessState = CompletenessState.NOT_RUN

    def __post_init__(self) -> None:
        for name in (
            "row_id",
            "agent_product",
            "model_family",
            "provider",
            "model_id",
            "claim_kind",
            "attribution_scope",
            "candidate_availability",
        ):
            value = str(getattr(self, name) or "").strip()
            if not value:
                raise ValueError(f"{name} must be nonempty")
            object.__setattr__(self, name, value)
        lanes = tuple(sorted({str(lane).strip() for lane in self.lanes if str(lane).strip()}))
        if not lanes:
            raise ValueError("lanes must be nonempty")
        object.__setattr__(self, "lanes", lanes)
        object.__setattr__(self, "completeness_state", CompletenessState(self.completeness_state))

    def to_dict(self) -> dict[str, Any]:
        return {
            "row_id": self.row_id,
            "agent_product": self.agent_product,
            "model_family": self.model_family,
            "provider": self.provider,
            "model_id": self.model_id,
            "lanes": list(self.lanes),
            "claim_kind": self.claim_kind,
            "attribution_scope": self.attribution_scope,
            "candidate_availability": self.candidate_availability,
            "completeness_state": self.completeness_state.value,
        }


@dataclass(frozen=True)
class AgentModelPanel:
    rows: tuple[MatrixRow, ...]
    common_family: str
    sentinel_family: str
    schema_version: str = MATRIX_SCHEMA_VERSION
    matrix_hash: str = field(init=False)

    def __post_init__(self) -> None:
        if len({row.row_id for row in self.rows}) != len(self.rows):
            raise ValueError("matrix row IDs must be unique")
        if self.common_family == self.sentinel_family:
            raise ValueError("common and sentinel families must differ")
        object.__setattr__(self, "matrix_hash", stable_json_hash(self.to_dict(include_hash=False)))

    @property
    def model_family_rows(self) -> tuple[MatrixRow, ...]:
        return tuple(row for row in self.rows if "model_family" in row.lanes)

    @property
    def common_runtime_rows(self) -> tuple[MatrixRow, ...]:
        return tuple(row for row in self.rows if "runtime_comparison" in row.lanes)

    @property
    def sentinel_rows(self) -> tuple[MatrixRow, ...]:
        return tuple(row for row in self.rows if "sentinel_interaction" in row.lanes)

    @property
    def native_control_rows(self) -> tuple[MatrixRow, ...]:
        return tuple(row for row in self.rows if "native_control" in row.lanes)

    @property
    def controlled_model_rows(self) -> tuple[MatrixRow, ...]:
        return tuple(row for row in self.rows if row.claim_kind != "native_control")

    @property
    def is_connected(self) -> bool:
        rows = self.controlled_model_rows
        if not rows:
            return False
        graph: dict[str, set[str]] = {}
        for row in rows:
            agent = f"agent:{row.agent_product}"
            model = f"model:{row.model_family}"
            graph.setdefault(agent, set()).add(model)
            graph.setdefault(model, set()).add(agent)
        visited: set[str] = set()
        frontier = [next(iter(graph))]
        while frontier:
            node = frontier.pop()
            if node in visited:
                continue
            visited.add(node)
            frontier.extend(graph[node] - visited)
        return visited == set(graph)

    def to_dict(self, *, include_hash: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema_version": self.schema_version,
            "common_family": self.common_family,
            "sentinel_family": self.sentinel_family,
            "rows": [row.to_dict() for row in self.rows],
            "connected": self.is_connected,
            "claim_boundary": (
                "Switchable-runtime rows are completion-backend evidence until native-runtime "
                "conformance is independently proven. Hosted candidates support deployment-stack, "
                "not checkpoint-isolated, attribution."
            ),
        }
        if include_hash:
            payload["matrix_hash"] = self.matrix_hash
        return payload


def build_default_connected_panel(
    *,
    candidates: Mapping[str, ModelCandidate],
    common_family: str,
    sentinel_family: str,
) -> AgentModelPanel:
    normalized = {str(name).strip().lower(): candidate for name, candidate in candidates.items()}
    required = {"kimi", "deepseek", "qwen"}
    if set(normalized) != required:
        raise ValueError(f"candidates must contain exactly {sorted(required)}")
    common = str(common_family).strip().lower()
    sentinel = str(sentinel_family).strip().lower()
    if common not in normalized or sentinel not in normalized or common == sentinel:
        raise ValueError("common and sentinel families must be distinct declared candidates")

    rows: list[MatrixRow] = []
    for family in ("kimi", "deepseek", "qwen"):
        candidate = normalized[family]
        lanes = ["model_family"]
        if family == common:
            lanes.append("runtime_comparison")
        rows.append(_controlled_row("opencode", candidate, lanes=lanes))
    for runtime in ("hermes", "openclaw"):
        rows.append(_controlled_row(runtime, normalized[common], lanes=("runtime_comparison",)))
    for runtime in ("hermes", "openclaw"):
        rows.append(_controlled_row(runtime, normalized[sentinel], lanes=("sentinel_interaction",)))
    rows.extend(
        (
            _native_control_row("codex"),
            _native_control_row("claude-code"),
        )
    )
    return AgentModelPanel(rows=tuple(rows), common_family=common, sentinel_family=sentinel)


def _controlled_row(agent_product: str, candidate: ModelCandidate, *, lanes: Iterable[str]) -> MatrixRow:
    return MatrixRow(
        row_id=f"{agent_product}--{candidate.model_id}",
        agent_product=agent_product,
        model_family=candidate.family,
        provider=candidate.provider,
        model_id=candidate.model_id,
        lanes=tuple(lanes),
        claim_kind="completion_backend",
        attribution_scope=candidate.attribution_scope,
        candidate_availability=candidate.availability,
    )


def _native_control_row(agent_product: str) -> MatrixRow:
    return MatrixRow(
        row_id=f"{agent_product}--native",
        agent_product=agent_product,
        model_family="vendor-native",
        provider="vendor-native",
        model_id="runtime-resolved-required",
        lanes=("native_control",),
        claim_kind="native_control",
        attribution_scope="native_deployment_stack",
        candidate_availability="runtime_preflight_required",
    )


@dataclass(frozen=True)
class PreflightEvidence:
    model_family: str
    runtime: str
    clean_tasks_total: int
    clean_tasks_successful: int
    tool_calls_total: int
    tool_calls_valid: int
    availability_checks: int
    availability_successes: int
    checkpoint_reproducible: bool

    def __post_init__(self) -> None:
        family = str(self.model_family or "").strip().lower()
        if not family:
            raise ValueError("model_family must be nonempty")
        object.__setattr__(self, "model_family", family)
        runtime = str(self.runtime or "").strip().lower()
        if not runtime:
            raise ValueError("runtime must be nonempty")
        object.__setattr__(self, "runtime", runtime)
        for total_name, success_name in (
            ("clean_tasks_total", "clean_tasks_successful"),
            ("tool_calls_total", "tool_calls_valid"),
            ("availability_checks", "availability_successes"),
        ):
            total = int(getattr(self, total_name))
            success = int(getattr(self, success_name))
            if total <= 0 or success < 0 or success > total:
                raise ValueError(f"invalid preflight counts: {success_name}/{total_name}")
            object.__setattr__(self, total_name, total)
            object.__setattr__(self, success_name, success)

    @classmethod
    def from_mapping(cls, payload: Mapping[str, Any]) -> PreflightEvidence:
        keys = {str(key) for key in payload}
        forbidden = sorted(
            key for key in keys if any(token in key.lower() for token in _SELECTION_FORBIDDEN_TOKENS)
        )
        if forbidden:
            raise ValueError(f"selection-forbidden fields: {forbidden}")
        unknown = sorted(keys - _SELECTION_SOURCE_FIELDS)
        missing = sorted(_SELECTION_SOURCE_FIELDS - keys)
        if unknown or missing:
            raise ValueError(f"invalid selection fields: unknown={unknown}, missing={missing}")
        return cls(**{name: payload[name] for name in _SELECTION_SOURCE_FIELDS})

    @property
    def clean_utility_rate(self) -> float:
        return self.clean_tasks_successful / self.clean_tasks_total

    @property
    def tool_call_validity_rate(self) -> float:
        return self.tool_calls_valid / self.tool_calls_total

    @property
    def availability_rate(self) -> float:
        return self.availability_successes / self.availability_checks

    @property
    def compatibility_score(self) -> float:
        return (
            self.clean_utility_rate
            + self.tool_call_validity_rate
            + self.availability_rate
            + float(self.checkpoint_reproducible)
        ) / 4.0

    def selection_dict(self) -> dict[str, Any]:
        return {
            "model_family": self.model_family,
            "runtime": self.runtime,
            "clean_utility_rate": self.clean_utility_rate,
            "tool_call_validity_rate": self.tool_call_validity_rate,
            "availability_rate": self.availability_rate,
            "checkpoint_reproducible": self.checkpoint_reproducible,
            "compatibility_score": self.compatibility_score,
        }


@dataclass(frozen=True)
class ModelSelection:
    common_family: str
    sentinel_family: str
    ranked_families: tuple[str, ...]
    selection_inputs: tuple[str, ...]
    selection_hash: str


def select_common_and_sentinel_models(evidence: Sequence[PreflightEvidence]) -> ModelSelection:
    if len(evidence) < 5:
        raise ValueError("model selection requires runtime-specific preflight evidence")
    if len({(item.model_family, item.runtime) for item in evidence}) != len(evidence):
        raise ValueError("preflight evidence must contain one row per model-family/runtime pair")
    by_family: dict[str, dict[str, PreflightEvidence]] = {}
    for item in evidence:
        by_family.setdefault(item.model_family, {})[item.runtime] = item
    common_runtimes = {"opencode", "hermes", "openclaw"}
    common_candidates = {
        family: rows
        for family, rows in by_family.items()
        if common_runtimes.issubset(rows)
    }
    if not common_candidates:
        raise ValueError("no common-model candidate covers opencode, hermes, and openclaw")
    ranked = tuple(
        family
        for family, _rows in sorted(
            common_candidates.items(),
            key=lambda item: (_family_rank(item[1]), item[0]),
        )
    )
    common = ranked[0]
    sentinel_runtimes = {"hermes", "openclaw"}
    sentinel_candidates = {
        family: rows
        for family, rows in by_family.items()
        if family != common and sentinel_runtimes.issubset(rows)
    }
    if not sentinel_candidates:
        raise ValueError("no second sentinel candidate covers hermes and openclaw")
    sentinel = min(
        sentinel_candidates.items(),
        key=lambda item: (_family_rank(item[1]), item[0]),
    )[0]
    payload = {
        "selection_inputs": list(SELECTION_INPUTS),
        "ranked": [
            item.selection_dict()
            for item in sorted(evidence, key=lambda item: (item.model_family, item.runtime))
        ],
        "required_common_runtimes": sorted(common_runtimes),
        "required_sentinel_runtimes": sorted(sentinel_runtimes),
        "common_family": common,
        "sentinel_family": sentinel,
    }
    return ModelSelection(
        common_family=common,
        sentinel_family=sentinel,
        ranked_families=ranked,
        selection_inputs=SELECTION_INPUTS,
        selection_hash=stable_json_hash(payload),
    )


def _family_rank(rows: Mapping[str, PreflightEvidence]) -> tuple[float, float]:
    scores = [item.compatibility_score for item in rows.values()]
    return (-min(scores), -(sum(scores) / len(scores)))


@dataclass(frozen=True)
class CapabilityThresholds:
    minimum_clean_utility_rate: float
    minimum_tool_call_validity_rate: float

    def __post_init__(self) -> None:
        for name in ("minimum_clean_utility_rate", "minimum_tool_call_validity_rate"):
            value = float(getattr(self, name))
            if not 0.0 <= value <= 1.0:
                raise ValueError(f"{name} must be between zero and one")
            object.__setattr__(self, name, value)


@dataclass(frozen=True)
class CapabilityGateResult:
    model_family: str
    runtime: str
    passed: bool
    reasons: tuple[str, ...]
    claim_status: str


def evaluate_capability_gate(
    evidence: PreflightEvidence,
    *,
    thresholds: CapabilityThresholds,
) -> CapabilityGateResult:
    reasons: list[str] = []
    if evidence.clean_utility_rate < thresholds.minimum_clean_utility_rate:
        reasons.append("clean_utility_below_gate")
    if evidence.tool_call_validity_rate < thresholds.minimum_tool_call_validity_rate:
        reasons.append("tool_call_validity_below_gate")
    passed = not reasons
    return CapabilityGateResult(
        model_family=evidence.model_family,
        runtime=evidence.runtime,
        passed=passed,
        reasons=tuple(reasons),
        claim_status="security_effect_candidate" if passed else "capability_only",
    )


@dataclass(frozen=True)
class SecurityEffectEligibility:
    status: str
    eligible: bool
    baseline_attack_successes: int


def evaluate_security_effect_eligibility(
    *,
    capability: CapabilityGateResult,
    baseline_attack_successes: int,
) -> SecurityEffectEligibility:
    successes = int(baseline_attack_successes)
    if successes < 0:
        raise ValueError("baseline_attack_successes cannot be negative")
    if not capability.passed:
        status = "ineligible_capability_gate"
    elif successes == 0:
        status = "ineligible_zero_attack_opportunity"
    else:
        status = "eligible_security_effect"
    return SecurityEffectEligibility(
        status=status,
        eligible=status == "eligible_security_effect",
        baseline_attack_successes=successes,
    )


@dataclass(frozen=True)
class SentinelGateDefinition:
    metric: str
    absolute_threshold: float

    def __post_init__(self) -> None:
        metric = str(self.metric or "").strip()
        if not metric:
            raise ValueError("metric must be nonempty")
        object.__setattr__(self, "metric", metric)
        threshold = float(self.absolute_threshold)
        if threshold < 0:
            raise ValueError("absolute_threshold cannot be negative")
        object.__setattr__(self, "absolute_threshold", threshold)


@dataclass(frozen=True)
class SentinelObservation:
    runtime: str
    common_effect: float
    sentinel_effect: float

    def __post_init__(self) -> None:
        runtime = str(self.runtime or "").strip()
        if not runtime:
            raise ValueError("runtime must be nonempty")
        object.__setattr__(self, "runtime", runtime)
        object.__setattr__(self, "common_effect", float(self.common_effect))
        object.__setattr__(self, "sentinel_effect", float(self.sentinel_effect))


@dataclass(frozen=True)
class SentinelGateDecision:
    metric: str
    threshold: float
    statistic: float
    triggered: bool
    expansion_decision: str
    decision_hash: str


def evaluate_sentinel_interaction_gate(
    *,
    definition: SentinelGateDefinition,
    observations: Sequence[SentinelObservation],
) -> SentinelGateDecision:
    if len(observations) != 2 or len({item.runtime for item in observations}) != 2:
        raise ValueError("sentinel interaction gate requires exactly two distinct runtimes")
    ordered = tuple(sorted(observations, key=lambda item: item.runtime))
    gaps = [item.common_effect - item.sentinel_effect for item in ordered]
    statistic = abs(gaps[0] - gaps[1])
    triggered = statistic >= definition.absolute_threshold
    payload = {
        "definition": {
            "metric": definition.metric,
            "absolute_threshold": definition.absolute_threshold,
        },
        "observations": [
            {
                "runtime": item.runtime,
                "common_effect": item.common_effect,
                "sentinel_effect": item.sentinel_effect,
            }
            for item in ordered
        ],
        "statistic": statistic,
        "expansion_decision": "expand_missing_cells" if triggered else "retain_connected_panel",
    }
    return SentinelGateDecision(
        metric=definition.metric,
        threshold=definition.absolute_threshold,
        statistic=statistic,
        triggered=triggered,
        expansion_decision=payload["expansion_decision"],
        decision_hash=stable_json_hash(payload),
    )


_AGENT_VERSION_PREFIXES = {
    "opencode": (),
    "hermes": ("Hermes Agent",),
    "openclaw": (),
    "codex": ("codex-cli",),
    "claude-code": (),
}
_AGENT_BINARIES = {
    "opencode": "opencode",
    "hermes": "hermes",
    "openclaw": "openclaw",
    "codex": "codex",
    "claude-code": "claude",
}


def probe_local_agent_runtimes() -> dict[str, dict[str, Any]]:
    report: dict[str, dict[str, Any]] = {}
    for agent, binary in _AGENT_BINARIES.items():
        if shutil.which(binary) is None:
            report[agent] = {"status": "missing_runtime", "binary": binary, "version": None}
            continue
        try:
            completed = subprocess.run(
                [binary, "--version"],
                text=True,
                capture_output=True,
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            report[agent] = {
                "status": "runtime_probe_error",
                "binary": binary,
                "version": None,
                "error_type": type(exc).__name__,
            }
            continue
        combined = "\n".join(part for part in (completed.stdout, completed.stderr) if part)
        version = _select_version_line(agent, combined)
        report[agent] = {
            "status": "available" if completed.returncode == 0 and version else "runtime_probe_error",
            "binary": binary,
            "version": version,
            "version_output_hash": stable_json_hash({"output": _redact_local_home(combined)}),
            "exit_code": completed.returncode,
        }
    return report


def materialize_connected_panel_plan(
    *,
    out_dir: Path,
    runtime_preflight: Mapping[str, Mapping[str, Any]] | None = None,
    common_family: str = "deepseek",
    sentinel_family: str = "qwen",
) -> dict[str, Any]:
    root = out_dir.expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    candidates = default_model_candidates()
    panel = build_default_connected_panel(
        candidates=candidates,
        common_family=common_family,
        sentinel_family=sentinel_family,
    )
    runtimes = {
        str(agent): {str(key): value for key, value in details.items()}
        for agent, details in (runtime_preflight or probe_local_agent_runtimes()).items()
    }
    row_preflight = [_row_preflight(row, runtimes=runtimes) for row in panel.rows]
    payload = {
        "schema_version": "invart.agent_model_panel_plan.v0.1",
        "status": "preflight_incomplete"
        if any(item["blocking_reasons"] for item in row_preflight)
        else "ready_for_clean_preflight",
        "selection_status": "preregistered_candidates_not_frozen",
        "panel": panel.to_dict(),
        "candidates": {
            family: candidates[family].to_dict() for family in sorted(candidates)
        },
        "runtime_preflight": runtimes,
        "row_preflight": row_preflight,
        "required_next_evidence": [
            "install or bind every required agent runtime",
            "bind a verified Kimi provider model ID or checkpoint revision",
            "persist clean model-by-runtime utility and tool-conformance preflight",
            "freeze common and sentinel selection before reading attack outcomes",
            "bind an approval packet before provider-scale execution",
        ],
        "claim_boundary": (
            "This artifact is a connected-panel execution plan and local runtime preflight. It contains no "
            "AgentDojo outcome and cannot support a security-effect, native-runtime, or checkpoint-isolated claim."
        ),
    }
    json_path = write_json_artifact(root / "agent_model_panel_plan.json", payload)
    markdown_path = root / "agent_model_panel_plan.md"
    markdown_path.write_text(_render_panel_markdown(payload), encoding="utf-8")
    secure_provider_artifact_tree(root)
    scan = scan_provider_artifact_tree(root)
    if scan["status"] != "pass":
        raise RuntimeError("agent-model panel plan failed artifact safety scan")
    return {
        "status": payload["status"],
        "root": str(root),
        "json": str(json_path),
        "markdown": str(markdown_path),
        "matrix_hash": panel.matrix_hash,
        "rows": len(panel.rows),
        "scan": scan,
    }


def _row_preflight(
    row: MatrixRow,
    *,
    runtimes: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    reasons: list[str] = []
    runtime = runtimes.get(row.agent_product, {})
    if runtime.get("status") != "available":
        reasons.append("missing_or_unverified_runtime")
    if row.provider.startswith("unresolved"):
        reasons.append("provider_unresolved")
    if row.claim_kind == "native_control":
        reasons.append("runtime_model_receipt_required")
    else:
        reasons.append("clean_model_runtime_preflight_not_frozen")
    return {
        "row_id": row.row_id,
        "completeness_state": "missing_runtime"
        if "missing_or_unverified_runtime" in reasons
        else "not_run",
        "blocking_reasons": reasons,
    }


def _select_version_line(agent: str, output: str) -> str | None:
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    prefixes = _AGENT_VERSION_PREFIXES[agent]
    if prefixes:
        selected = next((line for line in lines if line.startswith(prefixes)), None)
    else:
        selected = lines[0] if lines else None
    if not selected:
        return None
    return _redact_local_home(selected)[:200]


def _redact_local_home(value: str) -> str:
    return str(value).replace(str(Path.home()), "$HOME")


def _render_panel_markdown(payload: Mapping[str, Any]) -> str:
    panel = payload["panel"]
    preflight = {item["row_id"]: item for item in payload["row_preflight"]}
    lines = [
        "# Agent-Model Connected Panel Plan",
        "",
        f"- Status: `{payload['status']}`",
        f"- Selection: `{payload['selection_status']}`",
        f"- Matrix hash: `{panel['matrix_hash']}`",
        "",
        "| Row | Lanes | Claim kind | Attribution | Preflight |",
        "|---|---|---|---|---|",
    ]
    for row in panel["rows"]:
        state = preflight[row["row_id"]]
        reasons = ", ".join(state["blocking_reasons"]) or "ready"
        lines.append(
            f"| `{row['row_id']}` | {', '.join(row['lanes'])} | {row['claim_kind']} | "
            f"{row['attribution_scope']} | {reasons} |"
        )
    lines.extend(["", str(payload["claim_boundary"]), ""])
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Materialize the pre-registered agent-model panel.")
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    result = materialize_connected_panel_plan(out_dir=args.out_dir)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
