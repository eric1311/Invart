from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Mapping

from invart.core.artifacts import stable_json_hash, write_json_artifact

from .benchmark_adapters.agentharm import AGENTHARM_DATASET_REVISION, AGENTHARM_DATASET_URL


SCHEMA_VERSION = "invart.benchmark_quality_registry.v0.1"


class DimensionStatus(str, Enum):
    PASS = "pass"
    PARTIAL = "partial"
    FAIL = "fail"
    UNKNOWN = "unknown"
    NOT_APPLICABLE = "not_applicable"


class EvidenceRole(str, Enum):
    PRIMARY_AGENT_SECURITY = "primary_agent_security"
    HISTORICAL_ANCHOR = "historical_anchor"
    EXTERNAL_VALIDITY = "external_validity"
    MODEL_COMPONENT_CONTROL = "model_component_control"
    BENIGN_UTILITY = "benign_utility"
    RESERVE_AGENT_SECURITY = "reserve_agent_security"
    DEFERRED_SURFACE = "deferred_surface"
    AGENT_RUNTIME_SECURITY = "agent_runtime_security"


class PortfolioDisposition(str, Enum):
    PLANNED = "planned"
    RESERVE = "reserve"
    DEFERRED = "deferred"
    REJECTED = "rejected"


REQUIRED_DIMENSIONS = (
    "official_source",
    "revision",
    "license",
    "data_access",
    "native_oracle",
    "clean_utility",
    "side_effect_fidelity",
    "split_policy",
    "judge_dependence",
    "community_reuse",
    "cost",
    "invart_fit",
    "runtime_probe",
)


@dataclass(frozen=True)
class QualificationDimension:
    name: str
    status: DimensionStatus
    reason: str

    def to_dict(self) -> dict[str, str]:
        return {
            "name": self.name,
            "status": self.status.value,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class BenchmarkSource:
    source_url: str
    revision: str
    license: str
    data_access: str


@dataclass(frozen=True)
class BenchmarkDefinition:
    benchmark_id: str
    display_name: str
    publication_status: str
    publication_venue: str
    source: BenchmarkSource
    disposition: PortfolioDisposition
    requested_claim_roles: tuple[EvidenceRole, ...]
    native_metrics: tuple[str, ...]
    dimensions: tuple[QualificationDimension, ...]
    forbidden_roles: tuple[EvidenceRole, ...] = ()
    forbidden_role_reason: str = ""


def build_benchmark_quality_registry(
    *,
    source_overrides: Mapping[str, Mapping[str, str]] | None = None,
    dimension_overrides: Mapping[str, Mapping[str, Mapping[str, str]]] | None = None,
    drop_dimensions: Mapping[str, set[str]] | None = None,
) -> dict[str, Any]:
    """Build the deterministic benchmark qualification registry.

    Overrides exist for source refreshes and runtime probes. They deliberately
    change the record hash so stale qualification decisions cannot be reused.
    """

    records: list[dict[str, Any]] = []
    for definition in _benchmark_definitions():
        source_payload = asdict(definition.source)
        source_payload.update((source_overrides or {}).get(definition.benchmark_id, {}))
        raw_dimensions = {
            item.name: item.to_dict() for item in definition.dimensions
        }
        for name, override in (dimension_overrides or {}).get(
            definition.benchmark_id, {}
        ).items():
            current = raw_dimensions.get(
                name,
                {"name": name, "status": DimensionStatus.UNKNOWN.value, "reason": ""},
            )
            current.update({str(key): str(value) for key, value in override.items()})
            current["name"] = name
            raw_dimensions[name] = current
        for name in (drop_dimensions or {}).get(definition.benchmark_id, set()):
            raw_dimensions.pop(name, None)
        records.append(
            _qualification_record(
                definition=definition,
                source=source_payload,
                dimensions=raw_dimensions,
            )
        )
    records.sort(key=lambda item: str(item["benchmark_id"]))
    portfolio_material = {
        "schema_version": SCHEMA_VERSION,
        "required_dimensions": list(REQUIRED_DIMENSIONS),
        "records": records,
    }
    return {
        **portfolio_material,
        "portfolio_hash": stable_json_hash(portfolio_material),
        "summary": _registry_summary(records),
        "claim_boundary": (
            "Qualification is dimension-level setup evidence. A structurally allowed claim role "
            "does not become paper evidence until the benchmark and result rows pass their runtime gates."
        ),
    }


def render_benchmark_quality_markdown(registry: Mapping[str, Any]) -> str:
    lines = [
        "# Benchmark Qualification Registry",
        "",
        f"Portfolio hash: `{registry.get('portfolio_hash')}`",
        "",
        "| Benchmark | Disposition | Publication | Qualification | Structurally allowed roles | Claim-ready roles | Unresolved |",
        "|---|---|---|---|---|---|---|",
    ]
    for item in registry.get("records", []):
        if not isinstance(item, Mapping):
            continue
        missing = list(item.get("missing_dimensions") or [])
        unresolved = list(item.get("unresolved_dimensions") or [])
        unresolved_text = ", ".join(str(value) for value in unresolved) or "none"
        if missing:
            unresolved_text = f"missing: {', '.join(str(value) for value in missing)}; {unresolved_text}"
        roles = ", ".join(str(value) for value in item.get("allowed_claim_roles", [])) or "none"
        claim_ready_roles = (
            ", ".join(str(value) for value in item.get("claim_ready_roles", []))
            or "none"
        )
        lines.append(
            "| {name} | `{disposition}` | {publication} | `{status}` | {roles} | {claim_ready_roles} | {unresolved} |".format(
                name=_markdown_cell(item.get("display_name")),
                disposition=_markdown_cell(item.get("portfolio_disposition")),
                publication=_markdown_cell(
                    f"{item.get('publication_status')} / {item.get('publication_venue')}"
                ),
                status=_markdown_cell(item.get("qualification_status")),
                roles=_markdown_cell(roles),
                claim_ready_roles=_markdown_cell(claim_ready_roles),
                unresolved=_markdown_cell(unresolved_text),
            )
        )
    lines.extend(
        [
            "",
            "No aggregate quality score is computed; missing or weak dimensions remain visible.",
            "",
        ]
    )
    return "\n".join(lines)


def write_benchmark_quality_artifacts(
    out_dir: Path,
    *,
    registry: Mapping[str, Any] | None = None,
) -> dict[str, str]:
    root = out_dir.expanduser().absolute()
    root.mkdir(parents=True, exist_ok=True)
    payload = dict(registry or build_benchmark_quality_registry())
    json_path = write_json_artifact(root / "benchmark_quality_registry.json", payload)
    markdown_path = root / "benchmark_quality_registry.md"
    markdown_path.write_text(render_benchmark_quality_markdown(payload), encoding="utf-8")
    return {"json": str(json_path), "markdown": str(markdown_path)}


def _qualification_record(
    *,
    definition: BenchmarkDefinition,
    source: Mapping[str, str],
    dimensions: Mapping[str, Mapping[str, str]],
) -> dict[str, Any]:
    missing = sorted(set(REQUIRED_DIMENSIONS) - set(dimensions))
    normalized_dimensions = [
        {
            "name": name,
            "status": str(dimensions[name].get("status") or DimensionStatus.UNKNOWN.value),
            "reason": str(dimensions[name].get("reason") or "No qualification reason recorded."),
        }
        for name in REQUIRED_DIMENSIONS
        if name in dimensions
    ]
    by_name = {item["name"]: item for item in normalized_dimensions}
    role_decisions = {
        role.value: _claim_role_decision(definition, role, by_name, missing)
        for role in definition.requested_claim_roles
    }
    unresolved = sorted(
        set(missing)
        | {
            item["name"]
            for item in normalized_dimensions
            if item["status"]
            not in {DimensionStatus.PASS.value, DimensionStatus.NOT_APPLICABLE.value}
        }
    )
    qualification_status = _qualification_status(definition, unresolved)
    allowed_claim_roles = sorted(
        role for role, decision in role_decisions.items() if decision["status"] == "allowed"
    )
    material = {
        "benchmark_id": definition.benchmark_id,
        "display_name": definition.display_name,
        "publication_status": definition.publication_status,
        "publication_venue": definition.publication_venue,
        "source": dict(source),
        "portfolio_disposition": definition.disposition.value,
        "qualification_status": qualification_status,
        "requested_claim_roles": [role.value for role in definition.requested_claim_roles],
        "allowed_claim_roles": allowed_claim_roles,
        "claim_ready_roles": (
            allowed_claim_roles if qualification_status == "qualified" else []
        ),
        "claim_role_decisions": role_decisions,
        "native_metrics": list(definition.native_metrics),
        "dimensions": normalized_dimensions,
        "missing_dimensions": missing,
        "unresolved_dimensions": unresolved,
    }
    return {**material, "qualification_hash": stable_json_hash(material)}


def _claim_role_decision(
    definition: BenchmarkDefinition,
    role: EvidenceRole,
    dimensions: Mapping[str, Mapping[str, str]],
    missing: list[str],
) -> dict[str, str]:
    if role in definition.forbidden_roles:
        return {
            "status": "rejected",
            "reason": definition.forbidden_role_reason
            or "The benchmark does not exercise the requested evidence boundary.",
        }
    if definition.disposition is PortfolioDisposition.REJECTED:
        return {"status": "rejected", "reason": "The benchmark is rejected from this portfolio."}
    requirements: tuple[str, ...]
    if role in {
        EvidenceRole.PRIMARY_AGENT_SECURITY,
        EvidenceRole.HISTORICAL_ANCHOR,
        EvidenceRole.RESERVE_AGENT_SECURITY,
    }:
        requirements = ("official_source", "data_access", "native_oracle", "invart_fit")
    elif role is EvidenceRole.BENIGN_UTILITY:
        requirements = ("official_source", "data_access", "native_oracle", "clean_utility")
    elif role in {EvidenceRole.EXTERNAL_VALIDITY, EvidenceRole.MODEL_COMPONENT_CONTROL}:
        requirements = ("official_source", "data_access", "invart_fit")
    else:
        requirements = ()
    failed = [
        name
        for name in requirements
        if name in missing
        or dimensions.get(name, {}).get("status")
        in {DimensionStatus.FAIL.value, DimensionStatus.NOT_APPLICABLE.value}
    ]
    unresolved = [
        name
        for name in requirements
        if name not in failed
        and dimensions.get(name, {}).get("status")
        not in {DimensionStatus.PASS.value, DimensionStatus.NOT_APPLICABLE.value}
    ]
    if failed:
        return {
            "status": "rejected",
            "reason": f"Required claim dimensions failed or are missing: {', '.join(failed)}.",
        }
    if unresolved:
        return {
            "status": "conditional",
            "reason": f"Required claim dimensions remain unresolved: {', '.join(unresolved)}.",
        }
    return {
        "status": "allowed",
        "reason": "The benchmark structurally supports this evidence role; runtime qualification is still required.",
    }


def _qualification_status(
    definition: BenchmarkDefinition,
    unresolved: list[str],
) -> str:
    if definition.disposition is PortfolioDisposition.REJECTED:
        return "rejected"
    return "qualified" if not unresolved else "conditional"


def _registry_summary(records: list[dict[str, Any]]) -> dict[str, Any]:
    dispositions: dict[str, int] = {}
    statuses: dict[str, int] = {}
    for record in records:
        disposition = str(record["portfolio_disposition"])
        status = str(record["qualification_status"])
        dispositions[disposition] = dispositions.get(disposition, 0) + 1
        statuses[status] = statuses.get(status, 0) + 1
    return {
        "records": len(records),
        "portfolio_dispositions": dispositions,
        "qualification_statuses": statuses,
    }


def _benchmark_definitions() -> tuple[BenchmarkDefinition, ...]:
    return (
        _definition(
            "agentharm",
            "AgentHarm",
            "peer_reviewed",
            "ICLR 2025",
            AGENTHARM_DATASET_URL,
            PortfolioDisposition.PLANNED,
            (EvidenceRole.PRIMARY_AGENT_SECURITY,),
            ("harmful_task_success", "refusal", "functional_grader"),
            oracle="pass",
            clean_utility="partial",
            side_effect_fidelity="pass",
            revision=AGENTHARM_DATASET_REVISION,
            license_name="MIT-with-safety-and-security-use-clause",
            revision_status="pass",
            license_status="pass",
        ),
        _definition(
            "mcptox",
            "MCPTox",
            "peer_reviewed",
            "AAAI 2026",
            "https://github.com/zhiqiangwang4/MCPTox-Benchmark",
            PortfolioDisposition.PLANNED,
            (EvidenceRole.PRIMARY_AGENT_SECURITY,),
            ("attack_success_rate", "benign_task_success"),
            oracle="pass",
            clean_utility="partial",
            side_effect_fidelity="partial",
            revision="f85189f9ad12504c197c7f920ab818a40657b1fa",
            license_name="unresolved-no-license-file-at-pinned-revision",
            revision_status="pass",
        ),
        _definition(
            "mcp_agentbench",
            "MCP-AgentBench",
            "peer_reviewed",
            "AAAI 2026",
            "https://doi.org/10.1609/aaai.v40i37.40347",
            PortfolioDisposition.PLANNED,
            (EvidenceRole.BENIGN_UTILITY,),
            ("task_success_rate", "tool_call_correctness"),
            oracle="pass",
            clean_utility="pass",
            side_effect_fidelity="partial",
            revision="aaai-2026-volume-40-issue-37-article-40347",
            license_name="AAAI-publication-copyright-code-license-unresolved",
            revision_status="pass",
            data_access_status="partial",
        ),
        _definition(
            "agentdojo",
            "AgentDojo",
            "peer_reviewed",
            "NeurIPS 2024",
            "https://github.com/ethz-spylab/agentdojo",
            PortfolioDisposition.PLANNED,
            (EvidenceRole.HISTORICAL_ANCHOR,),
            ("utility", "security", "attack_success_rate"),
            oracle="pass",
            clean_utility="pass",
            side_effect_fidelity="pass",
            runtime_reason="Prior false-zero artifacts are invalid; a transport-valid full rerun is required.",
        ),
        _definition(
            "agentdyn",
            "AgentDyn",
            "preprint",
            "arXiv 2026",
            "https://github.com/leolee99/AgentDyn",
            PortfolioDisposition.PLANNED,
            (EvidenceRole.EXTERNAL_VALIDITY,),
            ("task_success", "attack_success", "trajectory_length"),
            oracle="partial",
            clean_utility="pass",
            side_effect_fidelity="pass",
        ),
        _definition(
            "skill_inject",
            "Skill-Inject",
            "preprint",
            "arXiv 2026",
            "https://github.com/aisa-group/skill-inject",
            PortfolioDisposition.PLANNED,
            (EvidenceRole.EXTERNAL_VALIDITY,),
            ("injection_success", "benign_success", "attempted_harm"),
            oracle="partial",
            clean_utility="pass",
            side_effect_fidelity="pass",
        ),
        _definition(
            "harmbench",
            "HarmBench",
            "peer_reviewed",
            "ICML 2024",
            "https://github.com/centerforaisafety/HarmBench",
            PortfolioDisposition.PLANNED,
            (EvidenceRole.MODEL_COMPONENT_CONTROL, EvidenceRole.AGENT_RUNTIME_SECURITY),
            ("attack_success_rate", "classifier_success"),
            oracle="partial",
            clean_utility="not_applicable",
            side_effect_fidelity="not_applicable",
            forbidden_roles=(EvidenceRole.AGENT_RUNTIME_SECURITY,),
            forbidden_reason=(
                "HarmBench evaluates model responses and cannot establish an Invart agent runtime effect."
            ),
        ),
        _definition(
            "b3",
            "b³ / Breaking Agent Backbones",
            "peer_reviewed",
            "ICLR 2026",
            "https://arxiv.org/abs/2510.22620",
            PortfolioDisposition.PLANNED,
            (EvidenceRole.MODEL_COMPONENT_CONTROL, EvidenceRole.AGENT_RUNTIME_SECURITY),
            ("snapshot_attack_success", "backbone_vulnerability"),
            oracle="partial",
            clean_utility="not_applicable",
            side_effect_fidelity="not_applicable",
            forbidden_roles=(EvidenceRole.AGENT_RUNTIME_SECURITY,),
            forbidden_reason=(
                "b³ isolates backbone snapshots and cannot establish an Invart agent runtime effect."
            ),
        ),
        _definition(
            "swe_bench",
            "SWE-Bench",
            "peer_reviewed",
            "ICLR 2024",
            "https://github.com/SWE-bench/SWE-bench",
            PortfolioDisposition.PLANNED,
            (EvidenceRole.BENIGN_UTILITY,),
            ("resolved_rate", "official_test_outcome"),
            oracle="pass",
            clean_utility="pass",
            side_effect_fidelity="pass",
        ),
        _definition(
            "agent_security_bench",
            "Agent Security Bench",
            "peer_reviewed",
            "ICLR 2025",
            "https://github.com/agiresearch/ASB",
            PortfolioDisposition.RESERVE,
            (EvidenceRole.RESERVE_AGENT_SECURITY,),
            ("attack_success_rate", "task_success_rate"),
            oracle="partial",
            clean_utility="pass",
            side_effect_fidelity="partial",
        ),
        _definition(
            "vpi_bench",
            "VPI-Bench",
            "peer_reviewed",
            "ICLR 2026",
            "https://arxiv.org/abs/2506.02456",
            PortfolioDisposition.DEFERRED,
            (EvidenceRole.DEFERRED_SURFACE,),
            ("visual_injection_success", "task_success"),
            oracle="partial",
            clean_utility="pass",
            side_effect_fidelity="pass",
        ),
        _definition(
            "agentlab",
            "AgentLAB",
            "preprint",
            "arXiv 2026",
            "https://arxiv.org/abs/2602.16901",
            PortfolioDisposition.DEFERRED,
            (EvidenceRole.DEFERRED_SURFACE,),
            ("long_horizon_attack_success", "task_success"),
            oracle="partial",
            clean_utility="partial",
            side_effect_fidelity="pass",
        ),
        _definition(
            "mpbench",
            "MPBench",
            "preprint",
            "arXiv 2026",
            "https://arxiv.org/abs/2606.04329",
            PortfolioDisposition.DEFERRED,
            (EvidenceRole.DEFERRED_SURFACE,),
            ("write_success", "retrieval_success", "behavior_influence"),
            oracle="partial",
            clean_utility="pass",
            side_effect_fidelity="partial",
        ),
        _definition(
            "converse",
            "ConVerse",
            "peer_reviewed",
            "Findings of EACL 2026",
            "https://aclanthology.org/2026.findings-eacl.170/",
            PortfolioDisposition.DEFERRED,
            (EvidenceRole.DEFERRED_SURFACE,),
            ("contextual_safety", "privacy_attack_success"),
            oracle="partial",
            clean_utility="partial",
            side_effect_fidelity="partial",
        ),
    )


def _definition(
    benchmark_id: str,
    display_name: str,
    publication_status: str,
    venue: str,
    source_url: str,
    disposition: PortfolioDisposition,
    roles: tuple[EvidenceRole, ...],
    native_metrics: tuple[str, ...],
    *,
    oracle: str,
    clean_utility: str,
    side_effect_fidelity: str,
    runtime_reason: str = "No current-environment runtime probe has been attached.",
    forbidden_roles: tuple[EvidenceRole, ...] = (),
    forbidden_reason: str = "",
    revision: str = "unpinned",
    license_name: str = "unverified",
    revision_status: str = "unknown",
    license_status: str = "unknown",
    data_access_status: str = "pass",
) -> BenchmarkDefinition:
    status = DimensionStatus
    dimensions = (
        QualificationDimension("official_source", status.PASS, "An official publication or repository URL is recorded."),
        QualificationDimension("revision", status(revision_status), "The recorded source revision is immutable when this dimension passes."),
        QualificationDimension("license", status(license_status), "The source and data license is recorded; unresolved code licenses remain visible."),
        QualificationDimension("data_access", status(data_access_status), "Public source access and executable code availability are qualified separately from publication."),
        QualificationDimension("native_oracle", status(oracle), "Native metrics are recorded; judge and deterministic components remain separated."),
        QualificationDimension("clean_utility", status(clean_utility), "Clean utility coverage is recorded without substituting it for security outcomes."),
        QualificationDimension("side_effect_fidelity", status(side_effect_fidelity), "Environment side effects are assessed relative to Invart's runtime boundary."),
        QualificationDimension("split_policy", status.UNKNOWN, "Development, public test, and hidden-test use must be frozen before execution."),
        QualificationDimension("judge_dependence", status.PARTIAL, "Judge usage and deterministic outcomes require benchmark-specific separation."),
        QualificationDimension("community_reuse", status.PARTIAL, "Publication is recorded; adoption is treated only as a weak supporting signal."),
        QualificationDimension("cost", status.UNKNOWN, "Pilot cost and full-denominator budget have not yet been measured."),
        QualificationDimension("invart_fit", status.PASS, "The planned evidence role is explicitly bounded to Invart's observable runtime surface."),
        QualificationDimension("runtime_probe", status.UNKNOWN, runtime_reason),
    )
    return BenchmarkDefinition(
        benchmark_id=benchmark_id,
        display_name=display_name,
        publication_status=publication_status,
        publication_venue=venue,
        source=BenchmarkSource(
            source_url=source_url,
            revision=revision,
            license=license_name,
            data_access="public_source_documented",
        ),
        disposition=disposition,
        requested_claim_roles=roles,
        native_metrics=native_metrics,
        dimensions=dimensions,
        forbidden_roles=forbidden_roles,
        forbidden_role_reason=forbidden_reason,
    )


def _markdown_cell(value: Any) -> str:
    return str(value if value is not None else "").replace("|", "\\|").replace("\n", " ")


__all__ = [
    "BenchmarkDefinition",
    "BenchmarkSource",
    "DimensionStatus",
    "EvidenceRole",
    "PortfolioDisposition",
    "QualificationDimension",
    "REQUIRED_DIMENSIONS",
    "build_benchmark_quality_registry",
    "render_benchmark_quality_markdown",
    "write_benchmark_quality_artifacts",
]
