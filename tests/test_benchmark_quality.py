from __future__ import annotations

import json
from pathlib import Path

from invart.evaluation.benchmark_registry import (
    list_external_benchmark_qualifications,
)
from invart.evaluation.real_agent_benchmark.benchmark_quality import (
    build_benchmark_quality_registry,
    render_benchmark_quality_markdown,
    write_benchmark_quality_artifacts,
)
from invart.evaluation.real_agent_benchmark.case_manifest import (
    default_p0_case_manifest,
)


def _record(payload: dict[str, object], benchmark_id: str) -> dict[str, object]:
    records = payload["records"]
    assert isinstance(records, list)
    return next(
        item
        for item in records
        if isinstance(item, dict) and item.get("benchmark_id") == benchmark_id
    )


def test_peer_review_does_not_hide_missing_code_or_runtime_probe() -> None:
    payload = build_benchmark_quality_registry(
        dimension_overrides={
            "agentharm": {
                "data_access": {
                    "status": "fail",
                    "reason": "Official tasks are not available to this execution environment.",
                }
            }
        }
    )

    agentharm = _record(payload, "agentharm")
    assert agentharm["publication_status"] == "peer_reviewed"
    assert agentharm["qualification_status"] == "conditional"
    assert "primary_agent_security" not in agentharm["allowed_claim_roles"]
    assert {"data_access", "runtime_probe"}.issubset(
        set(agentharm["unresolved_dimensions"])
    )
    assert "quality_score" not in json.dumps(payload)


def test_missing_independent_oracle_rejects_primary_security_role() -> None:
    payload = build_benchmark_quality_registry(
        dimension_overrides={
            "agentharm": {
                "native_oracle": {
                    "status": "fail",
                    "reason": "Only a non-frozen model judge is available.",
                }
            }
        }
    )

    agentharm = _record(payload, "agentharm")
    assert "primary_agent_security" in agentharm["requested_claim_roles"]
    assert "primary_agent_security" not in agentharm["allowed_claim_roles"]
    assert agentharm["claim_role_decisions"]["primary_agent_security"]["status"] == "rejected"


def test_required_oracle_cannot_be_hidden_as_not_applicable() -> None:
    payload = build_benchmark_quality_registry(
        dimension_overrides={
            "agentharm": {
                "native_oracle": {
                    "status": "not_applicable",
                    "reason": "Attempted role bypass.",
                }
            }
        }
    )

    agentharm = _record(payload, "agentharm")
    decision = agentharm["claim_role_decisions"]["primary_agent_security"]
    assert decision["status"] == "rejected"
    assert "native_oracle" in decision["reason"]


def test_component_benchmarks_cannot_claim_agent_runtime_effect() -> None:
    payload = build_benchmark_quality_registry()

    for benchmark_id in ("harmbench", "b3"):
        record = _record(payload, benchmark_id)
        assert record["allowed_claim_roles"] == ["model_component_control"]
        decision = record["claim_role_decisions"]["agent_runtime_security"]
        assert decision["status"] == "rejected"
        assert "runtime" in decision["reason"].lower()


def test_source_revision_or_license_change_forces_new_qualification_hash() -> None:
    baseline = build_benchmark_quality_registry()
    revised = build_benchmark_quality_registry(
        source_overrides={
            "agentdojo": {
                "revision": "future-revision-for-test",
                "license": "future-license-for-test",
            }
        }
    )

    baseline_agentdojo = _record(baseline, "agentdojo")
    revised_agentdojo = _record(revised, "agentdojo")
    assert baseline_agentdojo["qualification_hash"] != revised_agentdojo["qualification_hash"]
    assert baseline["portfolio_hash"] != revised["portfolio_hash"]


def test_missing_dimension_stays_visible_and_artifacts_are_deterministic(
    tmp_path: Path,
) -> None:
    payload = build_benchmark_quality_registry(
        drop_dimensions={"mcp_agentbench": {"license"}}
    )

    mcp_utility = _record(payload, "mcp_agentbench")
    assert mcp_utility["qualification_status"] == "conditional"
    assert "license" in mcp_utility["missing_dimensions"]
    assert "license" in mcp_utility["unresolved_dimensions"]

    first = write_benchmark_quality_artifacts(tmp_path, registry=payload)
    first_json = Path(first["json"]).read_text(encoding="utf-8")
    first_markdown = Path(first["markdown"]).read_text(encoding="utf-8")
    second = write_benchmark_quality_artifacts(tmp_path, registry=payload)

    assert Path(second["json"]).read_text(encoding="utf-8") == first_json
    assert Path(second["markdown"]).read_text(encoding="utf-8") == first_markdown
    assert first_markdown == render_benchmark_quality_markdown(payload)
    assert "MCP-AgentBench" in first_markdown
    assert "missing: license" in first_markdown
    assert "Structurally allowed roles" in first_markdown
    assert "Claim-ready roles" in first_markdown


def test_public_registry_and_case_manifest_reference_same_qualification_records() -> None:
    registry = list_external_benchmark_qualifications()
    manifest = default_p0_case_manifest(agents=["codex"])

    assert registry["schema_version"] == "invart.benchmark_quality_registry.v0.1"
    assert all(not record["claim_ready_roles"] for record in registry["records"])
    assert manifest["benchmark_qualification_registry"]["portfolio_hash"] == registry["portfolio_hash"]
    family_map = manifest["benchmark_qualification_registry"]["family_benchmark_ids"]
    assert family_map["agentdojo"] == "agentdojo"
    assert family_map["skill_inject"] == "skill_inject"
    assert family_map["swe_bench_verified"] == "swe_bench"
    assert family_map["agentsecbench"] == "agent_security_bench"
    assert manifest["validation"]["status"] == "pass"
