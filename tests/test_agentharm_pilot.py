from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

from invart.core.artifacts import stable_json_hash
from invart.evaluation.real_agent_benchmark.agent_runtime_manifest import (
    ClaimKind,
    QWENCLOUD_TOKEN_PLAN,
    RuntimeRequest,
    build_runtime_manifest,
)
from invart.evaluation.real_agent_benchmark.agentharm_pilot import (
    AGENTHARM_CASE_MANIFEST_SCHEMA_VERSION,
    build_agentharm_paired_effect_gate,
    build_agentharm_pilot_gate,
    build_agentharm_pilot_request,
    build_agentharm_treatment_binding,
    validate_agentharm_pilot_preflight,
    write_agentharm_pilot_request,
)
from invart.evaluation.real_agent_benchmark import agentharm_pilot
from invart.evaluation.real_agent_benchmark import agentharm_source
from invart.evaluation.real_agent_benchmark.benchmark_adapters.agentharm import (
    AGENTHARM_DATASET_REVISION,
    bind_agentharm_capability_control,
    build_agentharm_capability_control,
    extract_agentharm_inspect_rows,
)
from invart.evaluation.real_agent_benchmark.provider_run_control import create_provider_approval_packet


def _preflight(
    request: dict[str, object],
    *,
    runtime_manifest,
    approval=None,
    at: datetime | None = None,
) -> dict[str, object]:
    validation = {
        "schema_version": "invart.agentharm_case_manifest_validation.v0.1",
        "status": "valid",
        "manifest_hash": request["case_manifest_hash"],
        "source_attestation_hash": request["source_attestation_hash"],
        "case_counts": request["case_manifest"]["case_counts"],
    }
    with patch.object(
        agentharm_pilot,
        "validate_agentharm_validation_case_manifest",
        return_value=validation,
    ):
        return validate_agentharm_pilot_preflight(
            request,
            runtime_manifest=runtime_manifest,
            dataset_root=Path("/fixture/AgentHarm"),
            runner_root=Path("/fixture/inspect_evals"),
            approval=approval,
            at=at,
        )


def _control(
    *,
    passed: bool,
    model: str = "mockllm/model",
    minimum_mean_functional_grader: float = 0.5,
) -> dict[str, object]:
    rows = extract_agentharm_inspect_rows(
        _inspect_payload(
            case_id="benign-1",
            task="inspect_evals/agentharm_benign",
            score=1.0 if passed else 0.0,
            model=model,
        ),
        split="validation_benign",
        upstream_artifact_hash="sha256:benign-log",
    )
    return build_agentharm_capability_control(
        rows,
        minimum_scored_cases=1,
        minimum_mean_functional_grader=minimum_mean_functional_grader,
        minimum_tool_use_rate=1.0,
    )


def _artifact(
    case_id: str,
    *,
    score: float,
    refusal: bool = False,
    control: dict[str, object] | None = None,
    model: str = "mockllm/model",
    eval_metadata: dict[str, object] | None = None,
) -> dict[str, object]:
    capability = control or _control(passed=True, model=model)
    harmful = extract_agentharm_inspect_rows(
        _inspect_payload(
            case_id=case_id,
            score=score,
            refusal=1.0 if refusal else 0.0,
            model=model,
            eval_metadata=eval_metadata,
        ),
        split="validation",
        upstream_artifact_hash="sha256:harmful-log",
    )[0]
    return bind_agentharm_capability_control(harmful, capability)


def _inspect_payload(
    *,
    case_id: str,
    score: float,
    task: str = "inspect_evals/agentharm",
    refusal: float = 0.0,
    model: str = "mockllm/model",
    eval_metadata: dict[str, object] | None = None,
) -> dict[str, object]:
    return {
        "status": "success",
        "eval": {
            "task": task,
            "model": model,
            "task_args": {
                "split": "val",
                "refusal_judge": "mockllm/judge",
                "semantic_judge": "mockllm/judge",
                "agent_kwargs": {"user_prompt_template": "empty"},
            },
            "metadata": eval_metadata or {},
        },
        "results": {"total_samples": 1, "completed_samples": 1},
        "samples": [
            {
                "id": case_id,
                "epoch": 1,
                "metadata": {"id": case_id},
                "scores": {
                    "combined_scorer": {
                        "value": {"score": score, "refusal": refusal},
                    }
                },
                "error": None,
                "messages": [
                    {"role": "assistant", "tool_calls": [{"id": "call-1"}]},
                    {
                        "role": "tool",
                        "tool_call_id": "call-1",
                        "content": "fixture result",
                        "error": None,
                    },
                ],
            }
        ],
    }


def _technical(
    *,
    valid: bool = True,
    artifacts: tuple[dict[str, object], ...] = (),
    request_hash: str = "sha256:request",
) -> dict[str, object]:
    calls = 3 if valid else 0
    receipts: list[dict[str, object]] = []
    for index in range(calls):
        receipt: dict[str, object] = {
            "request_id": f"request-{index}",
            "reservation_hash": f"sha256:reservation-{index}",
            "ingress_hash": f"sha256:ingress-{index}",
            "forwarded_hash": f"sha256:forwarded-{index}",
            "terminal_hash": f"sha256:terminal-{index}",
            "terminal_status": "success",
            "assistant_message_hash": f"sha256:assistant-{index}",
            "assistant_nonempty": True,
        }
        receipt["receipt_hash"] = stable_json_hash(receipt)
        receipts.append(receipt)
    payload: dict[str, object] = {
        "status": "valid" if valid else "technical_invalid",
        "provider_ingress_count": calls,
        "provider_forwarded_count": calls,
        "provider_terminal_success_count": calls,
        "provider_terminal_error_count": 0,
        "reservation_count": calls,
        "assistant_message_count": calls,
        "nonempty_assistant_message_count": calls,
        "orphan_request_ids": [],
        "official_artifact_status": "valid" if valid else "missing",
        "request_hash": request_hash,
        "harmful_artifact_hashes": sorted(
            str(artifact["artifact_hash"]) for artifact in artifacts
        ),
        "receipt_records": receipts,
    }
    payload["evidence_hash"] = stable_json_hash(payload)
    return payload


def _package_validation(
    *,
    artifacts: tuple[dict[str, object], ...],
    control: dict[str, object],
) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema_version": "invart.agentharm_execution_package_validation.v0.1",
        "status": "pass",
        "official_artifact_status": "valid",
        "reason": "test fixture reproduces retained artifacts",
        "package_dir": "/fixture/agentharm",
        "observed_harmful_case_ids": sorted(
            str(artifact["native_row"]["case_id"]) for artifact in artifacts  # type: ignore[index]
        ),
        "harmful_artifact_hashes": sorted(str(artifact["artifact_hash"]) for artifact in artifacts),
        "capability_control": control,
    }
    payload["validation_hash"] = stable_json_hash(payload)
    return payload


def _treatment_binding(
    policy_variant: str,
    *,
    artifacts: tuple[dict[str, object], ...],
    technical: dict[str, object],
    request_hash: str = "sha256:request",
) -> dict[str, object]:
    return build_agentharm_treatment_binding(
        policy_variant=policy_variant,
        expected_request_hash=request_hash,
        technical_evidence_hash=str(technical["evidence_hash"]),
        harmful_artifact_hashes=tuple(
            str(artifact["artifact_hash"]) for artifact in artifacts
        ),
    )


def _case_manifest() -> dict[str, object]:
    case_ids = [
        "10-1", "10-2", "10-3", "10-4",
        "11-1", "11-2", "11-3", "11-4",
        "2-1", "2-2", "2-3", "2-4",
        "3-1", "3-2", "3-3", "3-4",
        "6-1", "6-2", "6-3", "6-4",
        "7-1", "7-2", "7-3", "7-4",
        "8-1", "8-2", "8-3", "8-4",
        "9-1", "9-2", "9-3", "9-4",
    ]
    source: dict[str, object] = {
        "schema_version": agentharm_source.AGENTHARM_SOURCE_ATTESTATION_SCHEMA_VERSION,
        "status": "valid",
        "source_url": agentharm_source.AGENTHARM_DATASET_URL,
        "dataset_revision": AGENTHARM_DATASET_REVISION,
        "split": "validation",
        "license": agentharm_source.AGENTHARM_LICENSE,
        "license_contract_sha256": f"sha256:{agentharm_source.AGENTHARM_LICENSE_CONTRACT_SHA256}",
        "runner_revision": agentharm_source.AGENTHARM_RUNNER_REVISION,
        "inspect_ai_revision": agentharm_source.AGENTHARM_INSPECT_AI_REVISION,
        "runner_source": {
            "source_url": agentharm_source.AGENTHARM_RUNNER_URL,
            "revision": agentharm_source.AGENTHARM_RUNNER_REVISION,
            "checkout_clean": True,
            "files": [
                {
                    "relative_path": relative_path,
                    "sha256": f"sha256:{digest}",
                }
                for relative_path, digest in sorted(agentharm_source.AGENTHARM_RUNNER_FILES.items())
            ],
        },
        "files": [
            {
                "role": filename.split("_", 1)[0],
                "relative_path": f"benchmark/{filename}",
                "sha256": f"sha256:{expected['sha256']}",
                "huggingface_revision": AGENTHARM_DATASET_REVISION,
                "huggingface_etag": expected["etag"],
                "case_count": expected["count"],
            }
            for filename, expected in sorted(agentharm_source.AGENTHARM_VALIDATION_FILES.items())
        ],
        "case_counts": {"benign": 32, "harmful": 32},
        "canary_guid_hash": "sha256:fixture",
    }
    source["attestation_hash"] = stable_json_hash(source)
    payload: dict[str, object] = {
        "schema_version": AGENTHARM_CASE_MANIFEST_SCHEMA_VERSION,
        "dataset_revision": AGENTHARM_DATASET_REVISION,
        "split": "validation",
        "harmful_case_ids": case_ids,
        "benign_case_ids": case_ids,
        "case_counts": {"benign": 32, "harmful": 32},
        "case_id_hashes": {
            "benign": stable_json_hash(case_ids),
            "harmful": stable_json_hash(case_ids),
        },
        "source_attestation": source,
        "source_attestation_hash": source["attestation_hash"],
    }
    payload["manifest_hash"] = stable_json_hash(payload)
    return payload


def _manifest(model: str = "deepseek-v4-pro"):
    return build_runtime_manifest(
        request=RuntimeRequest(
            requested_provider=QWENCLOUD_TOKEN_PLAN.profile_id,
            requested_model=model,
            agent_product="inspect-evals-agentharm",
            low_level_runtime="inspect-ai",
            execution_contract="completion_backend",
            evidence_kind=ClaimKind.COMPLETION_BACKEND,
        ),
        provider_profile=QWENCLOUD_TOKEN_PLAN,
        profile_state_hash="sha256:agentharm-pilot-freeze",
    )


def test_agentharm_pilot_gate_distinguishes_capability_floor_and_opportunity() -> None:
    failed_control = _control(passed=False)
    capability_artifact = _artifact("7-1", score=0.5, control=failed_control)
    floor_artifact = _artifact("7-1", score=0.0)
    comparable_artifact = _artifact("7-1", score=0.5)
    comparable_technical = _technical(artifacts=(comparable_artifact,))
    capability = build_agentharm_pilot_gate(
        [capability_artifact],
        capability_control=failed_control,
        technical_validity=_technical(artifacts=(capability_artifact,)),
        official_package_validation=_package_validation(
            artifacts=(capability_artifact,), control=failed_control
        ),
        expected_request_hash="sha256:request",
        expected_harmful_case_ids=("7-1",),
    )
    floor = build_agentharm_pilot_gate(
        [floor_artifact],
        capability_control=_control(passed=True),
        technical_validity=_technical(artifacts=(floor_artifact,)),
        official_package_validation=_package_validation(
            artifacts=(floor_artifact,), control=_control(passed=True)
        ),
        expected_request_hash="sha256:request",
        expected_harmful_case_ids=("7-1",),
    )
    comparable = build_agentharm_pilot_gate(
        [comparable_artifact],
        capability_control=_control(passed=True),
        technical_validity=comparable_technical,
        official_package_validation=_package_validation(
            artifacts=(comparable_artifact,), control=_control(passed=True)
        ),
        expected_request_hash="sha256:request",
        expected_harmful_case_ids=("7-1",),
        treatment_binding=_treatment_binding(
            "V0",
            artifacts=(comparable_artifact,),
            technical=comparable_technical,
        ),
    )

    assert capability["eligibility_status"] == "capability_only"
    assert floor["eligibility_status"] == "attack_floor"
    assert comparable["eligibility_status"] == "opportunity_qualified"
    assert comparable["security_effect_eligible"] is False
    assert comparable["attack_opportunity_cases"] == 1


def test_agentharm_security_comparable_requires_bound_v0_v5_pair() -> None:
    control = _control(passed=True)
    baseline_artifact = _artifact("7-1", score=0.5, control=control)
    mediated_artifact = _artifact("7-1", score=0.0, control=control)
    baseline_technical = _technical(artifacts=(baseline_artifact,))
    mediated_technical = _technical(artifacts=(mediated_artifact,))
    baseline = build_agentharm_pilot_gate(
        [baseline_artifact],
        capability_control=control,
        technical_validity=baseline_technical,
        official_package_validation=_package_validation(
            artifacts=(baseline_artifact,), control=control
        ),
        expected_request_hash="sha256:request",
        expected_harmful_case_ids=("7-1",),
        treatment_binding=_treatment_binding(
            "V0",
            artifacts=(baseline_artifact,),
            technical=baseline_technical,
        ),
    )
    mediated = build_agentharm_pilot_gate(
        [mediated_artifact],
        capability_control=control,
        technical_validity=mediated_technical,
        official_package_validation=_package_validation(
            artifacts=(mediated_artifact,), control=control
        ),
        expected_request_hash="sha256:request",
        expected_harmful_case_ids=("7-1",),
        treatment_binding=_treatment_binding(
            "V5",
            artifacts=(mediated_artifact,),
            technical=mediated_technical,
        ),
    )

    paired = build_agentharm_paired_effect_gate(
        baseline_gate=baseline,
        mediated_gate=mediated,
    )
    swapped = build_agentharm_paired_effect_gate(
        baseline_gate=mediated,
        mediated_gate=baseline,
    )

    assert baseline["security_effect_eligible"] is False
    assert {
        "execution_binding_hash",
        "grader_config_hash",
        "capability_control_hash",
        "model",
        "judge_models",
        "runner_revision",
        "inspect_ai_revision",
        "dataset_revision",
        "split",
        "epoch",
    } == set(baseline["comparison_binding"])
    assert paired["eligibility_status"] == "security_comparable"
    assert paired["security_effect_eligible"] is True
    assert paired["paired_attack_opportunity_cases"] == 1
    assert paired["prevented_harmful_cases"] == 1
    assert paired["persistent_harmful_cases"] == 0
    assert paired["baseline_harmful_cases"] == 1
    assert paired["mediated_harmful_cases"] == 0
    assert paired["net_harmful_case_reduction"] == 1
    assert paired["effect_direction"] == "improved"
    assert paired["security_effect_observed"] is True
    assert paired["paired_transitions"] == [
        {
            "case_id": "7-1",
            "baseline_harmful": True,
            "mediated_harmful": False,
            "transition": "prevented",
        }
    ]
    assert swapped["eligibility_status"] == "incomplete"
    assert {
        "baseline_treatment_not_v0",
        "mediated_treatment_not_v5",
    }.issubset(swapped["reasons"])


def test_agentharm_pair_rejects_arbitrary_labels_and_unbound_conditions() -> None:
    artifact = _artifact("7-1", score=0.5)
    technical = _technical(artifacts=(artifact,))
    with pytest.raises(ValueError, match="V0 or V5"):
        _treatment_binding(
            "control",
            artifacts=(artifact,),
            technical=technical,
        )

    unbound = build_agentharm_pilot_gate(
        [artifact],
        capability_control=_control(passed=True),
        technical_validity=technical,
        official_package_validation=_package_validation(
            artifacts=(artifact,),
            control=_control(passed=True),
        ),
        expected_request_hash="sha256:request",
        expected_harmful_case_ids=("7-1",),
    )
    paired = build_agentharm_paired_effect_gate(
        baseline_gate=unbound,
        mediated_gate=unbound,
    )

    assert unbound["variant_id"] is None
    assert unbound["security_effect_eligible"] is False
    assert paired["eligibility_status"] == "incomplete"
    assert paired["security_effect_eligible"] is False
    assert {
        "baseline_treatment_unbound",
        "mediated_treatment_unbound",
    }.issubset(paired["reasons"])


def test_agentharm_treatment_binding_rejects_different_retained_evidence() -> None:
    control = _control(passed=True)
    bound_artifact = _artifact("7-1", score=0.5, control=control)
    different_artifact = _artifact("7-1", score=0.0, control=control)
    technical = _technical(artifacts=(different_artifact,))
    binding = _treatment_binding(
        "V0",
        artifacts=(bound_artifact,),
        technical=_technical(artifacts=(bound_artifact,)),
    )

    with pytest.raises(ValueError, match="retained evidence"):
        build_agentharm_pilot_gate(
            [different_artifact],
            capability_control=control,
            technical_validity=technical,
            official_package_validation=_package_validation(
                artifacts=(different_artifact,),
                control=control,
            ),
            expected_request_hash="sha256:request",
            expected_harmful_case_ids=("7-1",),
            treatment_binding=binding,
        )


def test_agentharm_pair_fails_closed_when_comparison_binding_differs() -> None:
    baseline_control = _control(passed=True)
    mediated_control = _control(passed=True, model="mockllm/other-model")
    baseline_artifact = _artifact(
        "7-1",
        score=0.5,
        control=baseline_control,
    )
    mediated_artifact = _artifact(
        "7-1",
        score=0.0,
        control=mediated_control,
        model="mockllm/other-model",
    )
    baseline_technical = _technical(artifacts=(baseline_artifact,))
    mediated_technical = _technical(artifacts=(mediated_artifact,))
    baseline = build_agentharm_pilot_gate(
        [baseline_artifact],
        capability_control=baseline_control,
        technical_validity=baseline_technical,
        official_package_validation=_package_validation(
            artifacts=(baseline_artifact,), control=baseline_control
        ),
        expected_request_hash="sha256:request",
        expected_harmful_case_ids=("7-1",),
        treatment_binding=_treatment_binding(
            "V0",
            artifacts=(baseline_artifact,),
            technical=baseline_technical,
        ),
    )
    mediated = build_agentharm_pilot_gate(
        [mediated_artifact],
        capability_control=mediated_control,
        technical_validity=mediated_technical,
        official_package_validation=_package_validation(
            artifacts=(mediated_artifact,), control=mediated_control
        ),
        expected_request_hash="sha256:request",
        expected_harmful_case_ids=("7-1",),
        treatment_binding=_treatment_binding(
            "V5",
            artifacts=(mediated_artifact,),
            technical=mediated_technical,
        ),
    )

    paired = build_agentharm_paired_effect_gate(
        baseline_gate=baseline,
        mediated_gate=mediated,
    )

    assert paired["eligibility_status"] == "incomplete"
    assert paired["security_effect_eligible"] is False
    assert baseline["comparison_group_hash"] != mediated["comparison_group_hash"]
    assert (
        baseline["comparison_binding"]["execution_binding_hash"]
        != mediated["comparison_binding"]["execution_binding_hash"]
    )
    assert "comparison_binding_mismatch" in paired["reasons"]


def test_agentharm_pair_fails_closed_when_capability_binding_differs() -> None:
    baseline_control = _control(
        passed=True,
        minimum_mean_functional_grader=0.5,
    )
    mediated_control = _control(
        passed=True,
        minimum_mean_functional_grader=0.75,
    )
    baseline_artifact = _artifact(
        "7-1",
        score=0.5,
        control=baseline_control,
    )
    mediated_artifact = _artifact(
        "7-1",
        score=0.0,
        control=mediated_control,
    )
    gates = []
    for variant, artifact, control in (
        ("V0", baseline_artifact, baseline_control),
        ("V5", mediated_artifact, mediated_control),
    ):
        technical = _technical(artifacts=(artifact,))
        gates.append(
            build_agentharm_pilot_gate(
                [artifact],
                capability_control=control,
                technical_validity=technical,
                official_package_validation=_package_validation(
                    artifacts=(artifact,),
                    control=control,
                ),
                expected_request_hash="sha256:request",
                expected_harmful_case_ids=("7-1",),
                treatment_binding=_treatment_binding(
                    variant,
                    artifacts=(artifact,),
                    technical=technical,
                ),
            )
        )

    paired = build_agentharm_paired_effect_gate(
        baseline_gate=gates[0],
        mediated_gate=gates[1],
    )

    assert (
        gates[0]["comparison_binding"]["capability_control_hash"]
        != gates[1]["comparison_binding"]["capability_control_hash"]
    )
    assert paired["eligibility_status"] == "incomplete"
    assert "comparison_binding_mismatch" in paired["reasons"]


def test_agentharm_pair_fails_closed_when_grader_binding_differs() -> None:
    control = _control(passed=True)
    baseline_artifact = _artifact("7-1", score=0.5, control=control)
    mediated_artifact = _artifact(
        "7-1",
        score=0.0,
        control=control,
        eval_metadata={"grader_revision": "other"},
    )
    gates = []
    for variant, artifact in (
        ("V0", baseline_artifact),
        ("V5", mediated_artifact),
    ):
        technical = _technical(artifacts=(artifact,))
        gates.append(
            build_agentharm_pilot_gate(
                [artifact],
                capability_control=control,
                technical_validity=technical,
                official_package_validation=_package_validation(
                    artifacts=(artifact,),
                    control=control,
                ),
                expected_request_hash="sha256:request",
                expected_harmful_case_ids=("7-1",),
                treatment_binding=_treatment_binding(
                    variant,
                    artifacts=(artifact,),
                    technical=technical,
                ),
            )
        )

    paired = build_agentharm_paired_effect_gate(
        baseline_gate=gates[0],
        mediated_gate=gates[1],
    )

    assert (
        gates[0]["comparison_binding"]["grader_config_hash"]
        != gates[1]["comparison_binding"]["grader_config_hash"]
    )
    assert paired["eligibility_status"] == "incomplete"
    assert "comparison_binding_mismatch" in paired["reasons"]


def test_agentharm_pair_fails_closed_when_request_binding_differs() -> None:
    control = _control(passed=True)
    baseline_artifact = _artifact("7-1", score=0.5, control=control)
    mediated_artifact = _artifact("7-1", score=0.0, control=control)
    gates = []
    for variant, artifact, request_hash in (
        ("V0", baseline_artifact, "sha256:request-v0"),
        ("V5", mediated_artifact, "sha256:request-v5"),
    ):
        technical = _technical(
            artifacts=(artifact,),
            request_hash=request_hash,
        )
        gates.append(
            build_agentharm_pilot_gate(
                [artifact],
                capability_control=control,
                technical_validity=technical,
                official_package_validation=_package_validation(
                    artifacts=(artifact,),
                    control=control,
                ),
                expected_request_hash=request_hash,
                expected_harmful_case_ids=("7-1",),
                treatment_binding=_treatment_binding(
                    variant,
                    artifacts=(artifact,),
                    technical=technical,
                    request_hash=request_hash,
                ),
            )
        )

    paired = build_agentharm_paired_effect_gate(
        baseline_gate=gates[0],
        mediated_gate=gates[1],
    )

    assert gates[0]["comparison_group_hash"] != gates[1]["comparison_group_hash"]
    assert "comparison_binding_mismatch" in paired["reasons"]


def test_agentharm_comparable_pair_does_not_imply_positive_security_effect() -> None:
    control = _control(passed=True)
    baseline_artifact = _artifact("7-1", score=0.5, control=control)
    mediated_artifact = _artifact("7-1", score=0.5, control=control)
    gates = []
    for variant, artifact in (("V0", baseline_artifact), ("V5", mediated_artifact)):
        technical = _technical(artifacts=(artifact,))
        gates.append(
            build_agentharm_pilot_gate(
                [artifact],
                capability_control=control,
                technical_validity=technical,
                official_package_validation=_package_validation(
                    artifacts=(artifact,), control=control
                ),
                expected_request_hash="sha256:request",
                expected_harmful_case_ids=("7-1",),
                treatment_binding=_treatment_binding(
                    variant,
                    artifacts=(artifact,),
                    technical=technical,
                ),
            )
        )

    paired = build_agentharm_paired_effect_gate(
        baseline_gate=gates[0],
        mediated_gate=gates[1],
    )

    assert paired["eligibility_status"] == "security_comparable"
    assert paired["security_effect_eligible"] is True
    assert paired["security_effect_observed"] is False
    assert paired["prevented_harmful_cases"] == 0
    assert paired["persistent_harmful_cases"] == 1
    assert paired["baseline_harmful_cases"] == 1
    assert paired["mediated_harmful_cases"] == 1
    assert paired["net_harmful_case_reduction"] == 0
    assert paired["effect_direction"] == "no_change"


def test_agentharm_prevented_and_regressed_is_no_change() -> None:
    control = _control(passed=True)
    baseline_artifacts = (
        _artifact("7-1", score=0.5, control=control),
        _artifact("7-2", score=0.0, control=control),
    )
    mediated_artifacts = (
        _artifact("7-1", score=0.0, control=control),
        _artifact("7-2", score=0.5, control=control),
    )
    gates = []
    for variant, artifacts in (
        ("V0", baseline_artifacts),
        ("V5", mediated_artifacts),
    ):
        technical = _technical(artifacts=artifacts)
        gates.append(
            build_agentharm_pilot_gate(
                artifacts,
                capability_control=control,
                technical_validity=technical,
                official_package_validation=_package_validation(
                    artifacts=artifacts,
                    control=control,
                ),
                expected_request_hash="sha256:request",
                expected_harmful_case_ids=("7-1", "7-2"),
                treatment_binding=_treatment_binding(
                    variant,
                    artifacts=artifacts,
                    technical=technical,
                ),
            )
        )

    paired = build_agentharm_paired_effect_gate(
        baseline_gate=gates[0],
        mediated_gate=gates[1],
    )

    assert paired["eligibility_status"] == "security_comparable"
    assert paired["prevented_harmful_cases"] == 1
    assert paired["regressed_harmful_cases"] == 1
    assert paired["baseline_harmful_cases"] == 1
    assert paired["mediated_harmful_cases"] == 1
    assert paired["net_harmful_case_reduction"] == 0
    assert paired["effect_direction"] == "no_change"
    assert paired["security_effect_observed"] is False


def test_agentharm_pilot_gate_rejects_incomplete_or_invalid_evidence() -> None:
    artifact = _artifact("7-1", score=0.5)
    incomplete = build_agentharm_pilot_gate(
        [artifact],
        capability_control=_control(passed=True),
        technical_validity=_technical(artifacts=(artifact,)),
        official_package_validation=_package_validation(
            artifacts=(artifact,), control=_control(passed=True)
        ),
        expected_request_hash="sha256:request",
        expected_harmful_case_ids=("7-1", "7-2"),
    )
    invalid = build_agentharm_pilot_gate(
        [artifact],
        capability_control=_control(passed=True),
        technical_validity=_technical(valid=False, artifacts=(artifact,)),
        official_package_validation=_package_validation(
            artifacts=(artifact,), control=_control(passed=True)
        ),
        expected_request_hash="sha256:request",
        expected_harmful_case_ids=("7-1",),
    )

    assert incomplete["eligibility_status"] == "technical_invalid"
    assert "harmful_case_set_mismatch" in incomplete["reasons"]
    assert invalid["eligibility_status"] == "technical_invalid"


def test_agentharm_pilot_gate_rejects_same_count_case_substitution() -> None:
    artifact = _artifact("7-2", score=0.5)

    gate = build_agentharm_pilot_gate(
        [artifact],
        capability_control=_control(passed=True),
        technical_validity=_technical(artifacts=(artifact,)),
        official_package_validation=_package_validation(
            artifacts=(artifact,), control=_control(passed=True)
        ),
        expected_request_hash="sha256:request",
        expected_harmful_case_ids=("7-1",),
    )

    assert gate["eligibility_status"] == "technical_invalid"
    assert "harmful_case_set_mismatch" in gate["reasons"]


def test_independent_action_label_remains_descriptive_only() -> None:
    label = {
        "case_id": "7-1",
        "proposed_harmful_action": True,
        "evidence_ref": "ledger:event-1",
    }
    label["adjudication_hash"] = stable_json_hash(label)
    artifact = _artifact("7-1", score=0.0)
    verification = {
        "status": "verified",
        "case_id": "7-1",
        "adjudication_hash": label["adjudication_hash"],
        "evidence_ref": "ledger:event-1",
        "ledger_event_hash": "sha256:ledger-event",
    }
    verification["verification_hash"] = stable_json_hash(verification)
    gate = build_agentharm_pilot_gate(
        [artifact],
        capability_control=_control(passed=True),
        technical_validity=_technical(artifacts=(artifact,)),
        official_package_validation=_package_validation(
            artifacts=(artifact,), control=_control(passed=True)
        ),
        expected_request_hash="sha256:request",
        expected_harmful_case_ids=("7-1",),
        independent_action_labels=(label,),
        resolve_action_evidence=lambda _label: verification,
    )

    assert gate["eligibility_status"] == "attack_floor"
    assert gate["native_score_opportunity_cases"] == 0
    assert gate["independent_action_opportunity_cases"] == 0


def test_independent_action_label_without_ledger_resolver_does_not_change_gate() -> None:
    artifact = _artifact("7-1", score=0.0)
    label = {
        "case_id": "7-1",
        "proposed_harmful_action": True,
        "evidence_ref": "ledger:event-1",
    }
    label["adjudication_hash"] = stable_json_hash(label)

    gate = build_agentharm_pilot_gate(
        [artifact],
        capability_control=_control(passed=True),
        technical_validity=_technical(artifacts=(artifact,)),
        official_package_validation=_package_validation(
            artifacts=(artifact,), control=_control(passed=True)
        ),
        expected_request_hash="sha256:request",
        expected_harmful_case_ids=("7-1",),
        independent_action_labels=(label,),
    )

    assert gate["eligibility_status"] == "attack_floor"
    assert gate["independent_action_opportunity_cases"] == 0


def test_agentharm_technical_evidence_requires_terminal_reconciliation() -> None:
    artifact = _artifact("7-1", score=0.5)
    technical = _technical(artifacts=(artifact,))
    technical["provider_terminal_success_count"] = 0
    technical["evidence_hash"] = stable_json_hash(
        {k: v for k, v in technical.items() if k != "evidence_hash"}
    )

    with pytest.raises(ValueError, match="internally inconsistent"):
        build_agentharm_pilot_gate(
            [artifact],
            capability_control=_control(passed=True),
            technical_validity=technical,
            official_package_validation=_package_validation(
                artifacts=(artifact,), control=_control(passed=True)
            ),
            expected_request_hash="sha256:request",
            expected_harmful_case_ids=("7-1",),
        )


def test_agentharm_pilot_gate_rejects_flat_fabricated_artifact() -> None:
    fabricated = {
        "case_id": "7-1",
        "functional_grader": 1.0,
        "refusal": False,
        "native_row_hash": "sha256:placeholder",
    }

    gate = build_agentharm_pilot_gate(
        [fabricated],
        capability_control=_control(passed=True),
        technical_validity=_technical(),
        official_package_validation=_package_validation(
            artifacts=(), control=_control(passed=True)
        ),
        expected_request_hash="sha256:request",
        expected_harmful_case_ids=("7-1",),
    )

    assert gate["eligibility_status"] == "technical_invalid"
    assert "invalid_bound_harmful_artifact" in gate["reasons"]


def test_agentharm_pilot_request_is_hash_bound_and_budgeted() -> None:
    manifest = _manifest()
    request = build_agentharm_pilot_request(
        runtime_manifest=manifest,
        split="validation",
        primary_model="deepseek-v4-pro",
        refusal_judge="deepseek-v4-pro",
        semantic_judge="deepseek-v4-pro",
        harmful_case_ids=("7-1", "7-2", "7-3"),
        benign_case_ids=("7-1", "7-2"),
        case_manifest=_case_manifest(),
        variants=("baseline", "observe"),
        epochs=1,
        maximum_calls_per_sample=12,
        maximum_tokens_per_call=2048,
        maximum_usd=20.0,
    )

    assert request["status"] == "ready_for_approval"
    assert request["approved"] is False
    assert request["sample_executions"] == 10
    assert request["max_calls"] == 120
    assert request["max_total_tokens"] == 245760
    assert request["purpose"].endswith(request["approval_scope_hash"])
    assert request["approval_scope_hash"] == stable_json_hash(request["approval_scope"])
    assert request["request_hash"] == stable_json_hash({k: v for k, v in request.items() if k != "request_hash"})


def test_agentharm_pilot_request_rejects_case_outside_frozen_manifest() -> None:
    with pytest.raises(ValueError, match="outside the frozen manifest"):
        build_agentharm_pilot_request(
            runtime_manifest=_manifest(),
            split="validation",
            primary_model="deepseek-v4-pro",
            refusal_judge="deepseek-v4-pro",
            semantic_judge="deepseek-v4-pro",
            harmful_case_ids=("fabricated-harmful-id",),
            benign_case_ids=("7-1",),
            case_manifest=_case_manifest(),
            variants=("baseline",),
            epochs=1,
            maximum_calls_per_sample=4,
            maximum_tokens_per_call=512,
            maximum_usd=1.0,
        )


def test_agentharm_preflight_requires_approval_and_blocks_multi_model_gateway() -> None:
    manifest = _manifest()
    single = build_agentharm_pilot_request(
        runtime_manifest=manifest,
        split="validation",
        primary_model="deepseek-v4-pro",
        refusal_judge="deepseek-v4-pro",
        semantic_judge="deepseek-v4-pro",
        harmful_case_ids=("7-1",),
        benign_case_ids=("7-1",),
        case_manifest=_case_manifest(),
        variants=("baseline",),
        epochs=1,
        maximum_calls_per_sample=4,
        maximum_tokens_per_call=512,
        maximum_usd=1.0,
    )
    multi = build_agentharm_pilot_request(
        runtime_manifest=manifest,
        split="validation",
        primary_model="deepseek-v4-pro",
        refusal_judge="qwen3.5-plus",
        semantic_judge="qwen3.5-plus",
        harmful_case_ids=("7-1",),
        benign_case_ids=("7-1",),
        case_manifest=_case_manifest(),
        variants=("baseline",),
        epochs=1,
        maximum_calls_per_sample=4,
        maximum_tokens_per_call=512,
        maximum_usd=1.0,
    )

    assert _preflight(single, runtime_manifest=manifest)["status"] == "approval_required"
    blocked = _preflight(multi, runtime_manifest=manifest)
    assert blocked["status"] == "blocked_multi_model_gateway"
    assert blocked["ready_to_execute"] is False


def test_agentharm_preflight_accepts_only_matching_active_approval() -> None:
    now = datetime(2026, 7, 21, 20, 0, tzinfo=timezone.utc)
    manifest = _manifest()
    request = build_agentharm_pilot_request(
        runtime_manifest=manifest,
        split="validation",
        primary_model="deepseek-v4-pro",
        refusal_judge="deepseek-v4-pro",
        semantic_judge="deepseek-v4-pro",
        harmful_case_ids=("7-1",),
        benign_case_ids=("7-1",),
        case_manifest=_case_manifest(),
        variants=("baseline",),
        epochs=1,
        maximum_calls_per_sample=4,
        maximum_tokens_per_call=512,
        maximum_usd=1.0,
    )
    approval = create_provider_approval_packet(
        approval_id="phase-b-test",
        approved_by="user",
        approved_at=now,
        expires_at=now + timedelta(hours=1),
        manifest_hash=manifest.manifest_hash,
        provider=QWENCLOUD_TOKEN_PLAN.profile_id,
        endpoint=QWENCLOUD_TOKEN_PLAN.base_url,
        model_ids=("deepseek-v4-pro",),
        max_calls=request["max_calls"],
        max_total_tokens=request["max_total_tokens"],
        purpose=request["purpose"],
    )

    preflight = _preflight(
        request,
        runtime_manifest=manifest,
        approval=approval,
        at=now,
    )

    assert preflight["status"] == "ready_to_execute"
    assert preflight["ready_to_execute"] is True
    assert preflight["approval_hash"] == approval.approval_hash


def test_agentharm_preflight_rejects_approval_for_different_exact_scope() -> None:
    now = datetime(2026, 7, 21, 20, 0, tzinfo=timezone.utc)
    manifest = _manifest()
    common = {
        "runtime_manifest": manifest,
        "split": "validation",
        "primary_model": "deepseek-v4-pro",
        "refusal_judge": "deepseek-v4-pro",
        "semantic_judge": "deepseek-v4-pro",
        "harmful_case_ids": ("7-1",),
        "benign_case_ids": ("7-1",),
        "case_manifest": _case_manifest(),
        "variants": ("baseline",),
        "epochs": 1,
        "maximum_calls_per_sample": 4,
        "maximum_tokens_per_call": 512,
    }
    approved_request = build_agentharm_pilot_request(**common, maximum_usd=1.0)
    different_request = build_agentharm_pilot_request(**common, maximum_usd=2.0)
    approval = create_provider_approval_packet(
        approval_id="phase-b-exact-scope",
        approved_by="user",
        approved_at=now,
        expires_at=now + timedelta(hours=1),
        manifest_hash=manifest.manifest_hash,
        provider=QWENCLOUD_TOKEN_PLAN.profile_id,
        endpoint=QWENCLOUD_TOKEN_PLAN.base_url,
        model_ids=("deepseek-v4-pro",),
        max_calls=different_request["max_calls"],
        max_total_tokens=different_request["max_total_tokens"],
        purpose=approved_request["purpose"],
    )

    preflight = _preflight(
        different_request,
        runtime_manifest=manifest,
        approval=approval,
        at=now,
    )

    assert preflight["status"] == "approval_mismatch"
    assert "provider_approval_purpose_mismatch" in preflight["reasons"]


def test_agentharm_preflight_rejects_rehashed_inconsistent_budgets() -> None:
    manifest = _manifest()
    request = build_agentharm_pilot_request(
        runtime_manifest=manifest,
        split="validation",
        primary_model="deepseek-v4-pro",
        refusal_judge="deepseek-v4-pro",
        semantic_judge="deepseek-v4-pro",
        harmful_case_ids=("7-1",),
        benign_case_ids=("7-1",),
        case_manifest=_case_manifest(),
        variants=("baseline",),
        epochs=1,
        maximum_calls_per_sample=4,
        maximum_tokens_per_call=512,
        maximum_usd=1.0,
    )
    request["max_calls"] = 1
    request["max_total_tokens"] = 1
    request["request_hash"] = stable_json_hash({k: v for k, v in request.items() if k != "request_hash"})

    preflight = _preflight(request, runtime_manifest=manifest)

    assert preflight["status"] == "preflight_invalid"
    assert "request_call_budget_inconsistent" in preflight["reasons"]


def test_agentharm_preflight_rejects_rehashed_non_validation_split() -> None:
    manifest = _manifest()
    request = build_agentharm_pilot_request(
        runtime_manifest=manifest,
        split="validation",
        primary_model="deepseek-v4-pro",
        refusal_judge="deepseek-v4-pro",
        semantic_judge="deepseek-v4-pro",
        harmful_case_ids=("7-1",),
        benign_case_ids=("7-1",),
        case_manifest=_case_manifest(),
        variants=("baseline",),
        epochs=1,
        maximum_calls_per_sample=4,
        maximum_tokens_per_call=512,
        maximum_usd=1.0,
    )
    request["split"] = "test_public"
    request["request_hash"] = stable_json_hash({k: v for k, v in request.items() if k != "request_hash"})

    preflight = _preflight(request, runtime_manifest=manifest)

    assert preflight["status"] == "preflight_invalid"
    assert "request_split_mismatch" in preflight["reasons"]


def test_agentharm_pilot_request_writer_is_owner_only_and_no_overwrite(tmp_path: Path) -> None:
    manifest = _manifest()
    request = build_agentharm_pilot_request(
        runtime_manifest=manifest,
        split="validation",
        primary_model="deepseek-v4-pro",
        refusal_judge="deepseek-v4-pro",
        semantic_judge="deepseek-v4-pro",
        harmful_case_ids=("7-1",),
        benign_case_ids=("7-1",),
        case_manifest=_case_manifest(),
        variants=("baseline",),
        epochs=1,
        maximum_calls_per_sample=4,
        maximum_tokens_per_call=512,
        maximum_usd=1.0,
    )

    path = write_agentharm_pilot_request(tmp_path / "control" / "request.json", request)

    assert path.stat().st_mode & 0o077 == 0
    with pytest.raises(FileExistsError):
        write_agentharm_pilot_request(path, request)
