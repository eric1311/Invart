from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from invart.cli import main
from invart.evaluation.real_agent_benchmark import (
    analyze_agentdojo_full_results,
    audit_agentdojo_full_completeness,
    build_agentdojo_full_manifest,
    check_agentdojo_mode_isolation,
    collect_agentdojo_full_census,
    execute_agentdojo_full_jobs,
    prepare_agentdojo_full_run,
    summarize_agentdojo_full_job_artifact,
)
from invart.evaluation.real_agent_benchmark.agent_runtime_manifest import QWENCLOUD_TOKEN_PLAN
from invart.evaluation.real_agent_benchmark.agentdojo_cli_proxy import (
    build_opencode_runtime_manifest,
    build_reviewer_runtime_manifest,
)
from invart.evaluation.real_agent_benchmark.provider_run_control import (
    create_provider_approval_packet,
)
from invart.evaluation.real_agent_benchmark.full_benchmark_runner import (
    _absolute_optional_path,
    _analysis_execution_validity,
    classify_agentdojo_full_job_execution,
)


def test_control_paths_are_frozen_before_isolated_workspace_launch(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)

    assert _absolute_optional_path(Path("control/approval.json")) == (
        tmp_path / "control" / "approval.json"
    )
    assert _absolute_optional_path(None) is None


def test_agentdojo_full_census_manifest_and_completeness(tmp_path: Path, monkeypatch) -> None:
    _write_fake_agentdojo(tmp_path)
    existing = os.environ.get("PYTHONPATH")
    monkeypatch.setenv("PYTHONPATH", str(tmp_path) + (os.pathsep + existing if existing else ""))

    census_dir = tmp_path / "census"
    census = collect_agentdojo_full_census(
        out_dir=census_dir,
        python_executable=sys.executable,
        benchmark_version="v-test",
    )

    assert census["status"] == "pass"
    assert census["agentdojo_package_version"] == "9.9.9"
    assert census["summary"] == {
        "suites": 2,
        "user_tasks": 3,
        "injection_tasks": 3,
        "security_pairs": 5,
        "canonical_attack_task_executions": 8,
        "no_attack_task_executions": 3,
    }

    manifest_dir = tmp_path / "manifest"
    manifest = build_agentdojo_full_manifest(
        census_path=census_dir / "agentdojo_full_census.json",
        out_dir=manifest_dir,
        agents=["codex", "claude-code"],
        trials=1,
        policy_hash="sha256:test-policy",
    )

    assert manifest["status"] == "frozen"
    assert manifest["summary"]["jobs"] == 24
    assert manifest["summary"]["expected_result_channels"] == {
        "injection_utility": 18,
        "paired_utility": 30,
        "security": 30,
        "utility": 18,
    }
    assert (manifest_dir / "agentdojo_full_run_records.jsonl").read_text(encoding="utf-8") == ""
    pilot = build_agentdojo_full_manifest(
        census_path=census_dir / "agentdojo_full_census.json",
        out_dir=tmp_path / "pilot",
        agents=["codex"],
        suites=["banking"],
    )
    assert pilot["protocol"]["scope"] == "pilot"
    assert pilot["protocol"]["suites"] == ["banking"]
    assert pilot["summary"]["jobs"] == 6
    smoke = build_agentdojo_full_manifest(
        census_path=census_dir / "agentdojo_full_census.json",
        out_dir=tmp_path / "smoke",
        agents=["codex"],
        suites=["banking"],
        user_tasks=["user_0"],
        injection_tasks=["inj_0"],
    )
    assert smoke["protocol"]["scope"] == "smoke"
    assert smoke["summary"]["jobs"] == 6
    assert smoke["summary"]["expected_result_channels"] == {
        "injection_utility": 3,
        "paired_utility": 3,
        "security": 3,
        "utility": 3,
    }
    variants = build_agentdojo_full_manifest(
        census_path=census_dir / "agentdojo_full_census.json",
        out_dir=tmp_path / "variants",
        agents=["codex"],
        suites=["banking"],
        policy_variants=["V0", "V1", "V2", "V5"],
    )
    assert variants["summary"]["jobs"] == 8
    assert variants["protocol"]["policy_variants"] == ["V0", "V1", "V2", "V5"]
    assert {(job["policy_variant"], job["mode"]) for job in variants["jobs"]} == {
        ("V0", "baseline_agent"),
        ("V1", "invart_mediated"),
        ("V2", "invart_observe_only"),
        ("V5", "invart_mediated"),
    }

    records_path = tmp_path / "run-records.jsonl"
    first_job = manifest["jobs"][0]
    records_path.write_text(
        json.dumps(
            {
                "job_id": first_job["job_id"],
                "recorded_at": "2026-07-16T00:00:00+00:00",
                "run_status": "graded",
                "official_result_status": "graded",
                "official_result_counts": first_job["expected_results"],
                "artifact_path": "/tmp/fake-result",
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    incomplete = audit_agentdojo_full_completeness(
        manifest_path=manifest_dir / "agentdojo_full_manifest.json",
        run_records_path=records_path,
        out_dir=tmp_path / "audit-incomplete",
    )
    assert incomplete["status"] == "incomplete"
    assert incomplete["summary"]["graded_complete_jobs"] == 1
    assert incomplete["summary"]["missing_jobs"] == 23

    records_path.write_text(
        "".join(
            json.dumps(
                {
                    "job_id": job["job_id"],
                    "recorded_at": "2026-07-16T00:00:00+00:00",
                    "run_status": "graded",
                    "official_result_status": "graded",
                    "official_result_counts": job["expected_results"],
                    "artifact_path": f"/tmp/{job['job_id']}",
                },
                sort_keys=True,
            )
            + "\n"
            for job in manifest["jobs"]
        ),
        encoding="utf-8",
    )
    complete = audit_agentdojo_full_completeness(
        manifest_path=manifest_dir / "agentdojo_full_manifest.json",
        run_records_path=records_path,
        out_dir=tmp_path / "audit-complete",
    )
    assert complete["status"] == "complete"
    assert complete["summary"]["graded_complete_jobs"] == 24
    assert complete["summary"]["missing_jobs"] == 0
    assert complete["summary"]["observed_result_channels"] == complete["summary"]["expected_result_channels"]


def test_full_benchmark_cli_freezes_census_and_manifest(tmp_path: Path, monkeypatch) -> None:
    _write_fake_agentdojo(tmp_path)
    existing = os.environ.get("PYTHONPATH")
    monkeypatch.setenv("PYTHONPATH", str(tmp_path) + (os.pathsep + existing if existing else ""))

    census_dir = tmp_path / "cli-census"
    assert main(
        [
            "experiment",
            "full-benchmark",
            "agentdojo-census",
            "--out-dir",
            str(census_dir),
            "--python",
            sys.executable,
            "--benchmark-version",
            "v-test",
        ]
    ) == 0
    manifest_dir = tmp_path / "cli-manifest"
    assert main(
        [
            "experiment",
            "full-benchmark",
            "agentdojo-manifest",
            "--census",
            str(census_dir / "agentdojo_full_census.json"),
            "--out-dir",
            str(manifest_dir),
            "--agent",
            "codex",
            "--agent",
            "claude-code",
            "--policy-variant",
            "V0",
            "--policy-variant",
            "V5",
        ]
    ) == 0
    manifest = json.loads((manifest_dir / "agentdojo_full_manifest.json").read_text(encoding="utf-8"))
    assert manifest["status"] == "frozen"
    assert manifest["summary"]["jobs"] == 16
    assert manifest["protocol"]["policy_variants"] == ["V0", "V5"]


def test_completeness_audit_rejects_partial_official_counts(tmp_path: Path, monkeypatch) -> None:
    _write_fake_agentdojo(tmp_path)
    existing = os.environ.get("PYTHONPATH")
    monkeypatch.setenv("PYTHONPATH", str(tmp_path) + (os.pathsep + existing if existing else ""))
    census = collect_agentdojo_full_census(
        out_dir=tmp_path / "census",
        python_executable=sys.executable,
        benchmark_version="v-test",
    )
    manifest = build_agentdojo_full_manifest(
        census_path=tmp_path / "census" / "agentdojo_full_census.json",
        out_dir=tmp_path / "manifest",
        agents=["codex"],
    )
    job = next(item for item in manifest["jobs"] if item["condition"] == "canonical_attack")
    partial_counts = dict(job["expected_results"])
    partial_counts["security"] -= 1
    records = tmp_path / "partial.jsonl"
    records.write_text(
        json.dumps(
            {
                "job_id": job["job_id"],
                "recorded_at": "2026-07-16T00:00:00+00:00",
                "run_status": "graded",
                "official_result_status": "graded",
                "official_result_counts": partial_counts,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    audit = audit_agentdojo_full_completeness(
        manifest_path=tmp_path / "manifest" / "agentdojo_full_manifest.json",
        run_records_path=records,
        out_dir=tmp_path / "audit",
    )
    audited = next(item for item in audit["jobs"] if item["job_id"] == job["job_id"])
    assert audited["audit_status"] == "graded_partial"
    assert audit["status"] == "incomplete"


def test_agentdojo_mode_isolation_and_official_channel_parser(tmp_path: Path) -> None:
    isolation = check_agentdojo_mode_isolation()
    assert isolation["status"] == "pass"
    assert isolation["checks"]["mediated_removes_injected_tool_call"] is True
    assert isolation["checks"]["mediated_preserves_direct_user_authorization"] is True

    attack_job = {
        "condition": "canonical_attack",
        "attack": "tool_knowledge",
        "user_task_ids": ["user_0", "user_1"],
        "injection_task_ids": ["inj_0", "inj_1"],
        "expected_results": {
            "injection_utility": 2,
            "paired_utility": 4,
            "security": 4,
        },
    }
    logdir = tmp_path / "official-logdir"
    for injection in attack_job["injection_task_ids"]:
        _write_agentdojo_result(
            logdir / "local" / "banking" / injection / "none" / "none.json",
            user_task=injection,
            injection_task=None,
            attack=None,
        )
    for user in attack_job["user_task_ids"]:
        for injection in attack_job["injection_task_ids"]:
            _write_agentdojo_result(
                logdir / "local" / "banking" / user / "tool_knowledge" / f"{injection}.json",
                user_task=user,
                injection_task=injection,
                attack="tool_knowledge",
            )
    result = summarize_agentdojo_full_job_artifact(job=attack_job, logdir=logdir)
    assert result["status"] == "graded_complete"
    assert result["official_result_counts"] == attack_job["expected_results"]
    assert result["official_true_counts"] == attack_job["expected_results"]
    assert result["outcome_metrics"]["attack_successes"] == 4
    assert result["outcome_metrics"]["secure_outcomes"] == 0


def test_agentdojo_job_validity_joins_provider_receipts_completion_and_official_counts() -> None:
    job = {
        "expected_results": {"paired_utility": 1, "security": 1},
        "condition": "canonical_attack",
    }
    official = {
        "official_result_status": "graded",
        "official_result_counts": {"paired_utility": 1, "security": 1},
        "outcome_metrics": {"paired_utility_successes": 1, "attack_successes": 1},
    }
    proxy_records = [
        {
            "response_chars": 2,
            "supervision": {"returncode": 0},
            "backend_invocations": [
                {
                    "response_chars": 2,
                    "supervision": {"returncode": 0, "timed_out": False},
                    "provider_gateway_records": [
                        {"status": "reserved_pending", "gateway_request_id": "req-1"},
                        {"status": "forwarded", "gateway_request_id": "req-1"},
                    ]
                }
            ],
        }
    ]

    result = classify_agentdojo_full_job_execution(
        job=job,
        run_record={"run_status": "graded"},
        official=official,
        proxy_records=proxy_records,
        runtime_resolution_status="valid_runtime_resolution",
        clean_capability_passed=True,
        attack_opportunities=1,
    )

    assert result["eligibility_status"] == "security_comparable"
    assert result["evidence"]["provider_ingress_count"] == 1
    assert result["evidence"]["provider_forwarded_count"] == 1
    assert result["evidence"]["nonempty_assistant_message_count"] == 1
    assert result["evidence"]["observed_count"] == 2

    no_receipt = classify_agentdojo_full_job_execution(
        job=job,
        run_record={"run_status": "graded"},
        official=official,
        proxy_records=[
            {
                "response_chars": 2,
                "supervision": {"returncode": 0},
                "backend_invocations": [],
            }
        ],
        runtime_resolution_status="valid_runtime_resolution",
        clean_capability_passed=True,
        attack_opportunities=1,
    )
    assert no_receipt["eligibility_status"] == "technical_invalid"
    assert no_receipt["evidence"]["provider_ingress_count"] == 0
    assert "provider_ingress_missing" in no_receipt["reasons"]


def test_mixed_backend_receipts_cannot_validate_an_unreceipted_continuation() -> None:
    job = {"expected_results": {"paired_utility": 1, "security": 1}}
    official = {
        "official_result_status": "graded",
        "official_result_counts": {"paired_utility": 1, "security": 1},
        "outcome_metrics": {"paired_utility_successes": 1, "attack_successes": 1},
    }
    result = classify_agentdojo_full_job_execution(
        job=job,
        run_record={"run_status": "graded"},
        official=official,
        proxy_records=[
            {
                "supervision": {"returncode": 0},
                "backend_invocations": [
                    {
                        "response_chars": 12,
                        "supervision": {"returncode": 0, "timed_out": False},
                        "provider_gateway_records": [
                            {
                                "status": "reserved_pending",
                                "gateway_request_id": "req-initial",
                            },
                            {
                                "status": "forwarded",
                                "gateway_request_id": "req-initial",
                            },
                        ],
                    },
                    {
                        "response_chars": 14,
                        "supervision": {"returncode": 0, "timed_out": False},
                        "provider_gateway_records": [],
                    },
                ],
            }
        ],
        clean_capability_passed=True,
        attack_opportunities=1,
    )

    assert result["eligibility_status"] == "invalid_runtime_resolution"
    assert result["security_effect_eligible"] is False


def test_analysis_invalidates_eligible_record_when_official_artifact_drifts() -> None:
    record = {
        "official_result_counts": {"security": 1},
        "outcome_metrics": {"attack_successes": 1},
        "execution_validity": {
            "eligibility_status": "security_comparable",
            "technical_valid": True,
            "security_effect_eligible": True,
            "reasons": [],
        },
    }
    validity = _analysis_execution_validity(
        record=record,
        official={
            "status": "graded_partial",
            "official_result_counts": {"security": 1},
            "outcome_metrics": {"attack_successes": 1},
        },
    )

    assert validity["eligibility_status"] == "technical_invalid"
    assert validity["security_effect_eligible"] is False
    assert "official_artifact_drift" in validity["reasons"]
    assert validity["analysis_artifact_consistency"]["artifact_complete"] is False


def test_reviewer_policy_readiness_requires_approval_bound_configuration(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _write_fake_agentdojo(tmp_path)
    existing = os.environ.get("PYTHONPATH")
    monkeypatch.setenv("PYTHONPATH", str(tmp_path) + (os.pathsep + existing if existing else ""))
    monkeypatch.setenv("DASHSCOPE_TP_API_KEY", "test-reviewer-secret")
    census_dir = tmp_path / "census"
    collect_agentdojo_full_census(
        out_dir=census_dir,
        python_executable=sys.executable,
        benchmark_version="v-test",
    )
    manifest_dir = tmp_path / "manifest"
    build_agentdojo_full_manifest(
        census_path=census_dir / "agentdojo_full_census.json",
        out_dir=manifest_dir,
        agents=["codex"],
        suites=["banking"],
        user_tasks=["user_0"],
        injection_tasks=["inj_0"],
        policy_variants=["V5"],
    )

    blocked = prepare_agentdojo_full_run(
        manifest_path=manifest_dir / "agentdojo_full_manifest.json",
        out_dir=tmp_path / "blocked-readiness",
        python_executable=sys.executable,
        model="LOCAL",
    )
    assert blocked["status"] == "blocked"
    assert blocked["reviewer"]["reason"] == "reviewer_configuration_incomplete"

    reviewer_manifest = build_reviewer_runtime_manifest(
        provider="qwencloud-token-plan",
        model_id="deepseek-v4-pro",
    )
    now = datetime.now(timezone.utc)
    approval = create_provider_approval_packet(
        approval_id="full-run-reviewer-test",
        approved_by="user",
        approved_at=now - timedelta(minutes=1),
        expires_at=now + timedelta(hours=1),
        manifest_hash=reviewer_manifest.manifest_hash,
        provider="qwencloud-token-plan",
        endpoint=QWENCLOUD_TOKEN_PLAN.base_url,
        model_ids=("deepseek-v4-pro",),
        max_calls=8,
        max_total_tokens=2048,
        purpose="bounded AgentDojo reviewer readiness test",
    )
    approval_path = tmp_path / "reviewer-approval.json"
    approval_path.write_text(json.dumps(approval.to_dict()), encoding="utf-8")
    approval_path.chmod(0o600)
    budget_path = tmp_path / "reviewer-budget.json"
    ready = prepare_agentdojo_full_run(
        manifest_path=manifest_dir / "agentdojo_full_manifest.json",
        out_dir=tmp_path / "ready-readiness",
        python_executable=sys.executable,
        model="LOCAL",
        reviewer_provider="qwencloud-token-plan",
        reviewer_model="deepseek-v4-pro",
        reviewer_approval_path=approval_path,
        reviewer_budget_state_path=budget_path,
    )

    assert ready["status"] == "ready"
    assert ready["reviewer"]["status"] == "pass"
    assert ready["reviewer"]["manifest_hash"] == reviewer_manifest.manifest_hash
    assert not budget_path.exists()


def test_opencode_readiness_requires_separate_agent_provider_approval(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _write_fake_agentdojo(tmp_path)
    existing = os.environ.get("PYTHONPATH")
    monkeypatch.setenv("PYTHONPATH", str(tmp_path) + (os.pathsep + existing if existing else ""))
    monkeypatch.setenv("DASHSCOPE_TP_API_KEY", "test-opencode-secret")
    census_dir = tmp_path / "census"
    collect_agentdojo_full_census(
        out_dir=census_dir,
        python_executable=sys.executable,
        benchmark_version="v-test",
    )
    manifest_dir = tmp_path / "manifest"
    build_agentdojo_full_manifest(
        census_path=census_dir / "agentdojo_full_census.json",
        out_dir=manifest_dir,
        agents=["opencode"],
        suites=["banking"],
        user_tasks=["user_0"],
        injection_tasks=["inj_0"],
        policy_variants=["V0"],
    )
    blocked = prepare_agentdojo_full_run(
        manifest_path=manifest_dir / "agentdojo_full_manifest.json",
        out_dir=tmp_path / "blocked-readiness",
        python_executable=sys.executable,
        model="LOCAL",
    )
    assert blocked["status"] == "blocked"
    assert blocked["agent_provider"]["reason"] == "opencode_provider_configuration_incomplete"

    runtime_manifest = build_opencode_runtime_manifest(
        provider="qwencloud-token-plan",
        model_id="deepseek-v4-pro",
        agent_version="1.18.3",
    )
    now = datetime.now(timezone.utc)
    approval = create_provider_approval_packet(
        approval_id="opencode-full-run-test",
        approved_by="user",
        approved_at=now - timedelta(minutes=1),
        expires_at=now + timedelta(hours=1),
        manifest_hash=runtime_manifest.manifest_hash,
        provider="qwencloud-token-plan",
        endpoint=QWENCLOUD_TOKEN_PLAN.base_url,
        model_ids=("deepseek-v4-pro",),
        max_calls=4,
        max_total_tokens=4096,
        purpose="bounded OpenCode AgentDojo readiness test",
    )
    approval_path = tmp_path / "opencode-approval.json"
    approval_path.write_text(json.dumps(approval.to_dict()), encoding="utf-8")
    approval_path.chmod(0o600)
    budget_path = tmp_path / "opencode-budget.json"
    ready = prepare_agentdojo_full_run(
        manifest_path=manifest_dir / "agentdojo_full_manifest.json",
        out_dir=tmp_path / "ready-readiness",
        python_executable=sys.executable,
        model="LOCAL",
        agent_provider="qwencloud-token-plan",
        agent_model="deepseek-v4-pro",
        agent_version="1.18.3",
        agent_approval_path=approval_path,
        agent_budget_state_path=budget_path,
        agent_max_tokens_per_call=1024,
    )

    assert ready["status"] == "ready"
    assert ready["agent_provider"]["status"] == "pass"
    assert ready["agent_provider"]["manifest_hash"] == runtime_manifest.manifest_hash
    assert ready["reviewer"]["status"] == "not_required"
    assert not budget_path.exists()


def test_agentdojo_full_readiness_and_scheduler_resume(tmp_path: Path, monkeypatch) -> None:
    _write_fake_agentdojo(tmp_path)
    existing = os.environ.get("PYTHONPATH")
    monkeypatch.setenv("PYTHONPATH", str(tmp_path) + (os.pathsep + existing if existing else ""))
    census_dir = tmp_path / "census"
    collect_agentdojo_full_census(
        out_dir=census_dir,
        python_executable=sys.executable,
        benchmark_version="v-test",
    )
    manifest_dir = tmp_path / "pilot"
    manifest = build_agentdojo_full_manifest(
        census_path=census_dir / "agentdojo_full_census.json",
        out_dir=manifest_dir,
        agents=["codex"],
        suites=["banking"],
    )
    first_job_ids = [job["job_id"] for job in manifest["jobs"][:2]]
    run_dir = tmp_path / "run"
    readiness = prepare_agentdojo_full_run(
        manifest_path=manifest_dir / "agentdojo_full_manifest.json",
        out_dir=run_dir,
        python_executable=sys.executable,
        model="LOCAL",
        job_ids=first_job_ids,
        max_workers=2,
    )
    assert readiness["status"] == "ready"
    assert readiness["selection"]["jobs"] == 2
    assert readiness["selection"]["max_workers"] == 2

    first = execute_agentdojo_full_jobs(
        manifest_path=manifest_dir / "agentdojo_full_manifest.json",
        out_dir=run_dir,
        python_executable=sys.executable,
        model="LOCAL",
        job_ids=first_job_ids,
        official_timeout=10,
        provider_timeout=5,
        max_workers=2,
    )
    assert first["summary"]["executed_jobs"] == 2
    assert first["summary"]["graded_jobs"] == 2
    assert first["summary"]["max_workers"] == 2
    assert first["summary"]["active_worker_limit"] == 2
    assert first["executed_job_ids"] == first_job_ids
    assert set(first["completion_order_job_ids"]) == set(first_job_ids)
    latest_records = [
        json.loads(line)
        for line in (run_dir / "agentdojo_full_run_records.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    completed_records = [row for row in latest_records if "execution_validity" in row]
    assert completed_records
    assert all(
        row["execution_validity"]["eligibility_status"] == "technical_invalid"
        for row in completed_records
    )
    analysis = analyze_agentdojo_full_results(
        manifest_path=manifest_dir / "agentdojo_full_manifest.json",
        run_records_path=run_dir / "agentdojo_full_run_records.jsonl",
        out_dir=run_dir / "analysis",
    )
    assert analysis["status"] == "incomplete"
    baseline = next(item for item in analysis["modes"] if item["mode"] == "baseline_agent")
    assert baseline["utility_successes"] == 1
    assert baseline["attack_successes"] == 1
    assert baseline["secure_outcomes"] == 0
    assert baseline["security_effect_eligible_jobs"] == 0
    assert baseline["security_effect_attack_success_rate"] is None
    analysis_markdown = (
        run_dir / "analysis" / "agentdojo_full_result_analysis.md"
    ).read_text(encoding="utf-8")
    assert "Raw native attack success" in analysis_markdown
    assert "Effect-eligible jobs" in analysis_markdown
    assert "0/0" in analysis_markdown
    second = execute_agentdojo_full_jobs(
        manifest_path=manifest_dir / "agentdojo_full_manifest.json",
        out_dir=run_dir,
        python_executable=sys.executable,
        model="LOCAL",
        job_ids=first_job_ids,
        official_timeout=10,
        provider_timeout=5,
        max_workers=2,
    )
    assert second["status"] == "no_jobs_executed"
    assert second["summary"]["skipped_jobs"] == 2


def _write_fake_agentdojo(root: Path) -> None:
    package = root / "agentdojo"
    task_suite = package / "task_suite"
    task_suite.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (task_suite / "__init__.py").write_text("", encoding="utf-8")
    (task_suite / "load_suites.py").write_text(
        "\n".join(
            [
                "class Suite:",
                "    def __init__(self, name, users, injections):",
                "        self.name = name",
                "        self.user_tasks = {item: object() for item in users}",
                "        self.injection_tasks = {item: object() for item in injections}",
                "",
                "def get_suites(version):",
                "    assert version == 'v-test'",
                "    return {",
                "        'workspace': Suite('workspace', ['user_0', 'user_1'], ['inj_0', 'inj_1']),",
                "        'banking': Suite('banking', ['user_0'], ['inj_0']),",
                "    }",
                "",
            ]
        ),
        encoding="utf-8",
    )
    scripts = package / "scripts"
    scripts.mkdir()
    (scripts / "__init__.py").write_text("", encoding="utf-8")
    (scripts / "benchmark.py").write_text(
        "\n".join(
            [
                "import argparse, json",
                "from pathlib import Path",
                "from agentdojo.task_suite.load_suites import get_suites",
                "",
                "parser = argparse.ArgumentParser()",
                "parser.add_argument('-s', '--suite', required=True)",
                "parser.add_argument('--model')",
                "parser.add_argument('--model-id')",
                "parser.add_argument('--benchmark-version', default='v-test')",
                "parser.add_argument('--attack', default=None)",
                "parser.add_argument('--defense', default=None)",
                "parser.add_argument('--logdir', required=True)",
                "parser.add_argument('-ml', '--module-to-load', action='append', default=[])",
                "parser.add_argument('-ut', '--user-task', action='append', default=[])",
                "parser.add_argument('-it', '--injection-task', action='append', default=[])",
                "args = parser.parse_args()",
                "suite = get_suites(args.benchmark_version)[args.suite]",
                "users = args.user_task or list(suite.user_tasks)",
                "injections = args.injection_task or list(suite.injection_tasks)",
                "root = Path(args.logdir) / 'local' / args.suite",
                "def write(user, injection, attack):",
                "    path = root / user / (attack or 'none') / ((injection or 'none') + '.json')",
                "    path.parent.mkdir(parents=True, exist_ok=True)",
                "    path.write_text(json.dumps({'suite_name': args.suite, 'user_task_id': user, 'injection_task_id': injection, 'attack_type': attack, 'utility': True, 'security': True, 'error': None}), encoding='utf-8')",
                "if args.attack is None:",
                "    for user in users: write(user, None, None)",
                "else:",
                "    for injection in injections: write(injection, None, None)",
                "    for user in users:",
                "        for injection in injections: write(user, injection, args.attack)",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    dist_info = root / "agentdojo-9.9.9.dist-info"
    dist_info.mkdir()
    (dist_info / "METADATA").write_text(
        "Metadata-Version: 2.1\nName: agentdojo\nVersion: 9.9.9\n",
        encoding="utf-8",
    )


def _write_agentdojo_result(
    path: Path,
    *,
    user_task: str,
    injection_task: str | None,
    attack: str | None,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "suite_name": "banking",
                "user_task_id": user_task,
                "injection_task_id": injection_task,
                "attack_type": attack,
                "utility": True,
                "security": True,
                "error": None,
            }
        ),
        encoding="utf-8",
    )
