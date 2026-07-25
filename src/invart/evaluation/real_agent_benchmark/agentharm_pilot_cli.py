from __future__ import annotations

import argparse
import json
from pathlib import Path

from .agent_runtime_manifest import (
    ClaimKind,
    RuntimeRequest,
    build_runtime_manifest,
    provider_profile_for_id,
)
from .agentharm_pilot import (
    build_agentharm_pilot_request_from_source,
    validate_agentharm_pilot_preflight,
    write_agentharm_pilot_request,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Build and validate a bounded AgentHarm Phase B request. "
            "This command never creates approval or calls a provider."
        )
    )
    parser.add_argument("--dataset-root", type=Path, required=True)
    parser.add_argument("--runner-root", type=Path, required=True)
    parser.add_argument("--output-request", type=Path, required=True)
    parser.add_argument("--provider", default="qwencloud-token-plan")
    parser.add_argument("--model", default="deepseek-v4-pro")
    parser.add_argument("--refusal-judge")
    parser.add_argument("--semantic-judge")
    parser.add_argument("--harmful-case-id", action="append", required=True)
    parser.add_argument("--benign-case-id", action="append", required=True)
    parser.add_argument("--variant", action="append", required=True)
    parser.add_argument("--epochs", type=int, default=1)
    parser.add_argument("--maximum-calls-per-sample", type=int, required=True)
    parser.add_argument("--maximum-tokens-per-call", type=int, required=True)
    parser.add_argument("--maximum-usd", type=float, required=True)
    parser.add_argument("--timeout-seconds", type=int, default=120)
    parser.add_argument("--max-connections", type=int, default=1)
    parser.add_argument("--max-retries", type=int, default=0)
    parser.add_argument("--profile-state-hash", required=True)
    parser.add_argument("--agent-version", default="unknown")
    parser.add_argument("--runtime-version", default="unknown")
    args = parser.parse_args(argv)

    try:
        profile = provider_profile_for_id(args.provider)
        if profile is None:
            raise ValueError(f"unknown provider profile: {args.provider}")
        runtime_manifest = build_runtime_manifest(
            request=RuntimeRequest(
                requested_provider=profile.profile_id,
                requested_model=args.model,
                agent_product="inspect-evals-agentharm",
                low_level_runtime="inspect-ai",
                execution_contract="completion_backend",
                evidence_kind=ClaimKind.COMPLETION_BACKEND,
            ),
            provider_profile=profile,
            agent_version=args.agent_version,
            runtime_version=args.runtime_version,
            profile_state_hash=args.profile_state_hash,
        )
        request = build_agentharm_pilot_request_from_source(
            runtime_manifest=runtime_manifest,
            dataset_root=args.dataset_root,
            runner_root=args.runner_root,
            split="validation",
            primary_model=args.model,
            refusal_judge=args.refusal_judge or args.model,
            semantic_judge=args.semantic_judge or args.model,
            harmful_case_ids=args.harmful_case_id,
            benign_case_ids=args.benign_case_id,
            variants=args.variant,
            epochs=args.epochs,
            maximum_calls_per_sample=args.maximum_calls_per_sample,
            maximum_tokens_per_call=args.maximum_tokens_per_call,
            maximum_usd=args.maximum_usd,
            timeout_seconds=args.timeout_seconds,
            max_connections=args.max_connections,
            max_retries=args.max_retries,
        )
        output = write_agentharm_pilot_request(args.output_request, request)
        preflight = validate_agentharm_pilot_preflight(
            request,
            runtime_manifest=runtime_manifest,
            dataset_root=args.dataset_root,
            runner_root=args.runner_root,
        )
    except Exception as exc:
        print(
            json.dumps(
                {
                    "status": "blocked",
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                },
                ensure_ascii=False,
                sort_keys=True,
            )
        )
        return 2

    print(
        json.dumps(
            {
                "status": preflight["status"],
                "ready_to_execute": preflight["ready_to_execute"],
                "approved_inputs_validated": preflight["approved_inputs_validated"],
                "reasons": preflight["reasons"],
                "request_path": str(output),
                "request_hash": request["request_hash"],
                "approval_scope_hash": request["approval_scope_hash"],
                "runtime_manifest_hash": runtime_manifest.manifest_hash,
                "claim_boundary": (
                    "This command wrote a reviewable request and performed no provider call."
                ),
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())


__all__ = ["main"]
