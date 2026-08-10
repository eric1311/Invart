from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .agentharm_executor import execute_agentharm_launch_package
from .agentharm_pilot import load_agentharm_pilot_request
from .agentharm_scored_package import finalize_agentharm_scored_package
from .provider_run_control import load_provider_approval_packet


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Execute one approved AgentHarm Phase-B0 V0 smoke and finalize its "
            "official scored package."
        )
    )
    parser.add_argument("--launch-package", type=Path, required=True)
    parser.add_argument("--execution-dir", type=Path, required=True)
    parser.add_argument("--approval", type=Path, required=True)
    parser.add_argument("--dataset-root", type=Path, required=True)
    parser.add_argument("--runner-root", type=Path, required=True)
    parser.add_argument("--confirm-request-hash", required=True)
    parser.add_argument("--confirm-approval-hash", required=True)
    args = parser.parse_args(argv)

    try:
        request = load_agentharm_pilot_request(
            args.launch_package / "request.json"
        )
        expected_hash = str(request["request_hash"])
        if args.confirm_request_hash != expected_hash:
            raise ValueError(
                "confirmed request hash does not match the launch package"
            )
        approval = load_provider_approval_packet(args.approval)
        if args.confirm_approval_hash != approval.approval_hash:
            raise ValueError(
                "confirmed approval hash does not match the approval packet"
            )
        credential_name = str(request["credential_env_name"])
        execution = execute_agentharm_launch_package(
            package_dir=args.launch_package,
            output_dir=args.execution_dir,
            approval=approval,
            dataset_root=args.dataset_root,
            runner_root=args.runner_root,
            provider_environment={
                credential_name: str(os.environ.get(credential_name) or "")
            },
        )
        if execution.get("status") != "completed_unscored":
            print(
                json.dumps(
                    {
                        "status": execution.get("status"),
                        "execution_record_hash": execution.get(
                            "execution_record_hash"
                        ),
                    },
                    sort_keys=True,
                )
            )
            return 1
        scored = finalize_agentharm_scored_package(
            package_dir=args.launch_package,
            execution_dir=args.execution_dir,
            approval=approval,
            dataset_root=args.dataset_root,
            runner_root=args.runner_root,
        )
    except (OSError, RuntimeError, ValueError) as exc:
        print(
            json.dumps(
                {
                    "status": "failed_closed",
                    "error_type": type(exc).__name__,
                    "message": str(exc),
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2

    print(
        json.dumps(
            {
                "status": scored["status"],
                "request_hash": scored["request_hash"],
                "score_record_hash": scored["score_record_hash"],
                "eligibility_status": scored["pilot_gate"][
                    "eligibility_status"
                ],
                "security_effect_eligible": scored["pilot_gate"][
                    "security_effect_eligible"
                ],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
