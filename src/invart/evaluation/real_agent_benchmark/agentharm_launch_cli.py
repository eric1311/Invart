from __future__ import annotations

import argparse
import json
from pathlib import Path

from .agent_runtime_manifest import runtime_manifest_from_dict
from .agentharm_launch import prepare_agentharm_launch_package
from .agentharm_pilot import load_agentharm_pilot_request
from .provider_run_control import load_provider_approval_packet


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Prepare an AgentHarm launch package. This command stages data and command "
            "inputs but never starts the gateway, runner, or provider."
        )
    )
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--dataset-root", type=Path, required=True)
    parser.add_argument("--runner-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--gateway-base-url", default="http://127.0.0.1:43123/v1")
    parser.add_argument("--approval", type=Path)
    args = parser.parse_args(argv)
    try:
        request = load_agentharm_pilot_request(args.request)
        manifest_payload = request.get("runtime_manifest")
        if not isinstance(manifest_payload, dict):
            raise ValueError("AgentHarm request has no embedded runtime manifest")
        runtime_manifest = runtime_manifest_from_dict(manifest_payload)
        approval = (
            load_provider_approval_packet(args.approval)
            if args.approval is not None
            else None
        )
        package = prepare_agentharm_launch_package(
            args.output_dir,
            request=request,
            runtime_manifest=runtime_manifest,
            dataset_root=args.dataset_root,
            runner_root=args.runner_root,
            gateway_base_url=args.gateway_base_url,
            approval=approval,
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
                "status": package["status"],
                "ready_to_execute": package["ready_to_execute"],
                "provider_execution_performed": package["provider_execution_performed"],
                "request_hash": package["request_hash"],
                "package_hash": package["package_hash"],
                "output_dir": str(args.output_dir.expanduser().absolute()),
                "command_count": package["observed_command_count"],
                "reasons": package["reasons"],
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0 if package["status"] in {"approval_required", "executor_required"} else 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())


__all__ = ["main"]
