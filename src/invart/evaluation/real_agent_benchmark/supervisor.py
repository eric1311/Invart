from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from invart.surfaces.supervision import supervise_process_group

from .ground_truth import (
    collect_workspace_snapshot,
    create_ground_truth_canary,
    diff_workspace_snapshots,
    evaluate_ground_truth_canary,
    network_observation_from_process,
    shell_transcript_from_process,
    side_effect_record_from_diff,
)
from .mode_binding import mode_binding_for_command, should_block_for_mode


_CREDENTIAL_SUFFIXES = ("_API_KEY", "_TOKEN", "_SECRET", "_PASSWORD", "_CREDENTIALS")
_CREDENTIAL_NAMES = {
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "SSH_AUTH_SOCK",
}


@dataclass(frozen=True)
class UpstreamExecutionContract:
    """Fail-closed preflight for untrusted benchmark harnesses.

    This is deliberately not advertised as an OS sandbox. A caller may launch
    only after a deny-by-default network and filesystem boundary is actually
    available and represented here.
    """

    workspace_root: Path
    output_paths: tuple[Path, ...]
    allowed_network_destinations: tuple[str, ...]
    network_enforcement: str
    safe_simulation: bool

    def __post_init__(self) -> None:
        root = self.workspace_root.expanduser().resolve()
        object.__setattr__(self, "workspace_root", root)
        object.__setattr__(self, "output_paths", tuple(path.expanduser().resolve() for path in self.output_paths))
        object.__setattr__(
            self,
            "allowed_network_destinations",
            tuple(sorted({str(item).strip().lower() for item in self.allowed_network_destinations if str(item).strip()})),
        )
        if self.network_enforcement not in {"deny_by_default", "none"}:
            raise ValueError("unsupported network_enforcement")


def validate_upstream_execution_contract(
    *,
    contract: UpstreamExecutionContract,
    environment: Mapping[str, str],
    observed_network_destinations: Sequence[str] = (),
) -> dict[str, Any]:
    reasons: list[str] = []
    escaped = [str(path) for path in contract.output_paths if not path.is_relative_to(contract.workspace_root)]
    if escaped:
        reasons.append("output_path_outside_scoped_root")
    inherited_credentials = sorted(
        key
        for key, value in environment.items()
        if value and (key.upper().endswith(_CREDENTIAL_SUFFIXES) or key.upper() in _CREDENTIAL_NAMES)
    )
    if inherited_credentials:
        reasons.append("undeclared_host_credentials")
    observed = {str(item).strip().lower() for item in observed_network_destinations if str(item).strip()}
    allowed = set(contract.allowed_network_destinations)
    if contract.network_enforcement != "deny_by_default":
        reasons.append("network_boundary_not_enforced")
    if observed - allowed:
        reasons.append("unregistered_network_destination")
    if not contract.safe_simulation:
        reasons.append("unsafe_real_world_target")
    return {
        "status": "blocked" if reasons else "pass",
        "reasons": sorted(set(reasons)),
        "workspace_root": str(contract.workspace_root),
        "output_paths": [str(path) for path in contract.output_paths],
        "allowed_network_destinations": list(contract.allowed_network_destinations),
        "observed_network_destinations": sorted(observed),
        "inherited_credential_names": inherited_credentials,
        "claim_boundary": (
            "This preflight proves declared boundary consistency only. Runtime containment requires the "
            "deny-by-default mechanism represented by network_enforcement and separate process evidence."
        ),
    }


def supervise_p0_command(
    *,
    command: list[str],
    cwd: Path,
    timeout: float,
    case_id: str,
    agent: str,
    mode: str,
    env: Mapping[str, str] | None = None,
    redactions: Sequence[str] = (),
) -> dict[str, Any]:
    resolved_cwd = cwd.expanduser().resolve()
    resolved_cwd.mkdir(parents=True, exist_ok=True)
    mode_binding = mode_binding_for_command(command=command, case_id=case_id, agent=agent, mode=mode)
    canary_before = create_ground_truth_canary(root=resolved_cwd, case_id=case_id, agent=agent, mode=mode)
    before = collect_workspace_snapshot(resolved_cwd)
    if should_block_for_mode(mode_binding):
        supervision = _blocked_process(command=command, mode_binding=mode_binding)
    else:
        supervision = supervise_process_group(
            command,
            cwd=resolved_cwd,
            timeout=timeout,
            env=env,
            redactions=redactions,
        )
    after = collect_workspace_snapshot(resolved_cwd)
    diff = diff_workspace_snapshots(before, after)
    canary_after = evaluate_ground_truth_canary(root=resolved_cwd, canary=canary_before)
    transcript = shell_transcript_from_process(command=command, cwd=resolved_cwd, process=supervision)
    network = network_observation_from_process(command=command, process=supervision)
    side_effect = side_effect_record_from_diff(
        case_id=case_id,
        agent=agent,
        mode=mode,
        diff=diff,
        canary=canary_after,
        shell_transcript=transcript,
        network_observation=network,
        mode_binding=mode_binding,
    )
    return {
        "schema_version": "invart.p0_command_supervision.v0.1",
        "case_id": case_id,
        "agent": agent,
        "mode": mode,
        "command": command,
        "cwd": str(resolved_cwd),
        "process": supervision,
        "shell_transcript": transcript,
        "network_observation": network,
        "workspace_before": before,
        "workspace_after": after,
        "workspace_diff": diff,
        "canary": canary_after,
        "mode_binding": mode_binding,
        "side_effect": side_effect,
        "stability": {
            "returncode": supervision.get("returncode"),
            "timed_out": bool(supervision.get("timed_out")),
            "crashed": _crashed(supervision),
            "blocked": bool(supervision.get("blocked")),
        },
    }


def _blocked_process(*, command: list[str], mode_binding: dict[str, Any]) -> dict[str, Any]:
    timestamp = mode_binding.get("decision", {}).get("timestamp") if isinstance(mode_binding.get("decision"), dict) else None
    return {
        "schema_version": "invart.process_supervision.v0.10",
        "command": command,
        "returncode": 126,
        "timed_out": False,
        "blocked": True,
        "stdout": "",
        "stderr": "blocked by Invart P0 mediated pre-side-effect policy gate",
        "started_at": timestamp,
        "ended_at": timestamp,
        "process_group": {
            "pid": None,
            "pgid": None,
            "strong_consistency": True,
            "control": "pre_side_effect_block",
        },
        "snapshots": [],
    }


def _crashed(supervision: dict[str, Any]) -> bool:
    returncode = supervision.get("returncode")
    if returncode is None:
        return False
    try:
        return int(returncode) < 0
    except (TypeError, ValueError):
        return False
