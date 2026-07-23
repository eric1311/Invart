from __future__ import annotations

from pathlib import Path
from typing import Any

from invart.core.artifacts import write_json_artifact
from invart.core.models import utc_now

from .official_runners import build_agentdojo_command


def write_agentdojo_adapter_boundary(
    *,
    out_dir: Path,
    case_id: str,
    benchmark_case_ref: str,
    agent: str,
    mode: str,
    suite: str,
    user_task: str | None,
    model_env: str,
    python_executable: str = "python",
    module_to_load: str | None = None,
    attack: str | None = "tool_knowledge",
    defense: str | None = None,
) -> dict[str, Any]:
    root = out_dir.expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    command = build_agentdojo_command(
        python_executable=python_executable,
        model=f"${{{model_env}}}",
        suite=suite,
        module_to_load=module_to_load,
        user_tasks=[user_task] if user_task else None,
        attack=attack,
        defense=defense,
        logdir=str(root / "official-logdir"),
    )
    report = {
        "schema_version": "invart.p0_agentdojo_adapter_boundary.v0.1",
        "generated_at": utc_now(),
        "status": "requires_model_registration",
        "case_id": case_id,
        "benchmark_case_ref": benchmark_case_ref,
        "agent": agent,
        "mode": mode,
        "suite": suite,
        "user_task": user_task,
        "model_env": model_env,
        "module_to_load": module_to_load,
        "official_runner_command": command,
        "official_adapter_contract": {
            "schema_version": "invart.p0_agentdojo_official_adapter_contract.v0.1",
            "entrypoint": "python -m agentdojo.scripts.benchmark",
            "model_binding": f"${{{model_env}}}",
            "adapter_registration": (
                "Register a provider-specific model or local adapter with AgentDojo, then pass that id through --model. "
                "If custom registration code is needed, load it through AgentDojo's --module-to-load option."
            ),
            "result_artifact_shape": (
                "AgentDojo TraceLogger writes JSON task-result files under logdir/<pipeline>/<suite>/<user_task>/<attack>/<injection_task>.json. "
                "Official utility/security outcomes must be parsed from those files."
            ),
            "bridge_boundary": (
                "Claude Code, Codex, Hermes, or other provider CLIs are not official AgentDojo models until bound through a registered "
                "AgentDojo model/adapter id accepted by agentdojo.scripts.benchmark."
            ),
        },
        "reason": (
            "AgentDojo's official runner accepts registered model identifiers. This CLI agent row can become an official "
            f"AgentDojo row only when {model_env} names a model/adapter registered with agentdojo.scripts.benchmark."
        ),
        "safe_next_step": (
            f"Set {model_env} to a registered AgentDojo model id or adapter id, then rerun p0_first_batch_commands.sh. "
            "Until then, this row is adapter-boundary evidence, not an official AgentDojo score."
        ),
        "claim_boundary": (
            "This artifact records why a provider CLI agent row has not yet produced official AgentDojo evidence. "
            "It must not be counted as an official AgentDojo security or utility result."
        ),
    }
    write_json_artifact(root / "agentdojo_adapter_boundary.json", report)
    return report


def split_agentdojo_case_ref(ref: str) -> tuple[str, str | None]:
    if ":" in ref:
        suite, task = ref.split(":", 1)
        return suite or "workspace", task or None
    return ref or "workspace", None
