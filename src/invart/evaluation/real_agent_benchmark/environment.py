from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from invart.core.models import utc_now
from invart.surfaces.adapter_profiles import get_adapter_profile
from .provider_credentials import loopback_no_proxy_environment, provider_credential_options


BENCHMARK_IMPORTS = {
    "agentdojo": ["agentdojo"],
    "agentsecbench": ["benchmark"],
    "skill_inject": [],
    "swe_bench_verified": ["swebench"],
    "agentharm": ["inspect_ai"],
    "mcptox": [],
    "mcp_agentbench": [],
}


def freeze_p0_environment(*, manifest: dict[str, Any], cwd: Path | None = None) -> dict[str, Any]:
    agents = [str(item.get("agent")) for item in manifest.get("agents", []) if isinstance(item, dict) and item.get("agent")]
    families = sorted({str(item.get("family")) for item in manifest.get("cases", []) if isinstance(item, dict) and item.get("family")})
    return {
        "schema_version": "invart.p0_environment_freeze.v0.1",
        "captured_at": utc_now(),
        "python": {
            "executable": sys.executable,
            "version": sys.version.split()[0],
        },
        "cwd": str((cwd or Path.cwd()).expanduser().resolve()),
        "agents": [_agent_environment(agent) for agent in agents],
        "benchmarks": [_benchmark_environment(family) for family in families],
        "child_environment_contract": {
            "loopback_no_proxy": loopback_no_proxy_environment(),
            "reason": (
                "Both proxy-variable casings are explicit so isolated provider and benchmark "
                "children cannot route loopback traffic through an upstream proxy."
            ),
        },
        "auth_boundary": (
            "This freeze does not validate provider authentication or spend permission. A real P0 row requires a successful "
            "provider CLI or official benchmark process execution recorded in p0_run_matrix.jsonl."
        ),
        "claim_boundary": (
            "Environment availability is setup evidence only. It is not a benchmark result and must not be counted as "
            "baseline, observe-only, or mediated execution evidence."
        ),
    }


def _agent_environment(agent: str) -> dict[str, Any]:
    profile = get_adapter_profile(agent)
    binaries = []
    for candidate in profile.get("binary_candidates", []) or []:
        path = shutil.which(str(candidate))
        binaries.append({
            "candidate": candidate,
            "path": path,
            "available": path is not None,
            "version_probe": _version_probe(path) if path else {"status": "missing"},
        })
    return {
        "agent": agent,
        "display_name": profile.get("display_name"),
        "standard_bridge": _standard_bridge(profile),
        "binary_candidates": binaries,
        "available": any(item["available"] for item in binaries),
        "supports_mediation": profile.get("supports_mediation", False),
        "provider_credentials": provider_credential_options(agent),
        "claim_boundary": profile.get("claim_boundary"),
    }


def _benchmark_environment(family: str) -> dict[str, Any]:
    imports = [
        {"module": module, "available": importlib.util.find_spec(module) is not None}
        for module in BENCHMARK_IMPORTS.get(family, [])
    ]
    cli: dict[str, Any] = {"status": "not_applicable"}
    if family == "skill_inject":
        cli = {
            "docker": _docker_probe(),
            "bash": shutil.which("bash"),
            "api_keys": _api_key_presence(["OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY", "OPENROUTER_API_KEY"]),
        }
    if family in {"agentharm", "mcptox", "mcp_agentbench"}:
        cli = {
            "status": "probe_required" if family == "agentharm" else "blocked_upstream_contract",
            "api_keys": _api_key_presence(["OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GOOGLE_API_KEY"]),
            "credentials_inherited_by_default": False,
        }
    return {
        "family": family,
        "imports": imports,
        "import_available": all(item["available"] for item in imports) if imports else None,
        "cli": cli,
        "setup_boundary": _setup_boundary(family),
    }


def _version_probe(path: str) -> dict[str, Any]:
    for args in ([path, "--version"], [path, "version"]):
        try:
            completed = subprocess.run(args, capture_output=True, text=True, timeout=5)
        except Exception as exc:
            return {"status": "error", "error": type(exc).__name__}
        output = (completed.stdout or completed.stderr or "").strip()
        if completed.returncode == 0 or output:
            return {
                "status": "pass" if completed.returncode == 0 else "nonzero_with_output",
                "returncode": completed.returncode,
                "command": args,
                "output": output[-500:],
            }
    return {"status": "unknown"}


def _docker_probe() -> dict[str, Any]:
    path = shutil.which("docker")
    if not path:
        return {"status": "missing", "path": None}
    info = _run_probe([path, "info", "--format", "{{json .ServerVersion}} {{json .OSType}} {{json .Architecture}}"], timeout=10)
    image = _run_probe([path, "image", "inspect", "instruct-bench-agent", "--format", "{{json .RepoTags}} {{.Id}} {{.Size}}"], timeout=10)
    return {
        "status": "ready" if info.get("returncode") == 0 else "daemon_unavailable",
        "path": path,
        "daemon": info,
        "instruct_bench_agent_image": "present" if image.get("returncode") == 0 else "missing",
        "image_probe": image,
        "claim_boundary": "Docker/image availability is setup evidence only; it is not Skill-Inject benchmark execution evidence.",
    }


def _api_key_presence(names: list[str]) -> list[dict[str, Any]]:
    return [{"name": name, "set": bool(os.environ.get(name))} for name in names]


def _run_probe(command: list[str], *, timeout: int) -> dict[str, Any]:
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
        return {
            "command": command,
            "returncode": completed.returncode,
            "stdout_tail": (completed.stdout or "")[-500:],
            "stderr_tail": (completed.stderr or "")[-500:],
        }
    except Exception as exc:
        return {"command": command, "returncode": None, "error": type(exc).__name__}


def _standard_bridge(profile: dict[str, Any]) -> str:
    modes = set(profile.get("execution_modes") or [])
    if "managed_wrapper" in modes or "managed_runtime" in modes:
        return "provider_cli_process_wrapped_by_invart"
    if "managed_launcher_candidate" in modes:
        return "provider_cli_or_backend_launcher_with_explicit_evidence_import"
    if "vendor_evidence_import" in modes:
        return "vendor_native_evidence_import_only"
    return "generic_cli_process"


def _setup_boundary(family: str) -> str:
    if family == "swe_bench_verified":
        return "Requires swebench package, Docker-capable execution, predictions JSONL, and official harness output."
    if family == "agentdojo":
        return "Requires agentdojo package and an upstream-supported model/agent invocation."
    if family == "agentsecbench":
        return "Requires AgentSecBench repository checkout or package path exposing benchmark.run."
    if family == "skill_inject":
        return "Requires Skill-Inject repository checkout, Docker image build, provider keys, and upstream experiment outputs."
    if family == "agentharm":
        return "Requires pinned Inspect Evals AgentHarm code, pinned dataset revision, simulator-only tools, and native grader logs."
    if family == "mcptox":
        return "Pinned repository currently lacks a supported end-to-end runner; data qualification is possible but execution remains blocked."
    if family == "mcp_agentbench":
        return "Peer-reviewed paper is known, but official executable code, license, server freeze, and MCP-Eval artifacts remain unresolved."
    return "Unknown benchmark family."
