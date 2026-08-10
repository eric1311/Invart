from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from invart.core.artifacts import write_json_artifact
from invart.core.models import utc_now
from .provider_credentials import provider_api_keys, provider_credential_missing_label, provider_credential_options
from invart.surfaces.adapter_profiles import get_adapter_profile

from .swe_dataset import swe_instance_ids_from_manifest


def run_p0_doctor(*, run_dir: Path, manifest: dict[str, Any] | None = None, python_executable: str | None = None) -> dict[str, Any]:
    root = run_dir.expanduser().resolve()
    loaded_manifest = manifest or _read_json_object(root / "p0_case_manifest.json")
    python_bin = python_executable or sys.executable
    report = {
        "schema_version": "invart.p0_doctor.v0.1",
        "generated_at": utc_now(),
        "root": str(root),
        "status": "ready",
        "checks": {},
        "blocking": [],
        "warnings": [],
        "claim_boundary": (
            "P0 doctor is readiness evidence only. It checks whether the local environment can attempt real first-batch execution; "
            "it is not a benchmark result and cannot satisfy P0 execution completeness."
        ),
    }
    report["checks"]["artifacts"] = _artifact_checks(root)
    report["checks"]["scripts"] = _script_checks(root)
    report["checks"]["invart_import"] = _invart_import_check(root, python_bin)
    report["checks"]["agents"] = _agent_checks(loaded_manifest)
    report["checks"]["official_setup"] = _official_setup_checks(root)
    report["checks"]["swe_instances"] = _swe_instance_checks(root, loaded_manifest)
    report["checks"]["agentdojo_models"] = _agentdojo_model_checks(loaded_manifest)
    report["checks"]["skill_inject_readiness"] = _skill_inject_readiness_checks(root, loaded_manifest)
    report["checks"]["system_tools"] = _system_tool_checks()
    _classify(report)
    write_json_artifact(root / "p0_doctor.json", report)
    return report


def _artifact_checks(root: Path) -> dict[str, Any]:
    names = [
        "p0_case_manifest.json",
        "p0_first_batch_plan.json",
        "p0_first_batch_commands.sh",
        "reproduce_p0.sh",
    ]
    return {
        "status": "pass" if all((root / name).exists() for name in names) else "fail",
        "files": [{"name": name, "exists": (root / name).exists()} for name in names],
    }


def _script_checks(root: Path) -> dict[str, Any]:
    scripts = ["p0_first_batch_commands.sh", "reproduce_p0.sh"]
    rows = []
    for script in scripts:
        path = root / script
        if not path.exists():
            rows.append({"script": script, "status": "missing"})
            continue
        result = _run(["bash", "-n", str(path)], cwd=root, timeout=30)
        rows.append({"script": script, "status": "pass" if result["returncode"] == 0 else "fail", "probe": result})
    return {"status": "pass" if rows and all(row["status"] == "pass" for row in rows) else "fail", "scripts": rows}


def _invart_import_check(root: Path, python_bin: str) -> dict[str, Any]:
    repo_hint = _repo_hint()
    env = os.environ.copy()
    if repo_hint:
        env["PYTHONPATH"] = str(Path(repo_hint) / "src") + os.pathsep + env.get("PYTHONPATH", "")
    result = _run([python_bin, "-m", "invart.cli", "experiment", "list"], cwd=root, timeout=30, env=env)
    return {
        "status": "pass" if result["returncode"] == 0 else "fail",
        "python": python_bin,
        "invart_repo_hint": repo_hint,
        "probe": result,
    }


def _agent_checks(manifest: dict[str, Any]) -> dict[str, Any]:
    agents = [str(item.get("agent")) for item in manifest.get("agents", []) if isinstance(item, dict) and item.get("agent")]
    rows = []
    for agent in agents:
        profile = get_adapter_profile(agent)
        binaries = []
        for candidate in profile.get("binary_candidates", []) or []:
            path = shutil.which(str(candidate))
            binaries.append({"candidate": candidate, "path": path, "available": path is not None})
        rows.append({
            "agent": agent,
            "available": any(item["available"] for item in binaries),
            "binary_candidates": binaries,
            "claim_boundary": "Binary availability does not prove provider authentication or spend permission.",
        })
    return {"status": "pass" if rows and all(row["available"] for row in rows) else "blocked", "agents": rows}


def _official_setup_checks(root: Path) -> dict[str, Any]:
    path = root / "p0_official_setup.json"
    if not path.exists():
        return {"status": "blocked", "reason": "missing p0_official_setup.json"}
    setup = _read_json_object(path)
    entrypoints = setup.get("entrypoints", {})
    selected = {
        family: value
        for family, value in entrypoints.items()
        if family in {"agentdojo", "swe_bench_verified"}
    } if isinstance(entrypoints, dict) else {}
    entrypoints_ready = selected and all(isinstance(value, dict) and value.get("status") == "pass" for value in selected.values())
    return {
        "status": "pass" if entrypoints_ready else "needs_setup",
        "setup_status": setup.get("status"),
        "install_requested": setup.get("install_requested"),
        "entrypoints": selected,
        "note": "first-batch can run setup-official --install, but real benchmark execution requires these entrypoints to pass afterward.",
    }


def _swe_instance_checks(root: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    ids = swe_instance_ids_from_manifest(manifest)
    files = [{"instance_id": item, "path": str(root / "swe-instances" / f"{item}.json"), "exists": (root / "swe-instances" / f"{item}.json").exists()} for item in ids]
    return {
        "status": "pass" if files and all(item["exists"] for item in files) else "will_export",
        "instances": files,
        "note": "p0_first_batch_commands.sh exports missing official SWE rows before preparing workspaces.",
    }


def _agentdojo_model_checks(manifest: dict[str, Any]) -> dict[str, Any]:
    agents = [str(item.get("agent")) for item in manifest.get("agents", []) if isinstance(item, dict) and item.get("agent")]
    rows = []
    for agent in agents:
        env_name = "INVART_AGENTDOJO_MODEL_" + "".join(char.upper() if char.isalnum() else "_" for char in agent).strip("_")
        rows.append({"agent": agent, "env": env_name, "set": bool(os.environ.get(env_name))})
    return {
        "status": "pass" if rows and all(row["set"] for row in rows) else "boundary_only",
        "models": rows,
        "claim_boundary": "Unset AgentDojo model env means first-batch writes boundary artifacts instead of official AgentDojo score rows.",
    }


def _skill_inject_readiness_checks(root: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    cases = [item for item in manifest.get("cases", []) if isinstance(item, dict) and item.get("family") == "skill_inject"]
    rows = [row for row in _read_jsonl(root / "p0_run_matrix.jsonl") if row.get("family") == "skill_inject"]
    if not cases and not rows:
        return {"status": "skipped", "reason": "manifest has no Skill-Inject cases"}

    repo_candidates = _skill_inject_repo_candidates(root, rows)
    repo = next((path for path in repo_candidates if path.exists() and (path / "scripts" / "smoke_test_all.py").exists()), None)
    docker = _docker_skill_inject_probe(root)
    agents = _skill_inject_agents(manifest=manifest, rows=rows)
    required_keys = _skill_inject_required_keys(agents=agents)
    key_rows = [{"name": key, "set": bool(os.environ.get(key))} for key in required_keys]
    credential_rows = [
        {
            "agent": agent,
            "options": provider_credential_options(agent),
            "present": any(option.get("present") for option in provider_credential_options(agent)),
        }
        for agent in agents
    ]
    missing = []
    if repo is None:
        missing.append("upstream_repo")
    if docker["daemon"]["returncode"] != 0:
        missing.append("docker_daemon")
    if docker["instruct_bench_agent_image"] != "present":
        missing.append("instruct_bench_agent_image")
    missing.extend(provider_credential_missing_label(row["agent"]) for row in credential_rows if not row["present"])
    return {
        "status": "pass" if not missing else "needs_setup",
        "cases": len(cases),
        "rows": len(rows),
        "repository": {
            "status": "present" if repo is not None else "missing",
            "path": str(repo) if repo is not None else None,
            "candidates": [str(path) for path in repo_candidates],
        },
        "docker": docker,
        "api_keys": key_rows,
        "provider_credentials": credential_rows,
        "missing": missing,
        "next_actions": _skill_inject_next_actions(missing),
        "claim_boundary": (
            "Skill-Inject readiness proves only that the upstream runner can be attempted. Official benchmark claims "
            "still require non-dry-run upstream experiment outputs and judge artifacts attached to P0 rows."
        ),
    }


def _skill_inject_repo_candidates(root: Path, rows: list[dict[str, Any]]) -> list[Path]:
    candidates: list[Path] = []
    env_repo = os.environ.get("INVART_SKILL_INJECT_REPO")
    if env_repo:
        candidates.append(Path(env_repo).expanduser().resolve())
    candidates.append(Path.cwd().resolve() / ".local" / "upstream" / "skill-inject")
    for row in rows:
        cwd = row.get("cwd")
        if isinstance(cwd, str) and cwd:
            candidates.append(Path(cwd).expanduser().resolve())
    setup = _read_json_object(root / "p0_official_setup.json") if (root / "p0_official_setup.json").exists() else {}
    setup_root = setup.get("root")
    if isinstance(setup_root, str) and setup_root:
        candidates.append(Path(setup_root).expanduser().resolve() / "upstream" / "skill-inject")
        candidates.append(Path(setup_root).expanduser().resolve() / ".local" / "upstream" / "skill-inject")
    candidates.append(root / "upstream" / "skill-inject")
    seen: set[str] = set()
    unique = []
    for path in candidates:
        key = str(path)
        if key not in seen:
            seen.add(key)
            unique.append(path)
    return unique


def _docker_skill_inject_probe(root: Path) -> dict[str, Any]:
    docker = shutil.which("docker")
    if not docker:
        return {
            "path": None,
            "daemon": {"command": ["docker", "info"], "returncode": None, "error": "missing"},
            "instruct_bench_agent_image": "missing",
            "image_probe": {
                "command": ["docker", "image", "inspect", "instruct-bench-agent", "--format", "{{json .RepoTags}} {{.Id}} {{.Size}}"],
                "returncode": None,
                "error": "missing",
            },
        }
    daemon = _run([docker, "info", "--format", "{{json .ServerVersion}} {{json .OSType}} {{json .Architecture}}"], cwd=root, timeout=10)
    image = _run([docker, "image", "inspect", "instruct-bench-agent", "--format", "{{json .RepoTags}} {{.Id}} {{.Size}}"], cwd=root, timeout=10)
    return {
        "path": docker,
        "daemon": daemon,
        "instruct_bench_agent_image": "present" if image.get("returncode") == 0 else "missing",
        "image_probe": image,
    }


def _skill_inject_agents(*, manifest: dict[str, Any], rows: list[dict[str, Any]]) -> list[str]:
    agents = {str(item.get("agent")) for item in manifest.get("agents", []) if isinstance(item, dict) and item.get("agent")}
    agents.update(str(row.get("agent")) for row in rows if row.get("agent"))
    return sorted(agent for agent in agents if agent)


def _skill_inject_required_keys(*, agents: list[str]) -> list[str]:
    required: set[str] = set()
    for agent in agents:
        required.update(provider_api_keys(agent))
    return sorted(required)


def _skill_inject_next_actions(missing: list[str]) -> list[str]:
    actions = []
    if "upstream_repo" in missing:
        actions.append("prepare the official Skill-Inject repository checkout")
    if "docker_daemon" in missing:
        actions.append("start Docker Desktop or another Docker daemon")
    if "instruct_bench_agent_image" in missing:
        actions.append("build the upstream instruct-bench-agent image with bash docker/build.sh")
    credential_missing = [item for item in missing if item.startswith("provider_credential:")]
    if credential_missing:
        actions.append("provide API keys or mounted provider CLI config for: " + ", ".join(credential_missing))
    return actions


def _system_tool_checks() -> dict[str, Any]:
    tools = ["bash", "git", "docker"]
    rows = [{"tool": tool, "path": shutil.which(tool), "available": shutil.which(tool) is not None} for tool in tools]
    return {"status": "pass" if all(row["available"] for row in rows if row["tool"] != "docker") else "blocked", "tools": rows}


def _classify(report: dict[str, Any]) -> None:
    blocking = []
    warnings = []
    checks = report.get("checks", {})
    for name in ("artifacts", "scripts", "invart_import", "agents", "system_tools"):
        status = checks.get(name, {}).get("status") if isinstance(checks.get(name), dict) else None
        if status in {"fail", "blocked"}:
            blocking.append({"check": name, "status": status})
    for name in ("official_setup", "swe_instances", "agentdojo_models", "skill_inject_readiness"):
        status = checks.get(name, {}).get("status") if isinstance(checks.get(name), dict) else None
        if status not in {"pass", "skipped", None}:
            warnings.append({"check": name, "status": status})
    report["blocking"] = blocking
    report["warnings"] = warnings
    report["status"] = "ready" if not blocking else "blocked"


def _read_json_object(path: Path) -> dict[str, Any]:
    loaded = json.loads(path.read_text(encoding="utf-8"))
    return loaded if isinstance(loaded, dict) else {}


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        loaded = json.loads(line)
        if isinstance(loaded, dict):
            rows.append(loaded)
    return rows


def _repo_hint() -> str:
    path = Path(__file__).resolve()
    for parent in path.parents:
        if (parent / "src" / "invart").exists() and (parent / "pyproject.toml").exists():
            return str(parent)
    return ""


def _run(command: list[str], *, cwd: Path, timeout: int, env: dict[str, str] | None = None) -> dict[str, Any]:
    try:
        completed = subprocess.run(command, cwd=str(cwd), env=env, capture_output=True, text=True, timeout=timeout)
        return {
            "command": command,
            "returncode": completed.returncode,
            "stdout_tail": completed.stdout[-2000:],
            "stderr_tail": completed.stderr[-2000:],
        }
    except Exception as exc:
        return {"command": command, "returncode": None, "error": type(exc).__name__, "message": str(exc)}
