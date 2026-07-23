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


OFFICIAL_SETUP_PACKAGES = {
    "agentdojo": ["agentdojo"],
    "swe_bench_verified": ["swebench"],
    "agentsecbench": [],
    "skill_inject": [],
    "agentharm": [],
    "mcptox": [],
    "mcp_agentbench": [],
}

OFFICIAL_REPOSITORIES = {
    "agentsecbench": {
        "url": "https://github.com/Kalmantic/AgentSecBench.git",
        "directory": "AgentSecBench",
        "requirements": ["requirements.txt"],
        "entrypoint": ["-m", "benchmark.run", "--help"],
        "pythonpath": ".",
    },
    "skill_inject": {
        "url": "https://github.com/aisa-group/skill-inject.git",
        "directory": "skill-inject",
        "requirements": [],
        "entrypoint": ["scripts/smoke_test_all.py", "--help"],
        "pythonpath": ".",
    },
    "agentharm": {
        "url": "https://github.com/UKGovernmentBEIS/inspect_evals.git",
        "directory": "inspect_evals",
        "revision": "a02da4190544ea6b9ca643feed3708d1f7426756",
        "requirements": [],
        "uv_sync": ["uv", "sync", "--frozen", "--no-dev"],
        "entrypoint": ["inspect", "eval", "--help"],
        "entrypoint_kind": "repository_venv_executable",
        "pythonpath": "src",
    },
    "mcptox": {
        "url": "https://github.com/zhiqiangwang4/MCPTox-Benchmark.git",
        "directory": "MCPTox-Benchmark",
        "revision": "f85189f9ad12504c197c7f920ab818a40657b1fa",
        "requirements": [],
        "entrypoint": None,
        "pythonpath": ".",
    },
}

OFFICIAL_SETUP_BLOCKERS = {
    "mcptox": "Pinned source has data and analysis artifacts but no supported benchmark entrypoint.",
    "mcp_agentbench": "Official executable code revision and code license were not identified from the AAAI publication source.",
}

OFFICIAL_IMPORTS = {
    "agentdojo": ["agentdojo"],
    "swe_bench_verified": ["swebench"],
    "agentsecbench": ["benchmark"],
    "skill_inject": [],
    "agentharm": ["inspect_ai", "inspect_evals.agentharm"],
    "mcptox": [],
    "mcp_agentbench": [],
}

OFFICIAL_HELP_COMMANDS = {
    "agentdojo": ["-m", "agentdojo.scripts.benchmark", "--help"],
    "swe_bench_verified": ["-m", "swebench.harness.run_evaluation", "--help"],
    "agentsecbench": ["-m", "benchmark.run", "--help"],
}


def prepare_p0_official_environment(
    *,
    manifest: dict[str, Any],
    out_dir: Path,
    families: list[str] | None = None,
    python_executable: str | None = None,
    create_venv: bool = False,
    install: bool = False,
) -> dict[str, Any]:
    root = out_dir.expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    selected = families or _families_from_manifest(manifest)
    base_python = python_executable or sys.executable
    report: dict[str, Any] = {
        "schema_version": "invart.p0_official_setup.v0.1",
        "generated_at": utc_now(),
        "status": "planned",
        "root": str(root),
        "families": selected,
        "base_python": _python_probe(base_python),
        "venv": {"requested": create_venv, "path": str(root / ".p0-official-venv"), "created": False},
        "install_requested": install,
        "package_plan": {family: OFFICIAL_SETUP_PACKAGES.get(family, []) for family in selected},
        "repository_plan": {family: OFFICIAL_REPOSITORIES.get(family) for family in selected if family in OFFICIAL_REPOSITORIES},
        "preflight": {},
        "steps": [],
        "claim_boundary": (
            "Official setup evidence proves only environment readiness or installation attempts. It is not a real-agent "
            "benchmark row and cannot satisfy P0 execution completeness without official runner outputs."
        ),
    }
    runner_python = base_python
    if create_venv:
        venv_result = _run([base_python, "-m", "venv", str(root / ".p0-official-venv")], cwd=root, timeout=120)
        report["steps"].append({"name": "create_venv", **venv_result})
        venv_python = _venv_python(root / ".p0-official-venv")
        report["venv"]["created"] = venv_result["returncode"] == 0 and venv_python.exists()
        report["venv"]["python"] = str(venv_python)
        if report["venv"]["created"]:
            runner_python = str(venv_python)
    if install:
        report["steps"].append({"name": "pip_upgrade", **_run([runner_python, "-m", "pip", "install", "--upgrade", "pip"], cwd=root, timeout=300)})
        for family in selected:
            repository = OFFICIAL_REPOSITORIES.get(family)
            if repository:
                repo_result = _prepare_repository(root=root, family=family, repository=repository, runner_python=runner_python)
                report["steps"].extend(repo_result["steps"])
                continue
            packages = OFFICIAL_SETUP_PACKAGES.get(family, [])
            if not packages:
                report["steps"].append({"name": f"install_{family}", "status": "skipped", "reason": "no package plan"})
                continue
            report["steps"].append({"name": f"install_{family}", **_run([runner_python, "-m", "pip", "install", *packages], cwd=root, timeout=900)})
    report["runner_python"] = _python_probe(runner_python)
    report["preflight"] = {
        family: _import_probe(
            _repository_runtime_python(root=root, family=family, fallback=runner_python),
            OFFICIAL_IMPORTS.get(family, []),
            pythonpath=_repository_pythonpath(root, family),
        )
        for family in selected
    }
    report["entrypoints"] = {family: _entrypoint_probe(runner_python, family, root=root) for family in selected}
    report["source_revisions"] = {
        family: _repository_revision_probe(root=root, family=family)
        for family in selected
        if family in OFFICIAL_REPOSITORIES
    }
    report["status"] = _setup_status(report)
    write_json_artifact(root / "p0_official_setup.json", report)
    return report


def _families_from_manifest(manifest: dict[str, Any]) -> list[str]:
    return sorted({str(item.get("family")) for item in manifest.get("cases", []) if isinstance(item, dict) and item.get("family")})


def _python_probe(python: str) -> dict[str, Any]:
    path = shutil.which(python) or python
    result = _run([path, "--version"], cwd=Path.cwd(), timeout=10)
    return {
        "executable": path,
        "available": Path(path).exists() or shutil.which(python) is not None,
        "version": (result.get("stdout") or result.get("stderr") or "").strip(),
        "returncode": result.get("returncode"),
    }


def _prepare_repository(*, root: Path, family: str, repository: dict[str, Any], runner_python: str) -> dict[str, Any]:
    repo_root = root / "upstream" / str(repository["directory"])
    steps: list[dict[str, Any]] = []
    if repo_root.exists():
        steps.append({"name": f"clone_{family}", "status": "skipped", "reason": "repository already exists", "path": str(repo_root)})
    else:
        clone_command = ["git", "clone"]
        if not repository.get("revision"):
            clone_command.extend(["--depth", "1"])
        clone_command.extend([str(repository["url"]), str(repo_root)])
        steps.append({
            "name": f"clone_{family}",
            **_run(clone_command, cwd=root, timeout=300),
        })
    if repo_root.exists():
        revision = str(repository.get("revision") or "").strip()
        if revision:
            steps.append({
                "name": f"checkout_{family}_revision",
                **_run(["git", "-C", str(repo_root), "checkout", "--detach", revision], cwd=root, timeout=120),
            })
        packages = [str(item) for item in repository.get("packages") or ()]
        if packages:
            steps.append({
                "name": f"install_{family}_packages",
                **_run([runner_python, "-m", "pip", "install", *packages], cwd=repo_root, timeout=900),
            })
        if repository.get("editable_install"):
            steps.append({
                "name": f"install_{family}_editable",
                **_run([runner_python, "-m", "pip", "install", "-e", str(repo_root)], cwd=repo_root, timeout=900),
            })
        uv_sync = [str(item) for item in repository.get("uv_sync") or ()]
        if uv_sync:
            steps.append({
                "name": f"install_{family}_uv_sync",
                **_run(uv_sync, cwd=repo_root, timeout=900),
            })
        for requirement in repository.get("requirements") or []:
            requirement_path = repo_root / str(requirement)
            if requirement_path.exists():
                steps.append({
                    "name": f"install_{family}_requirements",
                    **_run([runner_python, "-m", "pip", "install", "-r", str(requirement_path)], cwd=repo_root, timeout=900),
                })
            else:
                steps.append({
                    "name": f"install_{family}_requirements",
                    "status": "skipped",
                    "reason": f"missing requirements file: {requirement}",
                    "path": str(requirement_path),
                })
    return {"steps": steps}


def _repository_root(root: Path, family: str) -> Path | None:
    repository = OFFICIAL_REPOSITORIES.get(family)
    if not repository:
        return None
    path = root / "upstream" / str(repository["directory"])
    return path if path.exists() else None


def _repository_pythonpath(root: Path, family: str) -> str | None:
    repository = OFFICIAL_REPOSITORIES.get(family)
    repo_root = _repository_root(root, family)
    if not repository or repo_root is None:
        return None
    pythonpath = str(repository.get("pythonpath") or ".")
    return str((repo_root / pythonpath).resolve())


def _repository_runtime_python(*, root: Path, family: str, fallback: str) -> str:
    repository = OFFICIAL_REPOSITORIES.get(family)
    repo_root = _repository_root(root, family)
    if not repository or repo_root is None or repository.get("entrypoint_kind") != "repository_venv_executable":
        return fallback
    candidate = repo_root / ".venv" / ("Scripts" if sys.platform == "win32" else "bin") / (
        "python.exe" if sys.platform == "win32" else "python"
    )
    return str(candidate) if candidate.exists() else fallback


def _import_probe(python: str, modules: list[str], *, pythonpath: str | None = None) -> dict[str, Any]:
    if not modules:
        return {"status": "not_applicable", "modules": []}
    code = (
        "import importlib.util, json; "
        f"mods={json.dumps(modules)}; "
        "print(json.dumps({m: importlib.util.find_spec(m) is not None for m in mods}, sort_keys=True))"
    )
    result = _run([python, "-c", code], cwd=Path.cwd(), timeout=30, extra_env=_pythonpath_env(pythonpath))
    parsed: dict[str, bool] = {}
    try:
        loaded = json.loads(result.get("stdout") or "{}")
        if isinstance(loaded, dict):
            parsed = {str(key): bool(value) for key, value in loaded.items()}
    except json.JSONDecodeError:
        parsed = {}
    return {
        "status": "pass" if parsed and all(parsed.values()) else "missing",
        "modules": [{"module": module, "available": parsed.get(module, False)} for module in modules],
        "probe": result,
    }


def _entrypoint_probe(python: str, family: str, *, root: Path) -> dict[str, Any]:
    blocker = OFFICIAL_SETUP_BLOCKERS.get(family)
    if blocker:
        return {"status": "blocked", "reason": blocker}
    repository = OFFICIAL_REPOSITORIES.get(family)
    repo_root = _repository_root(root, family)
    if repository:
        if repo_root is None:
            return {"status": "missing", "reason": "repository workspace is not prepared", "repository": repository}
        suffix = list(repository.get("entrypoint") or ())
        if not suffix:
            return {"status": "blocked", "reason": "repository has no supported entrypoint"}
        if repository.get("entrypoint_kind") == "repository_venv_executable":
            executable = repo_root / ".venv" / ("Scripts" if sys.platform == "win32" else "bin") / str(suffix[0])
            command = [str(executable), *suffix[1:]]
        elif repository.get("entrypoint_kind") == "sibling_executable":
            executable = Path(python).expanduser().absolute().parent / str(suffix[0])
            command = [str(executable), *suffix[1:]]
        elif suffix and str(suffix[0]).endswith(".py"):
            command = [python, *suffix]
        else:
            command = [python, *suffix]
        result = _run(command, cwd=repo_root, timeout=180, extra_env=_pythonpath_env(_repository_pythonpath(root, family)))
        return {
            "status": "pass" if result.get("returncode") == 0 else "fail",
            "command": command,
            "cwd": str(repo_root),
            "returncode": result.get("returncode"),
            "stdout_tail": str(result.get("stdout") or "")[-4000:],
            "stderr_tail": str(result.get("stderr") or "")[-4000:],
            "error": result.get("error"),
            "message": result.get("message"),
            "claim_boundary": "Repository entrypoint probing verifies that the official runner starts; it is not a benchmark execution.",
        }
    suffix = OFFICIAL_HELP_COMMANDS.get(family)
    if not suffix:
        return {"status": "skipped", "reason": "no module entrypoint probe for this family"}
    result = _run([python, *suffix], cwd=Path.cwd(), timeout=180)
    return {
        "status": "pass" if result.get("returncode") == 0 else "fail",
        "command": [python, *suffix],
        "returncode": result.get("returncode"),
        "stdout_tail": str(result.get("stdout") or "")[-4000:],
        "stderr_tail": str(result.get("stderr") or "")[-4000:],
        "error": result.get("error"),
        "message": result.get("message"),
        "claim_boundary": "Help entrypoint probing verifies that the official runner starts; it is not a benchmark execution.",
    }


def _setup_status(report: dict[str, Any]) -> str:
    if report.get("install_requested"):
        steps = [step for step in report.get("steps", []) if step.get("name", "").startswith("install_")]
        if any(step.get("returncode") not in {0, None} and step.get("status") != "skipped" for step in steps):
            return "failed"
    preflight = report.get("preflight", {})
    entrypoints = report.get("entrypoints", {})
    revisions = report.get("source_revisions", {})
    entrypoints_ok = all(item.get("status") in {"pass", "skipped"} for item in entrypoints.values() if isinstance(item, dict))
    revisions_ok = all(item.get("status") == "pass" for item in revisions.values() if isinstance(item, dict))
    if preflight and entrypoints_ok and revisions_ok and all(item.get("status") in {"pass", "not_applicable"} for item in preflight.values() if isinstance(item, dict)):
        return "ready"
    return "planned"


def _repository_revision_probe(*, root: Path, family: str) -> dict[str, Any]:
    repository = OFFICIAL_REPOSITORIES[family]
    expected = str(repository.get("revision") or "").strip()
    repo_root = _repository_root(root, family)
    if repo_root is None:
        return {"status": "missing", "expected": expected or None, "observed": None}
    if not expected:
        return {"status": "unresolved", "expected": None, "observed": None}
    result = _run(["git", "-C", str(repo_root), "rev-parse", "HEAD"], cwd=root, timeout=30)
    observed = str(result.get("stdout") or "").strip()
    return {
        "status": "pass" if result.get("returncode") == 0 and observed == expected else "mismatch",
        "expected": expected,
        "observed": observed or None,
    }


def _pythonpath_env(pythonpath: str | None) -> dict[str, str] | None:
    if not pythonpath:
        return None
    existing = os.environ.get("PYTHONPATH")
    return {"PYTHONPATH": pythonpath if not existing else f"{pythonpath}{os.pathsep}{existing}"}


def _run(command: list[str], *, cwd: Path, timeout: int, extra_env: dict[str, str] | None = None) -> dict[str, Any]:
    try:
        env = os.environ.copy()
        if extra_env:
            env.update(extra_env)
        completed = subprocess.run(command, cwd=str(cwd), check=False, capture_output=True, text=True, timeout=timeout, env=env)
        return {
            "status": "pass" if completed.returncode == 0 else "fail",
            "command": command,
            "returncode": completed.returncode,
            "stdout": completed.stdout[-4000:],
            "stderr": completed.stderr[-4000:],
        }
    except Exception as exc:
        return {
            "status": "error",
            "command": command,
            "returncode": None,
            "error": type(exc).__name__,
            "message": str(exc),
        }


def _venv_python(venv: Path) -> Path:
    if sys.platform == "win32":
        return venv / "Scripts" / "python.exe"
    return venv / "bin" / "python"
