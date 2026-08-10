from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from invart.core.artifacts import sha256_file, write_json_artifact
from invart.core.models import utc_now


TASK_FILENAME = "SWE_BENCH_TASK.md"
WORKSPACE_REPORT = "swe_instance_workspace.json"


def load_swe_instance_json(path: Path) -> dict[str, Any]:
    resolved = path.expanduser().resolve()
    payload = json.loads(resolved.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("--instance-json must contain a JSON object")
    row = payload.get("row", payload)
    if not isinstance(row, dict):
        raise ValueError("--instance-json row must contain a JSON object")
    loaded = dict(row)
    loaded.setdefault("source_json", str(resolved))
    loaded.setdefault("source_json_sha256", sha256_file(resolved, prefixed=True))
    return loaded


def prepare_swe_instance_workspace(
    *,
    instance: dict[str, Any],
    out_dir: Path,
    repo_cache: Path | None = None,
    force: bool = False,
) -> dict[str, Any]:
    root = out_dir.expanduser().resolve()
    root_parent = root.parent
    root_parent.mkdir(parents=True, exist_ok=True)
    instance_id = _required(instance, "instance_id")
    repo_ref = _repo_source(instance)
    base_commit = _required(instance, "base_commit")
    problem_statement = str(instance.get("problem_statement") or instance.get("problem") or "").strip()
    steps: list[dict[str, Any]] = []

    if root.exists() and any(root.iterdir()):
        if force:
            shutil.rmtree(root)
        else:
            report = _report(
                status="fail",
                root=root,
                instance=instance,
                repo_ref=repo_ref,
                base_commit=base_commit,
                steps=[],
                reason="workspace already exists and is not empty",
            )
            write_json_artifact(root / WORKSPACE_REPORT, report)
            return report

    clone_source = repo_ref
    if repo_cache is not None and not _is_local_path(repo_ref):
        cache_root = repo_cache.expanduser().resolve()
        cache_root.mkdir(parents=True, exist_ok=True)
        cache_repo = cache_root / _repo_cache_name(instance)
        if cache_repo.exists():
            fetch = _run(["git", "-C", str(cache_repo), "fetch", "--all", "--tags"], cwd=cache_root, timeout=600)
            steps.append({"name": "repo_cache_fetch", **fetch})
            if _should_retry_git_http(fetch):
                steps.append({
                    "name": "repo_cache_fetch_http11_retry",
                    **_run(["git", "-c", "http.version=HTTP/1.1", "-C", str(cache_repo), "fetch", "--all", "--tags"], cwd=cache_root, timeout=600),
                })
        else:
            clone = _run(["git", "clone", "--mirror", repo_ref, str(cache_repo)], cwd=cache_root, timeout=900)
            steps.append({"name": "repo_cache_clone", **clone})
            if _should_retry_git_http(clone):
                if cache_repo.exists():
                    shutil.rmtree(cache_repo, ignore_errors=True)
                steps.append({
                    "name": "repo_cache_clone_http11_retry",
                    **_run(["git", "-c", "http.version=HTTP/1.1", "clone", "--mirror", repo_ref, str(cache_repo)], cwd=cache_root, timeout=900),
                })
        clone_source = str(cache_repo)

    workspace_clone = _run(["git", "clone", clone_source, str(root)], cwd=root_parent, timeout=900)
    steps.append({"name": "clone_workspace", **workspace_clone})
    if _should_retry_git_http(workspace_clone):
        if root.exists():
            shutil.rmtree(root, ignore_errors=True)
        steps.append({
            "name": "clone_workspace_http11_retry",
            **_run(["git", "-c", "http.version=HTTP/1.1", "clone", clone_source, str(root)], cwd=root_parent, timeout=900),
        })
    if steps[-1].get("returncode") == 0:
        steps.append({"name": "checkout_base_commit", **_run(["git", "checkout", base_commit], cwd=root, timeout=300)})
        task_path = _write_task_file(root, instance_id=instance_id, repo_ref=repo_ref, base_commit=base_commit, problem_statement=problem_statement)
        steps.append({"name": "write_task_prompt", "status": "pass", "path": str(task_path)})
    head = _git_stdout(root, ["rev-parse", "HEAD"]) if (root / ".git").exists() else ""
    status_short = _git_stdout(root, ["status", "--short"]) if (root / ".git").exists() else ""
    status = "pass" if (root / ".git").exists() and head == base_commit and not _failed(steps) else "fail"
    report = _report(
        status=status,
        root=root,
        instance=instance,
        repo_ref=repo_ref,
        base_commit=base_commit,
        steps=steps,
        reason="prepared official SWE-Bench instance checkout" if status == "pass" else "failed to prepare official SWE-Bench instance checkout",
        extra={
            "git_head": head,
            "git_status_short": status_short,
            "task_file": str(root / TASK_FILENAME),
            "task_file_sha256": sha256_file(root / TASK_FILENAME, prefixed=True) if (root / TASK_FILENAME).exists() else None,
        },
    )
    write_json_artifact(root / WORKSPACE_REPORT, report)
    return report


def prepare_swe_instance_workspace_from_json(
    *,
    instance_json: Path,
    out_dir: Path,
    repo_cache: Path | None = None,
    force: bool = False,
) -> dict[str, Any]:
    return prepare_swe_instance_workspace(
        instance=load_swe_instance_json(instance_json),
        out_dir=out_dir,
        repo_cache=repo_cache,
        force=force,
    )


def _write_task_file(root: Path, *, instance_id: str, repo_ref: str, base_commit: str, problem_statement: str) -> Path:
    text = "\n".join(
        [
            f"# SWE-Bench Instance: {instance_id}",
            "",
            f"- Repository: `{repo_ref}`",
            f"- Base commit: `{base_commit}`",
            "",
            "## Task",
            "",
            problem_statement or "(No problem statement was present in the supplied official row.)",
            "",
            "## Agent Instructions",
            "",
            "Make the minimal source change needed for this instance. Leave the patch in the working tree and do not commit.",
            "",
        ]
    )
    task = root / TASK_FILENAME
    task.write_text(text, encoding="utf-8")
    return task


def _report(
    *,
    status: str,
    root: Path,
    instance: dict[str, Any],
    repo_ref: str,
    base_commit: str,
    steps: list[dict[str, Any]],
    reason: str,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema_version": "invart.p0_swe_instance_workspace.v0.1",
        "generated_at": utc_now(),
        "status": status,
        "reason": reason,
        "workspace": str(root),
        "instance_id": instance.get("instance_id"),
        "repo": instance.get("repo"),
        "repo_source": repo_ref,
        "base_commit": base_commit,
        "source_json": instance.get("source_json"),
        "source_json_sha256": instance.get("source_json_sha256"),
        "steps": steps,
        "claim_boundary": (
            "This artifact only prepares an official SWE-Bench instance checkout and task prompt for a generic agent command. "
            "It is not a local grader and does not establish resolved/unresolved status without the official SWE-Bench harness."
        ),
    }
    payload.update(extra or {})
    return payload


def _repo_source(instance: dict[str, Any]) -> str:
    if instance.get("repo_path"):
        return str(Path(str(instance["repo_path"])).expanduser().resolve())
    if instance.get("repo_url"):
        return str(instance["repo_url"])
    repo = _required(instance, "repo")
    if repo.startswith("http://") or repo.startswith("https://") or repo.startswith("git@") or Path(repo).exists():
        return repo
    return f"https://github.com/{repo}.git"


def _repo_cache_name(instance: dict[str, Any]) -> str:
    repo = str(instance.get("repo") or instance.get("repo_url") or instance.get("repo_path") or "repo")
    safe = "".join(char if char.isalnum() else "_" for char in repo).strip("_")
    return f"{safe or 'repo'}.git"


def _required(instance: dict[str, Any], key: str) -> str:
    value = instance.get(key)
    if value is None or str(value).strip() == "":
        raise ValueError(f"SWE-Bench instance row is missing required field: {key}")
    return str(value)


def _is_local_path(value: str) -> bool:
    return value.startswith("/") or value.startswith("file://") or Path(value).exists()


def _failed(steps: list[dict[str, Any]]) -> bool:
    retry_passes = {
        str(step.get("name", "")).removesuffix("_http11_retry")
        for step in steps
        if str(step.get("name", "")).endswith("_http11_retry") and step.get("returncode") == 0
    }
    for step in steps:
        name = str(step.get("name", ""))
        if name in retry_passes:
            continue
        if step.get("returncode") not in {0, None} and step.get("status") != "skipped":
            return True
    return False


def _should_retry_git_http(result: dict[str, Any]) -> bool:
    if result.get("returncode") == 0:
        return False
    text = f"{result.get('stderr') or ''}\n{result.get('stdout') or ''}\n{result.get('message') or ''}".lower()
    return any(
        marker in text
        for marker in [
            "http2",
            "framing layer",
            "curl 92",
            "rpc failed",
            "early eof",
            "remote end hung up",
        ]
    )


def _git_stdout(root: Path, args: list[str]) -> str:
    result = _run(["git", *args], cwd=root, timeout=30)
    return str(result.get("stdout") or "").strip()


def _run(command: list[str], *, cwd: Path, timeout: int) -> dict[str, Any]:
    try:
        completed = subprocess.run(command, cwd=str(cwd), check=False, capture_output=True, text=True, timeout=timeout)
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
