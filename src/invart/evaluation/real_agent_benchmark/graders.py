from __future__ import annotations

from pathlib import Path
from typing import Any

from invart.core.artifacts import sha256_file, stable_json_hash
from .official_runners import validate_official_grader_artifact


def pending_grader_results() -> dict[str, Any]:
    return {
        "schema_version": "invart.p0_grader_results.v0.1",
        "status": "pending",
        "reason": "official benchmark runs have not been attached yet",
        "families": {},
    }


def resolve_official_grader_artifact(
    *,
    family: str,
    requested_artifact: Path,
    cwd: Path | None = None,
    report_dir: Path | None = None,
    run_id: str | None = None,
    model_name_or_path: str | None = None,
) -> dict[str, Any]:
    requested = requested_artifact.expanduser().resolve()
    candidates = _official_grader_candidates(
        family=family,
        requested_artifact=requested,
        cwd=cwd.expanduser().resolve() if cwd is not None else None,
        report_dir=report_dir.expanduser().resolve() if report_dir is not None else None,
        run_id=run_id,
        model_name_or_path=model_name_or_path,
    )
    checked: list[dict[str, Any]] = []
    for candidate in candidates:
        validation = validate_official_grader_artifact(family=family, artifact=candidate)
        checked.append({
            "artifact": str(candidate),
            "exists": candidate.exists(),
            "validation_status": validation.get("status"),
        })
        if validation.get("status") == "pass":
            return {
                "schema_version": "invart.p0_official_grader_resolution.v0.1",
                "status": "resolved",
                "requested_artifact": str(requested),
                "artifact": str(candidate),
                "checked": checked,
                "claim_boundary": "Resolution only selects a valid upstream runner artifact; it does not create benchmark results.",
            }
    return {
        "schema_version": "invart.p0_official_grader_resolution.v0.1",
        "status": "missing",
        "requested_artifact": str(requested),
        "artifact": str(requested),
        "checked": checked,
        "reason": "no valid official grader artifact found at requested or known runner output paths",
        "claim_boundary": "Missing official grader artifacts mean the row is an incomplete official-run attempt, not an official benchmark result.",
    }


def attach_official_grader_artifact(
    *,
    family: str,
    artifact: Path,
    status: str = "attached",
    resolution: dict[str, Any] | None = None,
) -> dict[str, Any]:
    resolved = artifact.expanduser().resolve()
    validation = validate_official_grader_artifact(family=family, artifact=resolved)
    resolved_status = status if validation["status"] == "pass" else "pending"
    return {
        "schema_version": "invart.p0_grader_results.v0.1",
        "status": resolved_status,
        "families": {
            family: {
                "artifact": str(resolved),
                "sha256": _artifact_hash(resolved) if resolved.exists() else None,
                "exists": resolved.exists(),
                "validation": validation,
                "resolution": resolution or {
                    "schema_version": "invart.p0_official_grader_resolution.v0.1",
                    "status": "explicit",
                    "artifact": str(resolved),
                },
                "claim_boundary": "Official grader artifacts are claimable only for rows produced by the matching upstream runner.",
            }
        },
    }


def _artifact_hash(path: Path) -> str:
    if path.is_file():
        return sha256_file(path, prefixed=True)
    files = []
    for item in sorted(child for child in path.rglob("*") if child.is_file()):
        try:
            relative = str(item.relative_to(path))
        except ValueError:
            relative = str(item)
        files.append({
            "path": relative,
            "bytes": item.stat().st_size,
            "sha256": sha256_file(item, prefixed=True),
        })
    return stable_json_hash({"directory": str(path.name), "files": files}, prefixed=True)


def merge_grader_results(current: dict[str, Any], attached: dict[str, Any]) -> dict[str, Any]:
    families: dict[str, Any] = {}
    if isinstance(current.get("families"), dict):
        families.update(current["families"])
    if isinstance(attached.get("families"), dict):
        families.update(attached["families"])
    status = (
        "attached"
        if families
        and all(
            item.get("exists") is not False and (item.get("validation") or {}).get("status") == "pass"
            for item in families.values()
            if isinstance(item, dict)
        )
        else "pending"
    )
    return {
        "schema_version": "invart.p0_grader_results.v0.1",
        "status": status,
        "families": families,
        "claim_boundary": "Attached grader artifacts must come from official benchmark runners for official-score claims.",
    }


def _official_grader_candidates(
    *,
    family: str,
    requested_artifact: Path,
    cwd: Path | None,
    report_dir: Path | None,
    run_id: str | None,
    model_name_or_path: str | None,
) -> list[Path]:
    candidates: list[Path] = [requested_artifact]
    roots = [root for root in [report_dir, cwd] if root is not None]
    if family == "swe_bench_verified" and run_id:
        model = (model_name_or_path or "").replace("/", "__")
        for root in roots:
            if model:
                candidates.append(root / f"{model}.{run_id}.json")
            candidates.append(root / f"{run_id}.json")
            candidates.extend(sorted(root.glob(f"*.{run_id}.json")) if root.exists() else [])
            candidates.extend(sorted(root.glob(f"**/*.{run_id}.json")) if root.exists() else [])
    seen: set[str] = set()
    unique: list[Path] = []
    for candidate in candidates:
        key = str(candidate)
        if key in seen:
            continue
        seen.add(key)
        unique.append(candidate)
    return unique
