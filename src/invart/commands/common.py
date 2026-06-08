from __future__ import annotations

import argparse
import json

from invart.governance.profiles import resolve_profile_from_paths

def add_profile_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--team-profile", default=None)
    parser.add_argument("--repo-profile", default=None)
    parser.add_argument("--session-profile", default=None)

def resolved_profile_from_args(args: argparse.Namespace) -> dict[str, Any] | None:
    return resolve_profile_from_paths(
        team=getattr(args, "team_profile", None),
        repo=getattr(args, "repo_profile", None),
        session=getattr(args, "session_profile", None),
    )

def emit(payload: dict[str, object], output: str) -> int:
    if output == "json":
        print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    summary = payload.get("summary", {})
    print(f"target: {payload.get('target')}")
    print(f"findings: {summary.get('total_findings', 0)}")
    print(f"highest_severity: {summary.get('highest_severity', 'info')}")
    return 0
