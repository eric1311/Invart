from __future__ import annotations

import os
import signal
import subprocess
from pathlib import Path
from typing import Any

from invart.core.models import utc_now


def supervise_process_group(command: list[str], *, cwd: Path | None = None, timeout: float = 30.0) -> dict[str, Any]:
    if not command:
        raise ValueError("process supervision requires a command")
    started_at = utc_now()
    popen_kwargs: dict[str, Any] = {
        "cwd": str(cwd) if cwd else None,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "text": True,
    }
    if hasattr(os, "setsid"):
        popen_kwargs["start_new_session"] = True
    process = subprocess.Popen(command, **popen_kwargs)
    pid = process.pid
    pgid = _pgid(pid)
    snapshots = [_snapshot(pid, pgid, "started")]
    timed_out = False
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        if pgid is not None:
            try:
                os.killpg(pgid, signal.SIGTERM)
            except Exception:
                process.terminate()
        else:
            process.terminate()
        stdout, stderr = process.communicate(timeout=5)
    snapshots.append(_snapshot(pid, pgid, "finished"))
    ended_at = utc_now()
    return {
        "schema_version": "invart.process_supervision.v0.10",
        "command": command,
        "returncode": process.returncode,
        "timed_out": timed_out,
        "stdout": stdout[-4000:],
        "stderr": stderr[-4000:],
        "started_at": started_at,
        "ended_at": ended_at,
        "process_group": {
            "pid": pid,
            "pgid": pgid,
            "strong_consistency": pgid is not None,
            "control": "process_group" if pgid is not None else "single_process",
        },
        "snapshots": snapshots,
    }


def _pgid(pid: int) -> int | None:
    try:
        return os.getpgid(pid)
    except Exception:
        return None


def _snapshot(pid: int, pgid: int | None, phase: str) -> dict[str, Any]:
    return {
        "phase": phase,
        "captured_at": utc_now(),
        "pid": pid,
        "pgid": pgid,
    }
