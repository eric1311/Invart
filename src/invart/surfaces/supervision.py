from __future__ import annotations

import os
import signal
import subprocess
from pathlib import Path
from typing import Any, Mapping, Sequence

from invart.core.models import utc_now


def supervise_process_group(
    command: list[str],
    *,
    cwd: Path | None = None,
    timeout: float = 30.0,
    env: Mapping[str, str] | None = None,
    redactions: Sequence[str] = (),
) -> dict[str, Any]:
    if not command:
        raise ValueError("process supervision requires a command")
    started_at = utc_now()
    popen_kwargs: dict[str, Any] = {
        "cwd": str(cwd) if cwd else None,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "text": True,
    }
    if env is not None:
        popen_kwargs["env"] = {str(name): str(value) for name, value in env.items()}
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
        "stdout": _redact(stdout[-4000:], redactions),
        "stderr": _redact(stderr[-4000:], redactions),
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


def _redact(text: str, redactions: Sequence[str]) -> str:
    sanitized = str(text or "")
    for secret in sorted({str(value) for value in redactions if str(value)}, key=len, reverse=True):
        sanitized = sanitized.replace(secret, "<redacted>")
    return sanitized


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
        "network": _network_snapshot(pid),
    }


def _network_snapshot(pid: int) -> dict[str, Any]:
    try:
        completed = subprocess.run(
            ["lsof", "-nP", "-i", "-a", "-p", str(pid)],
            check=False,
            capture_output=True,
            text=True,
            timeout=2,
        )
    except FileNotFoundError:
        return {"status": "unavailable", "reason": "lsof_not_found"}
    except Exception as exc:
        return {"status": "error", "reason": type(exc).__name__}
    lines = [line for line in (completed.stdout or "").splitlines() if line.strip()]
    return {
        "status": "captured" if completed.returncode == 0 else "none_observed",
        "returncode": completed.returncode,
        "connections": lines[1:],
        "raw_tail": "\n".join(lines[-20:]),
        "claim_boundary": "lsof sampling is best-effort passive observation and may miss short-lived network connections.",
    }
