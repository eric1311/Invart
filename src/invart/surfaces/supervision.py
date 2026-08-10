from __future__ import annotations

import os
import signal
import subprocess
import tempfile
import time
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
    with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
        popen_kwargs: dict[str, Any] = {
            "cwd": str(cwd) if cwd else None,
            "stdout": stdout_file,
            "stderr": stderr_file,
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
        termination = {"requested": None, "escalated": None}
        try:
            process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            termination["requested"] = "SIGTERM"
            _signal_process(process, pgid=pgid, signal_number=signal.SIGTERM)
            try:
                process.communicate(timeout=1)
            except subprocess.TimeoutExpired:
                termination["escalated"] = "SIGKILL"
                _signal_process(process, pgid=pgid, signal_number=signal.SIGKILL)
                process.communicate()
        process_group_cleanup = _cleanup_remaining_process_group(pgid)
        stdout = _read_tail(stdout_file)
        stderr = _read_tail(stderr_file)
    snapshots.append(_snapshot(pid, pgid, "finished"))
    ended_at = utc_now()
    return {
        "schema_version": "invart.process_supervision.v0.10",
        "command": command,
        "returncode": process.returncode,
        "timed_out": timed_out,
        "stdout": _redact(stdout, redactions),
        "stderr": _redact(stderr, redactions),
        "started_at": started_at,
        "ended_at": ended_at,
        "process_group": {
            "pid": pid,
            "pgid": pgid,
            "strong_consistency": pgid is not None,
            "control": "process_group" if pgid is not None else "single_process",
        },
        "termination": termination,
        "process_group_cleanup": process_group_cleanup,
        "lifecycle_violation": process_group_cleanup["required"],
        "snapshots": snapshots,
    }


def _redact(text: str, redactions: Sequence[str]) -> str:
    sanitized = str(text or "")
    for secret in sorted({str(value) for value in redactions if str(value)}, key=len, reverse=True):
        sanitized = sanitized.replace(secret, "<redacted>")
    return sanitized


def _read_tail(stream: Any, maximum_bytes: int = 4000) -> str:
    stream.seek(0, os.SEEK_END)
    size = stream.tell()
    stream.seek(max(0, size - maximum_bytes))
    return stream.read().decode("utf-8", errors="replace")


def _pgid(pid: int) -> int | None:
    try:
        return os.getpgid(pid)
    except Exception:
        return None


def _signal_process(
    process: subprocess.Popen[str],
    *,
    pgid: int | None,
    signal_number: signal.Signals,
) -> None:
    if pgid is not None:
        try:
            os.killpg(pgid, signal_number)
            return
        except ProcessLookupError:
            return
        except Exception:
            pass
    try:
        process.send_signal(signal_number)
    except ProcessLookupError:
        return


def _cleanup_remaining_process_group(pgid: int | None) -> dict[str, Any]:
    if not _process_group_alive(pgid):
        return {
            "required": False,
            "requested": None,
            "escalated": None,
            "confirmed_dead": True,
        }
    requested = "SIGTERM"
    escalated: str | None = None
    try:
        os.killpg(int(pgid), signal.SIGTERM)
    except ProcessLookupError:
        pass
    if not _wait_for_process_group_death(pgid, timeout=1):
        escalated = "SIGKILL"
        try:
            os.killpg(int(pgid), signal.SIGKILL)
        except ProcessLookupError:
            pass
    confirmed_dead = _wait_for_process_group_death(pgid, timeout=1)
    return {
        "required": True,
        "requested": requested,
        "escalated": escalated,
        "confirmed_dead": confirmed_dead,
    }


def _process_group_alive(pgid: int | None) -> bool:
    if pgid is None:
        return False
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _wait_for_process_group_death(pgid: int | None, *, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while _process_group_alive(pgid):
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.02)
    return True


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
