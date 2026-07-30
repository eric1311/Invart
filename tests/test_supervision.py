from __future__ import annotations

import sys
import json

from invart.surfaces.supervision import supervise_process_group


def test_supervision_escalates_to_sigkill_when_process_group_ignores_sigterm(
    tmp_path,
) -> None:
    result = supervise_process_group(
        [
            sys.executable,
            "-c",
            (
                "import signal,time;"
                "signal.signal(signal.SIGTERM, signal.SIG_IGN);"
                "print('ready', flush=True);"
                "time.sleep(30)"
            ),
        ],
        cwd=tmp_path,
        timeout=0.2,
    )

    assert result["timed_out"] is True
    assert result["termination"]["requested"] == "SIGTERM"
    assert result["termination"]["escalated"] == "SIGKILL"
    assert result["returncode"] < 0


def test_supervision_cleans_up_descendant_after_normal_leader_exit(tmp_path) -> None:
    result = supervise_process_group(
        [
            sys.executable,
            "-c",
            (
                "import json,subprocess,sys;"
                "child=subprocess.Popen([sys.executable,'-c',"
                "'import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);time.sleep(30)']);"
                "print(json.dumps({'child_pid':child.pid}),flush=True)"
            ),
        ],
        cwd=tmp_path,
        timeout=5,
    )

    assert result["returncode"] == 0
    assert result["timed_out"] is False
    assert result["process_group_cleanup"]["required"] is True
    assert result["process_group_cleanup"]["confirmed_dead"] is True
    assert result["lifecycle_violation"] is True
    assert json.loads(result["stdout"])["child_pid"] > 0
