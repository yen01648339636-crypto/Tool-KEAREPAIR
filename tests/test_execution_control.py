"""Real operation hooks wait before requests/commands and exclude paused time."""

import json
import os
from pathlib import Path
import subprocess
import sys
import time

import pytest

from utils.experiment_manifest import write_json_atomic

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("operation", ["request", "timing", "progress", "command"])
def test_operation_gates_wait_and_resume_without_restarting(tmp_path, operation):
    control = tmp_path / "task_control.json"
    write_json_atomic(control, {"requested": True, "request_id": "pause-one"})
    target = tmp_path / "operation-started"
    actions = {
        "request": "from utils.telemetry import begin_call\nbegin_call('local','mock',{})",
        "timing": "from utils.telemetry import measure\nwith measure('test'):\n    pass",
        "progress": "from utils.runtime_progress import progress_event\nprogress_event('Starting tools','running')",
        "command": f"from Online.phase3_repair.validator import Validator\nv=Validator.__new__(Validator)\nv.compile_timeout=v.test_timeout=10\nv._publish_progress=lambda *a,**k:None\nv._progress_lock=__import__('threading').RLock()\nv._command({{'stage_details':{{}},'stage_status':{{}}}},{{'name':'unit','covers':['unit']}},[sys.executable,'-c','pass'])",
    }
    code = "import sys\nfrom pathlib import Path\n" + f"sys.path.insert(0,{str(ROOT)!r})\n" + actions[operation] + f"\nPath({str(target)!r}).write_text('executed')\n"
    process = subprocess.Popen([sys.executable, "-c", code], cwd=ROOT,
        env={**os.environ, "KEA_STUDIO_CONTROL": str(control), "KEA_STUDIO_EXECUTION_ID": "execution-one"},
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 10
        while not (tmp_path / 'pause_ack.json').exists() and process.poll() is None and time.monotonic() < deadline:
            time.sleep(.03)
        assert (tmp_path/'pause_ack.json').exists(), process.communicate(timeout=1)
        assert json.loads((tmp_path/'pause_ack.json').read_text())['execution_id'] == 'execution-one'
        time.sleep(.15)
        assert not target.exists() and process.poll() is None
        write_json_atomic(control, {"requested": False})
        stdout, stderr = process.communicate(timeout=10)
        assert process.returncode == 0, stderr.decode()
        assert target.read_text() == 'executed'
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=5)


def test_pause_time_is_separate_from_measured_operation_time(tmp_path):
    control = tmp_path/'task_control.json'
    write_json_atomic(control, {"requested": False})
    code = f"""
import sys,time
from pathlib import Path
sys.path.insert(0,{str(ROOT)!r})
from utils.telemetry import Recorder,measure
from utils.execution_control import wait_if_paused
from utils.experiment_manifest import write_json_atomic
with Recorder({str(tmp_path / 'records')!r}).activate(),measure('outer'):
    time.sleep(.03)
    write_json_atomic({str(control)!r},{{'requested':True,'request_id':'test-pause'}})
    wait_if_paused()
    time.sleep(.03)
"""
    process = subprocess.Popen([sys.executable,'-c',code],env={**os.environ,'KEA_STUDIO_CONTROL':str(control)})
    try:
        deadline = time.monotonic()+10
        while not (tmp_path/'pause_ack.json').exists() and time.monotonic()<deadline:
            time.sleep(.02)
        assert (tmp_path/'pause_ack.json').exists()
        time.sleep(.3)
        write_json_atomic(control, {'requested':False})
        assert process.wait(timeout=5) == 0
        timing=json.loads((tmp_path/'records/timings.jsonl').read_text())
        assert timing['paused_seconds'] >= .3
        assert .05 < timing['duration_seconds'] < .25
    finally:
        if process.poll() is None:
            process.terminate();process.wait(timeout=5)
