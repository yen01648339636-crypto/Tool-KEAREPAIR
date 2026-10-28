"""Run container scripts in isolated local directories without a Docker daemon."""

import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile

from utils.container_validation import PAYLOAD_PATH, EVIDENCE_PATH


class DockerSandbox:
    def __init__(self, original):
        self.original = original
        self.run_process = subprocess.run
        self.commands = []
        self.sources = []

    def __call__(self, argv, **kwargs):
        assert argv[:2] == ["docker", "run"]
        self.commands.append(argv)
        mounts = {}
        for index, argument in enumerate(argv):
            if argument == "-v":
                source, target, mode = argv[index + 1].rsplit(":", 2)
                mounts[target] = source
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            payload = root / "payload"
            shutil.copytree(mounts[PAYLOAD_PATH], payload)
            settings_file = payload / "environment.sh"
            settings = {
                key: shlex.split(value)[0]
                for key, value in (line.split("=", 1) for line in settings_file.read_text().splitlines())
            }
            settings["EVIDENCE_DIR"] = mounts[EVIDENCE_PATH]
            settings_file.write_text("\n".join(f"{key}={shlex.quote(value)}" for key, value in settings.items()))
            project = root / "project"
            target = project / settings["TARGET_PATH"]
            target.parent.mkdir(parents=True)
            target.write_text(self.original)
            command = argv[-1].replace(PAYLOAD_PATH, str(payload))
            output = self.run_process(
                ["bash", "-lc", command], cwd=project, env=os.environ.copy(),
                capture_output=True, text=True, timeout=kwargs.get("timeout", 10),
            )
            self.sources.append(target.read_text())
            return output
