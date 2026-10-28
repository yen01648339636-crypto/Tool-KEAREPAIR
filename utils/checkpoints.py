"""Identity-bound progress checkpoints for batch runs."""

from datetime import datetime, timezone
import json
from pathlib import Path

from .experiment_manifest import ManifestMismatchError, verify_checkpoint, write_json_atomic
from .schemas import SCHEMA_VERSION


class CheckpointManager:
    CHECKPOINT_FILE = "checkpoint.json"

    def __init__(self, output_dir, vul_files_dir, experiment_id):
        if not isinstance(experiment_id, str) or not experiment_id:
            raise ValueError("experiment_id is required")
        self.output_dir = Path(output_dir)
        self.path = self.output_dir / self.CHECKPOINT_FILE
        self._vul_files_dir = str(vul_files_dir)
        self.experiment_id = experiment_id
        self._data = self._empty()

    def _empty(self):
        return {
            "schema_version": SCHEMA_VERSION,
            "experiment_id": self.experiment_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "vul_files_dir": self._vul_files_dir,
            "processed": {},
        }

    def load(self):
        if not self.path.exists():
            return False
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
            verify_checkpoint(value, self.experiment_id)
            if value.get("schema_version") != SCHEMA_VERSION or not isinstance(value.get("processed"), dict):
                raise ManifestMismatchError("Invalid checkpoint schema")
        except (OSError, ValueError, TypeError, AttributeError) as exc:
            raise ManifestMismatchError(f"Cannot resume {self.path}: {exc}") from exc
        self._data = value
        return True

    def _save_atomic(self):
        if self.path.exists():
            try:
                verify_checkpoint(json.loads(self.path.read_text(encoding="utf-8")), self.experiment_id)
            except (OSError, ValueError, AttributeError) as exc:
                raise ManifestMismatchError(f"Cannot overwrite checkpoint {self.path}: {exc}") from exc
        self._data["last_updated"] = datetime.now(timezone.utc).isoformat()
        write_json_atomic(self.path, self._data)

    def is_done(self, cve_id, skip_failed=False):
        status = self._data["processed"].get(cve_id, {}).get("status")
        return status in {"success", "skipped"} or (skip_failed and status in {"failed", "error"})

    def is_processed(self, cve_id):
        return cve_id in self._data["processed"]

    def mark(self, cve_id, status, error=None):
        if status not in {"success", "failed", "skipped", "error"}:
            raise ValueError(f"Invalid checkpoint status: {status}")
        record = {"status": status, "finished_at": datetime.now(timezone.utc).isoformat()}
        if error:
            record["error"] = str(error)[:300]
        self._data["processed"][cve_id] = record
        self._save_atomic()

    def reset(self):
        self._data = self._empty()
        self._save_atomic()

    def clear_failed(self):
        self._data["processed"] = {
            key: value for key, value in self._data["processed"].items()
            if value.get("status") not in {"failed", "error"}
        }
        self._save_atomic()
