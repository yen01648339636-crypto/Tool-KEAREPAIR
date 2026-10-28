"""Read vulnerability source pairs without silently filtering input rows."""

import csv
import json
from pathlib import Path

from utils.knowledge import DatasetError


class BigVulLoader:
    def __init__(self, data_path):
        self.data_path = Path(data_path)
        self.data = None

    def load_records(self):
        with self.data_path.open(encoding="utf-8-sig", newline="") as stream:
            prefix = stream.read(100)
            stream.seek(0)
            if prefix.startswith("version https://git-lfs.github.com/spec/v1"):
                raise DatasetError(f"{self.data_path} is a Git LFS pointer; fetch the actual dataset first")
            if self.data_path.suffix.lower() == ".csv":
                reader = csv.DictReader(stream)
                if not reader.fieldnames or len(set(reader.fieldnames)) != len(reader.fieldnames):
                    raise DatasetError("CSV headers must be nonempty and unique")
                rows = list(reader)
                if any(None in row for row in rows):
                    raise DatasetError("CSV rows contain more values than their headers")
            elif self.data_path.suffix.lower() == ".json":
                rows = json.load(stream)
            elif self.data_path.suffix.lower() == ".jsonl":
                rows = [json.loads(line) for line in stream if line.strip()]
            else:
                raise DatasetError(f"Unsupported dataset format: {self.data_path.suffix}")
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            raise DatasetError("Dataset must contain a list of row objects")
        return rows

    def load(self):
        import pandas as pd

        self.data = pd.DataFrame(self.load_records())
        return self.data

    def filter_by_language(self, language="C"):
        if self.data is None:
            raise ValueError("Data not loaded. Call load() first.")
        return self.data[self.data["language"] == language]

    def get_sample(self, index):
        if self.data is None:
            raise ValueError("Data not loaded. Call load() first.")
        return self.data.iloc[index].to_dict()

    def get_train_test_split(self, test_size=0.2, random_state=42):
        if self.data is None:
            raise ValueError("Data not loaded. Call load() first.")
        from sklearn.model_selection import train_test_split

        return train_test_split(self.data, test_size=test_size, random_state=random_state)
