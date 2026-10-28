"""PyTorch dataset for vulnerability data."""

from typing import Dict, List, Optional
import torch
from torch.utils.data import Dataset
import pandas as pd


class VulnerabilityDataset(Dataset):
    """PyTorch dataset for vulnerability repair."""

    def __init__(
        self,
        data: pd.DataFrame,
        tokenizer=None,
        max_length: int = 512,
        include_patch: bool = True,
    ):
        """
        Initialize vulnerability dataset.

        Args:
            data: DataFrame containing vulnerability samples
            tokenizer: Tokenizer for code (e.g., from transformers)
            max_length: Maximum sequence length
            include_patch: Whether to include patch in samples
        """
        self.data = data
        self.tokenizer = tokenizer
        self.max_length = max_length
        self.include_patch = include_patch

    def __len__(self) -> int:
        """Return dataset size."""
        return len(self.data)

    def __getitem__(self, idx: int) -> Dict:
        """
        Get a single sample.

        Args:
            idx: Sample index

        Returns:
            Dictionary containing sample data
        """
        row = self.data.iloc[idx]

        sample = {
            "buggy_code": row.get("buggy_code", ""),
            "fixed_code": row.get("fixed_code", ""),
            "id": row.get("id", idx),
        }

        if self.include_patch:
            sample["patch"] = row.get("patch", "")

        # Tokenize if tokenizer is provided
        if self.tokenizer is not None:
            buggy_encoded = self.tokenizer(
                sample["buggy_code"],
                max_length=self.max_length,
                padding="max_length",
                truncation=True,
                return_tensors="pt",
            )
            sample["buggy_input_ids"] = buggy_encoded["input_ids"].squeeze(0)
            sample["buggy_attention_mask"] = buggy_encoded["attention_mask"].squeeze(0)

        return sample

    def get_statistics(self) -> Dict:
        """
        Get dataset statistics.

        Returns:
            Dictionary containing statistics
        """
        stats = {
            "total_samples": len(self.data),
            "avg_buggy_code_length": self.data["buggy_code"].str.len().mean(),
            "avg_fixed_code_length": self.data["fixed_code"].str.len().mean(),
        }

        if "cwe_id" in self.data.columns:
            stats["unique_cwes"] = self.data["cwe_id"].nunique()
            stats["cwe_distribution"] = self.data["cwe_id"].value_counts().to_dict()

        return stats
