"""Path management for KeaRepair project."""

from pathlib import Path
from typing import Optional


class ProjectPaths:
    """Centralized path management for the project."""

    def __init__(self, root_dir: Optional[Path] = None):
        """
        Initialize project paths.

        Args:
            root_dir: Root directory of the project. If None, uses parent of this file.
        """
        if root_dir is None:
            # Assume this file is in config/ subdirectory
            self.root = Path(__file__).parent.parent
        else:
            self.root = Path(root_dir)

        # Data directories
        self.data = self.root / "data"
        self.raw_data = self.data / "raw"
        self.processed_data = self.data / "processed"
        self.indices = self.data / "indices"

        # Config
        self.config = self.root / "config"

        # Logs
        self.logs = self.root / "logs"

        # Model checkpoints
        self.checkpoints = self.root / "checkpoints"

        # Create directories if they don't exist
        self._create_dirs()

    def _create_dirs(self):
        """Create necessary directories."""
        dirs_to_create = [
            self.data,
            self.raw_data,
            self.processed_data,
            self.indices,
            self.logs,
            self.checkpoints,
        ]
        for dir_path in dirs_to_create:
            dir_path.mkdir(parents=True, exist_ok=True)

    def get_index_path(self, view_type: str) -> Path:
        """
        Get path for a specific view index.

        Args:
            view_type: Type of view (data_flow, control_flow)

        Returns:
            Path to the index file
        """
        return self.indices / f"index_{view_type}"

    def get_processed_data_path(self, dataset_name: str) -> Path:
        """
        Get path for processed dataset.

        Args:
            dataset_name: Name of the dataset (e.g., 'bigvul')

        Returns:
            Path to processed data file
        """
        return self.processed_data / f"{dataset_name}_processed.pkl"
