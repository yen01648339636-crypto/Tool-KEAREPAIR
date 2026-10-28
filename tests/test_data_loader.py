"""Tests for data_loader module."""

import pytest
import pandas as pd
from data_loader import BigVulLoader, CodePreprocessor, VulnerabilityDataset


class TestBigVulLoader:
    """Tests for BigVulLoader."""

    def test_initialization(self, tmp_path):
        """Test loader initialization."""
        data_file = tmp_path / "test_data.csv"
        data_file.write_text("col1,col2\nval1,val2")
        
        loader = BigVulLoader(data_file)
        assert loader.data_path == data_file

    def test_load_csv(self, tmp_path):
        """Test loading CSV data."""
        data_file = tmp_path / "test.csv"
        data_file.write_text("buggy_code,fixed_code\ncode1,fix1")
        
        loader = BigVulLoader(data_file)
        data = loader.load()
        
        assert isinstance(data, pd.DataFrame)
        assert len(data) == 1


class TestCodePreprocessor:
    """Tests for CodePreprocessor."""

    def test_remove_comments(self):
        """Test comment removal."""
        preprocessor = CodePreprocessor(remove_comments=True)
        code = "int x = 5; // comment\n/* block comment */"
        
        processed = preprocessor.preprocess(code)
        assert "//" not in processed
        assert "/*" not in processed

    def test_normalize_whitespace(self):
        """Test whitespace normalization."""
        preprocessor = CodePreprocessor(normalize_whitespace=True)
        code = "int\tx\t=\t5;\n\n\n"
        
        processed = preprocessor.preprocess(code)
        assert "\t" not in processed

    def test_tokenize(self):
        """Test tokenization."""
        preprocessor = CodePreprocessor()
        code = "int x = 5;"
        
        tokens = preprocessor.tokenize(code)
        assert "int" in tokens
        assert "x" in tokens
        assert "5" in tokens


class TestVulnerabilityDataset:
    """Tests for VulnerabilityDataset."""

    def test_dataset_creation(self):
        """Test dataset creation."""
        data = pd.DataFrame({
            "buggy_code": ["code1", "code2"],
            "fixed_code": ["fix1", "fix2"],
        })
        
        dataset = VulnerabilityDataset(data)
        assert len(dataset) == 2

    def test_getitem(self):
        """Test getting item from dataset."""
        data = pd.DataFrame({
            "buggy_code": ["code1"],
            "fixed_code": ["fix1"],
        })
        
        dataset = VulnerabilityDataset(data)
        sample = dataset[0]
        
        assert sample["buggy_code"] == "code1"
        assert sample["fixed_code"] == "fix1"
