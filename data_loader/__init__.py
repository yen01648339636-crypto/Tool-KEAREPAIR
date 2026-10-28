"""Data loader module for Big-Vul dataset processing."""

def __getattr__(name):
    if name == "BigVulLoader":
        from .bigvul_loader import BigVulLoader
        return BigVulLoader
    if name == "CodePreprocessor":
        from .preprocessor import CodePreprocessor
        return CodePreprocessor
    if name == "VulnerabilityDataset":
        from .dataset import VulnerabilityDataset
        return VulnerabilityDataset
    raise AttributeError(name)

__all__ = ["BigVulLoader", "CodePreprocessor", "VulnerabilityDataset"]
