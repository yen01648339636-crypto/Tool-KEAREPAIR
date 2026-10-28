"""Logging configuration."""

import sys
from pathlib import Path
from loguru import logger


def setup_logger(
    log_file: str = "logs/mvbdsr.log",
    level: str = "INFO",
    rotation: str = "10 MB",
    retention: str = "7 days",
):
    """
    Setup logger with file and console output.

    Args:
        log_file: Path to log file
        level: Logging level
        rotation: Log rotation size
        retention: Log retention period
    """
    # Remove default handler
    logger.remove()

    # Console handler
    logger.add(
        sys.stderr,
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan> - <level>{message}</level>",
        level=level,
        colorize=True,
    )

    # File handler
    log_path = Path(log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    logger.add(
        log_file,
        format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} - {message}",
        level=level,
        rotation=rotation,
        retention=retention,
        compression="zip",
    )

    logger.info("Logger initialized")
