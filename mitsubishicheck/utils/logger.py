"""
Logging Configuration Module

Provides logging setup and utilities for the security audit tool.
"""

import logging
import sys
from typing import Optional


# ANSI color codes
class Colors:
    CRITICAL = "\033[91m"  # Red
    ERROR = "\033[91m"  # Red
    WARNING = "\033[93m"  # Yellow
    INFO = "\033[92m"  # Green
    DEBUG = "\033[94m"  # Blue
    RESET = "\033[0m"


class ColoredFormatter(logging.Formatter):
    """Custom formatter with color support."""

    COLORS = {
        logging.CRITICAL: Colors.CRITICAL,
        logging.ERROR: Colors.ERROR,
        logging.WARNING: Colors.WARNING,
        logging.INFO: Colors.INFO,
        logging.DEBUG: Colors.DEBUG,
    }

    def __init__(self, fmt: str, use_color: bool = True):
        super().__init__(fmt)
        self.use_color = use_color

    def format(self, record):
        if self.use_color and record.levelno in self.COLORS:
            record.levelname = (
                f"{self.COLORS[record.levelno]}{record.levelname}{Colors.RESET}"
            )
        return super().format(record)


def setup_logger(
    name: str = "mitsubishicheck",
    level: int = logging.INFO,
    log_file: Optional[str] = None,
    use_color: bool = True,
) -> logging.Logger:
    """
    Set up and configure the logger.

    Args:
        name: Logger name
        level: Logging level
        log_file: Optional file to write logs to
        use_color: Whether to use colored output

    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)

    # Remove existing handlers
    logger.handlers = []

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)

    # Detect if output supports color
    supports_color = use_color and hasattr(sys.stdout, "isatty") and sys.stdout.isatty()

    fmt = "%(asctime)s [%(levelname)s] %(message)s"
    console_handler.setFormatter(ColoredFormatter(fmt, use_color=supports_color))
    logger.addHandler(console_handler)

    # File handler
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(level)
        file_handler.setFormatter(logging.Formatter(fmt))
        logger.addHandler(file_handler)

    return logger


def get_logger(name: str = "mitsubishicheck") -> logging.Logger:
    """
    Get the logger instance.

    Args:
        name: Logger name

    Returns:
        Logger instance
    """
    return logging.getLogger(name)
