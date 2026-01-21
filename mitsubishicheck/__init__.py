"""
Mitsubishi PLC Security Audit Tool

A comprehensive security assessment tool for Mitsubishi PLCs
using the MELSEC protocol.
"""

__version__ = "1.0.0"
__author__ = "Security Research Team"
__license__ = "MIT"

from .core.melsec import MelsecClient
from .core.scanner import PLCScanner
from .core.device import DeviceInfo

__all__ = ["MelsecClient", "PLCScanner", "DeviceInfo", "__version__"]
