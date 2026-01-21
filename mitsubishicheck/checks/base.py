"""
Base Security Check Module

Defines the base class and interfaces for all security checks.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, List, Dict, Any
import time

from ..core.melsec import MelsecClient
from ..core.device import DeviceInfo


class Severity(Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    def __lt__(self, other):
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return order.index(self) < order.index(other)


@dataclass
class CheckResult:
    """Result from a security check."""
    check_id: str
    check_name: str
    passed: bool
    severity: Severity
    title: str
    description: str
    details: str = ""
    evidence: str = ""
    remediation: str = ""
    cve: Optional[str] = None
    cwe: Optional[str] = None
    references: List[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "check_id": self.check_id,
            "check_name": self.check_name,
            "passed": self.passed,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "details": self.details,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "cve": self.cve,
            "cwe": self.cwe,
            "references": self.references,
            "timestamp": self.timestamp,
            "metadata": self.metadata,
        }

    def __str__(self) -> str:
        status = "PASS" if self.passed else "FAIL"
        return f"[{self.severity.value.upper():8}] [{status}] {self.title}"


class SecurityCheck(ABC):
    """
    Abstract base class for security checks.

    All security check implementations must inherit from this class
    and implement the run() method.
    """

    # Check metadata - override in subclasses
    CHECK_ID: str = "BASE-000"
    CHECK_NAME: str = "Base Check"
    DESCRIPTION: str = "Base security check"
    CATEGORY: str = "general"
    RISK_LEVEL: Severity = Severity.INFO

    def __init__(
        self,
        client: Optional[MelsecClient] = None,
        device_info: Optional[DeviceInfo] = None,
        config: Optional[Dict[str, Any]] = None,
    ):
        """
        Initialize security check.

        Args:
            client: Connected MELSEC client
            device_info: Device information (if already gathered)
            config: Check-specific configuration
        """
        self.client = client
        self.device_info = device_info
        self.config = config or {}
        self.results: List[CheckResult] = []

    @abstractmethod
    def run(self) -> List[CheckResult]:
        """
        Execute the security check.

        Returns:
            List of CheckResult objects
        """
        pass

    def add_result(
        self,
        passed: bool,
        title: str,
        description: str,
        severity: Optional[Severity] = None,
        **kwargs,
    ) -> CheckResult:
        """
        Add a check result.

        Args:
            passed: Whether the check passed (no vulnerability found)
            title: Short title of the finding
            description: Detailed description
            severity: Override default severity
            **kwargs: Additional CheckResult fields
        """
        result = CheckResult(
            check_id=self.CHECK_ID,
            check_name=self.CHECK_NAME,
            passed=passed,
            severity=severity or self.RISK_LEVEL,
            title=title,
            description=description,
            **kwargs,
        )
        self.results.append(result)
        return result

    def requires_connection(self) -> bool:
        """Check if this check requires an active connection."""
        return True

    def get_info(self) -> Dict[str, Any]:
        """Get check metadata."""
        return {
            "id": self.CHECK_ID,
            "name": self.CHECK_NAME,
            "description": self.DESCRIPTION,
            "category": self.CATEGORY,
            "risk_level": self.RISK_LEVEL.value,
        }
