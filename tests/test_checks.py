"""
Tests for security check modules.
"""

import pytest
from mitsubishicheck.checks.base import SecurityCheck, CheckResult, Severity
from mitsubishicheck.checks import AVAILABLE_CHECKS


class TestSeverity:
    """Test suite for severity levels."""

    def test_severity_values(self):
        """Test severity value strings."""
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"
        assert Severity.INFO.value == "info"

    def test_severity_comparison(self):
        """Test severity comparison."""
        assert Severity.INFO < Severity.LOW
        assert Severity.LOW < Severity.MEDIUM
        assert Severity.MEDIUM < Severity.HIGH
        assert Severity.HIGH < Severity.CRITICAL


class TestCheckResult:
    """Test suite for check results."""

    def test_result_creation(self):
        """Test creating a check result."""
        result = CheckResult(
            check_id="TEST-001",
            check_name="Test Check",
            passed=False,
            severity=Severity.HIGH,
            title="Test Finding",
            description="This is a test finding",
        )

        assert result.check_id == "TEST-001"
        assert result.passed is False
        assert result.severity == Severity.HIGH

    def test_result_to_dict(self):
        """Test result serialization."""
        result = CheckResult(
            check_id="TEST-001",
            check_name="Test Check",
            passed=True,
            severity=Severity.INFO,
            title="Test",
            description="Test",
        )

        data = result.to_dict()
        assert isinstance(data, dict)
        assert data["check_id"] == "TEST-001"
        assert data["severity"] == "info"

    def test_result_str(self):
        """Test result string representation."""
        result = CheckResult(
            check_id="TEST-001",
            check_name="Test Check",
            passed=False,
            severity=Severity.CRITICAL,
            title="Critical Finding",
            description="Test",
        )

        str_repr = str(result)
        assert "CRITICAL" in str_repr
        assert "Critical Finding" in str_repr
        assert "FAIL" in str_repr


class TestAvailableChecks:
    """Test suite for available security checks."""

    def test_checks_registered(self):
        """Test that checks are registered."""
        assert len(AVAILABLE_CHECKS) > 0
        assert "discovery" in AVAILABLE_CHECKS
        assert "authentication" in AVAILABLE_CHECKS
        assert "memory" in AVAILABLE_CHECKS
        assert "cve" in AVAILABLE_CHECKS

    def test_check_instantiation(self):
        """Test that checks can be instantiated."""
        for name, check_class in AVAILABLE_CHECKS.items():
            check = check_class()
            assert hasattr(check, "CHECK_ID")
            assert hasattr(check, "CHECK_NAME")
            assert hasattr(check, "run")

    def test_check_info(self):
        """Test getting check information."""
        for name, check_class in AVAILABLE_CHECKS.items():
            check = check_class()
            info = check.get_info()

            assert "id" in info
            assert "name" in info
            assert "description" in info
            assert "category" in info
