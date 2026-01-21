"""
Tests for device information module.
"""

import pytest
from mitsubishicheck.core.device import (
    DeviceInfo,
    PLCSeries,
    DEFAULT_PORTS,
    DEFAULT_CREDENTIALS,
)


class TestPLCSeries:
    """Test suite for PLC series identification."""

    def test_series_values(self):
        """Test series enum values."""
        assert PLCSeries.UNKNOWN.value == "Unknown"
        assert PLCSeries.MELSEC_Q.value == "MELSEC-Q Series"
        assert PLCSeries.MELSEC_IQR.value == "MELSEC iQ-R Series"


class TestDeviceInfo:
    """Test suite for device information."""

    def test_device_info_creation(self):
        """Test creating device info."""
        info = DeviceInfo(ip_address="192.168.1.100", port=5007)

        assert info.ip_address == "192.168.1.100"
        assert info.port == 5007
        assert info.series == PLCSeries.UNKNOWN

    def test_device_info_to_dict(self):
        """Test device info serialization."""
        info = DeviceInfo(
            ip_address="192.168.1.100",
            port=5007,
            model="Q03UDECPU",
            series=PLCSeries.MELSEC_Q,
        )

        data = info.to_dict()
        assert isinstance(data, dict)
        assert data["ip_address"] == "192.168.1.100"
        assert data["model"] == "Q03UDECPU"

    def test_identify_series_q(self):
        """Test Q series identification."""
        series = DeviceInfo.identify_series("Q03UDECPU")
        assert series == PLCSeries.MELSEC_Q

    def test_identify_series_iq_r(self):
        """Test iQ-R series identification."""
        series = DeviceInfo.identify_series("R08SFCPU")
        assert series == PLCSeries.MELSEC_IQR

    def test_identify_series_iq_f(self):
        """Test iQ-F series identification."""
        series = DeviceInfo.identify_series("FX5UCPU")
        assert series == PLCSeries.MELSEC_IQF

    def test_identify_series_unknown(self):
        """Test unknown series."""
        series = DeviceInfo.identify_series("UNKNOWN123")
        assert series == PLCSeries.UNKNOWN

    def test_add_vulnerability(self):
        """Test adding vulnerability to device info."""
        info = DeviceInfo(ip_address="192.168.1.100")
        info.add_vulnerability(
            vuln_id="TEST-001",
            severity="high",
            title="Test Vulnerability",
            description="This is a test",
            cve="CVE-2024-0001",
        )

        assert len(info.vulnerabilities) == 1
        assert info.vulnerabilities[0]["cve"] == "CVE-2024-0001"


class TestDefaultPorts:
    """Test suite for default port definitions."""

    def test_mc_protocol_ports(self):
        """Test MC protocol port definitions."""
        assert DEFAULT_PORTS["mc_protocol_tcp"] == 5007
        assert DEFAULT_PORTS["mc_protocol_udp"] == 5006

    def test_all_ports_valid(self):
        """Test all ports are in valid range."""
        for name, port in DEFAULT_PORTS.items():
            assert 1 <= port <= 65535, f"Invalid port for {name}: {port}"


class TestDefaultCredentials:
    """Test suite for default credentials."""

    def test_credentials_defined(self):
        """Test default credentials are defined."""
        assert len(DEFAULT_CREDENTIALS) > 0

    def test_empty_password_included(self):
        """Test empty password is included."""
        assert "" in DEFAULT_CREDENTIALS
