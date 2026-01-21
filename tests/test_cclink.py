"""
Tests for CC-Link IE Field protocol and security checks.
"""

import pytest
import struct
from unittest.mock import Mock, patch, MagicMock

from mitsubishicheck.core.cclink import (
    CCLinkClient,
    CCLinkProtocol,
    CCLinkCommand,
    CCLinkEndCode,
    CCLinkDeviceCode,
    CCLinkFrame,
    CCLinkResponse,
    CCLINK_KNOWN_VULNERABILITIES,
    CCLINK_DEFAULT_CREDENTIALS,
)
from mitsubishicheck.checks.cclink import (
    CCLinkSecurityCheck,
    CCLinkDiscoveryCheck,
    CCLinkProtocolCheck,
)
from mitsubishicheck.checks.base import Severity


class TestCCLinkProtocol:
    """Tests for CC-Link protocol implementation."""

    def test_protocol_initialization(self):
        """Test protocol handler initialization."""
        protocol = CCLinkProtocol()
        assert protocol.binary is True
        assert protocol._serial_no == 0

    def test_next_serial(self):
        """Test serial number generation."""
        protocol = CCLinkProtocol()
        assert protocol._next_serial() == 1
        assert protocol._next_serial() == 2
        assert protocol._next_serial() == 3

    def test_serial_number_wraps(self):
        """Test serial number wraps at 0xFFFF."""
        protocol = CCLinkProtocol()
        protocol._serial_no = 0xFFFF
        assert protocol._next_serial() == 0

    def test_build_device_read(self):
        """Test building device read command."""
        protocol = CCLinkProtocol()
        cmd = protocol.build_device_read(CCLinkDeviceCode.D, 0, 10)

        assert isinstance(cmd, bytes)
        assert len(cmd) > 0
        # Check subheader (4E frame)
        subheader = struct.unpack("<H", cmd[:2])[0]
        assert subheader == 0x5400

    def test_build_device_write(self):
        """Test building device write command."""
        protocol = CCLinkProtocol()
        cmd = protocol.build_device_write(CCLinkDeviceCode.D, 0, [100, 200, 300])

        assert isinstance(cmd, bytes)
        assert len(cmd) > 0

    def test_build_loopback_test(self):
        """Test building loopback test command."""
        protocol = CCLinkProtocol()
        cmd = protocol.build_loopback_test(b"TEST")

        assert isinstance(cmd, bytes)
        # Should contain "TEST"
        assert b"TEST" in cmd

    def test_build_cpu_model_read(self):
        """Test building CPU model read command."""
        protocol = CCLinkProtocol()
        cmd = protocol.build_cpu_model_read()

        assert isinstance(cmd, bytes)
        assert len(cmd) > 0

    def test_build_remote_run(self):
        """Test building remote RUN command."""
        protocol = CCLinkProtocol()
        cmd = protocol.build_remote_run(forced=False)

        assert isinstance(cmd, bytes)
        assert len(cmd) > 0

    def test_build_remote_stop(self):
        """Test building remote STOP command."""
        protocol = CCLinkProtocol()
        cmd = protocol.build_remote_stop()

        assert isinstance(cmd, bytes)
        assert len(cmd) > 0

    def test_build_password_unlock(self):
        """Test building password unlock command."""
        protocol = CCLinkProtocol()
        cmd = protocol.build_password_unlock("1234")

        assert isinstance(cmd, bytes)
        assert len(cmd) > 0

    def test_build_password_lock(self):
        """Test building password lock command."""
        protocol = CCLinkProtocol()
        cmd = protocol.build_password_lock()

        assert isinstance(cmd, bytes)
        assert len(cmd) > 0

    def test_build_node_search(self):
        """Test building node search command."""
        protocol = CCLinkProtocol()
        cmd = protocol.build_node_search()

        assert isinstance(cmd, bytes)
        assert len(cmd) > 0

    def test_build_cyclic_data_read(self):
        """Test building cyclic data read command."""
        protocol = CCLinkProtocol()
        cmd = protocol.build_cyclic_data_read(0, 63)

        assert isinstance(cmd, bytes)
        assert len(cmd) > 0

    def test_get_error_message(self):
        """Test error message retrieval."""
        assert "Success" in CCLinkProtocol.get_error_message(CCLinkEndCode.SUCCESS)
        assert "Wrong command" in CCLinkProtocol.get_error_message(CCLinkEndCode.WRONG_COMMAND)
        assert "Wrong password" in CCLinkProtocol.get_error_message(CCLinkEndCode.WRONG_PASSWORD)
        assert "0xFFFF" in CCLinkProtocol.get_error_message(0xFFFF)


class TestCCLinkFrame:
    """Tests for CC-Link frame handling."""

    def test_frame_to_bytes(self):
        """Test frame serialization."""
        frame = CCLinkFrame(
            command=CCLinkCommand.LOOPBACK_TEST,
            subcommand=0x0000,
            data=b"TEST",
        )
        frame_bytes = frame.to_bytes()

        assert isinstance(frame_bytes, bytes)
        assert len(frame_bytes) > 0

    def test_frame_parse_response(self):
        """Test frame response parsing."""
        # Build a minimal valid response
        response = struct.pack(
            "<HHHBBHBHH",
            0xD400,  # Response subheader
            0x0001,  # Serial
            0x0000,  # Reserved
            0x00,    # Network
            0xFF,    # Station
            0x03FF,  # Module I/O
            0x00,    # Multidrop
            0x02,    # Data length
            0x0000,  # End code (success)
        )

        frame, end_code = CCLinkFrame.parse_response(response)

        assert frame.subheader == 0xD400
        assert end_code == 0x0000

    def test_frame_parse_short_response(self):
        """Test parsing of too-short response."""
        short_response = bytes([0x54, 0x00, 0x01])

        with pytest.raises(ValueError, match="too short"):
            CCLinkFrame.parse_response(short_response)


class TestCCLinkResponse:
    """Tests for CC-Link response handling."""

    def test_response_success(self):
        """Test successful response."""
        response = CCLinkResponse(
            success=True,
            end_code=CCLinkEndCode.SUCCESS,
            data=b"test_data",
        )

        assert response.success is True
        assert response.end_code == CCLinkEndCode.SUCCESS
        assert response.data == b"test_data"
        assert response.is_password_error is False

    def test_response_password_error(self):
        """Test password error detection."""
        response = CCLinkResponse(
            success=False,
            end_code=CCLinkEndCode.WRONG_PASSWORD,
        )

        assert response.is_password_error is True

        response2 = CCLinkResponse(
            success=False,
            end_code=CCLinkEndCode.PASSWORD_LOCKED,
        )

        assert response2.is_password_error is True


class TestCCLinkClient:
    """Tests for CC-Link client."""

    def test_client_initialization(self):
        """Test client initialization."""
        client = CCLinkClient("192.168.1.100", 45237)

        assert client.host == "192.168.1.100"
        assert client.port == 45237
        assert client.timeout == 5.0
        assert client.is_connected is False

    def test_client_default_port(self):
        """Test client default port."""
        assert CCLinkClient.DEFAULT_PORT == 45237

    def test_client_device_read_unknown_device(self):
        """Test device read with unknown device code."""
        client = CCLinkClient("192.168.1.100")
        client._connected = True
        client._socket = Mock()

        response = client.device_read("INVALID", 0, 1)

        assert response.success is False
        assert "Unknown device" in response.error_message

    def test_client_device_write_unknown_device(self):
        """Test device write with unknown device code."""
        client = CCLinkClient("192.168.1.100")
        client._connected = True
        client._socket = Mock()

        response = client.device_write("INVALID", 0, [100])

        assert response.success is False
        assert "Unknown device" in response.error_message

    def test_client_context_manager(self):
        """Test client context manager."""
        with patch.object(CCLinkClient, 'connect') as mock_connect, \
             patch.object(CCLinkClient, 'disconnect') as mock_disconnect:
            mock_connect.return_value = True

            with CCLinkClient("192.168.1.100") as client:
                pass

            mock_connect.assert_called_once()
            mock_disconnect.assert_called_once()


class TestCCLinkSecurityCheck:
    """Tests for CC-Link security checks."""

    def test_check_initialization(self):
        """Test security check initialization."""
        check = CCLinkSecurityCheck()

        assert check.CHECK_ID == "CCLINK-001"
        assert check.CHECK_NAME == "CC-Link IE Field Security Check"
        assert check.CATEGORY == "cclink"
        assert check.RISK_LEVEL == Severity.HIGH

    def test_check_without_client(self):
        """Test check without CC-Link client."""
        check = CCLinkSecurityCheck()
        results = check.run()

        assert len(results) == 1
        assert results[0].passed is True
        assert "not configured" in results[0].description

    def test_check_with_mock_client(self):
        """Test check with mock client."""
        mock_client = Mock(spec=CCLinkClient)
        mock_client.host = "192.168.1.100"
        mock_client.port = 45237

        # Setup mock responses
        mock_client.loopback_test.return_value = CCLinkResponse(
            success=True,
            end_code=CCLinkEndCode.SUCCESS,
        )
        mock_client.device_read.return_value = CCLinkResponse(
            success=True,
            end_code=CCLinkEndCode.SUCCESS,
            data=b"\x00\x00",
        )
        mock_client.read_cyclic_data.return_value = CCLinkResponse(
            success=False,
            end_code=CCLinkEndCode.WRONG_COMMAND,
        )
        mock_client.node_search.return_value = CCLinkResponse(
            success=False,
            end_code=CCLinkEndCode.WRONG_COMMAND,
        )
        mock_client.get_communication_settings.return_value = CCLinkResponse(
            success=False,
            end_code=CCLinkEndCode.WRONG_COMMAND,
        )
        mock_client.unlock_password.return_value = CCLinkResponse(
            success=False,
            end_code=CCLinkEndCode.WRONG_PASSWORD,
        )
        mock_client.lock_password.return_value = CCLinkResponse(
            success=True,
            end_code=CCLinkEndCode.SUCCESS,
        )
        mock_client._send_receive.side_effect = Exception("Connection refused")

        check = CCLinkSecurityCheck(cclink_client=mock_client)
        results = check.run()

        # Should have multiple results from various checks
        assert len(results) > 0

        # Find service exposure result
        exposure_results = [r for r in results if "exposed" in r.title.lower()]
        assert len(exposure_results) > 0

    def test_check_metadata(self):
        """Test check metadata."""
        check = CCLinkSecurityCheck()
        info = check.get_info()

        assert info["id"] == "CCLINK-001"
        assert info["category"] == "cclink"


class TestCCLinkDiscoveryCheck:
    """Tests for CC-Link discovery check."""

    def test_discovery_check_initialization(self):
        """Test discovery check initialization."""
        check = CCLinkDiscoveryCheck()

        assert check.CHECK_ID == "CCLINK-002"
        assert check.CHECK_NAME == "CC-Link Discovery Check"

    def test_discovery_without_host(self):
        """Test discovery check without host configured."""
        check = CCLinkDiscoveryCheck()
        results = check.run()

        assert len(results) == 1
        assert "skipped" in results[0].title.lower()

    @patch('socket.socket')
    def test_discovery_port_check(self, mock_socket_class):
        """Test port check in discovery."""
        mock_socket = Mock()
        mock_socket.connect_ex.return_value = 0
        mock_socket_class.return_value = mock_socket

        check = CCLinkDiscoveryCheck(config={"host": "192.168.1.100", "port": 45237})

        # Run only port check
        check.results = []
        check._check_port_open("192.168.1.100", 45237)

        assert len(check.results) == 1
        assert "open" in check.results[0].title.lower()


class TestCCLinkProtocolCheck:
    """Tests for CC-Link protocol security check."""

    def test_protocol_check_initialization(self):
        """Test protocol check initialization."""
        check = CCLinkProtocolCheck()

        assert check.CHECK_ID == "CCLINK-003"
        assert check.CHECK_NAME == "CC-Link Protocol Security Check"
        assert check.CATEGORY == "cclink"

    def test_protocol_check_without_client(self):
        """Test protocol check without client."""
        check = CCLinkProtocolCheck()
        results = check.run()

        assert len(results) == 0


class TestCCLinkConstants:
    """Tests for CC-Link constants and vulnerabilities."""

    def test_known_vulnerabilities(self):
        """Test known vulnerabilities database."""
        assert len(CCLINK_KNOWN_VULNERABILITIES) > 0

        # Check structure of vulnerability entries
        for cve_id, cve_info in CCLINK_KNOWN_VULNERABILITIES.items():
            assert cve_id.startswith("CVE-")
            assert "description" in cve_info
            assert "severity" in cve_info
            assert "affected_models" in cve_info
            assert isinstance(cve_info["affected_models"], list)

    def test_default_credentials(self):
        """Test default credentials list."""
        assert len(CCLINK_DEFAULT_CREDENTIALS) > 0
        assert "" in CCLINK_DEFAULT_CREDENTIALS  # Empty password

    def test_command_codes(self):
        """Test CC-Link command codes."""
        assert CCLinkCommand.DEVICE_READ == 0x0401
        assert CCLinkCommand.DEVICE_WRITE == 0x1401
        assert CCLinkCommand.REMOTE_RUN == 0x1001
        assert CCLinkCommand.REMOTE_STOP == 0x1002
        assert CCLinkCommand.LOOPBACK_TEST == 0x0619
        assert CCLinkCommand.NODE_SEARCH == 0x0E20

    def test_device_codes(self):
        """Test CC-Link device codes."""
        assert CCLinkDeviceCode.RX == 0x9C
        assert CCLinkDeviceCode.RY == 0x9D
        assert CCLinkDeviceCode.D == 0xA8
        assert CCLinkDeviceCode.M == 0x90

    def test_end_codes(self):
        """Test CC-Link end codes."""
        assert CCLinkEndCode.SUCCESS == 0x0000
        assert CCLinkEndCode.WRONG_COMMAND == 0xC059
        assert CCLinkEndCode.WRONG_PASSWORD == 0xC056
        assert CCLinkEndCode.PASSWORD_LOCKED == 0xC058


class TestCCLinkIntegration:
    """Integration tests for CC-Link functionality."""

    def test_check_registry(self):
        """Test CC-Link checks are registered."""
        from mitsubishicheck.checks import AVAILABLE_CHECKS

        assert "cclink" in AVAILABLE_CHECKS
        assert "cclink_discovery" in AVAILABLE_CHECKS
        assert "cclink_protocol" in AVAILABLE_CHECKS

    def test_check_exports(self):
        """Test CC-Link checks are exported."""
        from mitsubishicheck.checks import (
            CCLinkSecurityCheck,
            CCLinkDiscoveryCheck,
            CCLinkProtocolCheck,
        )

        assert CCLinkSecurityCheck is not None
        assert CCLinkDiscoveryCheck is not None
        assert CCLinkProtocolCheck is not None

    def test_core_exports(self):
        """Test CC-Link core modules are exported."""
        from mitsubishicheck.core import (
            CCLinkClient,
            CCLinkProtocol,
            CCLinkCommand,
            CCLinkEndCode,
            CCLinkDeviceCode,
            CCLinkResponse,
            CCLINK_PORTS,
        )

        assert CCLinkClient is not None
        assert CCLinkProtocol is not None
        assert CCLinkCommand is not None
        assert CCLinkEndCode is not None
        assert CCLinkDeviceCode is not None
        assert CCLinkResponse is not None
        assert len(CCLINK_PORTS) > 0

    def test_scanner_cclink_support(self):
        """Test scanner has CC-Link support."""
        from mitsubishicheck.core.scanner import PLCScanner

        scanner = PLCScanner(scan_cclink=True)
        assert scanner.scan_cclink is True

        # Check methods exist
        assert hasattr(scanner, 'quick_cclink_scan')
        assert hasattr(scanner, 'scan_cclink_network')
        assert hasattr(scanner, '_scan_cclink_port')
        assert hasattr(PLCScanner, 'discover_cclink_broadcast')
