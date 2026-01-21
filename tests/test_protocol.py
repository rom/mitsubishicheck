"""
Tests for MELSEC protocol implementation.
"""

import pytest
from mitsubishicheck.core.protocol import (
    MelsecProtocol,
    MelsecFrame,
    SubheaderType,
    CommandCode,
    DeviceCode,
    EndCode,
)


class TestMelsecProtocol:
    """Test suite for MELSEC protocol handler."""

    def test_protocol_initialization(self):
        """Test protocol handler initialization."""
        protocol = MelsecProtocol(frame_type="3E", binary=True)
        assert protocol.frame_type == "3E"
        assert protocol.binary is True

    def test_build_batch_read(self):
        """Test building batch read command."""
        protocol = MelsecProtocol()
        cmd = protocol.build_batch_read(DeviceCode.D, 0, 10)

        assert isinstance(cmd, bytes)
        assert len(cmd) > 0
        # Check subheader
        assert cmd[0:2] == b"\x00\x50"  # 3E request subheader (little-endian)

    def test_build_batch_write(self):
        """Test building batch write command."""
        protocol = MelsecProtocol()
        cmd = protocol.build_batch_write(DeviceCode.D, 100, [1, 2, 3, 4, 5])

        assert isinstance(cmd, bytes)
        assert len(cmd) > 0

    def test_build_loopback_test(self):
        """Test building loopback test command."""
        protocol = MelsecProtocol()
        cmd = protocol.build_loopback_test(b"TEST")

        assert isinstance(cmd, bytes)
        assert b"TEST" in cmd

    def test_build_cpu_model_read(self):
        """Test building CPU model read command."""
        protocol = MelsecProtocol()
        cmd = protocol.build_cpu_model_read()

        assert isinstance(cmd, bytes)
        assert len(cmd) > 0

    def test_build_password_unlock(self):
        """Test building password unlock command."""
        protocol = MelsecProtocol()
        cmd = protocol.build_password_unlock("1234")

        assert isinstance(cmd, bytes)

    def test_error_message_lookup(self):
        """Test error message lookup."""
        assert "Success" in MelsecProtocol.get_error_message(EndCode.SUCCESS)
        assert "Wrong password" in MelsecProtocol.get_error_message(EndCode.WRONG_PASSWORD)
        assert "Unknown" in MelsecProtocol.get_error_message(0xFFFF)


class TestMelsecFrame:
    """Test suite for MELSEC frame handling."""

    def test_frame_to_bytes_3e(self):
        """Test 3E frame serialization."""
        frame = MelsecFrame(
            subheader=SubheaderType.REQUEST_3E,
            command=CommandCode.BATCH_READ,
            subcommand=0x0000,
            data=b"\x00\x00\x00\xa8\x0a\x00",  # D0, 10 points
        )

        data = frame.to_bytes_3e()
        assert isinstance(data, bytes)
        assert len(data) > 10

    def test_frame_to_bytes_4e(self):
        """Test 4E frame serialization."""
        frame = MelsecFrame(
            subheader=SubheaderType.REQUEST_4E,
            command=CommandCode.BATCH_READ,
            subcommand=0x0000,
            data=b"\x00\x00\x00\xa8\x0a\x00",
        )

        data = frame.to_bytes_4e(serial_no=1)
        assert isinstance(data, bytes)
        # 4E frame should be longer than 3E due to serial number
        assert len(data) > 12


class TestDeviceCode:
    """Test suite for device codes."""

    def test_device_codes_exist(self):
        """Test that common device codes are defined."""
        assert DeviceCode.D == 0xA8
        assert DeviceCode.M == 0x90
        assert DeviceCode.X == 0x9C
        assert DeviceCode.Y == 0x9D

    def test_special_device_codes(self):
        """Test special device codes."""
        assert DeviceCode.SM == 0x91
        assert DeviceCode.SD == 0xA9


class TestEndCode:
    """Test suite for end/error codes."""

    def test_success_code(self):
        """Test success end code."""
        assert EndCode.SUCCESS == 0x0000

    def test_error_codes(self):
        """Test common error codes."""
        assert EndCode.WRONG_PASSWORD == 0xC056
        assert EndCode.PASSWORD_LOCKED == 0xC058
        assert EndCode.WRONG_COMMAND == 0xC059


class TestSubheaderType:
    """Test suite for subheader types."""

    def test_3e_subheaders(self):
        """Test 3E frame subheaders."""
        assert SubheaderType.REQUEST_3E == 0x5000
        assert SubheaderType.RESPONSE_3E == 0xD000

    def test_4e_subheaders(self):
        """Test 4E frame subheaders."""
        assert SubheaderType.REQUEST_4E == 0x5400
        assert SubheaderType.RESPONSE_4E == 0xD400
