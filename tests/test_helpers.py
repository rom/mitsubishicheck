"""
Tests for helper utilities.
"""

import pytest
from mitsubishicheck.utils.helpers import (
    format_hex,
    validate_ip,
    validate_network,
    parse_port_range,
    format_duration,
    sanitize_filename,
    bytes_to_words,
    words_to_bytes,
)


class TestFormatHex:
    """Test suite for hex formatting."""

    def test_format_empty(self):
        """Test formatting empty bytes."""
        result = format_hex(b"")
        assert result == "(empty)"

    def test_format_short(self):
        """Test formatting short data."""
        result = format_hex(b"\x00\x01\x02\x03")
        assert "00 01 02 03" in result

    def test_format_truncated(self):
        """Test formatting long data gets truncated."""
        data = bytes(range(100))
        result = format_hex(data, max_length=10)
        assert "..." in result
        assert "100 bytes" in result


class TestValidateIP:
    """Test suite for IP validation."""

    def test_valid_ip(self):
        """Test valid IP addresses."""
        assert validate_ip("192.168.1.1") is True
        assert validate_ip("10.0.0.1") is True
        assert validate_ip("255.255.255.255") is True

    def test_invalid_ip(self):
        """Test invalid IP addresses."""
        assert validate_ip("256.1.1.1") is False
        assert validate_ip("not.an.ip") is False
        assert validate_ip("") is False


class TestValidateNetwork:
    """Test suite for network validation."""

    def test_valid_network(self):
        """Test valid network specifications."""
        assert validate_network("192.168.1.0/24") is True
        assert validate_network("10.0.0.0/8") is True
        assert validate_network("192.168.1.100/32") is True

    def test_invalid_network(self):
        """Test invalid network specifications."""
        assert validate_network("192.168.1.0/33") is False
        assert validate_network("not.a.network/24") is False


class TestParsePortRange:
    """Test suite for port range parsing."""

    def test_single_port(self):
        """Test single port parsing."""
        ports = parse_port_range("5007")
        assert ports == [5007]

    def test_port_list(self):
        """Test port list parsing."""
        ports = parse_port_range("5007,5006,5010")
        assert ports == [5006, 5007, 5010]

    def test_port_range(self):
        """Test port range parsing."""
        ports = parse_port_range("5000-5005")
        assert ports == [5000, 5001, 5002, 5003, 5004, 5005]

    def test_mixed_specification(self):
        """Test mixed port specification."""
        ports = parse_port_range("80,443,5000-5002")
        assert 80 in ports
        assert 443 in ports
        assert 5000 in ports
        assert 5001 in ports
        assert 5002 in ports

    def test_invalid_port_filtered(self):
        """Test invalid ports are filtered."""
        ports = parse_port_range("0,100000,5007")
        assert 5007 in ports
        assert 0 not in ports
        assert 100000 not in ports


class TestFormatDuration:
    """Test suite for duration formatting."""

    def test_milliseconds(self):
        """Test millisecond formatting."""
        assert "ms" in format_duration(0.5)

    def test_seconds(self):
        """Test second formatting."""
        result = format_duration(30)
        assert "s" in result

    def test_minutes(self):
        """Test minute formatting."""
        result = format_duration(120)
        assert "m" in result

    def test_hours(self):
        """Test hour formatting."""
        result = format_duration(7200)
        assert "h" in result


class TestSanitizeFilename:
    """Test suite for filename sanitization."""

    def test_simple_name(self):
        """Test simple filename."""
        result = sanitize_filename("report")
        assert result == "report"

    def test_special_chars(self):
        """Test special character removal."""
        result = sanitize_filename('test<>:"/\\|?*.txt')
        assert "<" not in result
        assert ">" not in result
        assert ":" not in result

    def test_whitespace(self):
        """Test whitespace handling."""
        result = sanitize_filename("my report name")
        assert " " not in result
        assert "_" in result


class TestBytesWordsConversion:
    """Test suite for bytes/words conversion."""

    def test_bytes_to_words(self):
        """Test bytes to words conversion."""
        data = b"\x01\x00\x02\x00\x03\x00"
        words = bytes_to_words(data)
        assert words == [1, 2, 3]

    def test_words_to_bytes(self):
        """Test words to bytes conversion."""
        words = [1, 2, 3]
        data = words_to_bytes(words)
        assert data == b"\x01\x00\x02\x00\x03\x00"

    def test_roundtrip(self):
        """Test roundtrip conversion."""
        original = [100, 200, 300, 65535]
        data = words_to_bytes(original)
        result = bytes_to_words(data)
        assert result == original
