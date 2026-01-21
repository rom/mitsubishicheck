"""
Helper Utilities Module

Common utility functions used throughout the security audit tool.
"""

import re
import ipaddress
from typing import List, Tuple, Optional


def format_hex(data: bytes, max_length: int = 32) -> str:
    """
    Format binary data as hex string.

    Args:
        data: Binary data
        max_length: Maximum bytes to display

    Returns:
        Formatted hex string
    """
    if not data:
        return "(empty)"

    hex_str = data[:max_length].hex()
    formatted = " ".join(hex_str[i:i+2] for i in range(0, len(hex_str), 2))

    if len(data) > max_length:
        formatted += f" ... ({len(data)} bytes total)"

    return formatted


def validate_ip(ip_string: str) -> bool:
    """
    Validate IP address format.

    Args:
        ip_string: IP address string

    Returns:
        True if valid IPv4 address
    """
    try:
        ipaddress.IPv4Address(ip_string)
        return True
    except ipaddress.AddressValueError:
        return False


def validate_network(network_string: str) -> bool:
    """
    Validate network CIDR notation.

    Args:
        network_string: Network in CIDR notation

    Returns:
        True if valid network
    """
    try:
        ipaddress.IPv4Network(network_string, strict=False)
        return True
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError):
        return False


def parse_port_range(port_string: str) -> List[int]:
    """
    Parse port specification string.

    Supports:
    - Single port: "5007"
    - Range: "5000-5010"
    - List: "5007,5006,5010"
    - Mixed: "5007,5010-5015"

    Args:
        port_string: Port specification

    Returns:
        List of port numbers
    """
    ports = set()

    for part in port_string.split(","):
        part = part.strip()

        if "-" in part:
            try:
                start, end = part.split("-")
                start, end = int(start), int(end)
                ports.update(range(start, end + 1))
            except ValueError:
                continue
        else:
            try:
                ports.add(int(part))
            except ValueError:
                continue

    return sorted(p for p in ports if 1 <= p <= 65535)


def format_duration(seconds: float) -> str:
    """
    Format duration in human-readable form.

    Args:
        seconds: Duration in seconds

    Returns:
        Formatted duration string
    """
    if seconds < 1:
        return f"{seconds*1000:.0f}ms"
    elif seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        mins = int(seconds // 60)
        secs = int(seconds % 60)
        return f"{mins}m {secs}s"
    else:
        hours = int(seconds // 3600)
        mins = int((seconds % 3600) // 60)
        return f"{hours}h {mins}m"


def sanitize_filename(name: str) -> str:
    """
    Sanitize string for use as filename.

    Args:
        name: Original name

    Returns:
        Sanitized filename
    """
    # Remove or replace invalid characters
    sanitized = re.sub(r'[<>:"/\\|?*]', '_', name)
    sanitized = re.sub(r'\s+', '_', sanitized)
    sanitized = sanitized.strip('._')

    return sanitized[:100] if sanitized else "unnamed"


def bytes_to_words(data: bytes) -> List[int]:
    """
    Convert bytes to list of 16-bit words (little-endian).

    Args:
        data: Binary data

    Returns:
        List of word values
    """
    words = []
    for i in range(0, len(data) - 1, 2):
        words.append(data[i] | (data[i + 1] << 8))
    return words


def words_to_bytes(words: List[int]) -> bytes:
    """
    Convert list of 16-bit words to bytes (little-endian).

    Args:
        words: List of word values

    Returns:
        Binary data
    """
    data = bytearray()
    for word in words:
        data.append(word & 0xFF)
        data.append((word >> 8) & 0xFF)
    return bytes(data)


def format_severity_color(severity: str) -> Tuple[str, str]:
    """
    Get color codes for severity level.

    Args:
        severity: Severity string

    Returns:
        Tuple of (start_code, end_code)
    """
    colors = {
        "critical": ("\033[91m", "\033[0m"),  # Red
        "high": ("\033[91m", "\033[0m"),  # Red
        "medium": ("\033[93m", "\033[0m"),  # Yellow
        "low": ("\033[94m", "\033[0m"),  # Blue
        "info": ("\033[92m", "\033[0m"),  # Green
    }
    return colors.get(severity.lower(), ("", ""))
