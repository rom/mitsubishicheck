"""
Mitsubishi PLC Device Information Module

Handles device identification, fingerprinting, and metadata.
"""

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from enum import Enum
import re


class PLCSeries(Enum):
    """Mitsubishi PLC Series identification."""
    UNKNOWN = "Unknown"
    MELSEC_A = "MELSEC-A Series"
    MELSEC_Q = "MELSEC-Q Series"
    MELSEC_QNA = "MELSEC-QnA Series"
    MELSEC_L = "MELSEC-L Series"
    MELSEC_IQR = "MELSEC iQ-R Series"
    MELSEC_IQF = "MELSEC iQ-F Series"
    FX_SERIES = "FX Series"


@dataclass
class DeviceInfo:
    """
    Contains information about a discovered Mitsubishi PLC device.
    """
    ip_address: str
    port: int = 5007
    series: PLCSeries = PLCSeries.UNKNOWN
    model: str = ""
    cpu_type: str = ""
    firmware_version: str = ""
    serial_number: str = ""
    mac_address: str = ""

    # Protocol capabilities
    supports_3e: bool = False
    supports_4e: bool = False
    supports_1e: bool = False
    supports_ascii: bool = False
    supports_binary: bool = True

    # Security status
    password_protected: bool = False
    password_locked: bool = False
    remote_password_enabled: bool = False

    # Operational status
    is_running: bool = False
    cpu_status: str = ""
    error_code: int = 0

    # Network info
    network_number: int = 0
    station_number: int = 0

    # Raw response data for analysis
    raw_responses: Dict[str, bytes] = field(default_factory=dict)

    # Discovered vulnerabilities
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)

    def __str__(self) -> str:
        """Format device info for display."""
        lines = [
            f"Device: {self.ip_address}:{self.port}",
            f"  Series: {self.series.value}",
            f"  Model: {self.model or 'Unknown'}",
            f"  CPU Type: {self.cpu_type or 'Unknown'}",
            f"  Firmware: {self.firmware_version or 'Unknown'}",
            f"  Running: {'Yes' if self.is_running else 'No'}",
            f"  Password Protected: {'Yes' if self.password_protected else 'No'}",
        ]
        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "ip_address": self.ip_address,
            "port": self.port,
            "series": self.series.value,
            "model": self.model,
            "cpu_type": self.cpu_type,
            "firmware_version": self.firmware_version,
            "serial_number": self.serial_number,
            "mac_address": self.mac_address,
            "supports_3e": self.supports_3e,
            "supports_4e": self.supports_4e,
            "supports_1e": self.supports_1e,
            "password_protected": self.password_protected,
            "password_locked": self.password_locked,
            "is_running": self.is_running,
            "cpu_status": self.cpu_status,
            "vulnerabilities": self.vulnerabilities,
        }

    @classmethod
    def identify_series(cls, model_string: str) -> PLCSeries:
        """Identify PLC series from model string."""
        model_upper = model_string.upper()

        patterns = {
            PLCSeries.MELSEC_IQR: [r"R\d{2}", r"IQ-R", r"RJ7"],
            PLCSeries.MELSEC_IQF: [r"FX5", r"IQ-F"],
            PLCSeries.MELSEC_Q: [r"Q\d{2}", r"QJ7", r"QnUDE"],
            PLCSeries.MELSEC_QNA: [r"QnA", r"AnS"],
            PLCSeries.MELSEC_L: [r"L\d{2}"],
            PLCSeries.MELSEC_A: [r"A\d[A-Z]", r"A1S", r"A2S"],
            PLCSeries.FX_SERIES: [r"FX[1-3]", r"FX\d"],
        }

        for series, pattern_list in patterns.items():
            for pattern in pattern_list:
                if re.search(pattern, model_upper):
                    return series

        return PLCSeries.UNKNOWN

    def add_vulnerability(
        self,
        vuln_id: str,
        severity: str,
        title: str,
        description: str,
        cve: Optional[str] = None,
        remediation: Optional[str] = None,
    ) -> None:
        """Add a discovered vulnerability."""
        self.vulnerabilities.append({
            "id": vuln_id,
            "severity": severity,
            "title": title,
            "description": description,
            "cve": cve,
            "remediation": remediation,
        })


# Known Mitsubishi PLC default ports
DEFAULT_PORTS = {
    "mc_protocol_tcp": 5007,
    "mc_protocol_udp": 5006,
    "fx_protocol": 5001,
    "slmp": 5010,
    "cc_link_ie_field": 45237,
    "melsec_net": 5002,
    "gx_works": 5556,
    "melsoft": 5561,
}

# Known vulnerable firmware versions (for educational/testing purposes)
KNOWN_VULNERABLE_VERSIONS = {
    "Q03UDECPU": {
        "versions": ["<= 07135"],
        "cves": ["CVE-2020-5527", "CVE-2020-5528"],
    },
    "R08SFCPU": {
        "versions": ["<= 05"],
        "cves": ["CVE-2022-25164"],
    },
}

# Default credentials commonly found
DEFAULT_CREDENTIALS = [
    "",  # No password
    "    ",  # 4 spaces
    "MITSUBISHI",
    "MELSEC",
    "1234",
    "0000",
    "PASS",
    "TEST",
    "USER",
    "ADMIN",
]
