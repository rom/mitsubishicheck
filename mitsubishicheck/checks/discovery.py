"""
Discovery Security Check Module

Checks for service exposure and network-level security issues.
"""

import socket
from typing import List, Optional, Dict, Any

from .base import SecurityCheck, CheckResult, Severity
from ..core.device import DEFAULT_PORTS
from ..core.melsec import MelsecClient


class DiscoveryCheck(SecurityCheck):
    """
    Security checks related to service discovery and exposure.

    Checks:
    - Open MELSEC ports
    - Service banner/fingerprint exposure
    - UDP service exposure
    - Multiple protocol support exposure
    """

    CHECK_ID = "DISC-001"
    CHECK_NAME = "Service Discovery"
    DESCRIPTION = "Check for exposed MELSEC services and ports"
    CATEGORY = "discovery"
    RISK_LEVEL = Severity.MEDIUM

    def run(self) -> List[CheckResult]:
        """Execute discovery checks."""
        self.results = []

        if not self.client:
            return self.results

        host = self.client.host

        # Check for open standard ports
        self._check_open_ports(host)

        # Check for TCP service exposure
        self._check_tcp_service(host)

        # Check for UDP service exposure
        self._check_udp_service(host)

        # Check protocol fingerprint leakage
        self._check_fingerprint_leakage()

        return self.results

    def _check_open_ports(self, host: str) -> None:
        """Check for open MELSEC-related ports."""
        open_ports = []
        timeout = self.config.get("timeout", 2.0)

        for name, port in DEFAULT_PORTS.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((host, port))
                sock.close()

                if result == 0:
                    open_ports.append((port, name))
            except socket.error:
                continue

        if open_ports:
            ports_str = ", ".join(f"{p} ({n})" for p, n in open_ports)
            self.add_result(
                passed=False,
                title="Multiple MELSEC ports exposed",
                description=f"The PLC has multiple MELSEC-related ports open: {ports_str}",
                severity=Severity.MEDIUM,
                details=f"Open ports: {open_ports}",
                remediation=(
                    "Restrict access to MELSEC ports using network segmentation "
                    "and firewall rules. Only allow connections from authorized "
                    "engineering workstations."
                ),
                cwe="CWE-284",
                references=[
                    "https://www.cisa.gov/uscert/ics/alerts/ICS-ALERT-12-046-01",
                    "https://attack.mitre.org/techniques/T0846/",
                ],
            )
        else:
            self.add_result(
                passed=True,
                title="Limited port exposure",
                description="Only expected MELSEC ports are exposed",
                severity=Severity.INFO,
            )

    def _check_tcp_service(self, host: str) -> None:
        """Check TCP service exposure."""
        port = self.client.port
        try:
            test_client = MelsecClient(host, port, timeout=2.0)
            test_client.connect()

            # Service is accepting connections without authentication
            response = test_client.loopback_test()
            test_client.disconnect()

            if response.success:
                self.add_result(
                    passed=False,
                    title="Unauthenticated MELSEC TCP service",
                    description=(
                        f"MELSEC service on TCP port {port} accepts "
                        "connections without authentication"
                    ),
                    severity=Severity.HIGH,
                    details="Loopback test succeeded without credentials",
                    evidence=f"Response: {response.data.hex() if response.data else 'empty'}",
                    remediation=(
                        "Enable remote password protection on the PLC. "
                        "Implement network-level access controls."
                    ),
                    cwe="CWE-306",
                )
        except Exception as e:
            self.add_result(
                passed=True,
                title="TCP service connection check",
                description=f"TCP connection check result: {str(e)}",
                severity=Severity.INFO,
            )

    def _check_udp_service(self, host: str) -> None:
        """Check UDP service exposure."""
        udp_port = DEFAULT_PORTS.get("mc_protocol_udp", 5006)
        timeout = self.config.get("timeout", 2.0)

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)

            # Send loopback test via UDP
            probe = bytes([
                0x50, 0x00, 0x00, 0xFF, 0xFF, 0x03, 0x00,
                0x08, 0x00, 0x10, 0x00, 0x19, 0x06, 0x00, 0x00,
                0x04, 0x00, 0x54, 0x45, 0x53, 0x54,
            ])

            sock.sendto(probe, (host, udp_port))
            response, _ = sock.recvfrom(1024)
            sock.close()

            self.add_result(
                passed=False,
                title="UDP MELSEC service exposed",
                description=f"MELSEC UDP service responding on port {udp_port}",
                severity=Severity.MEDIUM,
                details="UDP service accepts and responds to MELSEC commands",
                evidence=f"Response: {response.hex()}",
                remediation=(
                    "Disable UDP MELSEC if not required. "
                    "UDP lacks connection state and is harder to secure."
                ),
                cwe="CWE-284",
            )
        except socket.timeout:
            self.add_result(
                passed=True,
                title="UDP service not responding",
                description=f"No UDP MELSEC service detected on port {udp_port}",
                severity=Severity.INFO,
            )
        except socket.error:
            pass

    def _check_fingerprint_leakage(self) -> None:
        """Check for device fingerprint information leakage."""
        if not self.device_info:
            return

        leaked_info = []

        if self.device_info.model:
            leaked_info.append(f"Model: {self.device_info.model}")
        if self.device_info.cpu_type:
            leaked_info.append(f"CPU: {self.device_info.cpu_type}")
        if self.device_info.firmware_version:
            leaked_info.append(f"Firmware: {self.device_info.firmware_version}")

        if leaked_info:
            self.add_result(
                passed=False,
                title="Device information disclosure",
                description="PLC reveals detailed device information to unauthenticated users",
                severity=Severity.LOW,
                details="\n".join(leaked_info),
                remediation=(
                    "While device identification is often necessary for "
                    "engineering tools, ensure network segmentation prevents "
                    "unauthorized access to gather this information."
                ),
                cwe="CWE-200",
            )
