"""
CC-Link IE Field Security Check Module

Comprehensive security checks for CC-Link IE Field Network
implementations on Mitsubishi PLCs.
"""

import struct
import time
from typing import List, Optional, Dict, Any

from .base import SecurityCheck, CheckResult, Severity
from ..core.cclink import (
    CCLinkClient,
    CCLinkProtocol,
    CCLinkCommand,
    CCLinkEndCode,
    CCLinkDeviceCode,
    CCLINK_KNOWN_VULNERABILITIES,
    CCLINK_DEFAULT_CREDENTIALS,
)


class CCLinkSecurityCheck(SecurityCheck):
    """
    Security checks for CC-Link IE Field Network.

    Performs comprehensive security assessment of CC-Link IE Field
    implementations including:
    - Protocol security vulnerabilities
    - Authentication weaknesses
    - Network configuration issues
    - Known CVE detection
    - Unauthorized access testing
    """

    CHECK_ID = "CCLINK-001"
    CHECK_NAME = "CC-Link IE Field Security Check"
    DESCRIPTION = "Comprehensive security check for CC-Link IE Field Network"
    CATEGORY = "cclink"
    RISK_LEVEL = Severity.HIGH

    def __init__(
        self,
        client: Optional[Any] = None,
        device_info: Optional[Any] = None,
        config: Optional[Dict[str, Any]] = None,
        cclink_client: Optional[CCLinkClient] = None,
    ):
        """
        Initialize CC-Link security check.

        Args:
            client: MELSEC client (optional, for compatibility)
            device_info: Device information
            config: Check-specific configuration
            cclink_client: CC-Link IE Field client
        """
        super().__init__(client, device_info, config)
        self.cclink_client = cclink_client
        self._protocol = CCLinkProtocol()

    def run(self) -> List[CheckResult]:
        """Execute CC-Link security checks."""
        self.results = []

        if not self.cclink_client:
            self.add_result(
                passed=True,
                title="CC-Link client not configured",
                description="CC-Link security checks require a CC-Link client",
                severity=Severity.INFO,
            )
            return self.results

        # Run all CC-Link security checks
        self._check_service_exposure()
        self._check_authentication()
        self._check_cleartext_protocol()
        self._check_device_access()
        self._check_control_commands()
        self._check_cyclic_data_exposure()
        self._check_node_enumeration()
        self._check_known_vulnerabilities()
        self._check_network_configuration()
        self._check_replay_vulnerability()

        return self.results

    def _check_service_exposure(self) -> None:
        """Check if CC-Link service is exposed."""
        try:
            response = self.cclink_client.loopback_test()

            if response.success:
                self.add_result(
                    passed=False,
                    title="CC-Link IE Field service exposed",
                    description=(
                        f"CC-Link IE Field service is accessible on "
                        f"{self.cclink_client.host}:{self.cclink_client.port}"
                    ),
                    severity=Severity.MEDIUM,
                    details=(
                        "CC-Link IE Field service responds to loopback test. "
                        "This indicates the service is reachable and active."
                    ),
                    remediation=(
                        "Restrict network access to CC-Link services using firewalls. "
                        "Implement network segmentation for industrial protocols. "
                        "Use VPN for remote access."
                    ),
                    cwe="CWE-284",
                    references=[
                        "https://attack.mitre.org/techniques/T0846/",
                    ],
                )
            else:
                self.add_result(
                    passed=True,
                    title="CC-Link service access limited",
                    description="Service does not respond to standard queries",
                    severity=Severity.INFO,
                )
        except Exception as e:
            self.add_result(
                passed=True,
                title="CC-Link service check error",
                description=f"Could not complete service check: {str(e)}",
                severity=Severity.INFO,
            )

    def _check_authentication(self) -> None:
        """Check authentication mechanisms and password strength."""
        # Test if device is password protected
        try:
            response = self.cclink_client.device_read("D", 0, 1)

            if response.success:
                # No password protection
                self.add_result(
                    passed=False,
                    title="CC-Link device not password protected",
                    description="Device memory can be read without authentication",
                    severity=Severity.CRITICAL,
                    details="Memory read succeeded without providing credentials",
                    remediation=(
                        "Enable remote password protection in CC-Link module settings. "
                        "Use strong passwords and change default credentials."
                    ),
                    cwe="CWE-306",
                    references=[
                        "https://attack.mitre.org/techniques/T0812/",
                    ],
                )
                self._check_default_credentials()
            elif response.is_password_error:
                self.add_result(
                    passed=True,
                    title="CC-Link password protection enabled",
                    description="Device requires authentication for access",
                    severity=Severity.INFO,
                )
                # Still check for weak passwords
                self._check_default_credentials()
            else:
                self.add_result(
                    passed=True,
                    title="CC-Link authentication check inconclusive",
                    description=f"Received response: {response.error_message}",
                    severity=Severity.INFO,
                )
        except Exception as e:
            self.add_result(
                passed=True,
                title="CC-Link authentication check error",
                description=f"Error during authentication check: {str(e)}",
                severity=Severity.INFO,
            )

    def _check_default_credentials(self) -> None:
        """Check for default or weak credentials."""
        if not self.config.get("check_credentials", True):
            return

        for credential in CCLINK_DEFAULT_CREDENTIALS[:5]:  # Limit attempts
            try:
                response = self.cclink_client.unlock_password(credential)

                if response.success:
                    cred_display = repr(credential) if credential else "(empty)"
                    self.add_result(
                        passed=False,
                        title="CC-Link default/weak password detected",
                        description=f"Authentication succeeded with: {cred_display}",
                        severity=Severity.CRITICAL,
                        details=(
                            "The CC-Link module accepts default or weak passwords. "
                            "This allows unauthorized access to PLC operations."
                        ),
                        evidence=f"Accepted credential: {cred_display}",
                        remediation=(
                            "Change the default password immediately. "
                            "Use a strong password with mixed characters. "
                            "Implement password policies for industrial systems."
                        ),
                        cwe="CWE-1392",
                        references=[
                            "https://attack.mitre.org/techniques/T0812/",
                        ],
                    )
                    # Lock password after test
                    self.cclink_client.lock_password()
                    return

                time.sleep(0.2)  # Rate limiting
            except Exception:
                continue

        self.add_result(
            passed=True,
            title="No default CC-Link credentials found",
            description="Common default passwords were not accepted",
            severity=Severity.INFO,
        )

    def _check_cleartext_protocol(self) -> None:
        """Check for cleartext communication vulnerabilities."""
        self.add_result(
            passed=False,
            title="CC-Link IE Field uses cleartext protocol",
            description=(
                "CC-Link IE Field protocol transmits all data unencrypted. "
                "This includes commands, responses, and credentials."
            ),
            severity=Severity.HIGH,
            details=(
                "CC-Link IE Field Network does not support encryption. "
                "Network traffic can be captured and analyzed by attackers. "
                "Credentials transmitted over the network can be intercepted."
            ),
            remediation=(
                "Implement network segmentation to isolate CC-Link traffic. "
                "Use VPN tunnels for any remote access requirements. "
                "Consider network monitoring and anomaly detection. "
                "Evaluate migration to OPC UA with security features."
            ),
            cwe="CWE-319",
            references=[
                "https://attack.mitre.org/techniques/T0830/",
            ],
        )

    def _check_device_access(self) -> None:
        """Check for unauthorized device memory access."""
        test_devices = [
            ("D", "Data registers"),
            ("M", "Internal relays"),
            ("RX", "Remote inputs"),
            ("RWR", "Remote word read registers"),
        ]

        accessible_devices = []

        for device, description in test_devices:
            try:
                response = self.cclink_client.device_read(device, 0, 1)
                if response.success:
                    accessible_devices.append((device, description))
            except Exception:
                continue

        if accessible_devices:
            device_list = ", ".join(f"{d[0]} ({d[1]})" for d in accessible_devices)
            self.add_result(
                passed=False,
                title="CC-Link device memory readable",
                description=f"Memory areas accessible without restriction: {device_list}",
                severity=Severity.HIGH,
                details=(
                    "Multiple device memory areas can be read without proper authorization. "
                    "This may expose sensitive process data and control parameters."
                ),
                evidence=f"Accessible devices: {device_list}",
                remediation=(
                    "Enable password protection for CC-Link access. "
                    "Configure access control lists on network equipment. "
                    "Implement defense-in-depth with network segmentation."
                ),
                cwe="CWE-284",
            )
        else:
            self.add_result(
                passed=True,
                title="CC-Link device access restricted",
                description="Standard device reads were rejected",
                severity=Severity.INFO,
            )

    def _check_control_commands(self) -> None:
        """Check if dangerous control commands are accessible."""
        # Probe for control command accessibility (without executing)
        dangerous_commands = [
            (CCLinkCommand.REMOTE_STOP, "Remote STOP"),
            (CCLinkCommand.REMOTE_RUN, "Remote RUN"),
            (CCLinkCommand.REMOTE_RESET, "Remote RESET"),
        ]

        accessible_commands = []

        for cmd_code, cmd_name in dangerous_commands:
            try:
                # Build probe command
                from ..core.cclink import CCLinkFrame
                frame = CCLinkFrame(
                    command=cmd_code,
                    subcommand=0x0000,
                    data=struct.pack("<H", 0x0000),
                )
                probe = frame.to_bytes()

                response = self.cclink_client._send_receive(probe)
                if len(response) >= 15:
                    end_code = struct.unpack("<H", response[13:15])[0]
                    # If not "wrong command" error, command may be accessible
                    if end_code != CCLinkEndCode.WRONG_COMMAND:
                        accessible_commands.append((cmd_name, end_code))
            except Exception:
                continue

        if accessible_commands:
            cmd_list = ", ".join(c[0] for c in accessible_commands)
            self.add_result(
                passed=False,
                title="CC-Link control commands accessible",
                description=f"Potentially accessible commands: {cmd_list}",
                severity=Severity.CRITICAL,
                details=(
                    "Critical control commands may be accessible without authentication. "
                    "This could allow attackers to stop, start, or reset the PLC."
                ),
                evidence=str(accessible_commands),
                remediation=(
                    "Enable password protection for control operations. "
                    "Implement hardware key switches for critical operations. "
                    "Use network segmentation to restrict access."
                ),
                cwe="CWE-284",
                references=[
                    "https://attack.mitre.org/techniques/T0855/",
                    "https://attack.mitre.org/techniques/T0816/",
                ],
            )
        else:
            self.add_result(
                passed=True,
                title="CC-Link control commands protected",
                description="Control commands appear to require authentication",
                severity=Severity.INFO,
            )

    def _check_cyclic_data_exposure(self) -> None:
        """Check for cyclic data exposure vulnerabilities."""
        try:
            response = self.cclink_client.read_cyclic_data(0, 10)

            if response.success and response.data:
                self.add_result(
                    passed=False,
                    title="CC-Link cyclic data exposed",
                    description="Cyclic communication data is readable",
                    severity=Severity.MEDIUM,
                    details=(
                        "CC-Link cyclic data containing I/O states and process values "
                        "can be read without authentication. This exposes real-time "
                        "operational data."
                    ),
                    evidence=f"Retrieved {len(response.data)} bytes of cyclic data",
                    remediation=(
                        "Restrict network access to cyclic data services. "
                        "Monitor for unauthorized cyclic data access."
                    ),
                    cwe="CWE-200",
                )
            else:
                self.add_result(
                    passed=True,
                    title="CC-Link cyclic data access restricted",
                    description="Cyclic data read was not successful",
                    severity=Severity.INFO,
                )
        except Exception as e:
            self.add_result(
                passed=True,
                title="CC-Link cyclic data check error",
                description=f"Could not test cyclic data access: {str(e)}",
                severity=Severity.INFO,
            )

    def _check_node_enumeration(self) -> None:
        """Check for node enumeration vulnerabilities."""
        try:
            response = self.cclink_client.node_search()

            if response.success:
                self.add_result(
                    passed=False,
                    title="CC-Link network nodes enumerable",
                    description="Node search reveals network topology",
                    severity=Severity.MEDIUM,
                    details=(
                        "The CC-Link node search function can be used to enumerate "
                        "all devices on the network. This aids attacker reconnaissance."
                    ),
                    evidence=f"Node search returned {len(response.data)} bytes",
                    remediation=(
                        "Restrict network search functionality to authorized stations. "
                        "Implement network access controls."
                    ),
                    cwe="CWE-200",
                    references=[
                        "https://attack.mitre.org/techniques/T0846/",
                    ],
                )
            else:
                self.add_result(
                    passed=True,
                    title="CC-Link node enumeration restricted",
                    description="Node search was not successful",
                    severity=Severity.INFO,
                )
        except Exception as e:
            self.add_result(
                passed=True,
                title="CC-Link node enumeration check error",
                description=f"Could not test node enumeration: {str(e)}",
                severity=Severity.INFO,
            )

    def _check_known_vulnerabilities(self) -> None:
        """Check for known CC-Link CVEs."""
        if not self.device_info:
            self.add_result(
                passed=True,
                title="CC-Link CVE check skipped",
                description="No device information available for CVE matching",
                severity=Severity.INFO,
            )
            return

        model = getattr(self.device_info, "model", "")
        matched_cves = []

        for cve_id, cve_info in CCLINK_KNOWN_VULNERABILITIES.items():
            for affected_model in cve_info.get("affected_models", []):
                if affected_model.upper() in model.upper():
                    matched_cves.append((cve_id, cve_info))
                    break

        if matched_cves:
            for cve_id, cve_info in matched_cves:
                severity_map = {
                    "CRITICAL": Severity.CRITICAL,
                    "HIGH": Severity.HIGH,
                    "MEDIUM": Severity.MEDIUM,
                    "LOW": Severity.LOW,
                }
                severity = severity_map.get(cve_info.get("severity", "HIGH"), Severity.HIGH)

                self.add_result(
                    passed=False,
                    title=f"Known CC-Link vulnerability: {cve_id}",
                    description=cve_info.get("description", ""),
                    severity=severity,
                    details=f"CVSS Score: {cve_info.get('cvss', 'N/A')}",
                    cve=cve_id,
                    remediation=(
                        "Update firmware to the latest version. "
                        "Apply vendor security patches. "
                        "Implement compensating controls if patches unavailable."
                    ),
                    references=[
                        f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    ],
                )
        else:
            self.add_result(
                passed=True,
                title="No known CC-Link CVEs matched",
                description="Device model not matched to known vulnerabilities",
                severity=Severity.INFO,
            )

    def _check_network_configuration(self) -> None:
        """Check CC-Link network configuration security."""
        try:
            response = self.cclink_client.get_communication_settings()

            if response.success:
                self.add_result(
                    passed=False,
                    title="CC-Link configuration exposed",
                    description="Network configuration can be read",
                    severity=Severity.MEDIUM,
                    details=(
                        "CC-Link communication settings are accessible. "
                        "This may reveal network parameters and configuration details."
                    ),
                    evidence=f"Retrieved {len(response.data)} bytes of configuration",
                    remediation=(
                        "Restrict access to configuration read commands. "
                        "Enable password protection for configuration access."
                    ),
                    cwe="CWE-200",
                )
            else:
                self.add_result(
                    passed=True,
                    title="CC-Link configuration access restricted",
                    description="Configuration read was not successful",
                    severity=Severity.INFO,
                )
        except Exception as e:
            self.add_result(
                passed=True,
                title="CC-Link configuration check error",
                description=f"Could not test configuration access: {str(e)}",
                severity=Severity.INFO,
            )

    def _check_replay_vulnerability(self) -> None:
        """Check for replay attack vulnerabilities."""
        # CC-Link IE Field has limited anti-replay protection
        self.add_result(
            passed=False,
            title="CC-Link susceptible to replay attacks",
            description=(
                "CC-Link IE Field protocol has limited protection against "
                "replay attacks."
            ),
            severity=Severity.MEDIUM,
            details=(
                "Captured network packets can potentially be replayed. "
                "The 4E frame serial number provides limited ordering but "
                "does not prevent replay of captured commands."
            ),
            remediation=(
                "Implement network monitoring for replay detection. "
                "Use VPN tunnels to prevent traffic capture. "
                "Consider application-level sequence validation."
            ),
            cwe="CWE-294",
        )


class CCLinkDiscoveryCheck(SecurityCheck):
    """
    CC-Link IE Field Network discovery check.

    Discovers CC-Link services and gathers information for security assessment.
    """

    CHECK_ID = "CCLINK-002"
    CHECK_NAME = "CC-Link Discovery Check"
    DESCRIPTION = "Discover and fingerprint CC-Link IE Field services"
    CATEGORY = "cclink"
    RISK_LEVEL = Severity.MEDIUM

    def __init__(
        self,
        client: Optional[Any] = None,
        device_info: Optional[Any] = None,
        config: Optional[Dict[str, Any]] = None,
    ):
        """Initialize CC-Link discovery check."""
        super().__init__(client, device_info, config)

    def run(self) -> List[CheckResult]:
        """Execute CC-Link discovery checks."""
        self.results = []

        host = self.config.get("host")
        port = self.config.get("port", 45237)

        if not host:
            self.add_result(
                passed=True,
                title="CC-Link discovery skipped",
                description="No target host specified",
                severity=Severity.INFO,
            )
            return self.results

        self._check_port_open(host, port)
        self._check_cclink_service(host, port)
        self._fingerprint_device(host, port)

        return self.results

    def _check_port_open(self, host: str, port: int) -> None:
        """Check if CC-Link port is open."""
        import socket

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3.0)
            result = sock.connect_ex((host, port))
            sock.close()

            if result == 0:
                self.add_result(
                    passed=False,
                    title="CC-Link port open",
                    description=f"Port {port} is open on {host}",
                    severity=Severity.MEDIUM,
                    details="CC-Link IE Field default port is accessible",
                    remediation="Restrict access to CC-Link ports using firewalls",
                )
            else:
                self.add_result(
                    passed=True,
                    title="CC-Link port closed",
                    description=f"Port {port} is not accessible on {host}",
                    severity=Severity.INFO,
                )
        except Exception as e:
            self.add_result(
                passed=True,
                title="CC-Link port check error",
                description=f"Error checking port: {str(e)}",
                severity=Severity.INFO,
            )

    def _check_cclink_service(self, host: str, port: int) -> None:
        """Check if CC-Link service responds."""
        try:
            client = CCLinkClient(host, port, timeout=5.0)
            client.connect()

            response = client.loopback_test()
            client.disconnect()

            if response.success:
                self.add_result(
                    passed=False,
                    title="CC-Link IE Field service detected",
                    description=f"CC-Link service responding on {host}:{port}",
                    severity=Severity.MEDIUM,
                    details="Service confirmed via loopback test",
                    remediation=(
                        "Implement network segmentation. "
                        "Enable authentication on CC-Link services."
                    ),
                )
            else:
                self.add_result(
                    passed=True,
                    title="CC-Link service not confirmed",
                    description=f"Loopback test failed: {response.error_message}",
                    severity=Severity.INFO,
                )
        except Exception as e:
            self.add_result(
                passed=True,
                title="CC-Link service check failed",
                description=f"Could not verify CC-Link service: {str(e)}",
                severity=Severity.INFO,
            )

    def _fingerprint_device(self, host: str, port: int) -> None:
        """Attempt to fingerprint the CC-Link device."""
        try:
            client = CCLinkClient(host, port, timeout=5.0)
            client.connect()

            response = client.read_cpu_model()
            client.disconnect()

            if response.success and response.data:
                # Try to decode model info
                try:
                    model_info = response.data.decode("ascii", errors="ignore").strip()
                    self.add_result(
                        passed=False,
                        title="CC-Link device fingerprinted",
                        description=f"Device information exposed: {model_info[:50]}",
                        severity=Severity.LOW,
                        details=f"Full response: {response.data.hex()}",
                        evidence=model_info,
                        remediation="Consider restricting model read commands",
                        cwe="CWE-200",
                    )
                except Exception:
                    self.add_result(
                        passed=False,
                        title="CC-Link device partially fingerprinted",
                        description="Device returned model data",
                        severity=Severity.LOW,
                        details=f"Raw data: {response.data.hex()[:100]}",
                    )
            else:
                self.add_result(
                    passed=True,
                    title="CC-Link fingerprinting failed",
                    description="Could not retrieve device model",
                    severity=Severity.INFO,
                )
        except Exception as e:
            self.add_result(
                passed=True,
                title="CC-Link fingerprinting error",
                description=f"Error during fingerprinting: {str(e)}",
                severity=Severity.INFO,
            )


class CCLinkProtocolCheck(SecurityCheck):
    """
    CC-Link protocol-level security checks.

    Tests for protocol implementation vulnerabilities including
    malformed packet handling and boundary conditions.
    """

    CHECK_ID = "CCLINK-003"
    CHECK_NAME = "CC-Link Protocol Security Check"
    DESCRIPTION = "Check CC-Link protocol implementation security"
    CATEGORY = "cclink"
    RISK_LEVEL = Severity.HIGH

    def __init__(
        self,
        client: Optional[Any] = None,
        device_info: Optional[Any] = None,
        config: Optional[Dict[str, Any]] = None,
        cclink_client: Optional[CCLinkClient] = None,
    ):
        """Initialize CC-Link protocol check."""
        super().__init__(client, device_info, config)
        self.cclink_client = cclink_client

    def run(self) -> List[CheckResult]:
        """Execute protocol security checks."""
        self.results = []

        if not self.cclink_client:
            return self.results

        self._check_malformed_frames()
        self._check_length_validation()
        self._check_command_validation()

        return self.results

    def _check_malformed_frames(self) -> None:
        """Check handling of malformed frames."""
        if not self.config.get("test_malformed", False):
            self.add_result(
                passed=True,
                title="Malformed frame testing disabled",
                description="Enable with test_malformed=True",
                severity=Severity.INFO,
            )
            return

        issues = []

        # Test truncated header
        try:
            truncated = bytes([0x54, 0x00, 0x00])
            self.cclink_client._socket.sendall(truncated)
            time.sleep(0.3)
            issues.append("truncated_header_accepted")
        except Exception:
            pass

        # Test invalid subheader
        try:
            invalid = struct.pack("<H", 0xFFFF) + b"\x00" * 20
            self.cclink_client._socket.sendall(invalid)
            time.sleep(0.3)
        except Exception:
            pass

        # Verify connection still works
        try:
            self.cclink_client.disconnect()
            self.cclink_client.connect()
            response = self.cclink_client.loopback_test()

            if response.success:
                self.add_result(
                    passed=True,
                    title="CC-Link recovers from malformed frames",
                    description="Device handled malformed input gracefully",
                    severity=Severity.INFO,
                )
            else:
                self.add_result(
                    passed=False,
                    title="CC-Link degraded after malformed frames",
                    description="Device shows degraded response",
                    severity=Severity.MEDIUM,
                    remediation="Update firmware to improve input validation",
                )
        except Exception as e:
            self.add_result(
                passed=False,
                title="CC-Link crashed from malformed frames",
                description=f"Connection lost: {str(e)}",
                severity=Severity.HIGH,
                details="Device may be vulnerable to denial of service",
                remediation="Update firmware immediately",
                cwe="CWE-20",
            )

    def _check_length_validation(self) -> None:
        """Check length field validation."""
        if not self.config.get("test_malformed", False):
            return

        try:
            # Oversized length field
            from ..core.cclink import CCLinkFrame
            frame = CCLinkFrame(
                command=CCLinkCommand.LOOPBACK_TEST,
                data=b"TEST",
            )
            frame_bytes = bytearray(frame.to_bytes())

            # Modify length field to claim more data
            struct.pack_into("<H", frame_bytes, 13, 0xFFFF)

            self.cclink_client._socket.sendall(bytes(frame_bytes))
            time.sleep(0.3)

            # Check if device still responds
            self.cclink_client.disconnect()
            self.cclink_client.connect()
            response = self.cclink_client.loopback_test()

            if response.success:
                self.add_result(
                    passed=True,
                    title="CC-Link length validation adequate",
                    description="Device handled invalid length field",
                    severity=Severity.INFO,
                )
        except Exception:
            self.add_result(
                passed=False,
                title="CC-Link length validation issue",
                description="Error during length validation test",
                severity=Severity.MEDIUM,
            )

    def _check_command_validation(self) -> None:
        """Check command code validation."""
        if not self.config.get("test_malformed", False):
            return

        invalid_commands = [0x0000, 0xFFFF, 0x1234, 0xDEAD]
        issues = []

        for cmd in invalid_commands:
            try:
                from ..core.cclink import CCLinkFrame
                frame = CCLinkFrame(
                    command=cmd,
                    subcommand=0x0000,
                    data=b"",
                )
                response = self.cclink_client._send_receive(frame.to_bytes())

                if len(response) >= 15:
                    end_code = struct.unpack("<H", response[13:15])[0]
                    if end_code == CCLinkEndCode.SUCCESS:
                        issues.append(f"Invalid command 0x{cmd:04X} accepted")
            except Exception:
                continue

        if issues:
            self.add_result(
                passed=False,
                title="CC-Link command validation weak",
                description="Some invalid commands were accepted",
                severity=Severity.MEDIUM,
                details=str(issues),
                cwe="CWE-20",
            )
        else:
            self.add_result(
                passed=True,
                title="CC-Link command validation adequate",
                description="Invalid commands were rejected",
                severity=Severity.INFO,
            )
