"""
Protocol Security Check Module

Checks for protocol-level security vulnerabilities.
"""

import struct
import time
from typing import List, Optional

from .base import SecurityCheck, CheckResult, Severity
from ..core.protocol import SubheaderType, CommandCode


class ProtocolCheck(SecurityCheck):
    """
    Security checks for MELSEC protocol vulnerabilities.

    Checks:
    - Protocol version vulnerabilities
    - Malformed packet handling
    - Command injection
    - Replay attack susceptibility
    - Cleartext communication
    """

    CHECK_ID = "PROTO-001"
    CHECK_NAME = "Protocol Security Check"
    DESCRIPTION = "Check for MELSEC protocol security vulnerabilities"
    CATEGORY = "protocol"
    RISK_LEVEL = Severity.HIGH

    def run(self) -> List[CheckResult]:
        """Execute protocol checks."""
        self.results = []

        if not self.client:
            return self.results

        # Check for cleartext communication
        self._check_cleartext_communication()

        # Check malformed packet handling
        self._check_malformed_packets()

        # Check for dangerous commands
        self._check_dangerous_commands()

        # Check replay attack susceptibility
        self._check_replay_susceptibility()

        # Check protocol frame support
        self._check_frame_support()

        return self.results

    def _check_cleartext_communication(self) -> None:
        """Check if communication is in cleartext."""
        # MELSEC protocol is inherently cleartext
        self.add_result(
            passed=False,
            title="Cleartext communication protocol",
            description=(
                "MELSEC protocol transmits all data including passwords in cleartext. "
                "Network sniffing can capture sensitive information."
            ),
            severity=Severity.HIGH,
            details=(
                "Standard MELSEC MC Protocol does not support encryption. "
                "All commands, responses, and credentials are transmitted unencrypted."
            ),
            remediation=(
                "Use VPN or encrypted tunnels for remote access. "
                "Implement network segmentation to isolate PLC traffic. "
                "Consider newer protocols with encryption support (OPC UA Secure)."
            ),
            cwe="CWE-319",
            references=[
                "https://attack.mitre.org/techniques/T0830/",
            ],
        )

    def _check_malformed_packets(self) -> None:
        """Check handling of malformed packets."""
        malformed_tests = []

        # Test 1: Truncated header
        try:
            truncated = bytes([0x50, 0x00, 0x00])  # Incomplete 3E header
            self.client._socket.sendall(truncated)
            time.sleep(0.5)
            # If we get here without error, device may be vulnerable
            malformed_tests.append("truncated_header")
        except Exception:
            pass

        # Test 2: Invalid subheader
        try:
            invalid_header = struct.pack("<HBBHBHHH",
                0xFFFF,  # Invalid subheader
                0x00, 0xFF, 0x03FF, 0x00,
                0x04, 0x10, 0x00
            )
            self.client._socket.sendall(invalid_header)
            time.sleep(0.5)
        except Exception:
            pass

        # Test 3: Oversized length field
        try:
            oversized = struct.pack("<HBBHBH",
                SubheaderType.REQUEST_3E,
                0x00, 0xFF, 0x03FF, 0x00,
                0xFFFF,  # Max length
            ) + b"\x00" * 10
            self.client._socket.sendall(oversized)
            time.sleep(0.5)
        except Exception:
            pass

        # Reconnect after tests
        try:
            self.client.disconnect()
            self.client.connect()
            response = self.client.loopback_test()

            if response.success:
                self.add_result(
                    passed=True,
                    title="Device recovers from malformed packets",
                    description="PLC recovered after receiving malformed packets",
                    severity=Severity.INFO,
                )
            else:
                self.add_result(
                    passed=False,
                    title="Device affected by malformed packets",
                    description="PLC shows degraded response after malformed packets",
                    severity=Severity.MEDIUM,
                    remediation="May indicate DoS vulnerability - update firmware.",
                )
        except Exception as e:
            self.add_result(
                passed=False,
                title="Device crashed from malformed packets",
                description=f"Connection lost after malformed packet tests: {str(e)}",
                severity=Severity.HIGH,
                details="Device may be vulnerable to denial of service",
                remediation="Update firmware and implement input filtering.",
                cwe="CWE-20",
            )

    def _check_dangerous_commands(self) -> None:
        """Check if dangerous commands are accessible."""
        dangerous_commands = [
            (CommandCode.REMOTE_STOP, "Remote STOP", Severity.CRITICAL),
            (CommandCode.REMOTE_RUN, "Remote RUN", Severity.CRITICAL),
            (CommandCode.REMOTE_RESET, "Remote RESET", Severity.CRITICAL),
            (CommandCode.DEVICE_MEMORY_CLEAR, "Memory Clear", Severity.CRITICAL),
        ]

        accessible_commands = []

        for cmd_code, cmd_name, severity in dangerous_commands:
            # Build a probe command (won't execute, just checks response)
            probe = struct.pack("<HBBHBHHHH",
                SubheaderType.REQUEST_3E,
                0x00, 0xFF, 0x03FF, 0x00,
                0x06, 0x10, 0x00,
                cmd_code,
                0x0000,
            ) + struct.pack("<H", 0x0000)

            try:
                response = self.client._send_receive(probe)
                # Parse response to check if command was recognized
                if len(response) >= 11:
                    end_code = struct.unpack("<H", response[9:11])[0]
                    # If not "wrong command" error, command might be accessible
                    if end_code != 0xC059:  # Not "wrong command"
                        accessible_commands.append((cmd_name, end_code))
            except Exception:
                continue

        if accessible_commands:
            cmd_list = ", ".join(c[0] for c in accessible_commands)
            self.add_result(
                passed=False,
                title="Dangerous commands potentially accessible",
                description=f"Commands that may be accessible: {cmd_list}",
                severity=Severity.CRITICAL,
                details=str(accessible_commands),
                remediation=(
                    "Enable password protection to restrict access to "
                    "dangerous commands like STOP, RUN, and RESET."
                ),
                cwe="CWE-284",
                references=[
                    "https://attack.mitre.org/techniques/T0855/",
                ],
            )
        else:
            self.add_result(
                passed=True,
                title="Dangerous commands not immediately accessible",
                description="Control commands appear to be protected",
                severity=Severity.INFO,
            )

    def _check_replay_susceptibility(self) -> None:
        """Check for replay attack vulnerability."""
        # MELSEC protocol has no anti-replay mechanisms
        self.add_result(
            passed=False,
            title="Protocol susceptible to replay attacks",
            description=(
                "MELSEC protocol has no sequence numbers, timestamps, or "
                "cryptographic protection against replay attacks."
            ),
            severity=Severity.MEDIUM,
            details=(
                "An attacker capturing network traffic can replay commands. "
                "This includes captured authentication and control commands."
            ),
            remediation=(
                "Implement network monitoring for duplicate/replayed commands. "
                "Use encrypted VPN tunnels to prevent traffic capture."
            ),
            cwe="CWE-294",
        )

    def _check_frame_support(self) -> None:
        """Check which protocol frames are supported."""
        supported_frames = []

        # Test 3E frame
        try:
            response = self.client.loopback_test()
            if response.success:
                supported_frames.append("3E")
        except Exception:
            pass

        # Report findings
        if supported_frames:
            self.add_result(
                passed=True,
                title="Protocol frame detection",
                description=f"Supported frames: {', '.join(supported_frames)}",
                severity=Severity.INFO,
                details=(
                    "3E frame: Standard QnA-compatible frame\n"
                    "4E frame: Enhanced frame with serial numbers (iQ-R)"
                ),
            )


class FuzzingCheck(SecurityCheck):
    """
    Protocol fuzzing security check.

    WARNING: This check may cause device instability.
    Only run with explicit authorization.
    """

    CHECK_ID = "FUZZ-001"
    CHECK_NAME = "Protocol Fuzzing"
    DESCRIPTION = "Fuzz test MELSEC protocol for vulnerabilities"
    CATEGORY = "fuzzing"
    RISK_LEVEL = Severity.HIGH

    def run(self) -> List[CheckResult]:
        """Execute fuzzing checks."""
        self.results = []

        if not self.config.get("enable_fuzzing", False):
            self.add_result(
                passed=True,
                title="Fuzzing disabled",
                description="Protocol fuzzing is disabled by default for safety",
                severity=Severity.INFO,
                details="Enable with --fuzz flag if authorized",
            )
            return self.results

        if not self.client:
            return self.results

        # Run limited fuzzing tests
        self._fuzz_command_codes()
        self._fuzz_data_lengths()

        return self.results

    def _fuzz_command_codes(self) -> None:
        """Fuzz command code field."""
        crashes = []
        errors = []

        test_codes = [0x0000, 0xFFFF, 0x1234, 0x9999, 0xDEAD]

        for code in test_codes:
            try:
                probe = struct.pack("<HBBHBHHHH",
                    SubheaderType.REQUEST_3E,
                    0x00, 0xFF, 0x03FF, 0x00,
                    0x04, 0x10, 0x00,
                    code,
                    0x0000,
                )
                response = self.client._send_receive(probe, recv_size=256)
                if len(response) >= 11:
                    end_code = struct.unpack("<H", response[9:11])[0]
                    errors.append((code, end_code))
            except Exception as e:
                crashes.append((code, str(e)))

        if crashes:
            self.add_result(
                passed=False,
                title="Command code fuzzing caused errors",
                description="Some fuzzed command codes caused connection issues",
                severity=Severity.MEDIUM,
                details=str(crashes),
            )

    def _fuzz_data_lengths(self) -> None:
        """Fuzz data length field."""
        test_lengths = [0, 1, 0xFF, 0xFFFF, 0x1000]
        issues = []

        for length in test_lengths:
            try:
                probe = struct.pack("<HBBHBH",
                    SubheaderType.REQUEST_3E,
                    0x00, 0xFF, 0x03FF, 0x00,
                    length,
                )
                # Add minimal data
                probe += b"\x10\x00" + b"\x00" * min(length, 10)

                self.client._socket.sendall(probe)
                time.sleep(0.1)
            except Exception as e:
                issues.append((length, str(e)))

        if issues:
            self.add_result(
                passed=False,
                title="Length field fuzzing issues",
                description="Malformed length fields caused errors",
                severity=Severity.LOW,
                details=str(issues),
            )
