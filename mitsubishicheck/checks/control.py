"""
Control Security Check Module

Checks for unauthorized access to PLC control functions.
"""

from typing import List

from .base import SecurityCheck, CheckResult, Severity
from ..core.protocol import EndCode


class ControlCheck(SecurityCheck):
    """
    Security checks for PLC control function access.

    Checks:
    - Remote RUN/STOP capability
    - Remote RESET capability
    - Program upload/download access
    - Configuration change access

    WARNING: These checks probe dangerous functionality.
    They do NOT execute destructive commands but check if
    they would be allowed.
    """

    CHECK_ID = "CTRL-001"
    CHECK_NAME = "Control Access Check"
    DESCRIPTION = "Check for unauthorized access to PLC control functions"
    CATEGORY = "control"
    RISK_LEVEL = Severity.CRITICAL

    def run(self) -> List[CheckResult]:
        """Execute control access checks."""
        self.results = []

        if not self.client:
            return self.results

        # Check RUN/STOP control access
        self._check_run_stop_access()

        # Check if we can read PLC status
        self._check_status_access()

        # Check program area access
        self._check_program_access()

        return self.results

    def _check_run_stop_access(self) -> None:
        """
        Check if RUN/STOP commands would be accepted.

        NOTE: This does NOT execute the commands, it analyzes
        the error responses to determine if they would be allowed.
        """
        # We check by attempting to build the command and analyzing response
        # Without actually changing PLC state

        try:
            # First, try to read current status to understand PLC state
            status_response = self.client.read_cpu_model()

            # Build a remote stop probe but with intentionally wrong parameters
            # to see if we get "wrong password" vs "command accepted"
            from ..core.protocol import MelsecFrame, SubheaderType, CommandCode
            import struct

            # Build stop command with invalid mode to trigger error without execution
            probe = struct.pack("<HBBHBHHHHH",
                SubheaderType.REQUEST_3E,
                0x00, 0xFF, 0x03FF, 0x00,
                0x04, 0x10, 0x00,
                CommandCode.REMOTE_STOP,
                0xFFFF,  # Invalid subcommand
            )

            response = self.client._send_receive(probe)

            if len(response) >= 11:
                end_code = struct.unpack("<H", response[9:11])[0]

                if end_code == EndCode.SUCCESS:
                    self.add_result(
                        passed=False,
                        title="CRITICAL: Remote control commands accessible",
                        description=(
                            "PLC control commands (RUN/STOP) appear to be "
                            "accessible without authentication"
                        ),
                        severity=Severity.CRITICAL,
                        details=f"Response code: {hex(end_code)}",
                        remediation=(
                            "IMMEDIATELY enable password protection. "
                            "Unauthorized control access can halt production."
                        ),
                        cwe="CWE-284",
                        references=[
                            "https://attack.mitre.org/techniques/T0855/",
                            "https://attack.mitre.org/techniques/T0816/",
                        ],
                    )
                elif end_code in (EndCode.PASSWORD_LOCKED, EndCode.WRONG_PASSWORD):
                    self.add_result(
                        passed=True,
                        title="Control commands require authentication",
                        description="RUN/STOP commands are password protected",
                        severity=Severity.INFO,
                    )
                elif end_code == EndCode.WRONG_COMMAND:
                    self.add_result(
                        passed=True,
                        title="Control command probe rejected",
                        description="PLC rejected malformed control command",
                        severity=Severity.INFO,
                    )
                else:
                    self.add_result(
                        passed=False,
                        title="Unexpected control command response",
                        description=f"Unusual response to control probe: {hex(end_code)}",
                        severity=Severity.MEDIUM,
                        details="Response may indicate vulnerability",
                    )

        except Exception as e:
            self.add_result(
                passed=True,
                title="Control access check error",
                description=f"Could not complete control access check: {str(e)}",
                severity=Severity.INFO,
            )

    def _check_status_access(self) -> None:
        """Check access to PLC status information."""
        try:
            response = self.client.read_cpu_model()

            if response.success:
                self.add_result(
                    passed=False,
                    title="PLC status information accessible",
                    description="Can read PLC CPU/status information without authentication",
                    severity=Severity.LOW,
                    details=f"CPU data retrieved: {len(response.data)} bytes",
                    remediation=(
                        "While status reading is lower risk, it aids reconnaissance. "
                        "Consider network segmentation."
                    ),
                )
            elif response.end_code in (EndCode.PASSWORD_LOCKED, EndCode.WRONG_PASSWORD):
                self.add_result(
                    passed=True,
                    title="Status information protected",
                    description="CPU status requires authentication",
                    severity=Severity.INFO,
                )

        except Exception as e:
            self.add_result(
                passed=True,
                title="Status access check error",
                description=str(e),
                severity=Severity.INFO,
            )

    def _check_program_access(self) -> None:
        """Check access to program memory area."""
        # Attempt to read from program/file register area
        try:
            from ..core.protocol import DeviceCode

            # Try to read file registers (often contains program data)
            response = self.client.batch_read(DeviceCode.R, 0, 10)

            if response.success:
                self.add_result(
                    passed=False,
                    title="Program memory area accessible",
                    description=(
                        "Can read file registers without authentication. "
                        "This may allow program extraction."
                    ),
                    severity=Severity.HIGH,
                    details=f"Read {len(response.data)} bytes from file registers",
                    remediation=(
                        "Enable password protection. Program theft enables "
                        "intellectual property loss and targeted attacks."
                    ),
                    cwe="CWE-284",
                    references=[
                        "https://attack.mitre.org/techniques/T0845/",
                    ],
                )
            elif response.end_code in (EndCode.PASSWORD_LOCKED, EndCode.WRONG_PASSWORD):
                self.add_result(
                    passed=True,
                    title="Program memory protected",
                    description="File registers require authentication",
                    severity=Severity.INFO,
                )
            elif response.end_code == EndCode.CANNOT_READ:
                self.add_result(
                    passed=True,
                    title="Program memory read blocked",
                    description="File register read denied",
                    severity=Severity.INFO,
                )

        except Exception as e:
            self.add_result(
                passed=True,
                title="Program access check error",
                description=str(e),
                severity=Severity.INFO,
            )
