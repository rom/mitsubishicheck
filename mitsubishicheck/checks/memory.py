"""
Memory Access Security Check Module

Checks for unauthorized memory access vulnerabilities.
"""

from typing import List, Optional, Tuple

from .base import SecurityCheck, CheckResult, Severity
from ..core.protocol import DeviceCode, EndCode


class MemoryAccessCheck(SecurityCheck):
    """
    Security checks for memory access vulnerabilities.

    Checks:
    - Unauthorized memory read access
    - Unauthorized memory write access
    - Memory boundary violations
    - Sensitive memory area exposure
    - Program memory access
    """

    CHECK_ID = "MEM-001"
    CHECK_NAME = "Memory Access Check"
    DESCRIPTION = "Check for unauthorized memory access vulnerabilities"
    CATEGORY = "memory"
    RISK_LEVEL = Severity.HIGH

    # Memory areas to test (device_code, start, count, description, sensitivity)
    MEMORY_AREAS = [
        (DeviceCode.D, 0, 10, "Data registers (D0-D9)", "low"),
        (DeviceCode.D, 8000, 10, "Data registers (D8000-D8009)", "medium"),
        (DeviceCode.M, 0, 16, "Internal relays (M0-M15)", "low"),
        (DeviceCode.M, 8000, 16, "Special relays area (M8000+)", "high"),
        (DeviceCode.X, 0, 16, "Input bits (X0-X15)", "medium"),
        (DeviceCode.Y, 0, 16, "Output bits (Y0-Y15)", "high"),
        (DeviceCode.SM, 0, 16, "Special registers (SM0-SM15)", "high"),
        (DeviceCode.SD, 0, 10, "Special data registers", "high"),
    ]

    def run(self) -> List[CheckResult]:
        """Execute memory access checks."""
        self.results = []

        if not self.client:
            return self.results

        # Check read access to various memory areas
        self._check_read_access()

        # Check write access (non-destructive test)
        if self.config.get("test_write", False):
            self._check_write_access()

        # Check for memory boundary violations
        self._check_boundary_violations()

        # Check sensitive memory areas
        self._check_sensitive_areas()

        return self.results

    def _check_read_access(self) -> None:
        """Check read access to memory areas."""
        readable_areas = []
        protected_areas = []

        for device_code, start, count, desc, sensitivity in self.MEMORY_AREAS:
            try:
                response = self.client.batch_read(device_code, start, count)

                if response.success:
                    readable_areas.append((desc, sensitivity, response.data))
                elif response.end_code in (EndCode.PASSWORD_LOCKED, EndCode.WRONG_PASSWORD):
                    protected_areas.append(desc)
                elif response.end_code == EndCode.CANNOT_READ:
                    protected_areas.append(desc)

            except Exception:
                continue

        if readable_areas:
            high_sens = [a[0] for a in readable_areas if a[1] == "high"]
            med_sens = [a[0] for a in readable_areas if a[1] == "medium"]

            if high_sens:
                self.add_result(
                    passed=False,
                    title="High-sensitivity memory areas readable",
                    description=(
                        f"Can read high-sensitivity areas without authorization: "
                        f"{', '.join(high_sens)}"
                    ),
                    severity=Severity.CRITICAL,
                    details=f"Readable areas: {[a[0] for a in readable_areas]}",
                    remediation=(
                        "Enable password protection and restrict access to "
                        "sensitive memory areas."
                    ),
                    cwe="CWE-284",
                )
            elif med_sens:
                self.add_result(
                    passed=False,
                    title="Medium-sensitivity memory areas readable",
                    description=(
                        f"Can read medium-sensitivity areas: {', '.join(med_sens)}"
                    ),
                    severity=Severity.MEDIUM,
                    details=f"Readable areas: {[a[0] for a in readable_areas]}",
                    remediation="Review access controls for these memory areas.",
                    cwe="CWE-284",
                )
            else:
                self.add_result(
                    passed=False,
                    title="Memory areas accessible",
                    description=f"Some memory areas are readable: {[a[0] for a in readable_areas]}",
                    severity=Severity.LOW,
                    remediation="Ensure only necessary areas are accessible.",
                )
        else:
            self.add_result(
                passed=True,
                title="Memory read access properly restricted",
                description="Could not read memory areas without authorization",
                severity=Severity.INFO,
            )

    def _check_write_access(self) -> None:
        """
        Check write access (non-destructive).

        WARNING: This test writes and restores values. Use with caution.
        """
        # Only test on a safe data register
        test_address = self.config.get("write_test_address", 9999)
        test_device = DeviceCode.D

        try:
            # Read current value
            read_resp = self.client.batch_read(test_device, test_address, 1)

            if not read_resp.success:
                self.add_result(
                    passed=True,
                    title="Write test skipped - cannot read test address",
                    description="Could not read test address to perform safe write test",
                    severity=Severity.INFO,
                )
                return

            original_value = read_resp.words[0] if read_resp.words else 0

            # Attempt write with different value
            test_value = (original_value + 1) & 0xFFFF
            write_resp = self.client.batch_write(test_device, test_address, [test_value])

            if write_resp.success:
                # Restore original value
                self.client.batch_write(test_device, test_address, [original_value])

                self.add_result(
                    passed=False,
                    title="Unauthorized write access possible",
                    description="Can write to PLC memory without proper authorization",
                    severity=Severity.CRITICAL,
                    details=f"Successfully wrote to D{test_address}",
                    remediation=(
                        "Enable password protection and restrict write access. "
                        "This vulnerability allows attackers to modify PLC logic and data."
                    ),
                    cwe="CWE-284",
                    references=[
                        "https://attack.mitre.org/techniques/T0821/",
                    ],
                )
            else:
                self.add_result(
                    passed=True,
                    title="Write access restricted",
                    description="Cannot write to memory without authorization",
                    severity=Severity.INFO,
                    details=f"Write error: {write_resp.error_message}",
                )

        except Exception as e:
            self.add_result(
                passed=True,
                title="Write access test error",
                description=f"Write test could not complete: {str(e)}",
                severity=Severity.INFO,
            )

    def _check_boundary_violations(self) -> None:
        """Check for memory boundary violation vulnerabilities."""
        # Test reading beyond normal boundaries
        test_cases = [
            (DeviceCode.D, 0, 10000, "Large read request"),
            (DeviceCode.D, 65535, 100, "Read near max address"),
            (DeviceCode.M, 0, 65535, "Maximum relay read"),
        ]

        boundary_issues = []

        for device_code, start, count, desc in test_cases:
            try:
                response = self.client.batch_read(device_code, start, count)

                if response.success:
                    boundary_issues.append(desc)
                elif response.end_code == EndCode.LENGTH_EXCEEDED:
                    # Expected behavior - length properly checked
                    pass
                elif response.end_code == EndCode.DEVICE_RANGE_ERROR:
                    # Expected behavior - range properly checked
                    pass

            except Exception:
                continue

        if boundary_issues:
            self.add_result(
                passed=False,
                title="Memory boundary issues detected",
                description=f"Large or boundary memory requests accepted: {boundary_issues}",
                severity=Severity.MEDIUM,
                details=str(boundary_issues),
                remediation="Unusual, may indicate firmware issues.",
                cwe="CWE-119",
            )
        else:
            self.add_result(
                passed=True,
                title="Memory boundaries properly enforced",
                description="Invalid memory access requests are rejected",
                severity=Severity.INFO,
            )

    def _check_sensitive_areas(self) -> None:
        """Check access to known sensitive memory areas."""
        # Special/system areas that shouldn't be accessible
        sensitive_checks = [
            (DeviceCode.SM, 0, 100, "System relays (SM)"),
            (DeviceCode.SD, 0, 100, "System data (SD)"),
        ]

        exposed = []

        for device_code, start, count, desc in sensitive_checks:
            try:
                response = self.client.batch_read(device_code, start, count)
                if response.success and response.data:
                    exposed.append({
                        "area": desc,
                        "data_sample": response.data[:20].hex(),
                    })
            except Exception:
                continue

        if exposed:
            self.add_result(
                passed=False,
                title="System memory areas exposed",
                description="Sensitive system memory areas are readable",
                severity=Severity.HIGH,
                details=str(exposed),
                evidence=str([e["area"] for e in exposed]),
                remediation=(
                    "System memory areas contain sensitive diagnostic and "
                    "configuration data. Restrict access via password protection."
                ),
                cwe="CWE-200",
            )
