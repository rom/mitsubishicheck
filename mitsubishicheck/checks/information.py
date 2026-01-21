"""
Information Disclosure Security Check Module

Checks for sensitive information disclosure vulnerabilities.
"""

from typing import List, Dict, Any

from .base import SecurityCheck, CheckResult, Severity
from ..core.protocol import DeviceCode


class InformationDisclosureCheck(SecurityCheck):
    """
    Security checks for information disclosure vulnerabilities.

    Checks:
    - Device identification disclosure
    - Network configuration disclosure
    - Error message information leakage
    - Memory content disclosure
    - Timing-based information leakage
    """

    CHECK_ID = "INFO-001"
    CHECK_NAME = "Information Disclosure Check"
    DESCRIPTION = "Check for sensitive information disclosure"
    CATEGORY = "information"
    RISK_LEVEL = Severity.MEDIUM

    def run(self) -> List[CheckResult]:
        """Execute information disclosure checks."""
        self.results = []

        if not self.client:
            return self.results

        # Check device identification disclosure
        self._check_device_id_disclosure()

        # Check special register disclosure
        self._check_special_register_disclosure()

        # Check error message disclosure
        self._check_error_disclosure()

        # Check for sensitive data in memory
        self._check_memory_disclosure()

        return self.results

    def _check_device_id_disclosure(self) -> None:
        """Check for device identification information disclosure."""
        disclosed_info = {}

        try:
            response = self.client.read_cpu_model()
            if response.success and response.data:
                disclosed_info["cpu_model"] = response.data.decode("ascii", errors="ignore").strip("\x00")
        except Exception:
            pass

        try:
            # Try to read system data registers
            response = self.client.batch_read(DeviceCode.SD, 0, 50)
            if response.success and response.data:
                disclosed_info["system_data"] = response.data[:100].hex()
        except Exception:
            pass

        if disclosed_info:
            self.add_result(
                passed=False,
                title="Device identification information disclosed",
                description="PLC reveals identification data without authentication",
                severity=Severity.LOW,
                details=str(disclosed_info),
                evidence=f"Disclosed: {list(disclosed_info.keys())}",
                remediation=(
                    "While device ID is often needed, ensure network "
                    "segmentation prevents unauthorized reconnaissance."
                ),
                cwe="CWE-200",
            )
        else:
            self.add_result(
                passed=True,
                title="Device identification protected",
                description="Could not retrieve device ID without authentication",
                severity=Severity.INFO,
            )

    def _check_special_register_disclosure(self) -> None:
        """Check disclosure of special/system registers."""
        special_areas = [
            (DeviceCode.SM, 0, 100, "Special relays"),
            (DeviceCode.SD, 0, 100, "Special data registers"),
        ]

        disclosed = []

        for device_code, start, count, name in special_areas:
            try:
                response = self.client.batch_read(device_code, start, count)
                if response.success and response.data:
                    # Check if data contains potentially sensitive info
                    non_zero = sum(1 for b in response.data if b != 0)
                    if non_zero > 0:
                        disclosed.append({
                            "area": name,
                            "non_zero_bytes": non_zero,
                            "sample": response.data[:20].hex(),
                        })
            except Exception:
                continue

        if disclosed:
            self.add_result(
                passed=False,
                title="Special registers accessible",
                description=(
                    "System/special registers are readable. These may contain "
                    "diagnostic information useful for attacks."
                ),
                severity=Severity.MEDIUM,
                details=str(disclosed),
                evidence=f"Accessible: {[d['area'] for d in disclosed]}",
                remediation=(
                    "Special registers contain system state, error counts, "
                    "and configuration. Restrict access via authentication."
                ),
                cwe="CWE-200",
            )

    def _check_error_disclosure(self) -> None:
        """Check for verbose error message disclosure."""
        # Send various invalid requests and analyze error responses
        error_details = []

        test_cases = [
            ("invalid_device", DeviceCode.D, 999999, 10),
            ("large_read", DeviceCode.D, 0, 65535),
            ("negative_addr", DeviceCode.D, -1, 1),
        ]

        for test_name, device, addr, count in test_cases:
            try:
                response = self.client.batch_read(device, addr & 0xFFFFFF, count)
                # Only consider actual PLC error responses, not client-side parsing failures
                # end_code == -1 indicates a parsing error (e.g., response too short),
                # which is not information disclosure from the PLC
                if not response.success and response.error_message and response.end_code >= 0:
                    error_details.append({
                        "test": test_name,
                        "error_code": hex(response.end_code),
                        "message": response.error_message,
                    })
            except Exception:
                continue

        if error_details:
            # Check if errors reveal too much
            verbose_errors = [e for e in error_details if len(e.get("message", "")) > 20]

            if verbose_errors:
                self.add_result(
                    passed=False,
                    title="Verbose error messages disclosed",
                    description="Error responses contain detailed information",
                    severity=Severity.LOW,
                    details=str(verbose_errors),
                    remediation=(
                        "Detailed errors aid debugging but also attackers. "
                        "This is inherent to the protocol."
                    ),
                    cwe="CWE-209",
                )
            else:
                self.add_result(
                    passed=True,
                    title="Error messages appropriately minimal",
                    description="Error responses don't reveal excessive detail",
                    severity=Severity.INFO,
                )

    def _check_memory_disclosure(self) -> None:
        """Check for sensitive data in accessible memory."""
        # Scan data registers for potential sensitive patterns
        sensitive_patterns = {
            "ip_address": b"\xc0\xa8",  # 192.168.x.x prefix
            "null_terminated": b"\x00\x00\x00\x00",
            "password_hint": b"pass",
        }

        findings = []

        # Scan common data register ranges
        scan_ranges = [
            (0, 100),
            (1000, 100),
            (8000, 100),
        ]

        for start, count in scan_ranges:
            try:
                response = self.client.batch_read(DeviceCode.D, start, count)
                if response.success and response.data:
                    data = response.data

                    # Check for ASCII strings (potential config data)
                    ascii_strings = self._extract_ascii_strings(data)
                    if ascii_strings:
                        findings.append({
                            "range": f"D{start}-D{start+count}",
                            "strings": ascii_strings[:5],  # Limit output
                        })

            except Exception:
                continue

        if findings:
            self.add_result(
                passed=False,
                title="Readable memory contains strings",
                description=(
                    "Data registers contain ASCII strings that may be "
                    "configuration data, names, or credentials."
                ),
                severity=Severity.MEDIUM,
                details=str(findings),
                remediation=(
                    "Review what data is stored in accessible registers. "
                    "Avoid storing credentials or sensitive config in plain text."
                ),
                cwe="CWE-312",
            )

    @staticmethod
    def _extract_ascii_strings(data: bytes, min_length: int = 4) -> List[str]:
        """Extract printable ASCII strings from binary data."""
        strings = []
        current = []

        for byte in data:
            if 32 <= byte < 127:  # Printable ASCII
                current.append(chr(byte))
            else:
                if len(current) >= min_length:
                    strings.append("".join(current))
                current = []

        if len(current) >= min_length:
            strings.append("".join(current))

        return strings
