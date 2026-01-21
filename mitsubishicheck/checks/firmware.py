"""
Firmware Security Check Module

Checks for firmware-related vulnerabilities and version issues.
"""

import re
from typing import List, Dict, Any

from .base import SecurityCheck, CheckResult, Severity
from ..core.device import KNOWN_VULNERABLE_VERSIONS


class FirmwareCheck(SecurityCheck):
    """
    Security checks for firmware vulnerabilities.

    Checks:
    - Outdated firmware versions
    - Known vulnerable firmware
    - Firmware version disclosure
    - End-of-life firmware
    """

    CHECK_ID = "FW-001"
    CHECK_NAME = "Firmware Check"
    DESCRIPTION = "Check for firmware vulnerabilities and version issues"
    CATEGORY = "firmware"
    RISK_LEVEL = Severity.HIGH

    # Known end-of-life models
    EOL_MODELS = [
        r"A\d[A-Z]",  # A-series
        r"AnS",  # AnS series
        r"QnA",  # QnA series
        r"FX[0-2]",  # Older FX series
    ]

    # Firmware version patterns
    VERSION_PATTERNS = {
        "Q_series": r"(\d{2})(\d{3})",  # e.g., "07135" -> major 07, minor 135
        "iQ_R_series": r"(\d{2})",  # e.g., "05"
        "FX_series": r"(\d+\.\d+)",  # e.g., "1.20"
    }

    def run(self) -> List[CheckResult]:
        """Execute firmware checks."""
        self.results = []

        if not self.client:
            return self.results

        # Get device info
        device_info = self.device_info
        if not device_info:
            try:
                device_info = self.client.get_device_info()
            except Exception:
                self.add_result(
                    passed=True,
                    title="Could not retrieve firmware information",
                    description="Unable to gather device information for firmware check",
                    severity=Severity.INFO,
                )
                return self.results

        # Check for known vulnerable versions
        self._check_known_vulnerabilities(device_info)

        # Check for end-of-life models
        self._check_eol_models(device_info)

        # Check firmware version disclosure
        self._check_version_disclosure(device_info)

        # Check for recommended updates
        self._check_update_recommendations(device_info)

        return self.results

    def _check_known_vulnerabilities(self, device_info) -> None:
        """Check if firmware has known vulnerabilities."""
        model = device_info.model or device_info.cpu_type
        if not model:
            return

        for vuln_model, vuln_info in KNOWN_VULNERABLE_VERSIONS.items():
            if vuln_model.lower() in model.lower():
                cves = vuln_info.get("cves", [])
                versions = vuln_info.get("versions", [])

                self.add_result(
                    passed=False,
                    title=f"Known vulnerabilities for {vuln_model}",
                    description=(
                        f"Model {model} has known security vulnerabilities. "
                        f"Affected versions: {', '.join(versions)}"
                    ),
                    severity=Severity.CRITICAL,
                    details=f"CVEs: {', '.join(cves)}",
                    evidence=f"Detected model: {model}",
                    cve=cves[0] if cves else None,
                    remediation=(
                        "Update firmware to the latest version. "
                        "Check Mitsubishi security advisories for patches."
                    ),
                    references=[
                        f"https://nvd.nist.gov/vuln/detail/{cve}"
                        for cve in cves
                    ],
                )
                return

        self.add_result(
            passed=True,
            title="No known firmware vulnerabilities",
            description=f"Model {model} has no known vulnerabilities in our database",
            severity=Severity.INFO,
        )

    def _check_eol_models(self, device_info) -> None:
        """Check if model is end-of-life."""
        model = device_info.model or ""

        for pattern in self.EOL_MODELS:
            if re.search(pattern, model, re.IGNORECASE):
                self.add_result(
                    passed=False,
                    title="End-of-life PLC model detected",
                    description=(
                        f"Model {model} appears to be an older/EOL series. "
                        "These may no longer receive security updates."
                    ),
                    severity=Severity.HIGH,
                    details=f"Model matches EOL pattern: {pattern}",
                    remediation=(
                        "Consider upgrading to a supported PLC model. "
                        "Implement additional network security controls "
                        "if replacement is not possible."
                    ),
                    cwe="CWE-1104",
                    references=[
                        "https://www.mitsubishielectric.com/fa/products/cnt/plc/",
                    ],
                )
                return

        self.add_result(
            passed=True,
            title="Model appears to be current",
            description="PLC model does not match known EOL patterns",
            severity=Severity.INFO,
        )

    def _check_version_disclosure(self, device_info) -> None:
        """Check for detailed version information disclosure."""
        disclosed = []

        if device_info.firmware_version:
            disclosed.append(f"Firmware: {device_info.firmware_version}")
        if device_info.model:
            disclosed.append(f"Model: {device_info.model}")
        if device_info.cpu_type:
            disclosed.append(f"CPU: {device_info.cpu_type}")
        if device_info.serial_number:
            disclosed.append(f"Serial: {device_info.serial_number}")

        if len(disclosed) >= 2:
            self.add_result(
                passed=False,
                title="Detailed version information disclosed",
                description=(
                    "PLC exposes detailed identification information "
                    "that could aid targeted attacks"
                ),
                severity=Severity.LOW,
                details="\n".join(disclosed),
                remediation=(
                    "This information disclosure is often necessary for "
                    "engineering tools. Ensure network segmentation "
                    "prevents unauthorized reconnaissance."
                ),
                cwe="CWE-200",
            )

    def _check_update_recommendations(self, device_info) -> None:
        """Provide update recommendations based on model."""
        series = device_info.series

        recommendations = {
            "MELSEC-Q Series": (
                "Consider upgrading to iQ-R series for improved security features "
                "including enhanced authentication and encrypted communications."
            ),
            "MELSEC-A Series": (
                "A-series PLCs lack modern security features. "
                "Strongly recommend upgrading to iQ-R or iQ-F series."
            ),
            "FX Series": (
                "Ensure you're using FX5 series for best security. "
                "Older FX series have limited security capabilities."
            ),
        }

        if series and series.value in recommendations:
            self.add_result(
                passed=False,
                title="Security upgrade recommended",
                description=recommendations[series.value],
                severity=Severity.MEDIUM,
                details=f"Current series: {series.value}",
                remediation=recommendations[series.value],
            )
