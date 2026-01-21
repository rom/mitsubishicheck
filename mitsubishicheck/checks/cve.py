"""
CVE Check Module

Checks for known CVE vulnerabilities in Mitsubishi PLCs.
"""

import re
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

from .base import SecurityCheck, CheckResult, Severity


@dataclass
class CVEEntry:
    """CVE vulnerability entry."""
    cve_id: str
    title: str
    description: str
    severity: Severity
    affected_products: List[str]
    affected_versions: List[str]
    cvss_score: Optional[float] = None
    remediation: str = ""
    references: List[str] = None

    def __post_init__(self):
        if self.references is None:
            self.references = [f"https://nvd.nist.gov/vuln/detail/{self.cve_id}"]


# Database of known Mitsubishi PLC CVEs
CVE_DATABASE: List[CVEEntry] = [
    CVEEntry(
        cve_id="CVE-2022-25164",
        title="iQ-R Series Authentication Bypass",
        description=(
            "Authentication bypass vulnerability in MELSEC iQ-R Series CPU modules "
            "allows remote attackers to bypass authentication and access the PLC."
        ),
        severity=Severity.CRITICAL,
        affected_products=["R08SFCPU", "R16SFCPU", "R32SFCPU", "R120SFCPU"],
        affected_versions=["firmware <= 05"],
        cvss_score=9.8,
        remediation="Update firmware to version 06 or later.",
        references=[
            "https://nvd.nist.gov/vuln/detail/CVE-2022-25164",
            "https://www.mitsubishielectric.com/en/psirt/vulnerability/",
        ],
    ),
    CVEEntry(
        cve_id="CVE-2021-20594",
        title="MELSEC iQ-R/iQ-F Denial of Service",
        description=(
            "Improper handling of malformed packets in MELSEC iQ-R and iQ-F series "
            "can cause denial of service condition."
        ),
        severity=Severity.HIGH,
        affected_products=["R00CPU", "R01CPU", "R02CPU", "FX5UCPU"],
        affected_versions=["Various"],
        cvss_score=7.5,
        remediation="Apply vendor patches and implement network filtering.",
    ),
    CVEEntry(
        cve_id="CVE-2020-5527",
        title="MELSEC Q Series Uncontrolled Resource Consumption",
        description=(
            "Resource exhaustion vulnerability in MELSEC Q series allows "
            "denial of service via specially crafted packets."
        ),
        severity=Severity.HIGH,
        affected_products=["Q03UDECPU", "Q04UDEHCPU", "Q06UDEHCPU"],
        affected_versions=["firmware <= 07135"],
        cvss_score=7.5,
        remediation="Update to latest firmware version.",
    ),
    CVEEntry(
        cve_id="CVE-2020-5528",
        title="MELSEC Q Series Improper Input Validation",
        description=(
            "Improper input validation in MELSEC Q series CPU modules "
            "allows remote code execution."
        ),
        severity=Severity.CRITICAL,
        affected_products=["Q03UDECPU", "Q04UDEHCPU", "Q06UDEHCPU", "Q13UDEHCPU"],
        affected_versions=["firmware <= 07135"],
        cvss_score=9.8,
        remediation="Update firmware and implement network segmentation.",
    ),
    CVEEntry(
        cve_id="CVE-2020-5529",
        title="MELSEC Communication Protocol Vulnerability",
        description=(
            "MELSEC Communication Protocol (MELSOFT) lacks proper authentication, "
            "allowing unauthorized access to PLC functions."
        ),
        severity=Severity.HIGH,
        affected_products=["Q Series", "L Series", "iQ-R Series"],
        affected_versions=["All versions without enhanced security"],
        cvss_score=8.6,
        remediation="Enable authentication features and use network segmentation.",
    ),
    CVEEntry(
        cve_id="CVE-2019-10976",
        title="MELSEC Q Series Buffer Overflow",
        description=(
            "Buffer overflow in MELSEC Q Series Ethernet modules allows "
            "remote attackers to execute arbitrary code."
        ),
        severity=Severity.CRITICAL,
        affected_products=["QJ71E71-100"],
        affected_versions=["All versions"],
        cvss_score=9.8,
        remediation="Replace with newer module or implement strict network controls.",
    ),
    CVEEntry(
        cve_id="CVE-2018-16059",
        title="MELSEC Q Series Information Disclosure",
        description=(
            "Information disclosure vulnerability allows remote attackers "
            "to read sensitive memory contents."
        ),
        severity=Severity.MEDIUM,
        affected_products=["Q Series CPUs"],
        affected_versions=["Various"],
        cvss_score=5.3,
        remediation="Apply firmware updates and restrict network access.",
    ),
    CVEEntry(
        cve_id="CVE-2022-33320",
        title="MELSEC iQ-R Series Cleartext Transmission",
        description=(
            "MELSEC iQ-R series transmits sensitive data in cleartext, "
            "allowing network-based attackers to capture credentials."
        ),
        severity=Severity.HIGH,
        affected_products=["iQ-R Series CPUs"],
        affected_versions=["Without OPC UA security"],
        cvss_score=7.5,
        remediation="Enable encrypted communications where available.",
    ),
    CVEEntry(
        cve_id="CVE-2023-1424",
        title="MELSEC Series Password Brute Force",
        description=(
            "Lack of brute force protection in MELSEC password authentication "
            "allows attackers to enumerate valid passwords."
        ),
        severity=Severity.MEDIUM,
        affected_products=["Q Series", "L Series", "iQ-R Series", "iQ-F Series"],
        affected_versions=["All versions"],
        cvss_score=6.5,
        remediation="Implement network-level rate limiting and monitoring.",
    ),
]


class CVECheck(SecurityCheck):
    """
    Security checks for known CVE vulnerabilities.

    Checks against a database of known Mitsubishi PLC CVEs
    and provides remediation guidance.
    """

    CHECK_ID = "CVE-001"
    CHECK_NAME = "CVE Vulnerability Check"
    DESCRIPTION = "Check for known CVE vulnerabilities"
    CATEGORY = "vulnerability"
    RISK_LEVEL = Severity.CRITICAL

    def run(self) -> List[CheckResult]:
        """Execute CVE checks."""
        self.results = []

        # Get device info
        device_info = self.device_info
        if not device_info:
            if self.client:
                try:
                    device_info = self.client.get_device_info()
                except Exception:
                    pass

        if not device_info or not device_info.model:
            self.add_result(
                passed=True,
                title="CVE check requires device identification",
                description="Could not identify device model for CVE matching",
                severity=Severity.INFO,
            )
            return self.results

        model = device_info.model or ""
        series = device_info.series.value if device_info.series else ""
        firmware = device_info.firmware_version or ""

        # Check against CVE database
        matching_cves = self._find_matching_cves(model, series, firmware)

        if matching_cves:
            for cve in matching_cves:
                self.add_result(
                    passed=False,
                    title=f"{cve.cve_id}: {cve.title}",
                    description=cve.description,
                    severity=cve.severity,
                    details=(
                        f"CVSS Score: {cve.cvss_score}\n"
                        f"Affected Products: {', '.join(cve.affected_products)}\n"
                        f"Affected Versions: {', '.join(cve.affected_versions)}"
                    ),
                    cve=cve.cve_id,
                    remediation=cve.remediation,
                    references=cve.references,
                )
        else:
            self.add_result(
                passed=True,
                title="No matching CVEs found",
                description=f"No known CVEs match device: {model}",
                severity=Severity.INFO,
                details=f"Checked against {len(CVE_DATABASE)} known CVEs",
            )

        # Always report protocol-level CVEs as they affect most devices
        self._check_protocol_cves()

        return self.results

    def _find_matching_cves(
        self,
        model: str,
        series: str,
        firmware: str,
    ) -> List[CVEEntry]:
        """Find CVEs matching the device."""
        matching = []

        for cve in CVE_DATABASE:
            # Check product match
            product_match = False
            for affected in cve.affected_products:
                if affected.lower() in model.lower():
                    product_match = True
                    break
                if affected.lower() in series.lower():
                    product_match = True
                    break

            if product_match:
                # For now, include all matching CVEs
                # More sophisticated version checking could be added
                matching.append(cve)

        return matching

    def _check_protocol_cves(self) -> None:
        """Check for protocol-level CVEs that affect most devices."""
        # CVE-2020-5529 affects the MELSEC protocol itself
        protocol_cve = next(
            (c for c in CVE_DATABASE if c.cve_id == "CVE-2020-5529"),
            None
        )

        if protocol_cve:
            self.add_result(
                passed=False,
                title="Protocol-level vulnerability (CVE-2020-5529)",
                description=(
                    "The MELSEC protocol lacks inherent authentication. "
                    "This affects all devices using the standard protocol."
                ),
                severity=Severity.MEDIUM,
                cve=protocol_cve.cve_id,
                remediation=(
                    "Enable available authentication features. "
                    "Implement network segmentation and access controls."
                ),
                references=protocol_cve.references,
            )

    @classmethod
    def get_cve_database(cls) -> List[Dict[str, Any]]:
        """Get the CVE database for external use."""
        return [
            {
                "cve_id": cve.cve_id,
                "title": cve.title,
                "severity": cve.severity.value,
                "cvss_score": cve.cvss_score,
                "affected_products": cve.affected_products,
            }
            for cve in CVE_DATABASE
        ]
