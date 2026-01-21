"""
Authentication Security Check Module

Checks for authentication weaknesses and credential vulnerabilities.
"""

import time
from typing import List, Optional

from .base import SecurityCheck, CheckResult, Severity
from ..core.device import DEFAULT_CREDENTIALS
from ..core.protocol import EndCode


class AuthenticationCheck(SecurityCheck):
    """
    Security checks for authentication mechanisms.

    Checks:
    - No password protection
    - Default/weak passwords
    - Password brute force susceptibility
    - Authentication bypass
    - Password lock status
    """

    CHECK_ID = "AUTH-001"
    CHECK_NAME = "Authentication Check"
    DESCRIPTION = "Check for authentication weaknesses and credential issues"
    CATEGORY = "authentication"
    RISK_LEVEL = Severity.CRITICAL

    def run(self) -> List[CheckResult]:
        """Execute authentication checks."""
        self.results = []

        if not self.client:
            return self.results

        # Check if password protection is enabled
        self._check_password_protection()

        # Check for default credentials
        if self.config.get("check_defaults", True):
            self._check_default_credentials()

        # Check for password lockout mechanism
        self._check_lockout_mechanism()

        # Check for authentication bypass
        self._check_auth_bypass()

        return self.results

    def _check_password_protection(self) -> None:
        """Check if password protection is enabled."""
        try:
            # Attempt to read memory without authentication
            response = self.client.batch_read("D", 0, 1)

            if response.success:
                self.add_result(
                    passed=False,
                    title="No password protection enabled",
                    description=(
                        "PLC memory can be read without any authentication. "
                        "Remote password protection is not enabled."
                    ),
                    severity=Severity.CRITICAL,
                    details="Memory read succeeded without password",
                    remediation=(
                        "Enable remote password protection in the PLC settings. "
                        "Use GX Works or equivalent software to set a strong password."
                    ),
                    cwe="CWE-306",
                    references=[
                        "https://www.mitsubishielectric.com/fa/products/cnt/plc/security/",
                    ],
                )
            elif response.end_code == EndCode.PASSWORD_LOCKED:
                self.add_result(
                    passed=True,
                    title="Password protection is enabled and locked",
                    description="PLC requires authentication for memory access",
                    severity=Severity.INFO,
                    details="Memory read denied with password lock status",
                )
            elif response.end_code == EndCode.WRONG_PASSWORD:
                self.add_result(
                    passed=True,
                    title="Password protection is enabled",
                    description="PLC requires password for memory access",
                    severity=Severity.INFO,
                )

        except Exception as e:
            self.add_result(
                passed=True,
                title="Password protection check inconclusive",
                description=f"Could not determine password status: {str(e)}",
                severity=Severity.INFO,
            )

    def _check_default_credentials(self) -> None:
        """Check for default or common credentials."""
        found_passwords = []
        max_attempts = self.config.get("max_password_attempts", 10)
        delay = self.config.get("attempt_delay", 0.5)

        credentials_to_test = DEFAULT_CREDENTIALS[:max_attempts]

        for password in credentials_to_test:
            try:
                response = self.client.unlock_password(password)

                if response.success:
                    found_passwords.append(password if password else "(empty)")
                    # Re-lock to continue testing
                    self.client.lock_password()

                time.sleep(delay)

            except Exception:
                continue

        if found_passwords:
            self.add_result(
                passed=False,
                title="Default/weak password in use",
                description=(
                    f"PLC accepts default or weak passwords: "
                    f"{', '.join(repr(p) for p in found_passwords)}"
                ),
                severity=Severity.CRITICAL,
                details=f"Working passwords found: {found_passwords}",
                remediation=(
                    "Change the PLC password to a strong, unique value. "
                    "Avoid common passwords or factory defaults."
                ),
                cwe="CWE-521",
                references=[
                    "https://attack.mitre.org/techniques/T0812/",
                ],
            )
        else:
            self.add_result(
                passed=True,
                title="No default credentials found",
                description="Common default passwords were not accepted",
                severity=Severity.INFO,
                details=f"Tested {len(credentials_to_test)} common passwords",
            )

    def _check_lockout_mechanism(self) -> None:
        """Check for account/password lockout after failed attempts."""
        lockout_threshold = self.config.get("lockout_test_attempts", 5)
        delay = self.config.get("attempt_delay", 0.2)

        failed_attempts = 0
        locked_out = False

        for i in range(lockout_threshold):
            try:
                # Use an obviously wrong password
                response = self.client.unlock_password(f"WRONG{i:03d}")

                if response.end_code == EndCode.PASSWORD_LOCKED:
                    # Device has locked out
                    locked_out = True
                    failed_attempts = i + 1
                    break

                time.sleep(delay)
                failed_attempts += 1

            except Exception:
                break

        if not locked_out:
            self.add_result(
                passed=False,
                title="No password lockout mechanism",
                description=(
                    f"PLC did not lock out after {failed_attempts} failed "
                    "password attempts, making brute force attacks feasible."
                ),
                severity=Severity.HIGH,
                details=f"Attempted {failed_attempts} wrong passwords without lockout",
                remediation=(
                    "If available, enable password lockout features. "
                    "Implement network-level rate limiting or IDS rules."
                ),
                cwe="CWE-307",
            )
        else:
            self.add_result(
                passed=True,
                title="Password lockout mechanism present",
                description=f"PLC locked after {failed_attempts} failed attempts",
                severity=Severity.INFO,
            )

    def _check_auth_bypass(self) -> None:
        """Check for authentication bypass vulnerabilities."""
        # Test various bypass techniques

        # 1. Check if certain commands work without authentication
        bypass_found = False

        try:
            # Try CPU model read (often allowed without auth)
            response = self.client.read_cpu_model()
            if response.success:
                bypass_found = True
                self.add_result(
                    passed=False,
                    title="CPU information accessible without authentication",
                    description="CPU model information can be read without password",
                    severity=Severity.LOW,
                    details=f"CPU model data: {response.data}",
                    remediation="This is often by design but exposes device fingerprint.",
                    cwe="CWE-200",
                )
        except Exception:
            pass

        # 2. Check if loopback works without auth (indicates other commands might too)
        try:
            response = self.client.loopback_test()
            if response.success:
                self.add_result(
                    passed=False,
                    title="Loopback test accessible without authentication",
                    description="Network diagnostic commands work without authentication",
                    severity=Severity.LOW,
                    details="Loopback test succeeded",
                    remediation=(
                        "While loopback is low-risk, it confirms the PLC "
                        "accepts commands which may include more sensitive ones."
                    ),
                )
        except Exception:
            pass

        if not bypass_found:
            self.add_result(
                passed=True,
                title="No obvious authentication bypass found",
                description="Tested commands require proper authentication",
                severity=Severity.INFO,
            )
