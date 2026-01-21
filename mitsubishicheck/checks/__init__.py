"""Security check modules for Mitsubishi PLC auditing."""

from .base import SecurityCheck, CheckResult, Severity
from .discovery import DiscoveryCheck
from .authentication import AuthenticationCheck
from .memory import MemoryAccessCheck
from .firmware import FirmwareCheck
from .cve import CVECheck
from .protocol import ProtocolCheck
from .control import ControlCheck
from .information import InformationDisclosureCheck

__all__ = [
    "SecurityCheck",
    "CheckResult",
    "Severity",
    "DiscoveryCheck",
    "AuthenticationCheck",
    "MemoryAccessCheck",
    "FirmwareCheck",
    "CVECheck",
    "ProtocolCheck",
    "ControlCheck",
    "InformationDisclosureCheck",
]

# Registry of all available security checks
AVAILABLE_CHECKS = {
    "discovery": DiscoveryCheck,
    "authentication": AuthenticationCheck,
    "memory": MemoryAccessCheck,
    "firmware": FirmwareCheck,
    "cve": CVECheck,
    "protocol": ProtocolCheck,
    "control": ControlCheck,
    "information": InformationDisclosureCheck,
}
