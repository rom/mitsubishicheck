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
from .cclink import CCLinkSecurityCheck, CCLinkDiscoveryCheck, CCLinkProtocolCheck

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
    # CC-Link checks
    "CCLinkSecurityCheck",
    "CCLinkDiscoveryCheck",
    "CCLinkProtocolCheck",
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
    # CC-Link IE Field checks
    "cclink": CCLinkSecurityCheck,
    "cclink_discovery": CCLinkDiscoveryCheck,
    "cclink_protocol": CCLinkProtocolCheck,
}
