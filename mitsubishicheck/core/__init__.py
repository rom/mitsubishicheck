"""Core modules for MELSEC and CC-Link protocol communication."""

from .melsec import MelsecClient
from .scanner import PLCScanner
from .device import DeviceInfo, CCLINK_PORTS
from .protocol import MelsecProtocol, SubheaderType, CommandCode
from .cclink import (
    CCLinkClient,
    CCLinkProtocol,
    CCLinkCommand,
    CCLinkEndCode,
    CCLinkDeviceCode,
    CCLinkResponse,
)

__all__ = [
    # MELSEC
    "MelsecClient",
    "PLCScanner",
    "DeviceInfo",
    "MelsecProtocol",
    "SubheaderType",
    "CommandCode",
    # CC-Link
    "CCLinkClient",
    "CCLinkProtocol",
    "CCLinkCommand",
    "CCLinkEndCode",
    "CCLinkDeviceCode",
    "CCLinkResponse",
    "CCLINK_PORTS",
]
