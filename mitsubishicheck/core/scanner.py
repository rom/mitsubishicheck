"""
PLC Network Scanner Module

Provides network discovery capabilities for finding Mitsubishi PLCs
on a network.
"""

import socket
import ipaddress
import concurrent.futures
from typing import List, Optional, Callable, Iterator
from dataclasses import dataclass

from .device import DeviceInfo, DEFAULT_PORTS
from .melsec import MelsecClient


@dataclass
class ScanResult:
    """Result from a network scan operation."""
    ip: str
    port: int
    is_open: bool
    is_melsec: bool = False
    device_info: Optional[DeviceInfo] = None
    error: Optional[str] = None


class PLCScanner:
    """
    Network scanner for discovering Mitsubishi PLCs.

    Supports:
    - Single host scanning
    - Network range scanning (CIDR)
    - Multi-port scanning
    - Protocol fingerprinting
    """

    def __init__(
        self,
        timeout: float = 2.0,
        max_workers: int = 50,
        callback: Optional[Callable[[ScanResult], None]] = None,
    ):
        """
        Initialize scanner.

        Args:
            timeout: Connection timeout in seconds
            max_workers: Maximum concurrent scan threads
            callback: Optional callback for each scan result
        """
        self.timeout = timeout
        self.max_workers = max_workers
        self.callback = callback

    def scan_host(
        self,
        host: str,
        ports: Optional[List[int]] = None,
        identify: bool = True,
    ) -> List[ScanResult]:
        """
        Scan a single host for MELSEC services.

        Args:
            host: IP address or hostname
            ports: Ports to scan (default: common MELSEC ports)
            identify: Attempt to identify/fingerprint the device

        Returns:
            List of scan results
        """
        if ports is None:
            ports = list(DEFAULT_PORTS.values())

        results = []
        for port in ports:
            result = self._scan_port(host, port, identify)
            results.append(result)

            if self.callback:
                self.callback(result)

        return results

    def scan_network(
        self,
        network: str,
        ports: Optional[List[int]] = None,
        identify: bool = True,
    ) -> Iterator[ScanResult]:
        """
        Scan a network range for MELSEC services.

        Args:
            network: Network in CIDR notation (e.g., "192.168.1.0/24")
            ports: Ports to scan
            identify: Attempt to identify devices

        Yields:
            ScanResult for each discovered service
        """
        if ports is None:
            ports = [DEFAULT_PORTS["mc_protocol_tcp"]]

        try:
            net = ipaddress.ip_network(network, strict=False)
        except ValueError as e:
            raise ValueError(f"Invalid network specification: {e}")

        # Generate all host/port combinations
        targets = [
            (str(ip), port)
            for ip in net.hosts()
            for port in ports
        ]

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(self._scan_port, ip, port, identify): (ip, port)
                for ip, port in targets
            }

            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if self.callback:
                    self.callback(result)
                yield result

    def _scan_port(self, host: str, port: int, identify: bool) -> ScanResult:
        """Scan a single port."""
        result = ScanResult(ip=host, port=port, is_open=False)

        # First check if port is open
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))
            sock.close()
            result.is_open = True
        except (socket.error, socket.timeout):
            return result

        # If port is open and identification requested, probe for MELSEC
        if identify:
            try:
                client = MelsecClient(host, port, timeout=self.timeout)
                client.connect()

                # Try loopback test to verify MELSEC protocol
                response = client.loopback_test()
                if response.success:
                    result.is_melsec = True
                    result.device_info = client.get_device_info()

                client.disconnect()
            except Exception as e:
                result.error = str(e)

        return result

    def quick_scan(self, host: str, port: int = 5007) -> bool:
        """
        Quick check if host has MELSEC service.

        Args:
            host: Target IP
            port: Target port

        Returns:
            True if MELSEC service detected
        """
        try:
            with MelsecClient(host, port, timeout=self.timeout) as client:
                response = client.loopback_test()
                return response.success
        except Exception:
            return False

    @staticmethod
    def discover_broadcast(
        port: int = 5007,
        timeout: float = 3.0,
    ) -> List[str]:
        """
        Attempt to discover PLCs via UDP broadcast.

        Note: This may not work on all network configurations.

        Args:
            port: UDP port to broadcast on
            timeout: Response timeout

        Returns:
            List of responding IP addresses
        """
        discovered = []

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.settimeout(timeout)

            # MELSEC discovery probe (basic loopback)
            probe = bytes([
                0x50, 0x00,  # Subheader
                0x00,        # Network No.
                0xFF,        # PC No.
                0xFF, 0x03,  # Request destination I/O
                0x00,        # Station No.
                0x08, 0x00,  # Data length
                0x10, 0x00,  # CPU timer
                0x19, 0x06,  # Loopback command
                0x00, 0x00,  # Subcommand
                0x04, 0x00,  # Test data length
                0x54, 0x45, 0x53, 0x54,  # "TEST"
            ])

            sock.sendto(probe, ("<broadcast>", port))

            # Collect responses
            while True:
                try:
                    _, addr = sock.recvfrom(1024)
                    if addr[0] not in discovered:
                        discovered.append(addr[0])
                except socket.timeout:
                    break

            sock.close()
        except Exception:
            pass

        return discovered
