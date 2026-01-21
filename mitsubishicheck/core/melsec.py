"""
MELSEC Client Implementation

High-level client for communicating with Mitsubishi PLCs
using the MELSEC Communication Protocol.
"""

import socket
import time
from typing import Optional, List, Tuple, Union
from dataclasses import dataclass

from .protocol import (
    MelsecProtocol,
    DeviceCode,
    EndCode,
    CommandCode,
)
from .device import DeviceInfo, PLCSeries


@dataclass
class MelsecResponse:
    """Response from a MELSEC command."""
    success: bool
    end_code: int
    data: bytes
    error_message: str = ""

    @property
    def words(self) -> List[int]:
        """Parse response data as 16-bit words."""
        if not self.data:
            return []
        words = []
        for i in range(0, len(self.data) - 1, 2):
            words.append(self.data[i] | (self.data[i + 1] << 8))
        return words


class MelsecClient:
    """
    Client for communicating with Mitsubishi PLCs via MELSEC protocol.

    Supports:
    - TCP and UDP communication
    - 3E and 4E frame formats
    - Binary protocol (ASCII planned)
    - Device memory read/write
    - Remote control operations
    - Authentication handling
    """

    def __init__(
        self,
        host: str,
        port: int = 5007,
        timeout: float = 5.0,
        frame_type: str = "3E",
        use_udp: bool = False,
    ):
        """
        Initialize MELSEC client.

        Args:
            host: PLC IP address or hostname
            port: MC Protocol port (default 5007)
            timeout: Socket timeout in seconds
            frame_type: "3E" or "4E" frame format
            use_udp: Use UDP instead of TCP
        """
        self.host = host
        self.port = port
        self.timeout = timeout
        self.frame_type = frame_type
        self.use_udp = use_udp

        self._socket: Optional[socket.socket] = None
        self._protocol = MelsecProtocol(frame_type=frame_type)
        self._connected = False
        self._authenticated = False

    def connect(self) -> bool:
        """
        Establish connection to the PLC.

        Returns:
            True if connection successful
        """
        try:
            if self.use_udp:
                self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            else:
                self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            self._socket.settimeout(self.timeout)

            if not self.use_udp:
                self._socket.connect((self.host, self.port))

            self._connected = True
            return True

        except (socket.error, socket.timeout) as e:
            self._connected = False
            raise ConnectionError(f"Failed to connect to {self.host}:{self.port}: {e}")

    def disconnect(self) -> None:
        """Close connection to the PLC."""
        if self._socket:
            try:
                self._socket.close()
            except socket.error:
                pass
            self._socket = None
        self._connected = False
        self._authenticated = False

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()
        return False

    def _send_receive(self, data: bytes, recv_size: int = 4096) -> bytes:
        """Send data and receive response."""
        if not self._socket:
            raise ConnectionError("Not connected")

        try:
            if self.use_udp:
                self._socket.sendto(data, (self.host, self.port))
                response, _ = self._socket.recvfrom(recv_size)
            else:
                self._socket.sendall(data)
                response = self._socket.recv(recv_size)

            return response

        except socket.timeout:
            raise TimeoutError(f"Timeout waiting for response from {self.host}")
        except socket.error as e:
            raise ConnectionError(f"Communication error: {e}")

    def _execute_command(self, command_data: bytes) -> MelsecResponse:
        """Execute a command and parse response."""
        response_data = self._send_receive(command_data)

        try:
            data, end_code = self._protocol.parse_response(response_data)
            success = end_code == EndCode.SUCCESS
            error_msg = "" if success else MelsecProtocol.get_error_message(end_code)

            return MelsecResponse(
                success=success,
                end_code=end_code,
                data=data,
                error_message=error_msg,
            )
        except ValueError as e:
            return MelsecResponse(
                success=False,
                end_code=-1,
                data=response_data,
                error_message=str(e),
            )

    def loopback_test(self, test_data: bytes = b"TEST") -> MelsecResponse:
        """
        Perform loopback test to verify connectivity.

        Args:
            test_data: Data to echo back

        Returns:
            MelsecResponse with echoed data
        """
        cmd = self._protocol.build_loopback_test(test_data)
        return self._execute_command(cmd)

    def read_cpu_model(self) -> MelsecResponse:
        """
        Read CPU model information.

        Returns:
            MelsecResponse containing CPU model data
        """
        cmd = self._protocol.build_cpu_model_read()
        return self._execute_command(cmd)

    def batch_read(
        self,
        device: Union[int, str],
        start_address: int,
        points: int,
    ) -> MelsecResponse:
        """
        Read multiple consecutive device points.

        Args:
            device: Device code (e.g., DeviceCode.D or "D")
            start_address: Starting address
            points: Number of points to read

        Returns:
            MelsecResponse with read data
        """
        device_code = self._resolve_device_code(device)
        cmd = self._protocol.build_batch_read(device_code, start_address, points)
        return self._execute_command(cmd)

    def batch_write(
        self,
        device: Union[int, str],
        start_address: int,
        values: List[int],
    ) -> MelsecResponse:
        """
        Write multiple consecutive device points.

        Args:
            device: Device code
            start_address: Starting address
            values: List of values to write

        Returns:
            MelsecResponse indicating success/failure
        """
        device_code = self._resolve_device_code(device)
        cmd = self._protocol.build_batch_write(device_code, start_address, values)
        return self._execute_command(cmd)

    def read_d_registers(self, start: int, count: int) -> MelsecResponse:
        """Convenience method to read D (data) registers."""
        return self.batch_read(DeviceCode.D, start, count)

    def read_m_relays(self, start: int, count: int) -> MelsecResponse:
        """Convenience method to read M (internal) relays."""
        return self.batch_read(DeviceCode.M, start, count)

    def remote_run(self, forced: bool = False, clear_device: bool = False) -> MelsecResponse:
        """
        Set PLC to RUN mode.

        WARNING: This is a dangerous operation that affects PLC operation.

        Args:
            forced: Force RUN even if errors present
            clear_device: Clear device memory

        Returns:
            MelsecResponse indicating success/failure
        """
        cmd = self._protocol.build_remote_run(forced, clear_device)
        return self._execute_command(cmd)

    def remote_stop(self) -> MelsecResponse:
        """
        Set PLC to STOP mode.

        WARNING: This is a dangerous operation that affects PLC operation.

        Returns:
            MelsecResponse indicating success/failure
        """
        cmd = self._protocol.build_remote_stop()
        return self._execute_command(cmd)

    def unlock_password(self, password: str) -> MelsecResponse:
        """
        Attempt to unlock PLC with password.

        Args:
            password: 4-character password

        Returns:
            MelsecResponse indicating success/failure
        """
        cmd = self._protocol.build_password_unlock(password)
        response = self._execute_command(cmd)
        if response.success:
            self._authenticated = True
        return response

    def lock_password(self) -> MelsecResponse:
        """
        Lock PLC password protection.

        Returns:
            MelsecResponse indicating success/failure
        """
        cmd = self._protocol.build_password_lock()
        response = self._execute_command(cmd)
        if response.success:
            self._authenticated = False
        return response

    def get_device_info(self) -> DeviceInfo:
        """
        Gather comprehensive device information.

        Returns:
            DeviceInfo object with discovered information
        """
        info = DeviceInfo(ip_address=self.host, port=self.port)

        # Test connectivity
        try:
            loopback = self.loopback_test()
            if loopback.success:
                info.supports_3e = True
                info.raw_responses["loopback"] = loopback.data
        except Exception:
            pass

        # Read CPU model
        try:
            cpu_resp = self.read_cpu_model()
            if cpu_resp.success and cpu_resp.data:
                # Parse CPU model response
                model_data = cpu_resp.data.decode("ascii", errors="ignore").strip("\x00")
                info.model = model_data
                info.cpu_type = model_data
                info.series = DeviceInfo.identify_series(model_data)
                info.raw_responses["cpu_model"] = cpu_resp.data
        except Exception:
            pass

        # Check password protection status
        try:
            # Attempt to read protected memory area
            mem_resp = self.batch_read(DeviceCode.D, 0, 1)
            if mem_resp.end_code == EndCode.PASSWORD_LOCKED:
                info.password_locked = True
                info.password_protected = True
            elif mem_resp.end_code == EndCode.WRONG_PASSWORD:
                info.password_protected = True
        except Exception:
            pass

        return info

    @staticmethod
    def _resolve_device_code(device: Union[int, str]) -> int:
        """Resolve device code from string or int."""
        if isinstance(device, int):
            return device

        device_map = {
            "D": DeviceCode.D,
            "M": DeviceCode.M,
            "X": DeviceCode.X,
            "Y": DeviceCode.Y,
            "W": DeviceCode.W,
            "B": DeviceCode.B,
            "R": DeviceCode.R,
            "L": DeviceCode.L,
            "SM": DeviceCode.SM,
            "SD": DeviceCode.SD,
        }

        code = device_map.get(device.upper())
        if code is None:
            raise ValueError(f"Unknown device type: {device}")
        return code

    @property
    def is_connected(self) -> bool:
        """Check if client is connected."""
        return self._connected

    @property
    def is_authenticated(self) -> bool:
        """Check if client is authenticated."""
        return self._authenticated
