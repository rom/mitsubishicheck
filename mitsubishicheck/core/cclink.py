"""
CC-Link IE Field Protocol Implementation

Implements the CC-Link IE Field Network protocol for Mitsubishi PLCs.
CC-Link IE Field is a high-speed industrial Ethernet network supporting
cyclic and transient communication.

Protocol Reference:
- CC-Link IE Field Network Reference Manual
- Mitsubishi Electric SLMP Protocol Specification
"""

import struct
import socket
from enum import IntEnum
from dataclasses import dataclass
from typing import Optional, Tuple, List, Dict, Any


class CCLinkCommand(IntEnum):
    """CC-Link IE Field SLMP command codes."""
    # Device Read/Write
    DEVICE_READ = 0x0401
    DEVICE_WRITE = 0x1401
    DEVICE_READ_RANDOM = 0x0403
    DEVICE_WRITE_RANDOM = 0x1402

    # Buffer Memory
    BUFFER_READ = 0x0613
    BUFFER_WRITE = 0x1613

    # Remote Control
    REMOTE_RUN = 0x1001
    REMOTE_STOP = 0x1002
    REMOTE_PAUSE = 0x1003
    REMOTE_LATCH_CLEAR = 0x1005
    REMOTE_RESET = 0x1006

    # Module Information
    READ_CPU_MODEL = 0x0101
    READ_TYPE_NAME = 0x0101

    # Loopback
    LOOPBACK_TEST = 0x0619

    # Password
    PASSWORD_LOCK = 0x1631
    PASSWORD_UNLOCK = 0x1630

    # CC-Link IE Field Specific
    CYCLIC_DATA_READ = 0x0E30
    CYCLIC_DATA_WRITE = 0x0E31
    NODE_SEARCH = 0x0E20
    IP_ADDRESS_SET = 0x0E24
    COMMUNICATION_SETTING_GET = 0x0E45


class CCLinkEndCode(IntEnum):
    """CC-Link IE Field end/error codes."""
    SUCCESS = 0x0000

    # Command Errors
    WRONG_COMMAND = 0xC059
    WRONG_FORMAT = 0xC05C
    WRONG_LENGTH = 0xC061
    BUSY = 0xC062
    EXCEEDS_LENGTH = 0xC064

    # Authentication
    WRONG_PASSWORD = 0xC056
    PASSWORD_LOCKED = 0xC058

    # Device Errors
    CANNOT_READ = 0xC05B
    CANNOT_WRITE = 0xC05D
    DEVICE_RANGE_ERROR = 0xC05F

    # CC-Link Specific
    STATION_NOT_FOUND = 0xCF10
    NETWORK_ERROR = 0xCF20
    PARAMETER_ERROR = 0xCF30
    TIMEOUT_ERROR = 0xCF40


class CCLinkDeviceCode(IntEnum):
    """CC-Link IE Field device codes."""
    # Remote I/O (RX/RY)
    RX = 0x9C  # Remote Input
    RY = 0x9D  # Remote Output

    # Remote Registers (RWr/RWw)
    RWR = 0xAF  # Remote Register (read)
    RWW = 0xB4  # Remote Register (write)

    # Station-specific
    SB = 0xA1  # Special Link Relay (bit)
    SW = 0xB5  # Special Link Register (word)

    # Standard devices (inherited from MELSEC)
    X = 0x9C   # Input
    Y = 0x9D   # Output
    M = 0x90   # Internal Relay
    D = 0xA8   # Data Register
    W = 0xB4   # Link Register


@dataclass
class CCLinkFrame:
    """Represents a CC-Link IE Field SLMP frame."""
    subheader: int = 0x5400  # 4E binary subheader
    serial_no: int = 0x0001
    reserved: int = 0x0000
    network_no: int = 0x00
    station_no: int = 0xFF
    module_io: int = 0x03FF
    multidrop: int = 0x00
    data_length: int = 0
    cpu_timer: int = 0x0010
    command: int = 0
    subcommand: int = 0x0000
    data: bytes = b""

    def to_bytes(self) -> bytes:
        """Serialize frame to binary format (4E frame)."""
        # Calculate data length (timer + command + subcommand + data)
        data_length = 2 + 2 + 2 + len(self.data)

        frame = struct.pack(
            "<HHHBBHBHHHH",
            self.subheader,
            self.serial_no,
            self.reserved,
            self.network_no,
            self.station_no,
            self.module_io,
            self.multidrop,
            data_length,
            self.cpu_timer,
            self.command,
            self.subcommand,
        )
        return frame + self.data

    @classmethod
    def parse_response(cls, data: bytes) -> Tuple["CCLinkFrame", int]:
        """Parse response frame and return frame with end code."""
        if len(data) < 15:
            raise ValueError(f"Response too short: {len(data)} bytes")

        (
            subheader, serial_no, reserved,
            network_no, station_no, module_io,
            multidrop, data_length
        ) = struct.unpack("<HHHBBHBH", data[:13])

        end_code = struct.unpack("<H", data[13:15])[0]
        response_data = data[15:13 + data_length] if data_length > 2 else b""

        frame = cls(
            subheader=subheader,
            serial_no=serial_no,
            reserved=reserved,
            network_no=network_no,
            station_no=station_no,
            module_io=module_io,
            multidrop=multidrop,
            data_length=data_length,
            data=response_data,
        )
        return frame, end_code


@dataclass
class CCLinkResponse:
    """Response from CC-Link communication."""
    success: bool
    end_code: int
    data: bytes = b""
    error_message: str = ""

    @property
    def is_password_error(self) -> bool:
        return self.end_code in (CCLinkEndCode.WRONG_PASSWORD, CCLinkEndCode.PASSWORD_LOCKED)


class CCLinkProtocol:
    """
    CC-Link IE Field protocol handler.

    Handles building and parsing CC-Link IE Field SLMP protocol messages.
    """

    def __init__(self, binary: bool = True):
        """
        Initialize protocol handler.

        Args:
            binary: Use binary format (True) or ASCII (False)
        """
        self.binary = binary
        self._serial_no = 0

    def _next_serial(self) -> int:
        """Get next serial number."""
        self._serial_no = (self._serial_no + 1) & 0xFFFF
        return self._serial_no

    def build_device_read(
        self,
        device_code: int,
        start_address: int,
        points: int,
    ) -> bytes:
        """Build device batch read command."""
        device_data = struct.pack("<I", start_address)[:3] + struct.pack("<BH", device_code, points)

        frame = CCLinkFrame(
            serial_no=self._next_serial(),
            command=CCLinkCommand.DEVICE_READ,
            subcommand=0x0000,
            data=device_data,
        )
        return frame.to_bytes()

    def build_device_write(
        self,
        device_code: int,
        start_address: int,
        values: List[int],
    ) -> bytes:
        """Build device batch write command."""
        device_data = struct.pack("<I", start_address)[:3] + struct.pack("<BH", device_code, len(values))
        write_data = b"".join(struct.pack("<H", v & 0xFFFF) for v in values)

        frame = CCLinkFrame(
            serial_no=self._next_serial(),
            command=CCLinkCommand.DEVICE_WRITE,
            subcommand=0x0000,
            data=device_data + write_data,
        )
        return frame.to_bytes()

    def build_cyclic_data_read(self, start_station: int = 0, end_station: int = 63) -> bytes:
        """Build cyclic data read command for CC-Link IE Field."""
        data = struct.pack("<BB", start_station, end_station)

        frame = CCLinkFrame(
            serial_no=self._next_serial(),
            command=CCLinkCommand.CYCLIC_DATA_READ,
            subcommand=0x0000,
            data=data,
        )
        return frame.to_bytes()

    def build_node_search(self) -> bytes:
        """Build node search/discovery command."""
        frame = CCLinkFrame(
            serial_no=self._next_serial(),
            command=CCLinkCommand.NODE_SEARCH,
            subcommand=0x0000,
            data=b"",
        )
        return frame.to_bytes()

    def build_loopback_test(self, test_data: bytes = b"TEST") -> bytes:
        """Build loopback test command."""
        data = struct.pack("<H", len(test_data)) + test_data

        frame = CCLinkFrame(
            serial_no=self._next_serial(),
            command=CCLinkCommand.LOOPBACK_TEST,
            subcommand=0x0000,
            data=data,
        )
        return frame.to_bytes()

    def build_cpu_model_read(self) -> bytes:
        """Build CPU model read command."""
        frame = CCLinkFrame(
            serial_no=self._next_serial(),
            command=CCLinkCommand.READ_CPU_MODEL,
            subcommand=0x0000,
            data=b"",
        )
        return frame.to_bytes()

    def build_communication_setting_get(self) -> bytes:
        """Build communication settings read command."""
        frame = CCLinkFrame(
            serial_no=self._next_serial(),
            command=CCLinkCommand.COMMUNICATION_SETTING_GET,
            subcommand=0x0000,
            data=b"",
        )
        return frame.to_bytes()

    def build_remote_run(self, forced: bool = False) -> bytes:
        """Build remote RUN command."""
        mode = 0x0001 if forced else 0x0000
        data = struct.pack("<HH", mode, 0x0000)

        frame = CCLinkFrame(
            serial_no=self._next_serial(),
            command=CCLinkCommand.REMOTE_RUN,
            subcommand=0x0000,
            data=data,
        )
        return frame.to_bytes()

    def build_remote_stop(self) -> bytes:
        """Build remote STOP command."""
        data = struct.pack("<H", 0x0001)

        frame = CCLinkFrame(
            serial_no=self._next_serial(),
            command=CCLinkCommand.REMOTE_STOP,
            subcommand=0x0000,
            data=data,
        )
        return frame.to_bytes()

    def build_password_unlock(self, password: str) -> bytes:
        """Build password unlock command."""
        pwd_bytes = password.encode("ascii").ljust(4, b" ")[:4]
        data = struct.pack("<H", 4) + pwd_bytes

        frame = CCLinkFrame(
            serial_no=self._next_serial(),
            command=CCLinkCommand.PASSWORD_UNLOCK,
            subcommand=0x0000,
            data=data,
        )
        return frame.to_bytes()

    def build_password_lock(self) -> bytes:
        """Build password lock command."""
        frame = CCLinkFrame(
            serial_no=self._next_serial(),
            command=CCLinkCommand.PASSWORD_LOCK,
            subcommand=0x0000,
            data=struct.pack("<H", 0x0000),
        )
        return frame.to_bytes()

    def parse_response(self, data: bytes) -> Tuple[Optional[bytes], int]:
        """Parse response and return (data, end_code)."""
        try:
            frame, end_code = CCLinkFrame.parse_response(data)
            return frame.data, end_code
        except (struct.error, ValueError) as e:
            raise ValueError(f"Failed to parse CC-Link response: {e}")

    @staticmethod
    def get_error_message(end_code: int) -> str:
        """Get human-readable error message for end code."""
        messages = {
            CCLinkEndCode.SUCCESS: "Success",
            CCLinkEndCode.WRONG_COMMAND: "Wrong command",
            CCLinkEndCode.WRONG_FORMAT: "Wrong format",
            CCLinkEndCode.WRONG_LENGTH: "Wrong length",
            CCLinkEndCode.BUSY: "CPU busy",
            CCLinkEndCode.EXCEEDS_LENGTH: "Data length exceeded",
            CCLinkEndCode.WRONG_PASSWORD: "Wrong password",
            CCLinkEndCode.PASSWORD_LOCKED: "Password locked",
            CCLinkEndCode.CANNOT_READ: "Cannot read device",
            CCLinkEndCode.CANNOT_WRITE: "Cannot write to device",
            CCLinkEndCode.DEVICE_RANGE_ERROR: "Device range error",
            CCLinkEndCode.STATION_NOT_FOUND: "Station not found on network",
            CCLinkEndCode.NETWORK_ERROR: "CC-Link network error",
            CCLinkEndCode.PARAMETER_ERROR: "Parameter error",
            CCLinkEndCode.TIMEOUT_ERROR: "Timeout error",
        }
        return messages.get(end_code, f"Unknown error (0x{end_code:04X})")


class CCLinkClient:
    """
    CC-Link IE Field client for PLC communication.

    Provides high-level methods for interacting with Mitsubishi PLCs
    via CC-Link IE Field network.
    """

    DEFAULT_PORT = 45237

    def __init__(
        self,
        host: str,
        port: int = DEFAULT_PORT,
        timeout: float = 5.0,
        network_no: int = 0,
        station_no: int = 0xFF,
    ):
        """
        Initialize CC-Link client.

        Args:
            host: Target IP address
            port: Target port (default: 45237)
            timeout: Connection timeout in seconds
            network_no: Network number
            station_no: Station number
        """
        self.host = host
        self.port = port
        self.timeout = timeout
        self.network_no = network_no
        self.station_no = station_no

        self._socket: Optional[socket.socket] = None
        self._protocol = CCLinkProtocol()
        self._connected = False

    def connect(self) -> bool:
        """Establish connection to the CC-Link device."""
        try:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._socket.settimeout(self.timeout)
            self._socket.connect((self.host, self.port))
            self._connected = True
            return True
        except socket.error as e:
            self._connected = False
            raise ConnectionError(f"Failed to connect to {self.host}:{self.port}: {e}")

    def disconnect(self) -> None:
        """Close the connection."""
        if self._socket:
            try:
                self._socket.close()
            except Exception:
                pass
            self._socket = None
        self._connected = False

    @property
    def is_connected(self) -> bool:
        """Check if client is connected."""
        return self._connected and self._socket is not None

    def _send_receive(self, data: bytes, recv_size: int = 4096) -> bytes:
        """Send data and receive response."""
        if not self._socket:
            raise ConnectionError("Not connected")

        self._socket.sendall(data)
        response = self._socket.recv(recv_size)

        if not response:
            raise ConnectionError("Empty response received")

        return response

    def loopback_test(self, test_data: bytes = b"TEST") -> CCLinkResponse:
        """Perform loopback test to verify connection."""
        cmd = self._protocol.build_loopback_test(test_data)

        try:
            response = self._send_receive(cmd)
            data, end_code = self._protocol.parse_response(response)

            return CCLinkResponse(
                success=(end_code == CCLinkEndCode.SUCCESS),
                end_code=end_code,
                data=data,
                error_message=CCLinkProtocol.get_error_message(end_code),
            )
        except Exception as e:
            return CCLinkResponse(
                success=False,
                end_code=0xFFFF,
                error_message=str(e),
            )

    def read_cpu_model(self) -> CCLinkResponse:
        """Read CPU model information."""
        cmd = self._protocol.build_cpu_model_read()

        try:
            response = self._send_receive(cmd)
            data, end_code = self._protocol.parse_response(response)

            return CCLinkResponse(
                success=(end_code == CCLinkEndCode.SUCCESS),
                end_code=end_code,
                data=data,
                error_message=CCLinkProtocol.get_error_message(end_code),
            )
        except Exception as e:
            return CCLinkResponse(
                success=False,
                end_code=0xFFFF,
                error_message=str(e),
            )

    def device_read(
        self,
        device: str,
        start_address: int,
        points: int,
    ) -> CCLinkResponse:
        """Read from device memory."""
        device_codes = {
            "RX": CCLinkDeviceCode.RX,
            "RY": CCLinkDeviceCode.RY,
            "RWR": CCLinkDeviceCode.RWR,
            "RWW": CCLinkDeviceCode.RWW,
            "D": CCLinkDeviceCode.D,
            "M": CCLinkDeviceCode.M,
            "X": CCLinkDeviceCode.X,
            "Y": CCLinkDeviceCode.Y,
            "W": CCLinkDeviceCode.W,
            "SB": CCLinkDeviceCode.SB,
            "SW": CCLinkDeviceCode.SW,
        }

        device_code = device_codes.get(device.upper())
        if device_code is None:
            return CCLinkResponse(
                success=False,
                end_code=0xFFFF,
                error_message=f"Unknown device: {device}",
            )

        cmd = self._protocol.build_device_read(device_code, start_address, points)

        try:
            response = self._send_receive(cmd)
            data, end_code = self._protocol.parse_response(response)

            return CCLinkResponse(
                success=(end_code == CCLinkEndCode.SUCCESS),
                end_code=end_code,
                data=data,
                error_message=CCLinkProtocol.get_error_message(end_code),
            )
        except Exception as e:
            return CCLinkResponse(
                success=False,
                end_code=0xFFFF,
                error_message=str(e),
            )

    def device_write(
        self,
        device: str,
        start_address: int,
        values: List[int],
    ) -> CCLinkResponse:
        """Write to device memory."""
        device_codes = {
            "RY": CCLinkDeviceCode.RY,
            "RWW": CCLinkDeviceCode.RWW,
            "D": CCLinkDeviceCode.D,
            "M": CCLinkDeviceCode.M,
            "Y": CCLinkDeviceCode.Y,
            "W": CCLinkDeviceCode.W,
        }

        device_code = device_codes.get(device.upper())
        if device_code is None:
            return CCLinkResponse(
                success=False,
                end_code=0xFFFF,
                error_message=f"Unknown device: {device}",
            )

        cmd = self._protocol.build_device_write(device_code, start_address, values)

        try:
            response = self._send_receive(cmd)
            data, end_code = self._protocol.parse_response(response)

            return CCLinkResponse(
                success=(end_code == CCLinkEndCode.SUCCESS),
                end_code=end_code,
                data=data,
                error_message=CCLinkProtocol.get_error_message(end_code),
            )
        except Exception as e:
            return CCLinkResponse(
                success=False,
                end_code=0xFFFF,
                error_message=str(e),
            )

    def read_cyclic_data(
        self,
        start_station: int = 0,
        end_station: int = 63,
    ) -> CCLinkResponse:
        """Read cyclic communication data."""
        cmd = self._protocol.build_cyclic_data_read(start_station, end_station)

        try:
            response = self._send_receive(cmd)
            data, end_code = self._protocol.parse_response(response)

            return CCLinkResponse(
                success=(end_code == CCLinkEndCode.SUCCESS),
                end_code=end_code,
                data=data,
                error_message=CCLinkProtocol.get_error_message(end_code),
            )
        except Exception as e:
            return CCLinkResponse(
                success=False,
                end_code=0xFFFF,
                error_message=str(e),
            )

    def node_search(self) -> CCLinkResponse:
        """Search for nodes on the CC-Link network."""
        cmd = self._protocol.build_node_search()

        try:
            response = self._send_receive(cmd)
            data, end_code = self._protocol.parse_response(response)

            return CCLinkResponse(
                success=(end_code == CCLinkEndCode.SUCCESS),
                end_code=end_code,
                data=data,
                error_message=CCLinkProtocol.get_error_message(end_code),
            )
        except Exception as e:
            return CCLinkResponse(
                success=False,
                end_code=0xFFFF,
                error_message=str(e),
            )

    def get_communication_settings(self) -> CCLinkResponse:
        """Get CC-Link communication settings."""
        cmd = self._protocol.build_communication_setting_get()

        try:
            response = self._send_receive(cmd)
            data, end_code = self._protocol.parse_response(response)

            return CCLinkResponse(
                success=(end_code == CCLinkEndCode.SUCCESS),
                end_code=end_code,
                data=data,
                error_message=CCLinkProtocol.get_error_message(end_code),
            )
        except Exception as e:
            return CCLinkResponse(
                success=False,
                end_code=0xFFFF,
                error_message=str(e),
            )

    def remote_run(self, forced: bool = False) -> CCLinkResponse:
        """Send remote RUN command."""
        cmd = self._protocol.build_remote_run(forced)

        try:
            response = self._send_receive(cmd)
            data, end_code = self._protocol.parse_response(response)

            return CCLinkResponse(
                success=(end_code == CCLinkEndCode.SUCCESS),
                end_code=end_code,
                data=data,
                error_message=CCLinkProtocol.get_error_message(end_code),
            )
        except Exception as e:
            return CCLinkResponse(
                success=False,
                end_code=0xFFFF,
                error_message=str(e),
            )

    def remote_stop(self) -> CCLinkResponse:
        """Send remote STOP command."""
        cmd = self._protocol.build_remote_stop()

        try:
            response = self._send_receive(cmd)
            data, end_code = self._protocol.parse_response(response)

            return CCLinkResponse(
                success=(end_code == CCLinkEndCode.SUCCESS),
                end_code=end_code,
                data=data,
                error_message=CCLinkProtocol.get_error_message(end_code),
            )
        except Exception as e:
            return CCLinkResponse(
                success=False,
                end_code=0xFFFF,
                error_message=str(e),
            )

    def unlock_password(self, password: str) -> CCLinkResponse:
        """Unlock remote password."""
        cmd = self._protocol.build_password_unlock(password)

        try:
            response = self._send_receive(cmd)
            data, end_code = self._protocol.parse_response(response)

            return CCLinkResponse(
                success=(end_code == CCLinkEndCode.SUCCESS),
                end_code=end_code,
                data=data,
                error_message=CCLinkProtocol.get_error_message(end_code),
            )
        except Exception as e:
            return CCLinkResponse(
                success=False,
                end_code=0xFFFF,
                error_message=str(e),
            )

    def lock_password(self) -> CCLinkResponse:
        """Lock remote password."""
        cmd = self._protocol.build_password_lock()

        try:
            response = self._send_receive(cmd)
            data, end_code = self._protocol.parse_response(response)

            return CCLinkResponse(
                success=(end_code == CCLinkEndCode.SUCCESS),
                end_code=end_code,
                data=data,
                error_message=CCLinkProtocol.get_error_message(end_code),
            )
        except Exception as e:
            return CCLinkResponse(
                success=False,
                end_code=0xFFFF,
                error_message=str(e),
            )

    def __enter__(self) -> "CCLinkClient":
        """Context manager entry."""
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Context manager exit."""
        self.disconnect()


# CC-Link IE Field known vulnerabilities
CCLINK_KNOWN_VULNERABILITIES = {
    "CVE-2020-5668": {
        "description": "Buffer overflow in CC-Link IE Field Network modules",
        "severity": "HIGH",
        "affected_models": ["RJ71GF11-T2", "RJ71EN71"],
        "cvss": 7.5,
    },
    "CVE-2020-5669": {
        "description": "Improper authentication in CC-Link IE Field modules",
        "severity": "CRITICAL",
        "affected_models": ["RJ71GF11-T2"],
        "cvss": 9.8,
    },
    "CVE-2021-20594": {
        "description": "Uncontrolled resource consumption in CC-Link IE TSN modules",
        "severity": "HIGH",
        "affected_models": ["RJ71GN11-T2", "RJ71GN11-EIP"],
        "cvss": 7.5,
    },
    "CVE-2022-25161": {
        "description": "Authentication bypass in CC-Link IE Field Network",
        "severity": "CRITICAL",
        "affected_models": ["RJ71GF11-T2", "QJ71GF11-T2"],
        "cvss": 9.8,
    },
}

# CC-Link default credentials
CCLINK_DEFAULT_CREDENTIALS = [
    "",          # No password
    "    ",      # 4 spaces
    "MITSUBISHI",
    "CCLINK",
    "1234",
    "0000",
]
