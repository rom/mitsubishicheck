"""
MELSEC Communication Protocol Implementation

Implements the Mitsubishi MELSEC Communication Protocol (MC Protocol)
supporting both binary and ASCII formats over TCP/UDP.

Protocol Reference:
- MELSEC Communication Protocol Reference Manual
- Mitsubishi Electric FA Engineering Documentation
"""

import struct
from enum import IntEnum
from dataclasses import dataclass
from typing import Optional, Tuple, List


class SubheaderType(IntEnum):
    """MELSEC subheader types for request/response identification."""
    # 3E Frame (QnA compatible)
    REQUEST_3E = 0x5000
    RESPONSE_3E = 0xD000

    # 4E Frame (iQ-R series)
    REQUEST_4E = 0x5400
    RESPONSE_4E = 0xD400

    # 1E Frame (A-series compatible)
    REQUEST_1E_READ = 0x01
    REQUEST_1E_WRITE = 0x03
    RESPONSE_1E = 0x00


class CommandCode(IntEnum):
    """MELSEC command codes for device operations."""
    # Batch read/write commands
    BATCH_READ = 0x0401
    BATCH_WRITE = 0x1401

    # Random read/write commands
    RANDOM_READ = 0x0403
    RANDOM_WRITE = 0x1402

    # Multiple block batch read/write
    MULTI_BLOCK_READ = 0x0406
    MULTI_BLOCK_WRITE = 0x1406

    # Remote control commands
    REMOTE_RUN = 0x1001
    REMOTE_STOP = 0x1002
    REMOTE_PAUSE = 0x1003
    REMOTE_RESET = 0x1006

    # CPU read commands
    CPU_MODEL_READ = 0x0101

    # Password/security commands
    REMOTE_PASSWORD_LOCK = 0x1631
    REMOTE_PASSWORD_UNLOCK = 0x1630

    # Self-test
    LOOPBACK_TEST = 0x0619

    # Clear commands
    DEVICE_MEMORY_CLEAR = 0x1620
    ERROR_CLEAR = 0x1617


class DeviceCode(IntEnum):
    """MELSEC device codes for memory areas."""
    # Bit devices
    X = 0x9C  # Input
    Y = 0x9D  # Output
    M = 0x90  # Internal relay
    L = 0x92  # Latch relay
    F = 0x93  # Annunciator
    V = 0x94  # Edge relay
    B = 0xA0  # Link relay

    # Word devices
    D = 0xA8  # Data register
    W = 0xB4  # Link register
    R = 0xAF  # File register
    ZR = 0xB0  # File register (extended)

    # Timer/Counter
    TS = 0xC1  # Timer contact
    TC = 0xC0  # Timer coil
    TN = 0xC2  # Timer current value
    SS = 0xC7  # Retentive timer contact
    SC = 0xC6  # Retentive timer coil
    SN = 0xC8  # Retentive timer current value
    CS = 0xC4  # Counter contact
    CC = 0xC3  # Counter coil
    CN = 0xC5  # Counter current value

    # Special
    SM = 0x91  # Special relay
    SD = 0xA9  # Special register


class EndCode(IntEnum):
    """MELSEC end/error codes."""
    SUCCESS = 0x0000

    # Command errors
    WRONG_COMMAND = 0xC059
    WRONG_FORMAT = 0xC05C
    WRONG_LENGTH = 0xC061
    BUSY = 0xC062
    LENGTH_EXCEEDED = 0xC064

    # Authentication errors
    WRONG_PASSWORD = 0xC056
    PASSWORD_LOCKED = 0xC058

    # Device errors
    CANNOT_READ = 0xC05B
    CANNOT_WRITE = 0xC05D
    DEVICE_RANGE_ERROR = 0xC05F

    # CPU errors
    CPU_ERROR = 0x4000
    CPU_OPERATION_ERROR = 0xC050


@dataclass
class MelsecFrame:
    """Represents a MELSEC protocol frame."""
    subheader: int
    network_no: int = 0x00
    pc_no: int = 0xFF  # PC number (0xFF = own station)
    io_no: int = 0x03FF  # Request destination module I/O
    station_no: int = 0x00
    cpu_timer: int = 0x0010  # Monitoring timer (x250ms)
    command: int = 0
    subcommand: int = 0x0000
    data: bytes = b""

    def to_bytes_3e(self) -> bytes:
        """Serialize frame to 3E binary format."""
        # Data length = command(2) + subcommand(2) + data
        data_length = 2 + 2 + len(self.data)

        # Request data length includes CPU timer + data length
        request_data_len = 2 + data_length

        frame = struct.pack(
            "<HBBHBHHHH",
            self.subheader,
            self.network_no,
            self.pc_no,
            self.io_no,
            self.station_no,
            request_data_len,
            self.cpu_timer,
            self.command,
            self.subcommand,
        )
        return frame + self.data

    def to_bytes_4e(self, serial_no: int = 0x0001) -> bytes:
        """Serialize frame to 4E binary format with serial number."""
        data_length = 2 + 2 + len(self.data)
        request_data_len = 2 + data_length

        frame = struct.pack(
            "<HHBBHBHHHH",
            self.subheader,
            serial_no,
            self.network_no,
            self.pc_no,
            self.io_no,
            self.station_no,
            request_data_len,
            self.cpu_timer,
            self.command,
            self.subcommand,
        )
        return frame + self.data

    @classmethod
    def parse_response_3e(cls, data: bytes) -> Tuple["MelsecFrame", int]:
        """Parse 3E binary response frame."""
        if len(data) < 11:
            raise ValueError(f"Response too short: {len(data)} bytes")

        subheader, network, pc, io_no, station, length = struct.unpack(
            "<HBBHBH", data[:9]
        )

        end_code = struct.unpack("<H", data[9:11])[0]
        response_data = data[11:9 + length] if length > 2 else b""

        frame = cls(
            subheader=subheader,
            network_no=network,
            pc_no=pc,
            io_no=io_no,
            station_no=station,
            data=response_data,
        )
        return frame, end_code

    @classmethod
    def parse_response_4e(cls, data: bytes) -> Tuple["MelsecFrame", int, int]:
        """Parse 4E binary response frame with serial number."""
        if len(data) < 15:
            raise ValueError(f"Response too short: {len(data)} bytes")

        subheader, serial, reserved, network, pc, io_no, station, length = struct.unpack(
            "<HHBBHBH", data[:13]
        )

        end_code = struct.unpack("<H", data[13:15])[0]
        response_data = data[15:13 + length] if length > 2 else b""

        frame = cls(
            subheader=subheader,
            network_no=network,
            pc_no=pc,
            io_no=io_no,
            station_no=station,
            data=response_data,
        )
        return frame, end_code, serial


class MelsecProtocol:
    """
    MELSEC Protocol handler for building and parsing protocol messages.
    """

    def __init__(self, frame_type: str = "3E", binary: bool = True):
        """
        Initialize protocol handler.

        Args:
            frame_type: Frame type ("3E", "4E", or "1E")
            binary: Use binary format (False = ASCII)
        """
        self.frame_type = frame_type
        self.binary = binary
        self._serial_no = 0

    def _next_serial(self) -> int:
        """Get next serial number for 4E frames."""
        self._serial_no = (self._serial_no + 1) & 0xFFFF
        return self._serial_no

    def build_batch_read(
        self,
        device_code: int,
        start_address: int,
        points: int,
    ) -> bytes:
        """
        Build batch read command.

        Args:
            device_code: Device type (e.g., DeviceCode.D)
            start_address: Starting address
            points: Number of points to read

        Returns:
            Command bytes
        """
        # Device specification (4 bytes for 3E frame)
        device_data = struct.pack(
            "<IBH",
            start_address & 0xFFFFFF,  # 3-byte address
            device_code,
            points,
        )
        # Remove extra byte from the pack (address is 3 bytes)
        device_data = struct.pack("<I", start_address)[:3] + struct.pack("<BH", device_code, points)

        frame = MelsecFrame(
            subheader=SubheaderType.REQUEST_3E if self.frame_type == "3E" else SubheaderType.REQUEST_4E,
            command=CommandCode.BATCH_READ,
            subcommand=0x0000,  # Word units
            data=device_data,
        )

        if self.frame_type == "4E":
            return frame.to_bytes_4e(self._next_serial())
        return frame.to_bytes_3e()

    def build_batch_write(
        self,
        device_code: int,
        start_address: int,
        values: List[int],
    ) -> bytes:
        """
        Build batch write command.

        Args:
            device_code: Device type
            start_address: Starting address
            values: List of word values to write

        Returns:
            Command bytes
        """
        device_data = struct.pack("<I", start_address)[:3] + struct.pack("<BH", device_code, len(values))
        write_data = b"".join(struct.pack("<H", v & 0xFFFF) for v in values)

        frame = MelsecFrame(
            subheader=SubheaderType.REQUEST_3E if self.frame_type == "3E" else SubheaderType.REQUEST_4E,
            command=CommandCode.BATCH_WRITE,
            subcommand=0x0000,
            data=device_data + write_data,
        )

        if self.frame_type == "4E":
            return frame.to_bytes_4e(self._next_serial())
        return frame.to_bytes_3e()

    def build_remote_run(self, forced: bool = False, clear_device: bool = False) -> bytes:
        """Build remote RUN command."""
        mode = 0x0001 if forced else 0x0000
        clear_mode = 0x0001 if clear_device else 0x0000
        data = struct.pack("<HH", mode, clear_mode)

        frame = MelsecFrame(
            subheader=SubheaderType.REQUEST_3E,
            command=CommandCode.REMOTE_RUN,
            subcommand=0x0000,
            data=data,
        )
        return frame.to_bytes_3e()

    def build_remote_stop(self) -> bytes:
        """Build remote STOP command."""
        frame = MelsecFrame(
            subheader=SubheaderType.REQUEST_3E,
            command=CommandCode.REMOTE_STOP,
            subcommand=0x0000,
            data=struct.pack("<H", 0x0001),
        )
        return frame.to_bytes_3e()

    def build_cpu_model_read(self) -> bytes:
        """Build CPU model read command."""
        frame = MelsecFrame(
            subheader=SubheaderType.REQUEST_3E,
            command=CommandCode.CPU_MODEL_READ,
            subcommand=0x0000,
            data=b"",
        )
        return frame.to_bytes_3e()

    def build_loopback_test(self, test_data: bytes = b"TEST") -> bytes:
        """Build loopback test command."""
        data = struct.pack("<H", len(test_data)) + test_data
        frame = MelsecFrame(
            subheader=SubheaderType.REQUEST_3E,
            command=CommandCode.LOOPBACK_TEST,
            subcommand=0x0000,
            data=data,
        )
        return frame.to_bytes_3e()

    def build_password_unlock(self, password: str) -> bytes:
        """Build password unlock command."""
        # Password is 4 characters, padded with spaces
        pwd_bytes = password.encode("ascii").ljust(4, b" ")[:4]
        data = struct.pack("<H", 4) + pwd_bytes

        frame = MelsecFrame(
            subheader=SubheaderType.REQUEST_3E,
            command=CommandCode.REMOTE_PASSWORD_UNLOCK,
            subcommand=0x0000,
            data=data,
        )
        return frame.to_bytes_3e()

    def build_password_lock(self) -> bytes:
        """Build password lock command."""
        frame = MelsecFrame(
            subheader=SubheaderType.REQUEST_3E,
            command=CommandCode.REMOTE_PASSWORD_LOCK,
            subcommand=0x0000,
            data=struct.pack("<H", 0x0000),
        )
        return frame.to_bytes_3e()

    def parse_response(self, data: bytes) -> Tuple[Optional[bytes], int]:
        """
        Parse response data.

        Returns:
            Tuple of (response_data, end_code)
        """
        try:
            if self.frame_type == "4E":
                frame, end_code, _ = MelsecFrame.parse_response_4e(data)
            else:
                frame, end_code = MelsecFrame.parse_response_3e(data)
            return frame.data, end_code
        except (struct.error, ValueError) as e:
            raise ValueError(f"Failed to parse response: {e}")

    @staticmethod
    def get_error_message(end_code: int) -> str:
        """Get human-readable error message for end code."""
        messages = {
            EndCode.SUCCESS: "Success",
            EndCode.WRONG_COMMAND: "Wrong command",
            EndCode.WRONG_FORMAT: "Wrong format",
            EndCode.WRONG_LENGTH: "Wrong length",
            EndCode.BUSY: "CPU busy",
            EndCode.LENGTH_EXCEEDED: "Data length exceeded",
            EndCode.WRONG_PASSWORD: "Wrong password",
            EndCode.PASSWORD_LOCKED: "Password locked",
            EndCode.CANNOT_READ: "Cannot read device",
            EndCode.CANNOT_WRITE: "Cannot write to device",
            EndCode.DEVICE_RANGE_ERROR: "Device range error",
            EndCode.CPU_ERROR: "CPU error",
            EndCode.CPU_OPERATION_ERROR: "CPU operation error",
        }
        return messages.get(end_code, f"Unknown error (0x{end_code:04X})")
