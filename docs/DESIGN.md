# Mitsubishi PLC Security Audit Tool - Design Document

## Overview

The Mitsubishi PLC Security Audit Tool (`mitsubishicheck`) is a comprehensive security assessment tool designed for evaluating the security posture of Mitsubishi Programmable Logic Controllers (PLCs) using the MELSEC Communication Protocol.

## Architecture

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         CLI Interface                                │
│                        (mitsubishicheck)                            │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────────┐ │
│  │   Scanner   │    │   Checks    │    │    Report Generator     │ │
│  │             │    │             │    │                         │ │
│  │ - Discovery │    │ - Auth      │    │ - Text/JSON/HTML/CSV   │ │
│  │ - Network   │    │ - Memory    │    │ - Markdown             │ │
│  │ - Identify  │    │ - Protocol  │    │                         │ │
│  └──────┬──────┘    │ - CVE       │    └─────────────────────────┘ │
│         │           │ - Control   │                                 │
│         │           │ - Firmware  │                                 │
│         │           │ - Info      │                                 │
│         │           └──────┬──────┘                                 │
│         │                  │                                        │
│  ┌──────▼──────────────────▼──────────────────────────────────────┐│
│  │                     MELSEC Client                               ││
│  │                                                                 ││
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐││
│  │  │  Protocol   │  │   Device    │  │       Utilities         │││
│  │  │  Handler    │  │   Info      │  │                         │││
│  │  │             │  │             │  │ - Logging               │││
│  │  │ - 3E Frame  │  │ - Series ID │  │ - Helpers               │││
│  │  │ - 4E Frame  │  │ - Model     │  │ - Validators            │││
│  │  │ - Commands  │  │ - Firmware  │  │                         │││
│  │  └─────────────┘  └─────────────┘  └─────────────────────────┘││
│  └────────────────────────────────────────────────────────────────┘│
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │   Mitsubishi PLC    │
                         │   (MELSEC Target)   │
                         └─────────────────────┘
```

### Module Structure

```
mitsubishicheck/
├── __init__.py          # Package initialization
├── __main__.py          # Module entry point
├── cli.py               # Command-line interface
│
├── core/                # Core protocol and communication
│   ├── __init__.py
│   ├── protocol.py      # MELSEC protocol implementation
│   ├── melsec.py        # High-level MELSEC client
│   ├── scanner.py       # Network scanner
│   └── device.py        # Device information handling
│
├── checks/              # Security check modules
│   ├── __init__.py
│   ├── base.py          # Base check class
│   ├── discovery.py     # Service discovery checks
│   ├── authentication.py # Authentication checks
│   ├── memory.py        # Memory access checks
│   ├── firmware.py      # Firmware vulnerability checks
│   ├── cve.py           # Known CVE checks
│   ├── protocol.py      # Protocol security checks
│   ├── control.py       # Control function checks
│   └── information.py   # Information disclosure checks
│
├── reports/             # Report generation
│   ├── __init__.py
│   └── generator.py     # Multi-format report generator
│
└── utils/               # Utilities
    ├── __init__.py
    ├── logger.py        # Logging configuration
    └── helpers.py       # Helper functions
```

## MELSEC Protocol Implementation

### Protocol Overview

MELSEC Communication Protocol (MC Protocol) is Mitsubishi's proprietary protocol for PLC communication. The tool implements:

- **3E Frame**: QnA-compatible binary frame format
- **4E Frame**: Extended frame format with serial numbers (iQ-R series)
- **TCP/UDP**: Both transport protocols supported

### Frame Structure (3E Binary)

```
┌────────────────────────────────────────────────────────────────────┐
│ Subheader │ Network │ PC │  I/O  │Station│ Data │ CPU  │ Command │
│  (2B)     │  (1B)   │(1B)│ (2B)  │ (1B)  │Length│Timer │  Data   │
│           │         │    │       │       │ (2B) │ (2B) │         │
│  0x5000   │  0x00   │0xFF│0x03FF │ 0x00  │      │0x0010│         │
└────────────────────────────────────────────────────────────────────┘
```

### Supported Commands

| Command | Code | Description |
|---------|------|-------------|
| Batch Read | 0x0401 | Read consecutive device points |
| Batch Write | 0x1401 | Write consecutive device points |
| Random Read | 0x0403 | Read non-consecutive points |
| Remote RUN | 0x1001 | Set PLC to RUN mode |
| Remote STOP | 0x1002 | Set PLC to STOP mode |
| CPU Model Read | 0x0101 | Read CPU identification |
| Password Unlock | 0x1630 | Attempt password authentication |
| Loopback Test | 0x0619 | Connection verification |

### Device Codes

| Device | Code | Description |
|--------|------|-------------|
| D | 0xA8 | Data register |
| M | 0x90 | Internal relay |
| X | 0x9C | Input |
| Y | 0x9D | Output |
| SM | 0x91 | Special relay |
| SD | 0xA9 | Special data register |

## Security Checks

### Check Categories

1. **Discovery (DISC)**: Network and service exposure
   - Open port detection
   - Protocol fingerprinting
   - UDP service exposure

2. **Authentication (AUTH)**: Credential security
   - Password protection status
   - Default credential testing
   - Lockout mechanism testing
   - Authentication bypass

3. **Memory (MEM)**: Unauthorized access
   - Read access to device memory
   - Write access testing (optional)
   - Boundary violation testing
   - Sensitive area exposure

4. **Firmware (FW)**: Version vulnerabilities
   - Known vulnerable versions
   - End-of-life detection
   - Version disclosure

5. **CVE**: Known vulnerabilities
   - CVE database matching
   - CVSS scoring
   - Remediation guidance

6. **Protocol (PROTO)**: Protocol weaknesses
   - Cleartext communication
   - Malformed packet handling
   - Replay attack susceptibility

7. **Control (CTRL)**: Dangerous functions
   - RUN/STOP access
   - Program memory access
   - Configuration access

8. **Information (INFO)**: Data leakage
   - Device identification
   - Error message verbosity
   - Memory content analysis

### Check Results

Each check produces results with:

- **Severity**: CRITICAL, HIGH, MEDIUM, LOW, INFO
- **Pass/Fail Status**: Whether vulnerability was found
- **Evidence**: Proof of finding
- **CVE Reference**: If applicable
- **CWE Reference**: Weakness classification
- **Remediation**: Fix recommendations

## Security Considerations

### Safe by Default

- No destructive operations without explicit flags
- Write testing disabled by default
- Fuzzing disabled by default
- Limited password attempts

### Authorization

The tool is designed for **authorized testing only**. Unauthorized use against systems you don't own or have permission to test is:

- Illegal in most jurisdictions
- Potentially dangerous for industrial processes
- Unethical

### ICS Safety

Industrial Control Systems present unique risks:

1. **Physical Impact**: PLCs control real-world processes
2. **Availability**: Downtime may have serious consequences
3. **Safety**: Critical safety systems may be affected

## CVE Database

The tool includes a database of known CVEs affecting Mitsubishi PLCs:

| CVE | Severity | Description |
|-----|----------|-------------|
| CVE-2022-25164 | Critical | iQ-R authentication bypass |
| CVE-2021-20594 | High | iQ-R/iQ-F DoS |
| CVE-2020-5527 | High | Q Series resource exhaustion |
| CVE-2020-5528 | Critical | Q Series input validation |
| CVE-2020-5529 | High | Protocol authentication weakness |
| CVE-2019-10976 | Critical | Q Series buffer overflow |

## Report Formats

### Supported Formats

1. **Text**: Plain text summary
2. **JSON**: Machine-readable structured data
3. **HTML**: Formatted web report
4. **CSV**: Spreadsheet-compatible
5. **Markdown**: Documentation format

### Report Contents

- Executive summary
- Vulnerability statistics
- Detailed findings
- Evidence and proof
- Remediation guidance
- Device information

## Future Enhancements

### Planned Features

1. **ASCII Protocol Support**: MELSEC ASCII format
2. **1E Frame Support**: Legacy A-series compatibility
3. **OPC UA Checks**: Modern protocol security
4. **Passive Mode**: Network traffic analysis
5. **Plugin System**: Custom check modules

### Integration Points

- SIEM integration via JSON output
- CI/CD pipeline integration
- Vulnerability management systems

## References

### Mitsubishi Documentation

- MELSEC Communication Protocol Reference Manual
- MELSEC iQ-R Ethernet User's Manual
- GX Works Programming Manual

### Security Resources

- ICS-CERT Advisories
- MITRE ATT&CK for ICS
- NIST SP 800-82 (ICS Security Guide)

### Related Tools

- Metasploit ICS modules
- Nmap ICS scripts
- Wireshark MELSEC dissector
