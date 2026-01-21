# Mitsubishi PLC Security Audit Tool (mitsubishicheck)

A comprehensive security assessment tool for Mitsubishi Programmable Logic Controllers (PLCs) using the MELSEC Communication Protocol.

## Features

- **MELSEC Protocol Support**: Full implementation of MELSEC MC Protocol (3E/4E frames)
- **Network Discovery**: Scan networks for Mitsubishi PLCs
- **Security Checks**: 8 categories of security assessments
- **CVE Database**: Known vulnerability detection
- **Multiple Report Formats**: Text, JSON, HTML, CSV, Markdown
- **No Dependencies**: Uses only Python standard library

## Security Checks

| Category | Description |
|----------|-------------|
| Discovery | Service exposure and network security |
| Authentication | Password protection and credential security |
| Memory | Unauthorized read/write access |
| Firmware | Version vulnerabilities and EOL detection |
| CVE | Known vulnerability matching |
| Protocol | Communication security weaknesses |
| Control | RUN/STOP and dangerous function access |
| Information | Sensitive data disclosure |

## Installation

### From Source

```bash
git clone https://github.com/example/mitsubishicheck.git
cd mitsubishicheck
pip install -e .
```

### Using pip

```bash
pip install mitsubishicheck
```

## Quick Start

### Scan a Single PLC

```bash
mitsubishicheck -t 192.168.1.100
```

### Run All Security Checks

```bash
mitsubishicheck -t 192.168.1.100 --all-checks
```

### Scan a Network

```bash
mitsubishicheck --network 192.168.1.0/24
```

### Generate HTML Report

```bash
mitsubishicheck -t 192.168.1.100 -o report.html --all-checks
```

## Usage

```
usage: mitsubishicheck [-h] [-t TARGET] [-p PORT] [--network NETWORK]
                       [--ports PORTS] [--checks CHECKS] [--all-checks]
                       [--exclude-checks EXCLUDE_CHECKS] [--list-checks]
                       [--test-write] [--fuzz] [--default-passwords]
                       [--max-password-attempts MAX_PASSWORD_ATTEMPTS]
                       [-o OUTPUT] [--format {text,json,html,csv,markdown}]
                       [-v] [-q] [--no-color] [--timeout TIMEOUT] [--udp]
                       [--frame {3E,4E}] [--version] [--disclaimer]

Mitsubishi PLC Security Audit Tool
```

### Target Specification

| Option | Description |
|--------|-------------|
| `-t, --target` | Target PLC IP address |
| `-p, --port` | Target port (default: 5007) |
| `--network` | Network range in CIDR notation |
| `--ports` | Port specification (e.g., 5007,5006,5001-5010) |

### Check Selection

| Option | Description |
|--------|-------------|
| `--checks` | Comma-separated list of checks to run |
| `--all-checks` | Run all available security checks |
| `--exclude-checks` | Comma-separated list of checks to exclude |
| `--list-checks` | List all available security checks |

### Check Options

| Option | Description |
|--------|-------------|
| `--test-write` | Enable memory write testing (USE WITH CAUTION) |
| `--fuzz` | Enable protocol fuzzing (MAY CAUSE INSTABILITY) |
| `--default-passwords` | Test for default/common passwords |
| `--max-password-attempts` | Maximum password attempts (default: 10) |

### Output Options

| Option | Description |
|--------|-------------|
| `-o, --output` | Output report file path |
| `--format` | Output format: text, json, html, csv, markdown |
| `-v, --verbose` | Increase verbosity (-v, -vv, -vvv) |
| `-q, --quiet` | Quiet mode - only show findings |
| `--no-color` | Disable colored output |

### Connection Options

| Option | Description |
|--------|-------------|
| `--timeout` | Connection timeout in seconds (default: 5.0) |
| `--udp` | Use UDP instead of TCP |
| `--frame` | MELSEC frame type: 3E or 4E (default: 3E) |

## Examples

### Basic Security Scan

```bash
# Scan with default checks
mitsubishicheck -t 192.168.1.100

# Verbose output
mitsubishicheck -t 192.168.1.100 -v

# Very verbose (debug)
mitsubishicheck -t 192.168.1.100 -vvv
```

### Specific Checks

```bash
# Only authentication checks
mitsubishicheck -t 192.168.1.100 --checks authentication

# Multiple specific checks
mitsubishicheck -t 192.168.1.100 --checks authentication,memory,cve

# All checks except fuzzing
mitsubishicheck -t 192.168.1.100 --all-checks --exclude-checks protocol
```

### Network Scanning

```bash
# Scan a /24 network
mitsubishicheck --network 192.168.1.0/24

# Scan specific ports
mitsubishicheck --network 192.168.1.0/24 --ports 5007,5006,5010

# Scan port range
mitsubishicheck --network 10.0.0.0/16 --ports 5000-5020
```

### Report Generation

```bash
# JSON report for SIEM integration
mitsubishicheck -t 192.168.1.100 -o report.json --format json

# HTML report for documentation
mitsubishicheck -t 192.168.1.100 -o report.html --all-checks

# CSV for spreadsheet analysis
mitsubishicheck -t 192.168.1.100 -o findings.csv --format csv

# Markdown for documentation
mitsubishicheck -t 192.168.1.100 -o SECURITY_REPORT.md --format markdown
```

### Advanced Options

```bash
# Test default passwords (authorized testing only)
mitsubishicheck -t 192.168.1.100 --default-passwords

# Enable write testing (DANGEROUS - use only if authorized)
mitsubishicheck -t 192.168.1.100 --test-write

# Use UDP protocol
mitsubishicheck -t 192.168.1.100 --udp --port 5006

# Use 4E frame format (iQ-R series)
mitsubishicheck -t 192.168.1.100 --frame 4E

# Custom timeout for slow networks
mitsubishicheck -t 192.168.1.100 --timeout 10
```

### List Available Checks

```bash
mitsubishicheck --list-checks
```

Output:
```
Available Security Checks:
============================================================

  discovery
    ID: DISC-001
    Category: discovery
    Risk Level: medium
    Description: Check for exposed MELSEC services and ports

  authentication
    ID: AUTH-001
    Category: authentication
    Risk Level: critical
    Description: Check for authentication weaknesses

  memory
    ID: MEM-001
    Category: memory
    Risk Level: high
    Description: Check for unauthorized memory access

  ...
```

## Supported PLC Series

- MELSEC iQ-R Series
- MELSEC iQ-F Series
- MELSEC-Q Series
- MELSEC-L Series
- MELSEC-QnA Series
- FX Series (FX3, FX5)
- MELSEC-A Series (legacy)

## Known CVE Coverage

The tool checks for these and other known vulnerabilities:

| CVE | Severity | Affected |
|-----|----------|----------|
| CVE-2022-25164 | Critical | iQ-R Series |
| CVE-2021-20594 | High | iQ-R/iQ-F Series |
| CVE-2020-5527 | High | Q Series |
| CVE-2020-5528 | Critical | Q Series |
| CVE-2020-5529 | High | Multiple Series |
| CVE-2019-10976 | Critical | Q Series |

## Output Example

```
============================================================
MITSUBISHI PLC SECURITY AUDIT REPORT
============================================================

Generated: 2024-01-15 10:30:00
Target: 192.168.1.100:5007
Model: Q03UDECPU

--------------------------------------------------------------
SUMMARY
--------------------------------------------------------------
Total Checks: 24
Passed: 18
Failed: 6

Findings by Severity:
  Critical: 2
  High: 2
  Medium: 1
  Low: 1
  Info: 0

--------------------------------------------------------------
FINDINGS
--------------------------------------------------------------

[1] CRITICAL: No password protection enabled
    Check: Authentication Check (AUTH-001)
    PLC memory can be read without any authentication.
    Remediation: Enable remote password protection in PLC settings.

[2] CRITICAL: Remote control commands accessible
    Check: Control Access Check (CTRL-001)
    RUN/STOP commands accessible without authentication.
    Remediation: IMMEDIATELY enable password protection.

...
```

## Python API

```python
from mitsubishicheck import MelsecClient, PLCScanner
from mitsubishicheck.checks import AuthenticationCheck

# Connect to PLC
with MelsecClient("192.168.1.100", port=5007) as client:
    # Get device info
    info = client.get_device_info()
    print(f"Model: {info.model}")

    # Read data registers
    response = client.read_d_registers(0, 10)
    if response.success:
        print(f"D0-D9: {response.words}")

    # Run security check
    check = AuthenticationCheck(client=client, device_info=info)
    results = check.run()

    for result in results:
        if not result.passed:
            print(f"[{result.severity.value}] {result.title}")

# Network scanning
scanner = PLCScanner(timeout=2.0)
for result in scanner.scan_network("192.168.1.0/24"):
    if result.is_melsec:
        print(f"Found PLC: {result.ip}:{result.port}")
```

## Security Notice

**This tool is intended for AUTHORIZED SECURITY TESTING ONLY.**

- Obtain written authorization before testing
- Industrial Control Systems control physical processes
- Unauthorized access is illegal in most jurisdictions
- Improper testing can cause equipment damage or safety hazards

Use the `--disclaimer` flag to view the full legal notice.

## Documentation

- [Design Document](docs/DESIGN.md) - Architecture and implementation details
- [Man Page](man/mitsubishicheck.1) - Unix manual page

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Submit a pull request

## License

MIT License - See [LICENSE](LICENSE) file for details.

## References

- [Mitsubishi Electric FA](https://www.mitsubishielectric.com/fa/)
- [MELSEC Communication Protocol Manual](https://www.mitsubishielectric.com/fa/products/cnt/plc/)
- [ICS-CERT Advisories](https://www.cisa.gov/uscert/ics/advisories)
- [MITRE ATT&CK for ICS](https://attack.mitre.org/matrices/ics/)

## Disclaimer

This tool is provided "as is" without warranty of any kind. The authors are not responsible for any misuse or damage caused by this tool. Always obtain proper authorization before conducting security assessments.
