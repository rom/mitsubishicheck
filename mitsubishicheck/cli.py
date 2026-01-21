"""
Command Line Interface Module

Provides the main CLI entry point for the Mitsubishi PLC Security Audit Tool.
"""

import argparse
import sys
import time
from typing import List, Optional

from . import __version__
from .core.melsec import MelsecClient
from .core.scanner import PLCScanner
from .core.device import DeviceInfo, DEFAULT_PORTS
from .checks import (
    AVAILABLE_CHECKS,
    SecurityCheck,
    CheckResult,
    Severity,
)
from .reports.generator import ReportGenerator, ReportFormat
from .utils.logger import setup_logger, get_logger
from .utils.helpers import validate_ip, validate_network, parse_port_range


def create_parser() -> argparse.ArgumentParser:
    """Create and configure argument parser."""
    parser = argparse.ArgumentParser(
        prog="mitsubishicheck",
        description=(
            "Mitsubishi PLC Security Audit Tool\n"
            "A comprehensive security assessment tool for Mitsubishi PLCs "
            "using the MELSEC protocol."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan a single PLC
  mitsubishicheck -t 192.168.1.100

  # Scan with all checks
  mitsubishicheck -t 192.168.1.100 --all-checks

  # Scan a network range
  mitsubishicheck --network 192.168.1.0/24

  # Generate HTML report
  mitsubishicheck -t 192.168.1.100 -o report.html

  # Run specific checks only
  mitsubishicheck -t 192.168.1.100 --checks authentication,memory

  # List available checks
  mitsubishicheck --list-checks

Security Notice:
  This tool is intended for authorized security testing only.
  Ensure you have proper authorization before scanning any PLC.
  Unauthorized access to industrial control systems is illegal.
        """
    )

    # Target specification
    target_group = parser.add_argument_group("Target Specification")
    target_group.add_argument(
        "-t", "--target",
        help="Target PLC IP address"
    )
    target_group.add_argument(
        "-p", "--port",
        type=int,
        default=5007,
        help="Target port (default: 5007)"
    )
    target_group.add_argument(
        "--network",
        help="Network range in CIDR notation (e.g., 192.168.1.0/24)"
    )
    target_group.add_argument(
        "--ports",
        help="Port specification (e.g., 5007,5006,5001-5010)"
    )

    # Check selection
    check_group = parser.add_argument_group("Check Selection")
    check_group.add_argument(
        "--checks",
        help="Comma-separated list of checks to run"
    )
    check_group.add_argument(
        "--all-checks",
        action="store_true",
        help="Run all available security checks"
    )
    check_group.add_argument(
        "--exclude-checks",
        help="Comma-separated list of checks to exclude"
    )
    check_group.add_argument(
        "--list-checks",
        action="store_true",
        help="List all available security checks and exit"
    )

    # Check options
    options_group = parser.add_argument_group("Check Options")
    options_group.add_argument(
        "--test-write",
        action="store_true",
        help="Enable memory write testing (USE WITH CAUTION)"
    )
    options_group.add_argument(
        "--fuzz",
        action="store_true",
        help="Enable protocol fuzzing (MAY CAUSE INSTABILITY)"
    )
    options_group.add_argument(
        "--default-passwords",
        action="store_true",
        help="Test for default/common passwords"
    )
    options_group.add_argument(
        "--max-password-attempts",
        type=int,
        default=10,
        help="Maximum password attempts (default: 10)"
    )

    # Output options
    output_group = parser.add_argument_group("Output Options")
    output_group.add_argument(
        "-o", "--output",
        help="Output report file path"
    )
    output_group.add_argument(
        "--format",
        choices=["text", "json", "html", "csv", "markdown"],
        default="text",
        help="Output format (default: text)"
    )
    output_group.add_argument(
        "-v", "--verbose",
        action="count",
        default=0,
        help="Increase verbosity (-v, -vv, -vvv)"
    )
    output_group.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Quiet mode - only show findings"
    )
    output_group.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output"
    )

    # Connection options
    conn_group = parser.add_argument_group("Connection Options")
    conn_group.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="Connection timeout in seconds (default: 5.0)"
    )
    conn_group.add_argument(
        "--udp",
        action="store_true",
        help="Use UDP instead of TCP"
    )
    conn_group.add_argument(
        "--frame",
        choices=["3E", "4E"],
        default="3E",
        help="MELSEC frame type (default: 3E)"
    )

    # Other options
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}"
    )
    parser.add_argument(
        "--disclaimer",
        action="store_true",
        help="Show legal disclaimer"
    )

    return parser


def list_checks() -> None:
    """List all available security checks."""
    print("\nAvailable Security Checks:")
    print("=" * 60)

    for name, check_class in AVAILABLE_CHECKS.items():
        check = check_class()
        info = check.get_info()
        print(f"\n  {name}")
        print(f"    ID: {info['id']}")
        print(f"    Category: {info['category']}")
        print(f"    Risk Level: {info['risk_level']}")
        print(f"    Description: {info['description']}")

    print("\n" + "=" * 60)
    print("Use --checks <name1,name2> to run specific checks")
    print("Use --all-checks to run all checks")


def show_disclaimer() -> None:
    """Show legal disclaimer."""
    print("""
================================================================================
                           LEGAL DISCLAIMER
================================================================================

This tool is intended for AUTHORIZED SECURITY TESTING ONLY.

By using this tool, you acknowledge and agree that:

1. You have explicit authorization to test the target systems.

2. Unauthorized access to computer systems is illegal under various laws
   including but not limited to:
   - Computer Fraud and Abuse Act (CFAA) in the United States
   - Computer Misuse Act in the United Kingdom
   - Similar laws in other jurisdictions

3. Industrial Control Systems (ICS) and PLCs control physical processes.
   Unauthorized or improper testing can cause:
   - Equipment damage
   - Production disruption
   - Safety hazards
   - Environmental harm

4. The authors and distributors of this tool are not responsible for any
   misuse or damage caused by this tool.

5. This tool should only be used by qualified security professionals with
   appropriate training in ICS security.

Always obtain written authorization before conducting any security testing.
================================================================================
""")


def run_scan(args: argparse.Namespace) -> int:
    """
    Run the security scan.

    Args:
        args: Parsed command line arguments

    Returns:
        Exit code
    """
    import logging

    # Setup logging
    log_level = logging.WARNING
    if args.verbose >= 3:
        log_level = logging.DEBUG
    elif args.verbose >= 2:
        log_level = logging.INFO
    elif args.verbose >= 1:
        log_level = logging.INFO
    elif args.quiet:
        log_level = logging.ERROR

    logger = setup_logger(level=log_level, use_color=not args.no_color)

    # Validate target
    if not args.target and not args.network:
        logger.error("No target specified. Use -t/--target or --network")
        return 1

    if args.target and not validate_ip(args.target):
        logger.error(f"Invalid IP address: {args.target}")
        return 1

    if args.network and not validate_network(args.network):
        logger.error(f"Invalid network specification: {args.network}")
        return 1

    # Determine checks to run
    checks_to_run = []

    if args.all_checks:
        checks_to_run = list(AVAILABLE_CHECKS.keys())
    elif args.checks:
        checks_to_run = [c.strip() for c in args.checks.split(",")]
        for check_name in checks_to_run:
            if check_name not in AVAILABLE_CHECKS:
                logger.error(f"Unknown check: {check_name}")
                return 1
    else:
        # Default checks
        checks_to_run = ["discovery", "authentication", "memory", "protocol", "cve"]

    # Exclude checks if specified
    if args.exclude_checks:
        excluded = [c.strip() for c in args.exclude_checks.split(",")]
        checks_to_run = [c for c in checks_to_run if c not in excluded]

    # Build check config
    check_config = {
        "test_write": args.test_write,
        "enable_fuzzing": args.fuzz,
        "check_defaults": args.default_passwords,
        "max_password_attempts": args.max_password_attempts,
        "timeout": args.timeout,
    }

    # Network scan mode
    if args.network:
        return run_network_scan(args, checks_to_run, check_config, logger)

    # Single target mode
    return run_single_scan(args, checks_to_run, check_config, logger)


def run_single_scan(
    args: argparse.Namespace,
    checks_to_run: List[str],
    check_config: dict,
    logger,
) -> int:
    """Run scan against single target."""
    target = args.target
    port = args.port

    logger.info(f"Starting security audit of {target}:{port}")
    logger.info(f"Checks to run: {', '.join(checks_to_run)}")

    all_results: List[CheckResult] = []
    device_info: Optional[DeviceInfo] = None
    start_time = time.time()

    try:
        # Connect to PLC
        client = MelsecClient(
            host=target,
            port=port,
            timeout=args.timeout,
            frame_type=args.frame,
            use_udp=args.udp,
        )

        logger.info("Connecting to target...")
        client.connect()
        logger.info("Connected successfully")

        # Get device info first
        logger.info("Gathering device information...")
        device_info = client.get_device_info()

        if device_info.model:
            logger.info(f"Identified: {device_info.model}")

        # Run checks
        for check_name in checks_to_run:
            if check_name not in AVAILABLE_CHECKS:
                continue

            check_class = AVAILABLE_CHECKS[check_name]
            check = check_class(
                client=client,
                device_info=device_info,
                config=check_config,
            )

            logger.info(f"Running check: {check.CHECK_NAME}")

            try:
                results = check.run()
                all_results.extend(results)

                # Report findings immediately
                for result in results:
                    if not result.passed:
                        logger.warning(f"  [{result.severity.value.upper()}] {result.title}")
                    elif args.verbose >= 2:
                        logger.info(f"  [PASS] {result.title}")

            except Exception as e:
                logger.error(f"  Check failed: {str(e)}")

        client.disconnect()

    except ConnectionError as e:
        logger.error(f"Connection failed: {e}")
        return 1
    except Exception as e:
        logger.error(f"Scan error: {e}")
        return 1

    elapsed = time.time() - start_time

    # Generate report
    generator = ReportGenerator(
        results=all_results,
        device_info=device_info,
        scan_metadata={
            "target": target,
            "port": port,
            "checks": checks_to_run,
            "duration": elapsed,
        }
    )

    # Output report
    if args.output:
        format_map = {
            "text": ReportFormat.TEXT,
            "json": ReportFormat.JSON,
            "html": ReportFormat.HTML,
            "csv": ReportFormat.CSV,
            "markdown": ReportFormat.MARKDOWN,
        }
        report_format = format_map.get(args.format, ReportFormat.TEXT)
        generator.save(args.output, report_format)
        logger.info(f"Report saved to: {args.output}")
    else:
        # Print summary to stdout
        print(generator.generate(ReportFormat.TEXT))

    # Summary
    summary = generator.get_summary()
    logger.info(f"Scan completed in {elapsed:.1f}s")
    logger.info(f"Total: {summary['total_checks']} checks, {summary['failed']} findings")

    # Return non-zero if critical/high findings
    if summary['critical'] > 0 or summary['high'] > 0:
        return 2

    return 0


def run_network_scan(
    args: argparse.Namespace,
    checks_to_run: List[str],
    check_config: dict,
    logger,
) -> int:
    """Run network-wide scan."""
    ports = [args.port]
    if args.ports:
        ports = parse_port_range(args.ports)

    logger.info(f"Starting network scan of {args.network}")
    logger.info(f"Ports: {ports}")

    scanner = PLCScanner(
        timeout=args.timeout,
        max_workers=50,
    )

    discovered = []

    def on_result(result):
        if result.is_melsec:
            logger.info(f"Found MELSEC device: {result.ip}:{result.port}")
            discovered.append(result)
        elif result.is_open:
            logger.debug(f"Open port: {result.ip}:{result.port}")

    scanner.callback = on_result

    logger.info("Scanning network...")
    list(scanner.scan_network(args.network, ports=ports, identify=True))

    logger.info(f"Discovered {len(discovered)} MELSEC devices")

    if not discovered:
        logger.warning("No MELSEC devices found")
        return 0

    # Scan each discovered device
    all_results = []
    for device in discovered:
        logger.info(f"\nScanning {device.ip}:{device.port}...")

        # Create temporary args for single scan
        device_args = argparse.Namespace(**vars(args))
        device_args.target = device.ip
        device_args.port = device.port
        device_args.network = None

        result = run_single_scan(device_args, checks_to_run, check_config, logger)
        all_results.append(result)

    # Return worst result
    return max(all_results) if all_results else 0


def main() -> int:
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()

    # Handle special commands
    if args.list_checks:
        list_checks()
        return 0

    if args.disclaimer:
        show_disclaimer()
        return 0

    # Show disclaimer warning
    if not args.quiet:
        print("=" * 60)
        print("MITSUBISHI PLC SECURITY AUDIT TOOL")
        print("For authorized security testing only.")
        print("Use --disclaimer for full legal notice.")
        print("=" * 60)
        print()

    return run_scan(args)


if __name__ == "__main__":
    sys.exit(main())
