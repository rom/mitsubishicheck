"""
Report Generator Module

Generates security audit reports in various formats.
"""

import json
import html
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional

from ..checks.base import CheckResult, Severity
from ..core.device import DeviceInfo


class ReportFormat(Enum):
    """Supported report output formats."""
    TEXT = "text"
    JSON = "json"
    HTML = "html"
    CSV = "csv"
    MARKDOWN = "markdown"


class ReportGenerator:
    """
    Generates security audit reports in various formats.
    """

    def __init__(
        self,
        results: List[CheckResult],
        device_info: Optional[DeviceInfo] = None,
        scan_metadata: Optional[Dict[str, Any]] = None,
    ):
        """
        Initialize report generator.

        Args:
            results: List of check results
            device_info: Device information
            scan_metadata: Scan metadata (target, port, duration, etc.)
        """
        self.results = results
        self.device_info = device_info
        self.scan_metadata = scan_metadata or {}

    def get_summary(self) -> Dict[str, Any]:
        """
        Get summary statistics of scan results.

        Returns:
            Dictionary with summary statistics
        """
        total = len(self.results)
        failed = sum(1 for r in self.results if not r.passed)
        critical = sum(1 for r in self.results if not r.passed and r.severity == Severity.CRITICAL)
        high = sum(1 for r in self.results if not r.passed and r.severity == Severity.HIGH)
        medium = sum(1 for r in self.results if not r.passed and r.severity == Severity.MEDIUM)
        low = sum(1 for r in self.results if not r.passed and r.severity == Severity.LOW)
        info = sum(1 for r in self.results if not r.passed and r.severity == Severity.INFO)
        passed = sum(1 for r in self.results if r.passed)

        return {
            "total_checks": total,
            "passed": passed,
            "failed": failed,
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "info": info,
        }

    def generate(self, format: ReportFormat) -> str:
        """
        Generate report in specified format.

        Args:
            format: Output format

        Returns:
            Report content as string
        """
        generators = {
            ReportFormat.TEXT: self._generate_text,
            ReportFormat.JSON: self._generate_json,
            ReportFormat.HTML: self._generate_html,
            ReportFormat.CSV: self._generate_csv,
            ReportFormat.MARKDOWN: self._generate_markdown,
        }

        generator = generators.get(format, self._generate_text)
        return generator()

    def save(self, path: str, format: ReportFormat) -> None:
        """
        Save report to file.

        Args:
            path: Output file path
            format: Output format
        """
        content = self.generate(format)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)

    def _generate_text(self) -> str:
        """Generate plain text report."""
        lines = []
        summary = self.get_summary()

        # Header
        lines.append("=" * 70)
        lines.append("MITSUBISHI PLC SECURITY AUDIT REPORT")
        lines.append("=" * 70)
        lines.append("")

        # Scan info
        lines.append("Scan Information:")
        lines.append("-" * 40)
        if self.scan_metadata.get("target"):
            lines.append(f"  Target: {self.scan_metadata['target']}:{self.scan_metadata.get('port', 5007)}")
        if self.scan_metadata.get("duration"):
            lines.append(f"  Duration: {self.scan_metadata['duration']:.1f} seconds")
        if self.scan_metadata.get("checks"):
            lines.append(f"  Checks: {', '.join(self.scan_metadata['checks'])}")
        lines.append(f"  Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("")

        # Device info
        if self.device_info:
            lines.append("Device Information:")
            lines.append("-" * 40)
            lines.append(f"  Series: {self.device_info.series.value}")
            lines.append(f"  Model: {self.device_info.model or 'Unknown'}")
            lines.append(f"  CPU Type: {self.device_info.cpu_type or 'Unknown'}")
            lines.append(f"  Firmware: {self.device_info.firmware_version or 'Unknown'}")
            lines.append(f"  Running: {'Yes' if self.device_info.is_running else 'No'}")
            lines.append(f"  Password Protected: {'Yes' if self.device_info.password_protected else 'No'}")
            lines.append("")

        # Summary
        lines.append("Summary:")
        lines.append("-" * 40)
        lines.append(f"  Total Checks: {summary['total_checks']}")
        lines.append(f"  Passed: {summary['passed']}")
        lines.append(f"  Findings: {summary['failed']}")
        lines.append(f"    Critical: {summary['critical']}")
        lines.append(f"    High: {summary['high']}")
        lines.append(f"    Medium: {summary['medium']}")
        lines.append(f"    Low: {summary['low']}")
        lines.append(f"    Info: {summary['info']}")
        lines.append("")

        # Findings
        findings = [r for r in self.results if not r.passed]
        if findings:
            lines.append("Findings:")
            lines.append("=" * 70)

            # Sort by severity
            severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
            findings.sort(key=lambda r: severity_order.index(r.severity))

            for result in findings:
                lines.append("")
                lines.append(f"[{result.severity.value.upper()}] {result.title}")
                lines.append("-" * 40)
                lines.append(f"  Check: {result.check_name} ({result.check_id})")
                lines.append(f"  Description: {result.description}")
                if result.details:
                    lines.append(f"  Details: {result.details}")
                if result.evidence:
                    lines.append(f"  Evidence: {result.evidence}")
                if result.cve:
                    lines.append(f"  CVE: {result.cve}")
                if result.cwe:
                    lines.append(f"  CWE: {result.cwe}")
                if result.remediation:
                    lines.append(f"  Remediation: {result.remediation}")
                if result.references:
                    lines.append(f"  References:")
                    for ref in result.references:
                        lines.append(f"    - {ref}")
        else:
            lines.append("No security findings detected.")

        lines.append("")
        lines.append("=" * 70)
        lines.append("End of Report")
        lines.append("=" * 70)

        return "\n".join(lines)

    def _generate_json(self) -> str:
        """Generate JSON report."""
        report = {
            "report_type": "mitsubishi_plc_security_audit",
            "generated_at": datetime.now().isoformat(),
            "scan_metadata": self.scan_metadata,
            "device_info": self.device_info.to_dict() if self.device_info else None,
            "summary": self.get_summary(),
            "results": [r.to_dict() for r in self.results],
        }
        return json.dumps(report, indent=2)

    def _generate_html(self) -> str:
        """Generate HTML report."""
        summary = self.get_summary()
        findings = [r for r in self.results if not r.passed]

        severity_colors = {
            "critical": "#dc3545",
            "high": "#fd7e14",
            "medium": "#ffc107",
            "low": "#17a2b8",
            "info": "#6c757d",
        }

        html_parts = [
            "<!DOCTYPE html>",
            "<html lang='en'>",
            "<head>",
            "<meta charset='UTF-8'>",
            "<meta name='viewport' content='width=device-width, initial-scale=1.0'>",
            "<title>Mitsubishi PLC Security Audit Report</title>",
            "<style>",
            "body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 20px; background: #f5f5f5; }",
            ".container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }",
            "h1 { color: #333; border-bottom: 2px solid #007bff; padding-bottom: 10px; }",
            "h2 { color: #555; margin-top: 30px; }",
            ".summary { display: flex; flex-wrap: wrap; gap: 10px; margin: 20px 0; }",
            ".summary-card { padding: 15px; border-radius: 4px; min-width: 120px; text-align: center; }",
            ".finding { border: 1px solid #ddd; border-radius: 4px; margin: 15px 0; padding: 15px; }",
            ".finding-header { display: flex; align-items: center; gap: 10px; margin-bottom: 10px; }",
            ".severity-badge { padding: 4px 12px; border-radius: 12px; color: white; font-weight: bold; font-size: 12px; }",
            ".detail { margin: 8px 0; }",
            ".detail-label { font-weight: bold; color: #666; }",
            "table { width: 100%; border-collapse: collapse; margin: 20px 0; }",
            "th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }",
            "th { background: #f8f9fa; }",
            "</style>",
            "</head>",
            "<body>",
            "<div class='container'>",
            "<h1>Mitsubishi PLC Security Audit Report</h1>",
            f"<p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>",
        ]

        # Scan info
        if self.scan_metadata.get("target"):
            html_parts.append("<h2>Scan Information</h2>")
            html_parts.append("<table>")
            html_parts.append(f"<tr><td><strong>Target</strong></td><td>{html.escape(str(self.scan_metadata['target']))}:{self.scan_metadata.get('port', 5007)}</td></tr>")
            if self.scan_metadata.get("duration"):
                html_parts.append(f"<tr><td><strong>Duration</strong></td><td>{self.scan_metadata['duration']:.1f} seconds</td></tr>")
            html_parts.append("</table>")

        # Device info
        if self.device_info:
            html_parts.append("<h2>Device Information</h2>")
            html_parts.append("<table>")
            html_parts.append(f"<tr><td><strong>Series</strong></td><td>{html.escape(self.device_info.series.value)}</td></tr>")
            html_parts.append(f"<tr><td><strong>Model</strong></td><td>{html.escape(self.device_info.model or 'Unknown')}</td></tr>")
            html_parts.append(f"<tr><td><strong>CPU Type</strong></td><td>{html.escape(self.device_info.cpu_type or 'Unknown')}</td></tr>")
            html_parts.append(f"<tr><td><strong>Firmware</strong></td><td>{html.escape(self.device_info.firmware_version or 'Unknown')}</td></tr>")
            html_parts.append("</table>")

        # Summary
        html_parts.append("<h2>Summary</h2>")
        html_parts.append("<div class='summary'>")
        html_parts.append(f"<div class='summary-card' style='background: #28a745; color: white;'><div style='font-size: 24px;'>{summary['passed']}</div><div>Passed</div></div>")
        html_parts.append(f"<div class='summary-card' style='background: {severity_colors['critical']}; color: white;'><div style='font-size: 24px;'>{summary['critical']}</div><div>Critical</div></div>")
        html_parts.append(f"<div class='summary-card' style='background: {severity_colors['high']}; color: white;'><div style='font-size: 24px;'>{summary['high']}</div><div>High</div></div>")
        html_parts.append(f"<div class='summary-card' style='background: {severity_colors['medium']}; color: black;'><div style='font-size: 24px;'>{summary['medium']}</div><div>Medium</div></div>")
        html_parts.append(f"<div class='summary-card' style='background: {severity_colors['low']}; color: white;'><div style='font-size: 24px;'>{summary['low']}</div><div>Low</div></div>")
        html_parts.append(f"<div class='summary-card' style='background: {severity_colors['info']}; color: white;'><div style='font-size: 24px;'>{summary['info']}</div><div>Info</div></div>")
        html_parts.append("</div>")

        # Findings
        html_parts.append("<h2>Findings</h2>")
        if findings:
            severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
            findings.sort(key=lambda r: severity_order.index(r.severity))

            for result in findings:
                color = severity_colors.get(result.severity.value, "#6c757d")
                html_parts.append("<div class='finding'>")
                html_parts.append("<div class='finding-header'>")
                html_parts.append(f"<span class='severity-badge' style='background: {color};'>{result.severity.value.upper()}</span>")
                html_parts.append(f"<strong>{html.escape(result.title)}</strong>")
                html_parts.append("</div>")
                html_parts.append(f"<div class='detail'><span class='detail-label'>Check:</span> {html.escape(result.check_name)} ({html.escape(result.check_id)})</div>")
                html_parts.append(f"<div class='detail'><span class='detail-label'>Description:</span> {html.escape(result.description)}</div>")
                if result.details:
                    html_parts.append(f"<div class='detail'><span class='detail-label'>Details:</span> {html.escape(result.details)}</div>")
                if result.evidence:
                    html_parts.append(f"<div class='detail'><span class='detail-label'>Evidence:</span> <code>{html.escape(result.evidence)}</code></div>")
                if result.cve:
                    html_parts.append(f"<div class='detail'><span class='detail-label'>CVE:</span> {html.escape(result.cve)}</div>")
                if result.remediation:
                    html_parts.append(f"<div class='detail'><span class='detail-label'>Remediation:</span> {html.escape(result.remediation)}</div>")
                html_parts.append("</div>")
        else:
            html_parts.append("<p>No security findings detected.</p>")

        html_parts.append("</div></body></html>")
        return "\n".join(html_parts)

    def _generate_csv(self) -> str:
        """Generate CSV report."""
        import csv
        import io

        output = io.StringIO()
        writer = csv.writer(output)

        # Header
        writer.writerow([
            "Check ID", "Check Name", "Passed", "Severity", "Title",
            "Description", "Details", "Evidence", "Remediation", "CVE", "CWE"
        ])

        # Results
        for result in self.results:
            writer.writerow([
                result.check_id,
                result.check_name,
                "Yes" if result.passed else "No",
                result.severity.value,
                result.title,
                result.description,
                result.details,
                result.evidence,
                result.remediation,
                result.cve or "",
                result.cwe or "",
            ])

        return output.getvalue()

    def _generate_markdown(self) -> str:
        """Generate Markdown report."""
        lines = []
        summary = self.get_summary()

        # Header
        lines.append("# Mitsubishi PLC Security Audit Report")
        lines.append("")
        lines.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("")

        # Scan info
        if self.scan_metadata.get("target"):
            lines.append("## Scan Information")
            lines.append("")
            lines.append(f"- **Target:** {self.scan_metadata['target']}:{self.scan_metadata.get('port', 5007)}")
            if self.scan_metadata.get("duration"):
                lines.append(f"- **Duration:** {self.scan_metadata['duration']:.1f} seconds")
            if self.scan_metadata.get("checks"):
                lines.append(f"- **Checks:** {', '.join(self.scan_metadata['checks'])}")
            lines.append("")

        # Device info
        if self.device_info:
            lines.append("## Device Information")
            lines.append("")
            lines.append(f"| Property | Value |")
            lines.append("|----------|-------|")
            lines.append(f"| Series | {self.device_info.series.value} |")
            lines.append(f"| Model | {self.device_info.model or 'Unknown'} |")
            lines.append(f"| CPU Type | {self.device_info.cpu_type or 'Unknown'} |")
            lines.append(f"| Firmware | {self.device_info.firmware_version or 'Unknown'} |")
            lines.append(f"| Running | {'Yes' if self.device_info.is_running else 'No'} |")
            lines.append(f"| Password Protected | {'Yes' if self.device_info.password_protected else 'No'} |")
            lines.append("")

        # Summary
        lines.append("## Summary")
        lines.append("")
        lines.append(f"| Metric | Count |")
        lines.append("|--------|-------|")
        lines.append(f"| Total Checks | {summary['total_checks']} |")
        lines.append(f"| Passed | {summary['passed']} |")
        lines.append(f"| Critical | {summary['critical']} |")
        lines.append(f"| High | {summary['high']} |")
        lines.append(f"| Medium | {summary['medium']} |")
        lines.append(f"| Low | {summary['low']} |")
        lines.append(f"| Info | {summary['info']} |")
        lines.append("")

        # Findings
        findings = [r for r in self.results if not r.passed]
        lines.append("## Findings")
        lines.append("")

        if findings:
            severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
            findings.sort(key=lambda r: severity_order.index(r.severity))

            for result in findings:
                lines.append(f"### [{result.severity.value.upper()}] {result.title}")
                lines.append("")
                lines.append(f"**Check:** {result.check_name} ({result.check_id})")
                lines.append("")
                lines.append(f"**Description:** {result.description}")
                lines.append("")
                if result.details:
                    lines.append(f"**Details:** {result.details}")
                    lines.append("")
                if result.evidence:
                    lines.append(f"**Evidence:**")
                    lines.append("```")
                    lines.append(result.evidence)
                    lines.append("```")
                    lines.append("")
                if result.cve:
                    lines.append(f"**CVE:** {result.cve}")
                    lines.append("")
                if result.cwe:
                    lines.append(f"**CWE:** {result.cwe}")
                    lines.append("")
                if result.remediation:
                    lines.append(f"**Remediation:** {result.remediation}")
                    lines.append("")
                if result.references:
                    lines.append("**References:**")
                    for ref in result.references:
                        lines.append(f"- {ref}")
                    lines.append("")
                lines.append("---")
                lines.append("")
        else:
            lines.append("No security findings detected.")
            lines.append("")

        return "\n".join(lines)
