"""Human-readable terminal report generator matching the DOCKSCAN report layout."""

from typing import List

from dockscan.models.finding import SEVERITY_ORDER, ScanReport


def format_terminal_report(report: ScanReport, verbose: bool = True) -> str:
    """Format a `ScanReport` into a structured, redacted `DOCKSCAN SECURITY REPORT`."""
    counts = report.severity_counts()

    lines: List[str] = [
        "DOCKSCAN SECURITY REPORT",
        "",
        f"Image: {report.target}",
        f"Image ID: {report.image_id or '(unknown)'}",
        (
            f"Scanned: {report.layers_scanned} layer(s), "
            f"{report.files_scanned} file(s), "
            f"{report.packages_scanned} package(s)"
        ),
        "",
        f"CRITICAL: {counts['Critical']}",
        f"HIGH: {counts['High']}",
        f"MEDIUM: {counts['Medium']}",
        f"LOW: {counts['Low']}",
    ]

    if report.warnings:
        lines.append("")
        lines.append(f"Warnings ({len(report.warnings)}):")
        for warning in report.warnings:
            lines.append(f"  [WARN] {warning}")

    lines.append("")
    lines.append("Findings:")

    if not report.findings:
        lines.append("")
        lines.append("[PASS] No security issues detected.")
        return "\n".join(lines)

    for finding in report.findings:
        lines.append("")
        sev_label = finding.severity.upper()
        lines.append(f"[{sev_label}] {finding.title}")
        display_location = finding.file_path or finding.location
        if finding.line_number is not None and finding.file_path:
            display_location = f"{finding.file_path}:{finding.line_number}"
        lines.append(f"Location: {display_location}")

        if finding.package:
            lines.append(f"Package: {finding.package}")
        if finding.detected_version:
            lines.append(f"Detected Version: {finding.detected_version}")
        if finding.cve:
            lines.append(f"CVE: {finding.cve}")
        if finding.fixed_version:
            lines.append(f"Fixed Version: {finding.fixed_version}")

        score_str = (
            f"{finding.confidence_score:.2f}"
            if finding.confidence_score is not None
            else "N/A"
        )
        lines.append(f"Confidence: {finding.confidence} ({score_str})")

        if finding.redacted_secret and finding.redacted_secret != "(none)" and not finding.package:
            lines.append(f"Evidence: {finding.redacted_secret}")
        if finding.occurrences > 1:
            lines.append(f"Occurrences: {finding.occurrences}")

        if verbose:
            lines.append(f"Rule: {finding.rule_id} ({finding.category})")
            lines.append(f"Remediation: {finding.remediation}")

    return "\n".join(lines)
