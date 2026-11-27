"""Human-readable terminal report formatter."""

from typing import List

from dockscan.models.finding import SEVERITY_ORDER, ScanReport


def format_terminal_report(report: ScanReport) -> str:
    """Format a `ScanReport` into a structured, redacted terminal report."""
    counts = report.severity_counts()
    summary_parts = [f"{sev}: {counts[sev]}" for sev in SEVERITY_ORDER]

    lines: List[str] = [
        f"Target:         {report.target}",
        f"Image ID:       {report.image_id or '(unknown)'}",
        f"Layers Scanned: {report.layers_scanned}",
        f"Files Scanned:  {report.files_scanned}",
        f"Summary:        {len(report.findings)} finding(s) ({', '.join(summary_parts)})",
        "-" * 72,
    ]

    if report.warnings:
        lines.append(f"Warnings ({len(report.warnings)}):")
        for warning in report.warnings:
            lines.append(f"  [WARN] {warning}")
        lines.append("")

    if not report.findings:
        lines.append("[PASS] No secrets or exposed credentials detected.")
        return "\n".join(lines)

    lines.append(f"Findings ({len(report.findings)}):")
    for idx, finding in enumerate(report.findings, start=1):
        lines.append(
            f"  {idx}. [{finding.severity} | Confidence: {finding.confidence}] "
            f"{finding.rule_id}: {finding.title}"
        )
        lines.append(f"     Source:      {finding.source} ({finding.detector})")
        lines.append(f"     Location:    {finding.location}")
        lines.append(f"     Match:       {finding.redacted_secret}")
        if finding.occurrences > 1:
            lines.append(f"     Occurrences: {finding.occurrences}")
        lines.append(f"     Details:     {finding.description}")
        lines.append(f"     Remediation: {finding.remediation}")

    return "\n".join(lines)
