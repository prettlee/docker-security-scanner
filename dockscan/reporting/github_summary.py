"""GitHub Actions Step Summary and CI failure threshold helpers."""

from pathlib import Path
from typing import List, Optional, Union

from dockscan.models.finding import SEVERITY_ORDER, ScanReport

FAIL_ON_CHOICES = ("critical", "high", "medium", "low", "none")


def should_fail_ci(report: ScanReport, fail_on: str = "low") -> bool:
    """Return True if `report` contains findings at or above the `fail_on` threshold."""
    normalized = fail_on.strip().lower()
    if normalized == "none":
        return False

    threshold_rank = SEVERITY_ORDER.get(normalized.capitalize(), SEVERITY_ORDER["Low"])
    return any(
        SEVERITY_ORDER.get(finding.severity, 99) <= threshold_rank
        for finding in report.findings
    )


def format_github_summary(report: ScanReport, max_findings: int = 25) -> str:
    """Render a Markdown summary suitable for `$GITHUB_STEP_SUMMARY`."""
    counts = report.severity_counts()
    lines: List[str] = [
        "## Dockscan Security Report",
        "",
        f"- **Target:** `{report.target}`",
        (
            f"- **Scanned:** {report.layers_scanned} layer(s), "
            f"{report.files_scanned} file(s), {report.packages_scanned} package(s)"
        ),
        "",
        "| Critical | High | Medium | Low | Total |",
        "| :---: | :---: | :---: | :---: | :---: |",
        (
            f"| {counts['Critical']} | {counts['High']} | "
            f"{counts['Medium']} | {counts['Low']} | {len(report.findings)} |"
        ),
        "",
    ]

    if not report.findings:
        lines.append("No security issues detected.")
        return "\n".join(lines)

    lines.extend(
        [
            "### Findings",
            "",
            "| Severity | Rule | Title | Location | Confidence |",
            "| :--- | :--- | :--- | :--- | :--- |",
        ]
    )
    for finding in report.findings[:max_findings]:
        loc = finding.file_path or finding.location
        if finding.line_number is not None and finding.file_path:
            loc = f"{finding.file_path}:{finding.line_number}"
        score = (
            f"{finding.confidence_score:.2f}"
            if finding.confidence_score is not None
            else "N/A"
        )
        title = finding.title.replace("|", "\\|")
        loc_escaped = loc.replace("|", "\\|")
        lines.append(
            f"| **{finding.severity.upper()}** | `{finding.rule_id}` | {title} | `{loc_escaped}` | {finding.confidence} ({score}) |"
        )

    if len(report.findings) > max_findings:
        remaining = len(report.findings) - max_findings
        lines.append("")
        lines.append(f"_...and {remaining} more finding(s). See the JSON artifact for full details._")

    return "\n".join(lines)


def write_github_summary(
    report: ScanReport, summary_path: Optional[Union[str, Path]] = None
) -> Optional[Path]:
    """Append Markdown summary to `summary_path` (e.g. `$GITHUB_STEP_SUMMARY`)."""
    if not summary_path:
        return None
    path = Path(summary_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(format_github_summary(report) + "\n\n")
    return path
