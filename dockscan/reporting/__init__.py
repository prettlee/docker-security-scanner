"""Reporting package for finding aggregation, scoring, terminal, and JSON output."""

from dockscan.reporting.aggregator import (
    aggregate_findings,
    convert_legacy_finding,
    normalize_finding,
)
from dockscan.reporting.github_summary import (
    FAIL_ON_CHOICES,
    format_github_summary,
    should_fail_ci,
    write_github_summary,
)
from dockscan.reporting.html_report import format_html_report, write_html_report
from dockscan.reporting.json_report import format_json_report, write_json_report
from dockscan.reporting.sarif_report import (
    build_sarif_dict,
    format_sarif_report,
    write_sarif_report,
)
from dockscan.reporting.scoring import (
    classify_severity,
    confidence_label_from_score,
    normalize_confidence,
    normalize_severity,
    score_confidence,
)
from dockscan.reporting.terminal import format_terminal_report

__all__ = [
    "FAIL_ON_CHOICES",
    "aggregate_findings",
    "build_sarif_dict",
    "classify_severity",
    "confidence_label_from_score",
    "convert_legacy_finding",
    "format_github_summary",
    "format_html_report",
    "format_json_report",
    "format_sarif_report",
    "format_terminal_report",
    "normalize_confidence",
    "normalize_finding",
    "normalize_severity",
    "score_confidence",
    "should_fail_ci",
    "write_github_summary",
    "write_html_report",
    "write_json_report",
    "write_sarif_report",
]
