"""Reporting package for finding aggregation, scoring, terminal, and JSON output."""

from dockscan.reporting.aggregator import (
    aggregate_findings,
    convert_legacy_finding,
    normalize_finding,
)
from dockscan.reporting.json_report import format_json_report, write_json_report
from dockscan.reporting.scoring import (
    classify_severity,
    confidence_label_from_score,
    normalize_confidence,
    normalize_severity,
    score_confidence,
)
from dockscan.reporting.terminal import format_terminal_report

__all__ = [
    "aggregate_findings",
    "classify_severity",
    "confidence_label_from_score",
    "convert_legacy_finding",
    "format_json_report",
    "format_terminal_report",
    "normalize_confidence",
    "normalize_finding",
    "normalize_severity",
    "score_confidence",
    "write_json_report",
]
