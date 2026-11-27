"""Reporting package for terminal and JSON output."""

from dockscan.reporting.json_report import format_json_report, write_json_report
from dockscan.reporting.terminal import format_terminal_report

__all__ = [
    "format_json_report",
    "format_terminal_report",
    "write_json_report",
]
