"""CLI for standalone Dockerfile security analysis."""

import argparse
from pathlib import Path
import sys
from typing import List, Optional

from dockscan.dockerfile.analyzer import analyze_dockerfile_file
from dockscan.reporting import (
    format_json_report,
    format_terminal_report,
    write_html_report,
    write_json_report,
    write_sarif_report,
)


def build_parser() -> argparse.ArgumentParser:
    """Build argument parser for `python3 -m dockscan.dockerfile`."""
    parser = argparse.ArgumentParser(
        prog="dockscan.dockerfile",
        description="Analyze a Dockerfile statically for insecure construction practices.",
    )
    parser.add_argument(
        "dockerfile",
        help="Path to the Dockerfile to analyze.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print the scan report as JSON.",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Write the JSON report to the specified file path.",
    )
    parser.add_argument(
        "--html",
        help="Write an interactive HTML dashboard report to the specified path.",
    )
    parser.add_argument(
        "--sarif",
        help="Write a SARIF v2.1.0 report for GitHub Code Scanning to the specified path.",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entry point. Returns 0 if clean, 1 if findings exist, 2 on file error."""
    parser = build_parser()
    args = parser.parse_args(argv)

    path = Path(args.dockerfile)
    if not path.is_file():
        print(f"Error: Dockerfile not found: {path}", file=sys.stderr)
        return 2

    report = analyze_dockerfile_file(path)
    if args.json:
        print(format_json_report(report))
    else:
        print(format_terminal_report(report))

    if args.output:
        write_json_report(report, args.output)

    if args.html:
        write_html_report(report, args.html)

    if args.sarif:
        write_sarif_report(report, args.sarif)

    return 1 if report.findings else 0
