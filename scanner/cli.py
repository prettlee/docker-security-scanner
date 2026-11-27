"""Command-line interface for the Docker security scanner."""

import argparse
import sys
from typing import List, Optional

from scanner.reports import format_json_report, format_text_report, write_report
from scanner.scanner import scan_target
from scanner.utils.docker import DockerInspectError


def build_parser() -> argparse.ArgumentParser:
    """Create the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="docker-security-scanner",
        description="Analyze Docker images/containers for insecure configurations.",
    )
    parser.add_argument(
        "target",
        help="Docker image name/ID or container name/ID to inspect.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output the scan report as JSON.",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Optional file path to save the scan report.",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entry point. Returns 0 if clean, 1 if findings exist, 2 on error."""
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        result = scan_target(args.target)
    except DockerInspectError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    output = format_json_report(result) if args.json else format_text_report(result)
    print(output)

    if args.output:
        write_report(result, args.output, as_json=args.json)

    return 1 if result.findings else 0
