"""Command-line interface for the Docker security scanner."""

import argparse
import json
import sys
from typing import List, Optional

from scanner.checks import run_checks
from scanner.inspector import DockerInspectError, inspect_target
from scanner.models import ScanResult


def _format_text_report(result: ScanResult) -> str:
    """Format scan metadata and findings into a readable terminal report."""
    meta = result.metadata
    lines: List[str] = [
        f"Target: {meta.target}",
        "-" * 60,
        "Metadata:",
        f"  User:          {meta.user or '(empty -> defaults to root)'}",
        f"  Exposed Ports: {', '.join(meta.exposed_ports) if meta.exposed_ports else '(none)'}",
        f"  Entrypoint:    {meta.entrypoint if meta.entrypoint else '(none)'}",
        f"  Env Vars:      {len(meta.env)} variable(s)",
    ]
    for key in sorted(meta.env):
        lines.append(f"    - {key}={meta.env[key]}")

    cap_add = ", ".join(meta.capabilities.add) if meta.capabilities.add else "(none)"
    cap_drop = ", ".join(meta.capabilities.drop) if meta.capabilities.drop else "(none)"
    lines.append(f"  Capabilities:  CapAdd={cap_add}, CapDrop={cap_drop}")
    lines.append("")
    lines.append(f"Findings ({len(result.findings)}):")

    if not result.findings:
        lines.append("  [PASS] No issues detected.")
    else:
        for finding in result.findings:
            lines.append(f"  [{finding.severity}] {finding.rule_id}: {finding.title}")
            if finding.evidence:
                lines.append(f"    Evidence:    {finding.evidence}")
            lines.append(f"    Why:         {finding.description}")
            lines.append(f"    Remediation: {finding.remediation}")

    return "\n".join(lines)


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
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entry point. Returns 0 if clean, 1 if findings exist, 2 on error."""
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        metadata = inspect_target(args.target)
    except DockerInspectError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    findings = run_checks(metadata)
    result = ScanResult(metadata=metadata, findings=findings)

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print(_format_text_report(result))

    return 1 if findings else 0
