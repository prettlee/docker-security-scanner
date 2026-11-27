"""Format and optionally write scan reports in text or JSON."""

import json
from pathlib import Path
from typing import List, Union

from scanner.checks.env_check import is_suspicious_env_key, redact_value
from scanner.models import ScanResult


def format_text_report(result: ScanResult) -> str:
    """Format scan metadata and findings into a readable terminal report."""
    meta = result.metadata
    lines: List[str] = [
        f"Target: {meta.target}",
        "-" * 60,
        "Metadata:",
        f"  User:          {meta.user or '(empty -> defaults to root)'}",
        f"  Exposed Ports: {', '.join(meta.exposed_ports) if meta.exposed_ports else '(none)'}",
    ]

    if meta.port_bindings:
        bindings_str = ", ".join(
            f"{b.host_ip or '0.0.0.0'}:{b.host_port}->{b.container_port}"
            for b in meta.port_bindings
        )
        lines.append(f"  Port Bindings: {bindings_str}")

    lines.extend(
        [
            f"  Entrypoint:    {meta.entrypoint if meta.entrypoint else '(none)'}",
            f"  Env Vars:      {len(meta.env)} variable(s)",
        ]
    )
    for key in sorted(meta.env):
        display_val = (
            redact_value(meta.env[key])
            if is_suspicious_env_key(key)
            else meta.env[key]
        )
        lines.append(f"    - {key}={display_val}")

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


def format_json_report(result: ScanResult) -> str:
    """Serialize a ScanResult into formatted JSON."""
    return json.dumps(result.to_dict(), indent=2)


def write_report(
    result: ScanResult, output_path: Union[str, Path], as_json: bool = False
) -> Path:
    """Write a text or JSON scan report to disk and return the destination path."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    content = format_json_report(result) if as_json else format_text_report(result)
    path.write_text(content + "\n", encoding="utf-8")
    return path
