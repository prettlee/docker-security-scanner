"""Core scanner orchestration combining inspection and security checks."""

from scanner.checks import run_checks
from scanner.models import ScanResult
from scanner.utils.docker import inspect_target, parse_inspect_output


def scan_target(target: str) -> ScanResult:
    """Inspect a Docker image or container via `docker inspect` and run checks."""
    metadata = inspect_target(target)
    findings = run_checks(metadata)
    return ScanResult(metadata=metadata, findings=findings)


def scan_inspect_json(raw_json: str, target: str) -> ScanResult:
    """Parse raw `docker inspect` JSON and run security checks."""
    metadata = parse_inspect_output(raw_json, target=target)
    findings = run_checks(metadata)
    return ScanResult(metadata=metadata, findings=findings)
