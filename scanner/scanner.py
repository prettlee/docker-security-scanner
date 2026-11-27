"""Core scanner orchestration combining inspection, package extraction, and checks."""

from typing import List

from scanner.checks import (
    check_dangerous_ports,
    check_root_user,
    check_suspicious_env,
    check_vulnerabilities,
    run_checks,
)
from scanner.models import Finding, ScanResult
from scanner.utils.docker import inspect_target, parse_inspect_output
from scanner.utils.osv import OSVApiError
from scanner.utils.packages import PackageExtractionError, extract_packages


def scan_target(target: str, include_vulns: bool = True) -> ScanResult:
    """Inspect a Docker image or container, extract packages, and run checks."""
    metadata = inspect_target(target)
    warnings: List[str] = []

    config_checks = [
        check_root_user,
        check_dangerous_ports,
        check_suspicious_env,
    ]
    findings: List[Finding] = run_checks(metadata, checks=config_checks)

    if include_vulns:
        try:
            metadata.packages = extract_packages(metadata)
        except PackageExtractionError as exc:
            warnings.append(str(exc))

        if metadata.packages:
            try:
                findings.extend(check_vulnerabilities(metadata))
            except OSVApiError as exc:
                warnings.append(f"Vulnerability lookup skipped: {exc}")

    return ScanResult(metadata=metadata, findings=findings, warnings=warnings)


def scan_inspect_json(raw_json: str, target: str) -> ScanResult:
    """Parse raw `docker inspect` JSON and run configuration security checks."""
    metadata = parse_inspect_output(raw_json, target=target)
    findings = run_checks(
        metadata,
        checks=[check_root_user, check_dangerous_ports, check_suspicious_env],
    )
    return ScanResult(metadata=metadata, findings=findings)
