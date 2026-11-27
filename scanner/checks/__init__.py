"""Security checks package."""

from typing import Callable, List

from scanner.checks.env_check import check_suspicious_env
from scanner.checks.ports_check import check_dangerous_ports
from scanner.checks.root_check import check_root_user
from scanner.checks.vuln_check import check_vulnerabilities
from scanner.models import Finding, ImageMetadata

CheckFn = Callable[[ImageMetadata], List[Finding]]

DEFAULT_CHECKS: List[CheckFn] = [
    check_root_user,
    check_dangerous_ports,
    check_suspicious_env,
    check_vulnerabilities,
]


def run_checks(
    metadata: ImageMetadata, checks: List[CheckFn] = DEFAULT_CHECKS
) -> List[Finding]:
    """Run all configured security checks against parsed metadata."""
    findings: List[Finding] = []
    for check in checks:
        findings.extend(check(metadata))
    return findings


__all__ = [
    "DEFAULT_CHECKS",
    "check_dangerous_ports",
    "check_root_user",
    "check_suspicious_env",
    "check_vulnerabilities",
    "run_checks",
]
