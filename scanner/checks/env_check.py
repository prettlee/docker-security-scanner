"""Suspicious environment variable (secret scanning) check."""

from typing import List, Tuple

from scanner.models import Finding, ImageMetadata

SUSPICIOUS_ENV_PATTERNS: Tuple[str, ...] = (
    "API_KEY",
    "SECRET",
    "PASSWORD",
    "TOKEN",
)


def is_suspicious_env_key(key: str) -> List[str]:
    """Return matching secret indicator patterns for an environment variable key."""
    upper_key = key.upper()
    return [pattern for pattern in SUSPICIOUS_ENV_PATTERNS if pattern in upper_key]


def redact_value(value: str) -> str:
    """Redact secret values so reports and findings never leak sensitive material."""
    if not value:
        return "<empty>"
    return f"***REDACTED*** ({len(value)} chars)"


def check_suspicious_env(metadata: ImageMetadata) -> List[Finding]:
    """Flag environment variable names that commonly hold secrets or credentials."""
    findings: List[Finding] = []

    for key in sorted(metadata.env):
        matched = is_suspicious_env_key(key)
        if not matched:
            continue

        value = metadata.env[key]
        has_value = bool(value)
        severity = "HIGH" if has_value else "MEDIUM"
        title = (
            f"Hardcoded secret-like environment variable '{key}'"
            if has_value
            else f"Suspicious secret-like environment variable '{key}'"
        )

        findings.append(
            Finding(
                rule_id="DOCKER-003",
                severity=severity,
                title=title,
                description=(
                    "Environment variables baked into a Docker image or container "
                    "configuration are readable via `docker inspect` and image layers. "
                    f"Variable '{key}' matches secret indicator(s): {', '.join(matched)}."
                ),
                remediation=(
                    "Remove credentials from Dockerfile `ENV` instructions and pass "
                    "secrets at runtime using Docker secrets, mounted files, or a "
                    "dedicated secret manager."
                ),
                evidence=f"Config.Env: {key}={redact_value(value)}",
            )
        )

    return findings
