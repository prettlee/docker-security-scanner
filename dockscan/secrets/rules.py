"""Regex and contextual secret detection rules."""

from dataclasses import dataclass
import re
from typing import Pattern, Tuple

SUSPICIOUS_KEY_INDICATORS: Tuple[str, ...] = (
    "API_KEY",
    "APIKEY",
    "SECRET",
    "PASSWORD",
    "PASSWD",
    "TOKEN",
    "PRIVATE_KEY",
    "ACCESS_KEY",
    "CLIENT_SECRET",
    "AUTH_KEY",
    "CREDENTIALS",
)

CONTEXT_KEYWORDS: Tuple[str, ...] = (
    "secret",
    "password",
    "passwd",
    "pwd",
    "token",
    "api_key",
    "apikey",
    "access_key",
    "private_key",
    "auth",
    "bearer",
    "credential",
    "client_secret",
)

_PLACEHOLDER_EXACT = frozenset(
    {
        "changeme",
        "change_me",
        "change-me",
        "example",
        "placeholder",
        "replace_me",
        "replace-me",
        "todo",
        "none",
        "null",
        "true",
        "false",
        "your_api_key",
        "your_secret",
        "your_token",
        "your_password",
    }
)


def is_placeholder(value: str) -> bool:
    """Return True if `value` looks like an unpopulated template or placeholder."""
    stripped = value.strip().strip("\"'")
    if not stripped:
        return True
    lower = stripped.lower()
    if lower in _PLACEHOLDER_EXACT:
        return True
    if stripped.startswith(("${", "{{", "<")) and stripped.endswith(("}", "}}", ">")):
        return True
    if len(set(stripped)) <= 2 and len(stripped) >= 6:
        return True
    return False


@dataclass(frozen=True)
class SecretRule:
    """Definition for a regex-based (and optionally contextual) secret rule."""

    rule_id: str
    title: str
    pattern: Pattern[str]
    severity: str
    confidence: str
    description: str
    remediation: str
    secret_group: int = 0
    requires_context: bool = False


SECRET_RULES: Tuple[SecretRule, ...] = (
    SecretRule(
        rule_id="SEC-001",
        title="AWS Access Key ID exposed",
        pattern=re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b"),
        severity="Critical",
        confidence="High",
        description="An AWS Access Key ID was found, enabling potential AWS API authentication.",
        remediation="Revoke the exposed key in AWS IAM, rotate credentials, and inject secrets at runtime.",
        secret_group=1,
    ),
    SecretRule(
        rule_id="SEC-002",
        title="AWS Secret Access Key exposed",
        pattern=re.compile(
            r"(?i)(?:aws_secret_access_key|aws_secret_key|secret_access_key)\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})[\"']?"
        ),
        severity="Critical",
        confidence="High",
        description="An AWS Secret Access Key assignment was detected.",
        remediation="Immediately deactivate the IAM access key and pass AWS credentials via IAM roles or runtime secrets.",
        secret_group=1,
    ),
    SecretRule(
        rule_id="SEC-003",
        title="Private cryptographic key material exposed",
        pattern=re.compile(
            r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----)"
        ),
        severity="Critical",
        confidence="High",
        description="A PEM-encoded private key header was found inside the image.",
        remediation="Remove private keys from the image layers, revoke/reissue the key pair, and mount keys at runtime.",
        secret_group=1,
    ),
    SecretRule(
        rule_id="SEC-004",
        title="GitHub personal or app token exposed",
        pattern=re.compile(
            r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}|github_pat_[A-Za-z0-9_]{22,})\b"
        ),
        severity="Critical",
        confidence="High",
        description="A GitHub access token was detected, risking repository and CI/CD compromise.",
        remediation="Revoke the GitHub token immediately and use short-lived tokens or secret mounts.",
        secret_group=1,
    ),
    SecretRule(
        rule_id="SEC-005",
        title="Stripe live API key exposed",
        pattern=re.compile(r"\b([sr]k_live_[0-9a-zA-Z]{16,})\b"),
        severity="Critical",
        confidence="High",
        description="A live Stripe secret or restricted key was detected.",
        remediation="Roll the key in the Stripe Dashboard and pass it via runtime environment/secrets.",
        secret_group=1,
    ),
    SecretRule(
        rule_id="SEC-006",
        title="Slack API or webhook token exposed",
        pattern=re.compile(r"\b(xox[baprs]-[0-9A-Za-z-]{10,})\b"),
        severity="High",
        confidence="High",
        description="A Slack token was found, allowing unauthorized workspace API access.",
        remediation="Revoke and regenerate the Slack token in your Slack app settings.",
        secret_group=1,
    ),
    SecretRule(
        rule_id="SEC-007",
        title="Google Cloud API key exposed",
        pattern=re.compile(r"\b(AIza[0-9A-Za-z_-]{35})\b"),
        severity="High",
        confidence="High",
        description="A Google Cloud API key was found in the image.",
        remediation="Restrict or regenerate the API key in Google Cloud Console and inject it at runtime.",
        secret_group=1,
    ),
    SecretRule(
        rule_id="SEC-008",
        title="Database or service URI with embedded credentials",
        pattern=re.compile(
            r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqp|mssql)://[^:\s/]+:([^@\s/]+)@[^\s\"']+"
        ),
        severity="High",
        confidence="High",
        description="A connection string containing an embedded password was detected.",
        remediation="Remove credentials from connection URLs in image files/configs and supply them at runtime.",
        secret_group=1,
    ),
    SecretRule(
        rule_id="SEC-009",
        title="JSON Web Token (JWT) embedded in image",
        pattern=re.compile(
            r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b"
        ),
        severity="Medium",
        confidence="Medium",
        description="A signed JWT was found hardcoded inside the image.",
        remediation="Ensure static or long-lived JWTs are not baked into container images.",
        secret_group=1,
    ),
    SecretRule(
        rule_id="SEC-010",
        title="Hardcoded credential assignment detected",
        pattern=re.compile(
            r"(?i)\b(?:api_key|apikey|secret_key|client_secret|auth_token|access_token|refresh_token|db_password|password|passwd|secret|token)\b\s*[:=]\s*[\"']?([A-Za-z0-9_./+=-]{8,})[\"']?"
        ),
        severity="High",
        confidence="Medium",
        description="A contextual assignment of a secret, password, or token literal was found.",
        remediation="Replace hardcoded credentials with runtime secret injection (Docker secrets, vault, or env injection).",
        secret_group=1,
        requires_context=True,
    ),
)
