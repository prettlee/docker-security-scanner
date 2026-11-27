"""Root user security check."""

from typing import List

from scanner.models import Finding, ImageMetadata


def check_root_user(metadata: ImageMetadata) -> List[Finding]:
    """Flag images or containers configured to run as root.

    In Docker, an empty `"User": ""` defaults to root (UID 0), and explicit
    `"User": "root"` or UID `"0"` (including `user:group` forms like `root:root`
    or `0:0`) runs the process as root.
    """
    user_part = metadata.user.split(":", 1)[0].strip()
    if user_part in ("", "root", "0"):
        configured = repr(metadata.user) if metadata.user else '"" (defaults to root)'
        return [
            Finding(
                rule_id="DOCKER-001",
                severity="HIGH",
                title="Container runs as root user",
                description=(
                    "The image/container is configured to run as root. "
                    "If an attacker compromises the application and achieves a "
                    "container escape, running as UID 0 makes privilege escalation "
                    "and host compromise significantly worse."
                ),
                remediation=(
                    "Create a dedicated non-root user and group in your Dockerfile "
                    "and switch to it with `USER <non-root-user>`."
                ),
                evidence=f"Config.User = {configured}",
            )
        ]
    return []
