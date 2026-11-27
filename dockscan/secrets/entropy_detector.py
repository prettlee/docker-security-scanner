"""Shannon entropy-based secret detector with contextual confidence scoring."""

from collections import Counter
import math
import re
from typing import List, Set, Tuple

from dockscan.models.finding import Finding, redact_secret
from dockscan.secrets.rules import CONTEXT_KEYWORDS, is_placeholder

_CANDIDATE_TOKEN_RE = re.compile(r"[A-Za-z0-9+/=_-]{20,}")
_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_DIGEST_PREFIX_RE = re.compile(r"(?i)(?:sha256|sha512|sha1|md5|integrity)[:=]\s*$")


def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy (bits per character) for `data`."""
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    return -sum(
        (count / length) * math.log2(count / length) for count in counts.values()
    )


def _has_secret_context(line: str) -> bool:
    lower = line.lower()
    return any(keyword in lower for keyword in CONTEXT_KEYWORDS)


def _is_likely_non_secret_token(token: str, line: str, start_idx: int) -> bool:
    """Filter common high-entropy non-secrets (UUIDs, digests, paths, package strings)."""
    if is_placeholder(token):
        return True
    if _UUID_RE.match(token):
        return True
    prefix = line[max(0, start_idx - 24) : start_idx]
    if _DIGEST_PREFIX_RE.search(prefix):
        return True
    if _HEX_RE.match(token) and not _has_secret_context(line):
        return True
    if (
        token.islower()
        and ("-" in token or "_" in token)
        and not any(c.isdigit() for c in token)
    ):
        return True
    return False


def detect_high_entropy_in_text(
    text: str,
    *,
    source: str,
    location_prefix: str,
    layer_id: str = "",
    file_path: str = "",
    include_line_numbers: bool = True,
    covered_spans: Set[Tuple[int, int, int]] = frozenset(),  # type: ignore[assignment]
    min_entropy_with_context: float = 3.8,
    min_entropy_without_context: float = 4.6,
) -> List[Finding]:
    """Scan lines for high-entropy tokens, separating severity and confidence."""
    findings: List[Finding] = []

    for line_no, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        has_context = _has_secret_context(line)

        for match in _CANDIDATE_TOKEN_RE.finditer(line):
            token = match.group(0)
            start_col, end_col = match.start(), match.end()

            if any(
                c_line == line_no and not (end_col <= c_start or start_col >= c_end)
                for c_line, c_start, c_end in covered_spans
            ):
                continue

            if _is_likely_non_secret_token(token, line, start_col):
                continue

            entropy = shannon_entropy(token)
            threshold = (
                min_entropy_with_context
                if has_context
                else min_entropy_without_context
            )
            if entropy < threshold:
                continue

            if has_context:
                severity = "High"
                confidence = "Medium"
                title = "High-entropy secret candidate with credential context"
            else:
                severity = "Low"
                confidence = "Low"
                title = "High-entropy string detected (possible secret)"

            location = (
                f"{location_prefix}:{line_no}"
                if include_line_numbers
                else location_prefix
            )
            findings.append(
                Finding(
                    rule_id="ENT-001",
                    title=title,
                    severity=severity,
                    confidence=confidence,
                    source=source,
                    location=location,
                    redacted_secret=redact_secret(token),
                    description=(
                        f"Detected a high-entropy token (Shannon entropy {entropy:.2f} bits/char) "
                        "which may represent an API key, cryptographic key, or password."
                    ),
                    remediation=(
                        "Verify whether this token is a credential. If so, rotate it and "
                        "move it out of the image into runtime secrets."
                    ),
                    detector="entropy",
                    layer_id=layer_id or None,
                    file_path=file_path or None,
                    line_number=line_no if include_line_numbers else None,
                )
            )

    return findings
