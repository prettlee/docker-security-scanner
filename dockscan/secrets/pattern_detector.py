"""Regex and contextual secret pattern detector."""

from dataclasses import dataclass
from typing import List

from dockscan.models.finding import Finding, redact_secret
from dockscan.secrets.rules import CONTEXT_KEYWORDS, SECRET_RULES, is_placeholder


@dataclass(frozen=True)
class PatternMatch:
    """Raw pattern match paired with its matched span for deduplication."""

    finding: Finding
    line_number: int
    start_col: int
    end_col: int


def _has_context_keyword(line: str) -> bool:
    lower = line.lower()
    return any(keyword in lower for keyword in CONTEXT_KEYWORDS)


def detect_patterns_in_text(
    text: str,
    *,
    source: str,
    location_prefix: str,
    layer_id: str = "",
    file_path: str = "",
    include_line_numbers: bool = True,
) -> List[PatternMatch]:
    """Scan multi-line text using regex and contextual secret rules."""
    matches: List[PatternMatch] = []

    for line_no, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue

        for rule in SECRET_RULES:
            if rule.requires_context and not _has_context_keyword(line):
                continue

            for match in rule.pattern.finditer(line):
                try:
                    raw_secret = match.group(rule.secret_group)
                except IndexError:
                    raw_secret = match.group(0)

                if is_placeholder(raw_secret):
                    continue

                location = (
                    f"{location_prefix}:{line_no}"
                    if include_line_numbers
                    else location_prefix
                )
                finding = Finding(
                    rule_id=rule.rule_id,
                    title=rule.title,
                    severity=rule.severity,
                    confidence=rule.confidence,
                    source=source,
                    location=location,
                    redacted_secret=redact_secret(raw_secret),
                    description=rule.description,
                    remediation=rule.remediation,
                    detector="regex",
                    layer_id=layer_id or None,
                    file_path=file_path or None,
                    line_number=line_no if include_line_numbers else None,
                )
                matches.append(
                    PatternMatch(
                        finding=finding,
                        line_number=line_no,
                        start_col=match.start(rule.secret_group),
                        end_col=match.end(rule.secret_group),
                    )
                )

    return matches
