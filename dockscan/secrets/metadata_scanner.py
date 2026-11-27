"""Scan Docker image metadata (ENV variables, labels, and build history) for secrets."""

from typing import Dict, List

from dockscan.docker.metadata import DockerMetadata
from dockscan.models.finding import Finding, redact_secret
from dockscan.secrets.entropy_detector import detect_high_entropy_in_text
from dockscan.secrets.pattern_detector import detect_patterns_in_text
from dockscan.secrets.rules import SUSPICIOUS_KEY_INDICATORS, is_placeholder


def _matching_key_indicators(key: str) -> List[str]:
    upper = key.upper()
    return [ind for ind in SUSPICIOUS_KEY_INDICATORS if ind in upper]


def _scan_key_value_mapping(
    mapping: Dict[str, str],
    section: str,
) -> List[Finding]:
    findings: List[Finding] = []

    for key in sorted(mapping):
        value = mapping[key]
        location = f"metadata:{section}:{key}"
        combined_line = f"{key}={value}"

        pattern_matches = detect_patterns_in_text(
            combined_line,
            source="metadata",
            location_prefix=location,
            include_line_numbers=False,
        )
        findings.extend(pm.finding for pm in pattern_matches)
        if pattern_matches:
            continue

        entropy_findings = detect_high_entropy_in_text(
            combined_line,
            source="metadata",
            location_prefix=location,
            include_line_numbers=False,
        )
        if entropy_findings:
            findings.extend(entropy_findings)
            continue

        indicators = _matching_key_indicators(key)
        if indicators:
            has_real_value = bool(value) and not is_placeholder(value)
            findings.append(
                Finding(
                    rule_id="META-001",
                    title=f"Suspicious {section} variable '{key}'",
                    severity="High" if has_real_value else "Low",
                    confidence="Medium" if has_real_value else "Low",
                    source="metadata",
                    location=location,
                    redacted_secret=redact_secret(value),
                    description=(
                        f"Image metadata `{section}` key '{key}' matches credential indicator(s) "
                        f"({', '.join(indicators)}). Image metadata is visible to anyone who can inspect the image."
                    ),
                    remediation=(
                        f"Remove sensitive values from Dockerfile `{section.upper()}` instructions "
                        "and pass secrets at runtime."
                    ),
                    detector="metadata",
                )
            )

    return findings


def _scan_history(metadata: DockerMetadata) -> List[Finding]:
    findings: List[Finding] = []
    for entry in metadata.history:
        text = "\n".join(part for part in (entry.created_by, entry.comment) if part)
        if not text.strip():
            continue

        location = f"metadata:history:step_{entry.index}"
        pattern_matches = detect_patterns_in_text(
            text,
            source="metadata",
            location_prefix=location,
            include_line_numbers=False,
        )
        findings.extend(pm.finding for pm in pattern_matches)
        covered_spans = {
            (pm.line_number, pm.start_col, pm.end_col) for pm in pattern_matches
        }
        findings.extend(
            detect_high_entropy_in_text(
                text,
                source="metadata",
                location_prefix=location,
                include_line_numbers=False,
                covered_spans=covered_spans,
            )
        )
    return findings


def scan_metadata(metadata: DockerMetadata) -> List[Finding]:
    """Scan ENV variables, labels, and build history for leaked secrets."""
    findings: List[Finding] = []
    findings.extend(_scan_key_value_mapping(metadata.env, section="env"))
    findings.extend(_scan_key_value_mapping(metadata.labels, section="label"))
    findings.extend(_scan_history(metadata))
    return findings
