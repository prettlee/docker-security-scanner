"""SARIF v2.1.0 report generator for GitHub Code Scanning integration."""

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Union

from dockscan.models.finding import Finding, ScanReport

SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/"
    "sarif-2.1/schema/sarif-schema-2.1.0.json"
)
SARIF_VERSION = "2.1.0"
TOOL_NAME = "dockscan"
TOOL_INFO_URI = "https://github.com/prettlee/docker-security-scanner"
TOOL_VERSION = "0.1.0"

_SARIF_LEVEL_BY_SEVERITY = {
    "Critical": "error",
    "High": "error",
    "Medium": "warning",
    "Low": "note",
}

_SECURITY_SEVERITY_SCORE = {
    "Critical": "9.5",
    "High": "7.5",
    "Medium": "5.0",
    "Low": "2.5",
}


def _normalize_artifact_uri(finding: Finding, fallback_target: str) -> str:
    """Return a clean relative-style URI compatible with GitHub Code Scanning."""
    candidate = finding.file_path or finding.location or fallback_target
    # Strip internal `layer:<id>:` prefix if present without file_path
    if candidate.startswith("layer:"):
        parts = candidate.split(":", 2)
        if len(parts) == 3:
            candidate = parts[2]
    cleaned = candidate.lstrip("/")
    return cleaned or "Dockerfile"


def _build_message(finding: Finding) -> str:
    """Build a descriptive SARIF message without leaking raw credentials."""
    parts = [f"{finding.title}.", finding.description]
    if finding.package:
        pkg_info = f"Package: {finding.package}"
        if finding.detected_version:
            pkg_info += f" ({finding.detected_version})"
        if finding.cve:
            pkg_info += f", Advisory: {finding.cve}"
        if finding.fixed_version:
            pkg_info += f", Fixed: {finding.fixed_version}"
        parts.append(pkg_info + ".")
    if (
        finding.redacted_secret
        and finding.redacted_secret != "(none)"
        and not finding.package
    ):
        parts.append(f"Evidence: {finding.redacted_secret}.")
    parts.append(f"Remediation: {finding.remediation}")
    return " ".join(p.strip() for p in parts if p and p.strip())


def _fingerprint(finding: Finding) -> str:
    raw = f"{finding.rule_id}|{finding.location}|{finding.redacted_secret}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def _build_rule_descriptor(finding: Finding) -> Dict[str, Any]:
    """Create a SARIF `reportingDescriptor` entry for a finding's rule."""
    sec_score = _SECURITY_SEVERITY_SCORE.get(finding.severity, "5.0")
    precision = finding.confidence.lower() if finding.confidence in ("High", "Medium", "Low") else "medium"
    return {
        "id": finding.rule_id,
        "name": finding.title,
        "shortDescription": {"text": finding.title},
        "fullDescription": {"text": finding.description},
        "help": {
            "text": finding.remediation,
            "markdown": f"**Remediation:** {finding.remediation}",
        },
        "properties": {
            "tags": ["security", "docker", finding.category],
            "precision": precision,
            "security-severity": sec_score,
        },
    }


def _build_result(finding: Finding, fallback_target: str) -> Dict[str, Any]:
    """Convert a single `Finding` into a SARIF v2.1.0 `result` object."""
    uri = _normalize_artifact_uri(finding, fallback_target)
    physical_location: Dict[str, Any] = {
        "artifactLocation": {
            "uri": uri,
            "uriBaseId": "%SRCROOT%",
        }
    }
    if finding.line_number is not None and finding.line_number >= 1:
        physical_location["region"] = {"startLine": finding.line_number}

    props: Dict[str, Any] = {
        "severity": finding.severity,
        "confidence": finding.confidence,
        "confidenceScore": finding.confidence_score,
        "category": finding.category,
        "source": finding.source,
        "detector": finding.detector,
        "occurrences": finding.occurrences,
    }
    if finding.package:
        props["package"] = finding.package
    if finding.detected_version:
        props["detectedVersion"] = finding.detected_version
    if finding.fixed_version:
        props["fixedVersion"] = finding.fixed_version
    if finding.cve:
        props["cve"] = finding.cve

    return {
        "ruleId": finding.rule_id,
        "level": _SARIF_LEVEL_BY_SEVERITY.get(finding.severity, "warning"),
        "message": {"text": _build_message(finding)},
        "locations": [{"physicalLocation": physical_location}],
        "partialFingerprints": {
            "dockscan/v1": _fingerprint(finding),
        },
        "properties": props,
    }


def build_sarif_dict(report: ScanReport) -> Dict[str, Any]:
    """Convert a `ScanReport` into a SARIF v2.1.0 JSON-serializable dictionary."""
    rules_by_id: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []

    for finding in report.findings:
        if finding.rule_id not in rules_by_id:
            rules_by_id[finding.rule_id] = _build_rule_descriptor(finding)
        results.append(_build_result(finding, fallback_target=report.target))

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "informationUri": TOOL_INFO_URI,
                        "version": TOOL_VERSION,
                        "rules": list(rules_by_id.values()),
                    }
                },
                "automationDetails": {
                    "id": f"dockscan/{report.target}",
                },
                "results": results,
            }
        ],
    }


def format_sarif_report(report: ScanReport) -> str:
    """Serialize a `ScanReport` to formatted SARIF v2.1.0 JSON."""
    return json.dumps(build_sarif_dict(report), indent=2)


def write_sarif_report(report: ScanReport, output_path: Union[str, Path]) -> Path:
    """Write a SARIF v2.1.0 report to `output_path` and return the path."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(format_sarif_report(report) + "\n", encoding="utf-8")
    return path
