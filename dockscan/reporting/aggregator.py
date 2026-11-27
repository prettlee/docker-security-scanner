"""Unified finding aggregation, normalization, and deduplication."""

import re
from typing import Dict, Iterable, List, Optional, Tuple

from dockscan.models.finding import CONFIDENCE_ORDER, SEVERITY_ORDER, Finding
from dockscan.reporting.scoring import classify_severity, score_confidence

_VULN_TITLE_RE = re.compile(
    r"^Vulnerable\s+(?P<eco>\S+)\s+package\s+'(?P<pkg>[^=]+)==(?P<ver>[^']+)':\s*(?P<ids>.+)$"
)
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b")


def _extract_vuln_fields(legacy_finding: object) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
    """Extract `(package, detected_version, cve, ecosystem)` from a Phase 3 finding."""
    title = str(getattr(legacy_finding, "title", ""))
    match = _VULN_TITLE_RE.match(title)
    if not match:
        return None, None, None, None

    ids_part = match.group("ids")
    cve_match = _CVE_RE.search(ids_part)
    cve = cve_match.group(0) if cve_match else ids_part.split("(", 1)[0].strip()
    return match.group("pkg"), match.group("ver"), cve, match.group("eco")


def convert_legacy_finding(legacy_finding: object) -> Finding:
    """Adapt a Phase 2/3 `scanner.models.Finding` into a unified `dockscan` `Finding`."""
    rule_id = str(getattr(legacy_finding, "rule_id", "DOCKER-000"))
    raw_sev = str(getattr(legacy_finding, "severity", "Medium"))
    title = str(getattr(legacy_finding, "title", "Security Finding"))
    description = str(getattr(legacy_finding, "description", ""))
    remediation = str(getattr(legacy_finding, "remediation", ""))
    evidence = getattr(legacy_finding, "evidence", None) or ""

    if rule_id == "DOCKER-004":
        pkg, ver, cve, eco = _extract_vuln_fields(legacy_finding)
        category = "vulnerability"
        source = "package"
        detector = "vulnerability"
        location = f"Package Database ({eco})" if eco else "Package Database"
        clean_title = f"Vulnerable {pkg} Package" if pkg else title
        confidence, confidence_score = score_confidence(detector="vulnerability")
    else:
        pkg, ver, cve = None, None, None
        category = "secret" if rule_id == "DOCKER-003" else "misconfiguration"
        source = "config"
        detector = "config"
        location = "Image Configuration"
        clean_title = title
        confidence, confidence_score = score_confidence(detector="config")

    severity = classify_severity(raw_severity=raw_sev, rule_id=rule_id)
    return Finding(
        rule_id=rule_id,
        title=clean_title,
        severity=severity,
        confidence=confidence,
        confidence_score=confidence_score,
        source=source,
        location=location,
        redacted_secret=str(evidence) if evidence else "(none)",
        description=description,
        remediation=remediation,
        detector=detector,
        category=category,
        package=pkg,
        detected_version=ver,
        cve=cve,
    )


def normalize_finding(finding: Finding) -> Finding:
    """Ensure severity classification and numeric confidence scoring are populated."""
    finding.severity = classify_severity(
        raw_severity=finding.severity, rule_id=finding.rule_id
    )
    label, score = score_confidence(
        detector=finding.detector,
        confidence=finding.confidence,
        has_context=finding.severity in ("High", "Critical"),
        explicit_score=finding.confidence_score,
    )
    finding.confidence = label
    finding.confidence_score = score
    return finding


def aggregate_findings(findings: Iterable[Finding]) -> List[Finding]:
    """Normalize, deduplicate, and rank findings by severity and confidence."""
    deduped: Dict[Tuple[str, str, str], Finding] = {}

    for raw in findings:
        finding = normalize_finding(raw)
        key = (finding.rule_id, finding.location, finding.redacted_secret)
        existing = deduped.get(key)
        if existing is None:
            deduped[key] = finding
        else:
            existing.occurrences += finding.occurrences
            if (finding.confidence_score or 0.0) > (existing.confidence_score or 0.0):
                existing.confidence = finding.confidence
                existing.confidence_score = finding.confidence_score

    ordered = list(deduped.values())
    ordered.sort(
        key=lambda f: (
            SEVERITY_ORDER.get(f.severity, 99),
            CONFIDENCE_ORDER.get(f.confidence, 99),
            -(f.confidence_score or 0.0),
            f.rule_id,
            f.location,
        )
    )
    return ordered
