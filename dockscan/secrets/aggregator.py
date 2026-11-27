"""Deduplicate, rank, and aggregate secret findings."""

from typing import Dict, Iterable, List, Tuple

from dockscan.models.finding import CONFIDENCE_ORDER, SEVERITY_ORDER, Finding


def aggregate_findings(findings: Iterable[Finding]) -> List[Finding]:
    """Deduplicate identical findings and sort by severity, confidence, and location."""
    deduped: Dict[Tuple[str, str, str], Finding] = {}

    for finding in findings:
        key = (finding.rule_id, finding.location, finding.redacted_secret)
        existing = deduped.get(key)
        if existing is None:
            deduped[key] = finding
        else:
            existing.occurrences += finding.occurrences

    ordered = list(deduped.values())
    ordered.sort(
        key=lambda f: (
            SEVERITY_ORDER.get(f.severity, 99),
            CONFIDENCE_ORDER.get(f.confidence, 99),
            f.rule_id,
            f.location,
        )
    )
    return ordered
