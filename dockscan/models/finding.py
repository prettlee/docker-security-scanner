"""Data models for Phase 4 & 5 security findings and unified scan reports."""

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

SEVERITY_ORDER: Dict[str, int] = {
    "Critical": 0,
    "High": 1,
    "Medium": 2,
    "Low": 3,
}

CONFIDENCE_ORDER: Dict[str, int] = {
    "High": 0,
    "Medium": 1,
    "Low": 2,
}

_DEFAULT_CONFIDENCE_SCORES: Dict[str, float] = {
    "High": 0.90,
    "Medium": 0.65,
    "Low": 0.35,
}


def redact_secret(value: str) -> str:
    """Return a redacted representation of a secret without leaking raw credentials."""
    cleaned = value.strip()
    if not cleaned:
        return "<empty>"
    if len(cleaned) <= 8:
        return f"***REDACTED*** ({len(cleaned)} chars)"
    return f"{cleaned[:4]}***REDACTED*** ({len(cleaned)} chars)"


@dataclass
class Finding:
    """Represents a unified security finding across secrets, config, and packages."""

    rule_id: str
    title: str
    severity: str
    confidence: str
    source: str  # "filesystem" | "metadata" | "config" | "package"
    location: str
    redacted_secret: str
    description: str
    remediation: str
    detector: str = "regex"  # "regex" | "entropy" | "metadata" | "config" | "vulnerability"
    category: str = "secret"  # "secret" | "misconfiguration" | "vulnerability"
    confidence_score: Optional[float] = None
    layer_id: Optional[str] = None
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    package: Optional[str] = None
    detected_version: Optional[str] = None
    fixed_version: Optional[str] = None
    cve: Optional[str] = None
    occurrences: int = 1

    def __post_init__(self) -> None:
        if self.confidence_score is None:
            self.confidence_score = _DEFAULT_CONFIDENCE_SCORES.get(self.confidence, 0.65)
        else:
            self.confidence_score = round(max(0.0, min(1.0, self.confidence_score)), 2)

    def to_dict(self) -> Dict[str, Any]:
        """Convert the finding to a JSON-serializable dictionary."""
        return asdict(self)


@dataclass
class ScanReport:
    """Aggregated scan output for a Docker image across all detectors."""

    target: str
    image_id: Optional[str] = None
    layers_scanned: int = 0
    files_scanned: int = 0
    packages_scanned: int = 0
    findings: List[Finding] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def severity_counts(self) -> Dict[str, int]:
        """Return finding counts grouped by severity level."""
        counts = {level: 0 for level in SEVERITY_ORDER}
        for finding in self.findings:
            if finding.severity in counts:
                counts[finding.severity] += 1
        return counts

    def category_counts(self) -> Dict[str, int]:
        """Return finding counts grouped by category."""
        counts: Dict[str, int] = {}
        for finding in self.findings:
            counts[finding.category] = counts.get(finding.category, 0) + 1
        return counts

    def confidence_counts(self) -> Dict[str, int]:
        """Return finding counts grouped by confidence tier."""
        counts = {level: 0 for level in CONFIDENCE_ORDER}
        for finding in self.findings:
            if finding.confidence in counts:
                counts[finding.confidence] += 1
        return counts

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the complete scan report."""
        return {
            "report_version": "1.0",
            "target": self.target,
            "image_id": self.image_id,
            "scan_stats": {
                "layers_scanned": self.layers_scanned,
                "files_scanned": self.files_scanned,
                "packages_scanned": self.packages_scanned,
            },
            # Retained for backwards compatibility with earlier report consumers.
            "layers_scanned": self.layers_scanned,
            "files_scanned": self.files_scanned,
            "summary": {
                "total_findings": len(self.findings),
                "by_severity": self.severity_counts(),
                "by_category": self.category_counts(),
                "by_confidence": self.confidence_counts(),
            },
            "warnings": list(self.warnings),
            "findings": [f.to_dict() for f in self.findings],
        }
