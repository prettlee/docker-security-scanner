"""Data models for Phase 4 secret findings and scan reports."""

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
    """Represents a single secret or credential exposure finding."""

    rule_id: str
    title: str
    severity: str
    confidence: str
    source: str  # "filesystem" | "metadata"
    location: str
    redacted_secret: str
    description: str
    remediation: str
    detector: str = "regex"  # "regex" | "entropy" | "metadata"
    layer_id: Optional[str] = None
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    occurrences: int = 1

    def to_dict(self) -> Dict[str, Any]:
        """Convert the finding to a JSON-serializable dictionary."""
        return asdict(self)


@dataclass
class ScanReport:
    """Aggregated scan output for a Docker image."""

    target: str
    image_id: Optional[str] = None
    layers_scanned: int = 0
    files_scanned: int = 0
    findings: List[Finding] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def severity_counts(self) -> Dict[str, int]:
        """Return finding counts grouped by severity level."""
        counts = {level: 0 for level in SEVERITY_ORDER}
        for finding in self.findings:
            if finding.severity in counts:
                counts[finding.severity] += 1
        return counts

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the complete scan report."""
        return {
            "target": self.target,
            "image_id": self.image_id,
            "layers_scanned": self.layers_scanned,
            "files_scanned": self.files_scanned,
            "summary": {
                "total_findings": len(self.findings),
                "by_severity": self.severity_counts(),
            },
            "warnings": list(self.warnings),
            "findings": [f.to_dict() for f in self.findings],
        }
