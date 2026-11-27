"""Severity classification and confidence scoring for security findings."""

from typing import Optional, Tuple

from dockscan.models.finding import CONFIDENCE_ORDER, SEVERITY_ORDER

_SEVERITY_ALIASES = {
    "CRITICAL": "Critical",
    "HIGH": "High",
    "MEDIUM": "Medium",
    "MODERATE": "Medium",
    "LOW": "Low",
}

_CONFIDENCE_ALIASES = {
    "HIGH": "High",
    "MEDIUM": "Medium",
    "LOW": "Low",
}

_DEFAULT_SCORE_BY_CONFIDENCE = {
    "High": 0.90,
    "Medium": 0.65,
    "Low": 0.35,
}


def normalize_severity(severity: Optional[str], default: str = "Medium") -> str:
    """Normalize any severity label to Critical, High, Medium, or Low."""
    if not severity:
        return default
    return _SEVERITY_ALIASES.get(severity.strip().upper(), default)


def classify_severity(
    *,
    raw_severity: Optional[str] = None,
    cvss_score: Optional[float] = None,
    rule_id: Optional[str] = None,
) -> str:
    """Classify a finding into Critical, High, Medium, or Low severity.

    Precedence: explicit CVSS v3 score -> known rule defaults -> normalized string.
    """
    if cvss_score is not None:
        if cvss_score >= 9.0:
            return "Critical"
        if cvss_score >= 7.0:
            return "High"
        if cvss_score >= 4.0:
            return "Medium"
        return "Low"

    if raw_severity:
        normalized = normalize_severity(raw_severity, default="")
        if normalized in SEVERITY_ORDER:
            return normalized

    if rule_id and rule_id.startswith(("SEC-001", "SEC-002", "SEC-003", "SEC-004", "SEC-005")):
        return "Critical"

    return "Medium"


def normalize_confidence(confidence: Optional[str], default: str = "Medium") -> str:
    """Normalize a confidence label to High, Medium, or Low."""
    if not confidence:
        return default
    return _CONFIDENCE_ALIASES.get(confidence.strip().upper(), default)


def confidence_label_from_score(score: float) -> str:
    """Map a numeric confidence score in [0.0, 1.0] to High, Medium, or Low."""
    if score >= 0.80:
        return "High"
    if score >= 0.50:
        return "Medium"
    return "Low"


def score_confidence(
    *,
    detector: str,
    confidence: Optional[str] = None,
    has_context: bool = False,
    entropy: Optional[float] = None,
    explicit_score: Optional[float] = None,
) -> Tuple[str, float]:
    """Compute `(confidence_label, confidence_score)` in [0.0, 1.0]."""
    if explicit_score is not None:
        clamped = round(max(0.0, min(1.0, explicit_score)), 2)
        return confidence_label_from_score(clamped), clamped

    det = detector.lower()
    if det in ("config", "vulnerability"):
        score = 1.0 if det == "config" else 0.90
    elif det == "regex":
        norm = normalize_confidence(confidence, default="High")
        score = 0.95 if norm == "High" else (0.70 if norm == "Medium" else 0.45)
    elif det == "entropy":
        if has_context:
            score = 0.72 if (entropy is not None and entropy >= 4.5) else 0.62
        else:
            score = 0.40 if (entropy is not None and entropy >= 5.0) else 0.30
    elif det == "metadata":
        norm = normalize_confidence(confidence, default="Medium")
        score = _DEFAULT_SCORE_BY_CONFIDENCE.get(norm, 0.65)
    else:
        norm = normalize_confidence(confidence, default="Medium")
        score = _DEFAULT_SCORE_BY_CONFIDENCE.get(norm, 0.65)

    clamped = round(max(0.0, min(1.0, score)), 2)
    label = confidence_label_from_score(clamped)
    if label not in CONFIDENCE_ORDER:
        label = "Medium"
    return label, clamped
