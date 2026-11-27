"""Secret detection engines, rules, scanners, and aggregator."""

from dockscan.secrets.aggregator import aggregate_findings
from dockscan.secrets.entropy_detector import (
    detect_high_entropy_in_text,
    shannon_entropy,
)
from dockscan.secrets.filesystem_scanner import scan_layer_file
from dockscan.secrets.metadata_scanner import scan_metadata
from dockscan.secrets.pattern_detector import PatternMatch, detect_patterns_in_text
from dockscan.secrets.rules import SECRET_RULES, SecretRule

__all__ = [
    "PatternMatch",
    "SECRET_RULES",
    "SecretRule",
    "aggregate_findings",
    "detect_high_entropy_in_text",
    "detect_patterns_in_text",
    "scan_layer_file",
    "scan_metadata",
    "shannon_entropy",
]
