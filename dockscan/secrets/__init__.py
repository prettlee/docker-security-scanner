"""Secret detection engines, rules, scanners, and aggregator."""

from dockscan.secrets.pattern_detector import PatternMatch, detect_patterns_in_text
from dockscan.secrets.rules import SECRET_RULES, SecretRule

__all__ = [
    "PatternMatch",
    "SECRET_RULES",
    "SecretRule",
    "detect_patterns_in_text",
]
