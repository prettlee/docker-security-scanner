"""Filesystem secret scanner across extracted Docker image layers."""

from typing import List

from dockscan.docker.layer_extractor import LayerFile
from dockscan.models.finding import Finding
from dockscan.secrets.entropy_detector import detect_high_entropy_in_text
from dockscan.secrets.pattern_detector import detect_patterns_in_text


def scan_layer_file(layer_file: LayerFile) -> List[Finding]:
    """Run regex + contextual and entropy secret detection on one layer file."""
    location_prefix = f"layer:{layer_file.layer_id}:{layer_file.file_path}"

    pattern_matches = detect_patterns_in_text(
        layer_file.content,
        source="filesystem",
        location_prefix=location_prefix,
        layer_id=layer_file.layer_id,
        file_path=layer_file.file_path,
        include_line_numbers=True,
    )
    findings: List[Finding] = [pm.finding for pm in pattern_matches]
    covered_spans = {
        (pm.line_number, pm.start_col, pm.end_col) for pm in pattern_matches
    }

    entropy_findings = detect_high_entropy_in_text(
        layer_file.content,
        source="filesystem",
        location_prefix=location_prefix,
        layer_id=layer_file.layer_id,
        file_path=layer_file.file_path,
        include_line_numbers=True,
        covered_spans=covered_spans,
    )
    findings.extend(entropy_findings)
    return findings
