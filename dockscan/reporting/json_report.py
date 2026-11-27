"""JSON report formatter and writer."""

import json
from pathlib import Path
from typing import Union

from dockscan.models.finding import ScanReport


def format_json_report(report: ScanReport) -> str:
    """Serialize a `ScanReport` to formatted JSON."""
    return json.dumps(report.to_dict(), indent=2)


def write_json_report(report: ScanReport, output_path: Union[str, Path]) -> Path:
    """Write a JSON `ScanReport` to `output_path` and return the resolved path."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(format_json_report(report) + "\n", encoding="utf-8")
    return path
