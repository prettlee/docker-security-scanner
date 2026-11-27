"""Main orchestrator and CLI for Phase 4 Docker secret scanning."""

import argparse
from pathlib import Path
import sys
import tempfile
from typing import List, Optional

from dockscan.docker.image_loader import ImageLoadError, cleanup_temp_tar, load_image_tar
from dockscan.docker.layer_extractor import (
    DEFAULT_MAX_FILE_BYTES,
    LayerExtractionError,
    iter_layer_text_files,
    read_image_manifest,
)
from dockscan.docker.metadata import extract_metadata_from_tar
from dockscan.models.finding import Finding, ScanReport
from dockscan.reporting import format_json_report, format_terminal_report, write_json_report
from dockscan.secrets.aggregator import aggregate_findings
from dockscan.secrets.filesystem_scanner import scan_layer_file
from dockscan.secrets.metadata_scanner import scan_metadata


def scan_image(
    target: str,
    *,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
    prefer_sdk: bool = True,
) -> ScanReport:
    """Statically scan a Docker image (or `.tar` archive) for secrets.

    Never executes the target image. Exports via Docker SDK or `docker image save`,
    extracts metadata and individual layers via Python `tarfile`, and runs regex,
    contextual, and entropy secret detection.
    """
    temp_dir: Optional[Path] = None
    target_path = Path(target)
    if not target_path.is_file():
        temp_dir = Path(tempfile.mkdtemp(prefix="dockscan_"))

    try:
        tar_path = load_image_tar(
            target,
            dest_dir=temp_dir or target_path.parent,
            prefer_sdk=prefer_sdk,
        )
        manifest = read_image_manifest(tar_path)
        metadata = extract_metadata_from_tar(tar_path, manifest.config_path)

        raw_findings: List[Finding] = []
        raw_findings.extend(scan_metadata(metadata))

        layers_seen = set()
        files_scanned = 0
        for layer_idx, _layer_id, layer_file in iter_layer_text_files(
            tar_path,
            manifest.layer_paths,
            max_file_bytes=max_file_bytes,
        ):
            layers_seen.add(layer_idx)
            if layer_file is not None:
                files_scanned += 1
                raw_findings.extend(scan_layer_file(layer_file))

        aggregated = aggregate_findings(raw_findings)
        return ScanReport(
            target=target,
            image_id=metadata.image_id or None,
            layers_scanned=len(layers_seen),
            files_scanned=files_scanned,
            findings=aggregated,
        )
    finally:
        cleanup_temp_tar(temp_dir)


def build_parser() -> argparse.ArgumentParser:
    """Build CLI argument parser for `dockscan`."""
    parser = argparse.ArgumentParser(
        prog="dockscan",
        description="Statically scan Docker image layers and metadata for exposed secrets.",
    )
    parser.add_argument(
        "target",
        help="Docker image name/tag/ID or path to a saved `.tar` image archive.",
    )
    parser.add_argument(
        "--max-file-mb",
        type=float,
        default=10.0,
        help="Maximum text file size to scan in MB (default: 10).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print the scan report as JSON.",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Write the JSON report to the specified file path.",
    )
    parser.add_argument(
        "--no-sdk",
        action="store_true",
        help="Skip Docker Python SDK and use `docker image save` directly.",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entry point. Returns 0 if clean, 1 if findings exist, 2 on load/parse error."""
    parser = build_parser()
    args = parser.parse_args(argv)
    max_bytes = max(1, int(args.max_file_mb * 1024 * 1024))

    try:
        report = scan_image(
            args.target,
            max_file_bytes=max_bytes,
            prefer_sdk=not args.no_sdk,
        )
    except (ImageLoadError, LayerExtractionError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(format_json_report(report))
    else:
        print(format_terminal_report(report))

    if args.output:
        write_json_report(report, args.output)

    return 1 if report.findings else 0


if __name__ == "__main__":
    sys.exit(main())
