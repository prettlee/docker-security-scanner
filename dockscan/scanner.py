"""Main orchestrator and CLI for unified Docker security & secret scanning."""

import argparse
import os
from pathlib import Path
import sys
import tempfile
from typing import List, Optional, Tuple

from dockscan.docker.image_loader import ImageLoadError, cleanup_temp_tar, load_image_tar
from dockscan.docker.layer_extractor import (
    DEFAULT_MAX_FILE_BYTES,
    LayerExtractionError,
    iter_layer_text_files,
    read_image_manifest,
)
from dockscan.docker.metadata import DockerMetadata, extract_metadata_from_tar
from dockscan.dockerfile.analyzer import analyze_dockerfile_file
from dockscan.models.finding import Finding, ScanReport
from dockscan.reporting import (
    FAIL_ON_CHOICES,
    aggregate_findings,
    convert_legacy_finding,
    format_json_report,
    format_terminal_report,
    should_fail_ci,
    write_github_summary,
    write_html_report,
    write_json_report,
)
from dockscan.secrets.filesystem_scanner import scan_layer_file
from dockscan.secrets.metadata_scanner import scan_metadata
from scanner.checks.ports_check import check_dangerous_ports
from scanner.checks.root_check import check_root_user
from scanner.checks.vuln_check import check_vulnerabilities
from scanner.models import ImageMetadata
from scanner.utils.osv import OSVApiError
from scanner.utils.packages import PackageExtractionError, extract_packages


def _run_static_config_checks(target: str, metadata: DockerMetadata) -> List[Finding]:
    """Run Phase 2 configuration checks statically using tar-extracted metadata."""
    legacy_meta = ImageMetadata(
        target=target,
        user=metadata.user,
        exposed_ports=list(metadata.exposed_ports),
        env=dict(metadata.env),
        entrypoint=list(metadata.entrypoint),
    )
    raw = check_root_user(legacy_meta) + check_dangerous_ports(legacy_meta)
    return [convert_legacy_finding(item) for item in raw]


def _run_package_vuln_scan(
    target: str, metadata: DockerMetadata
) -> Tuple[int, List[Finding], List[str]]:
    """Run Phase 3 package extraction and OSV.dev lookup for local Docker images."""
    legacy_meta = ImageMetadata(target=target, user=metadata.user)
    warnings: List[str] = []
    try:
        packages = extract_packages(legacy_meta)
    except PackageExtractionError as exc:
        warnings.append(str(exc))
        return 0, [], warnings

    legacy_meta.packages = packages
    if not packages:
        return 0, [], warnings

    try:
        raw_vulns = check_vulnerabilities(legacy_meta)
    except OSVApiError as exc:
        warnings.append(f"Vulnerability lookup skipped: {exc}")
        return len(packages), [], warnings

    return len(packages), [convert_legacy_finding(item) for item in raw_vulns], warnings


def scan_image(
    target: str,
    *,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
    prefer_sdk: bool = True,
    include_config: bool = True,
    include_vulns: bool = False,
) -> ScanReport:
    """Scan a Docker image (or `.tar` archive) for secrets, misconfigurations, and CVEs.

    Secret and configuration checks run completely statically without executing
    the target image. Package vulnerability scanning (`include_vulns=True`) is
    optional and only runs on Docker image references (skipped for `.tar` files).
    """
    temp_dir: Optional[Path] = None
    target_path = Path(target)
    is_tar_file = target_path.is_file()
    if not is_tar_file:
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
        warnings: List[str] = []

        raw_findings.extend(scan_metadata(metadata))
        if include_config:
            raw_findings.extend(_run_static_config_checks(target, metadata))

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

        packages_scanned = 0
        if include_vulns and not is_tar_file:
            packages_scanned, vuln_findings, vuln_warnings = _run_package_vuln_scan(
                target, metadata
            )
            raw_findings.extend(vuln_findings)
            warnings.extend(vuln_warnings)

        aggregated = aggregate_findings(raw_findings)
        return ScanReport(
            target=target,
            image_id=metadata.image_id or None,
            layers_scanned=len(layers_seen),
            files_scanned=files_scanned,
            packages_scanned=packages_scanned,
            findings=aggregated,
            warnings=warnings,
        )
    finally:
        cleanup_temp_tar(temp_dir)


def build_parser() -> argparse.ArgumentParser:
    """Build CLI argument parser for `dockscan`."""
    parser = argparse.ArgumentParser(
        prog="dockscan",
        description="Analyze Docker images for secrets, misconfigurations, and package vulnerabilities.",
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
        "--with-vulns",
        action="store_true",
        help="Also extract packages and query OSV.dev for known CVEs.",
    )
    parser.add_argument(
        "--secrets-only",
        action="store_true",
        help="Run only secret scanning (skip image configuration checks).",
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
        "--html",
        help="Write a self-contained interactive HTML dashboard to the specified path.",
    )
    parser.add_argument(
        "--dockerfile",
        action="store_true",
        help="Treat `target` as a Dockerfile path and run static Dockerfile analysis.",
    )
    parser.add_argument(
        "--fail-on",
        choices=FAIL_ON_CHOICES,
        default="low",
        help="Minimum severity that causes a non-zero exit code (default: low; use 'none' to never fail).",
    )
    parser.add_argument(
        "--github-summary",
        action="store_true",
        help="Append a Markdown security summary to $GITHUB_STEP_SUMMARY.",
    )
    parser.add_argument(
        "--no-sdk",
        action="store_true",
        help="Skip Docker Python SDK and use `docker image save` directly.",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entry point. Returns 0 if passing, 1 if failing threshold met, 2 on load/parse error."""
    parser = build_parser()
    args = parser.parse_args(argv)
    max_bytes = max(1, int(args.max_file_mb * 1024 * 1024))

    if args.dockerfile:
        df_path = Path(args.target)
        if not df_path.is_file():
            print(f"Error: Dockerfile not found: {df_path}", file=sys.stderr)
            return 2
        report = analyze_dockerfile_file(df_path)
    else:
        try:
            report = scan_image(
                args.target,
                max_file_bytes=max_bytes,
                prefer_sdk=not args.no_sdk,
                include_config=not args.secrets_only,
                include_vulns=args.with_vulns,
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

    if args.html:
        write_html_report(report, args.html)

    if args.github_summary:
        write_github_summary(report, os.environ.get("GITHUB_STEP_SUMMARY"))

    return 1 if should_fail_ci(report, fail_on=args.fail_on) else 0


if __name__ == "__main__":
    sys.exit(main())
