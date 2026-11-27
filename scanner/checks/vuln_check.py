"""Package vulnerability check backed by the OSV.dev batch API."""

from typing import Callable, Dict, Iterable, List, Optional, Sequence

from scanner.models import Finding, ImageMetadata, InstalledPackage
from scanner.utils.osv import VulnerabilityDetail, fetch_vuln_details, query_batch

BatchQueryFn = Callable[[Sequence[InstalledPackage]], Dict[InstalledPackage, List[str]]]
DetailFetchFn = Callable[[Iterable[str]], Dict[str, VulnerabilityDetail]]

_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def check_vulnerabilities(
    metadata: ImageMetadata,
    batch_query_fn: Optional[BatchQueryFn] = None,
    detail_fetch_fn: Optional[DetailFetchFn] = None,
) -> List[Finding]:
    """Compare extracted packages against OSV.dev and return CVE/OSV findings."""
    if not metadata.packages:
        return []

    query_fn = batch_query_fn or query_batch
    details_fn = detail_fetch_fn or fetch_vuln_details

    matches = query_fn(metadata.packages)
    if not matches:
        return []

    all_ids = [vid for ids in matches.values() for vid in ids]
    details = details_fn(all_ids)

    findings: List[Finding] = []
    for pkg, vuln_ids in matches.items():
        for vid in vuln_ids:
            detail = details.get(vid, VulnerabilityDetail(vuln_id=vid))
            cves = [alias for alias in detail.aliases if alias.startswith("CVE-")]
            display_id = f"{vid} ({', '.join(cves)})" if cves else vid

            description = (
                detail.summary
                or f"Known vulnerability {display_id} affects {pkg.ecosystem} package '{pkg.name}' version '{pkg.version}'."
            )
            if detail.fixed_versions:
                remediation = (
                    f"Upgrade `{pkg.name}` ({pkg.ecosystem}) to a fixed version: "
                    + ", ".join(detail.fixed_versions[:5])
                    + "."
                )
            else:
                remediation = (
                    f"Update `{pkg.name}` ({pkg.ecosystem}) or switch to a newer base image "
                    "with an upstream security patch."
                )

            findings.append(
                Finding(
                    rule_id="DOCKER-004",
                    severity=detail.severity,
                    title=f"Vulnerable {pkg.ecosystem} package '{pkg.name}=={pkg.version}': {display_id}",
                    description=description,
                    remediation=remediation,
                    evidence=f"{pkg.ecosystem} {pkg.name}@{pkg.version} -> {display_id}",
                )
            )

    findings.sort(key=lambda f: (_SEVERITY_ORDER.get(f.severity, 99), f.title))
    return findings
