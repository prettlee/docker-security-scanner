"""OSV.dev API client for batch vulnerability lookups."""

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
import json
from typing import Any, Dict, Iterable, List, Optional, Sequence
import urllib.error
import urllib.parse
import urllib.request

from scanner.models import InstalledPackage

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns"
_SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "MODERATE": 2, "LOW": 1}


class OSVApiError(RuntimeError):
    """Raised when querying the OSV.dev API fails."""


@dataclass(frozen=True)
class VulnerabilityDetail:
    """Normalized details for a single OSV vulnerability record."""

    vuln_id: str
    summary: str = ""
    severity: str = "MEDIUM"
    aliases: List[str] = field(default_factory=list)
    fixed_versions: List[str] = field(default_factory=list)


def _post_json(url: str, payload: Dict[str, Any], timeout: float) -> Dict[str, Any]:
    """Send an HTTP POST request with JSON body and parse the JSON response."""
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "docker-security-scanner/0.1",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace").strip()
        raise OSVApiError(f"OSV API returned HTTP {exc.code}: {body}") from exc
    except urllib.error.URLError as exc:
        raise OSVApiError(f"Failed to reach OSV API: {exc.reason}") from exc
    except (json.JSONDecodeError, TimeoutError, OSError) as exc:
        raise OSVApiError(f"Invalid or timed-out OSV API response: {exc}") from exc


def _get_json(url: str, timeout: float) -> Dict[str, Any]:
    """Send an HTTP GET request and parse the JSON response."""
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "docker-security-scanner/0.1"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError, TimeoutError, OSError) as exc:
        raise OSVApiError(f"Failed to fetch OSV record '{url}': {exc}") from exc


def _build_query(pkg: InstalledPackage, page_token: Optional[str] = None) -> Dict[str, Any]:
    """Build a single OSV querybatch query item."""
    query: Dict[str, Any] = {
        "package": {"ecosystem": pkg.ecosystem, "name": pkg.name},
        "version": pkg.version,
    }
    if page_token:
        query["page_token"] = page_token
    return query


def query_batch(
    packages: Sequence[InstalledPackage],
    batch_size: int = 500,
    timeout: float = 15.0,
) -> Dict[InstalledPackage, List[str]]:
    """Query OSV.dev `/v1/querybatch` for installed packages, handling pagination.

    Returns a mapping from each vulnerable `InstalledPackage` to its list of OSV IDs.
    """
    if not packages:
        return {}

    matches: Dict[InstalledPackage, List[str]] = {}

    for start in range(0, len(packages), batch_size):
        chunk = list(packages[start : start + batch_size])
        pending: List[tuple[InstalledPackage, Optional[str]]] = [
            (pkg, None) for pkg in chunk
        ]

        while pending:
            payload = {
                "queries": [_build_query(pkg, token) for pkg, token in pending]
            }
            response = _post_json(OSV_BATCH_URL, payload, timeout=timeout)
            results = response.get("results")
            if not isinstance(results, list) or len(results) != len(pending):
                raise OSVApiError("Unexpected `results` shape from OSV /v1/querybatch.")

            next_pending: List[tuple[InstalledPackage, Optional[str]]] = []
            for (pkg, _), item in zip(pending, results):
                if not isinstance(item, dict):
                    continue
                vulns = item.get("vulns") or []
                if isinstance(vulns, list):
                    ids = matches.setdefault(pkg, [])
                    for vuln in vulns:
                        if isinstance(vuln, dict) and vuln.get("id"):
                            vuln_id = str(vuln["id"])
                            if vuln_id not in ids:
                                ids.append(vuln_id)
                token = item.get("next_page_token")
                if token:
                    next_pending.append((pkg, str(token)))

            pending = next_pending

    return {pkg: ids for pkg, ids in matches.items() if ids}


def _extract_severity(raw: Dict[str, Any]) -> str:
    """Extract normalized severity label from an OSV vulnerability record."""
    db_specific = raw.get("database_specific")
    if isinstance(db_specific, dict):
        sev = str(db_specific.get("severity") or "").upper()
        if sev in _SEVERITY_RANK:
            return "MEDIUM" if sev == "MODERATE" else sev

    affected = raw.get("affected")
    best = ""
    if isinstance(affected, list):
        for item in affected:
            if not isinstance(item, dict):
                continue
            eco = item.get("ecosystem_specific")
            if isinstance(eco, dict):
                sev = str(eco.get("severity") or "").upper()
                if _SEVERITY_RANK.get(sev, 0) > _SEVERITY_RANK.get(best, 0):
                    best = sev

    if best in _SEVERITY_RANK:
        return "MEDIUM" if best == "MODERATE" else best
    return "MEDIUM"


def _extract_fixed_versions(raw: Dict[str, Any]) -> List[str]:
    """Extract sorted unique fixed versions from OSV affected ranges."""
    fixed: set[str] = set()
    affected = raw.get("affected")
    if not isinstance(affected, list):
        return []

    for item in affected:
        if not isinstance(item, dict):
            continue
        ranges = item.get("ranges")
        if not isinstance(ranges, list):
            continue
        for rng in ranges:
            if not isinstance(rng, dict):
                continue
            events = rng.get("events")
            if not isinstance(events, list):
                continue
            for event in events:
                if isinstance(event, dict) and event.get("fixed"):
                    fixed.add(str(event["fixed"]))
    return sorted(fixed)


def parse_vuln_detail(raw: Dict[str, Any], fallback_id: str) -> VulnerabilityDetail:
    """Normalize a raw `/v1/vulns/{id}` JSON object."""
    vuln_id = str(raw.get("id") or fallback_id)
    summary = str(raw.get("summary") or "").strip()
    if not summary:
        details = str(raw.get("details") or "").strip()
        summary = details.splitlines()[0][:180] if details else ""

    raw_aliases = raw.get("aliases")
    aliases = (
        [str(a) for a in raw_aliases if isinstance(a, str)]
        if isinstance(raw_aliases, list)
        else []
    )

    return VulnerabilityDetail(
        vuln_id=vuln_id,
        summary=summary,
        severity=_extract_severity(raw),
        aliases=aliases,
        fixed_versions=_extract_fixed_versions(raw),
    )


def fetch_vuln_details(
    vuln_ids: Iterable[str],
    timeout: float = 10.0,
    max_workers: int = 8,
) -> Dict[str, VulnerabilityDetail]:
    """Fetch full OSV records for unique vulnerability IDs in parallel.

    Individual fetch errors fall back to minimal VulnerabilityDetail records so
    the scan still surfaces matched IDs.
    """
    unique_ids = sorted(set(vuln_ids))
    if not unique_ids:
        return {}

    details: Dict[str, VulnerabilityDetail] = {}

    def _fetch_one(vid: str) -> VulnerabilityDetail:
        encoded = urllib.parse.quote(vid, safe="")
        raw = _get_json(f"{OSV_VULN_URL}/{encoded}", timeout=timeout)
        return parse_vuln_detail(raw, fallback_id=vid)

    with ThreadPoolExecutor(max_workers=min(max_workers, len(unique_ids))) as pool:
        futures = {pool.submit(_fetch_one, vid): vid for vid in unique_ids}
        for future in as_completed(futures):
            vid = futures[future]
            try:
                details[vid] = future.result()
            except OSVApiError:
                details[vid] = VulnerabilityDetail(vuln_id=vid)

    return details
