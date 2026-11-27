"""Extract installed apt, apk, pip, and npm packages from Docker images/containers."""

import json
import subprocess
from typing import Dict, List, Optional, Tuple

from scanner.models import ImageMetadata, InstalledPackage

_PROBE_SCRIPT = """
echo "===OS_RELEASE==="
cat /etc/os-release 2>/dev/null || true
echo "===DPKG==="
if command -v dpkg-query >/dev/null 2>&1; then
    dpkg-query -W -f='${Package}\\t${Version}\\n' 2>/dev/null || true
fi
echo "===APK==="
if command -v apk >/dev/null 2>&1; then
    apk info -v 2>/dev/null || true
fi
echo "===PIP==="
if command -v pip3 >/dev/null 2>&1; then
    pip3 list --format=json 2>/dev/null || true
elif command -v pip >/dev/null 2>&1; then
    pip list --format=json 2>/dev/null || true
fi
echo "===NPM==="
if command -v npm >/dev/null 2>&1; then
    npm list -g --depth=0 --json 2>/dev/null || true
fi
""".strip()

_SECTION_HEADERS = (
    "===OS_RELEASE===",
    "===DPKG===",
    "===APK===",
    "===PIP===",
    "===NPM===",
)


class PackageExtractionError(RuntimeError):
    """Raised when package extraction from a container/image fails."""


def _split_sections(output: str) -> Dict[str, str]:
    """Split probe command stdout into named sections."""
    sections: Dict[str, List[str]] = {header: [] for header in _SECTION_HEADERS}
    current: Optional[str] = None

    for line in output.splitlines():
        stripped = line.strip()
        if stripped in sections:
            current = stripped
            continue
        if current is not None:
            sections[current].append(line)

    return {key: "\n".join(lines).strip() for key, lines in sections.items()}


def _detect_dpkg_ecosystem(os_release: str) -> str:
    """Map /etc/os-release ID to OSV's canonical Debian/Ubuntu ecosystem."""
    distro_id = ""
    for line in os_release.splitlines():
        if line.startswith("ID="):
            distro_id = line.split("=", 1)[1].strip().strip('"').lower()
            break
    if distro_id == "ubuntu":
        return "Ubuntu"
    return "Debian"


def _parse_dpkg_packages(raw: str, ecosystem: str) -> List[InstalledPackage]:
    """Parse `dpkg-query -W -f='${Package}\\t${Version}\\n'` output."""
    packages: List[InstalledPackage] = []
    for line in raw.splitlines():
        if not line.strip() or "\t" not in line:
            continue
        name, version = line.split("\t", 1)
        name = name.strip()
        version = version.strip()
        if name and version:
            packages.append(
                InstalledPackage(ecosystem=ecosystem, name=name, version=version)
            )
    return packages


def _parse_apk_line(entry: str) -> Optional[Tuple[str, str]]:
    """Split an `apk info -v` entry like 'openssl-3.1.4-r5' into (name, version).

    APK package versions always take the form `<name>-<version>-r<rev>` (where
    `<version>` starts with a digit), so we split on the `-<digit>` boundary
    marking the start of the version segment.
    """
    text = entry.strip()
    if not text:
        return None

    parts = text.split("-")
    for idx in range(1, len(parts)):
        if parts[idx] and parts[idx][0].isdigit():
            name = "-".join(parts[:idx])
            version = "-".join(parts[idx:])
            if name and version:
                return name, version
    return None


def _parse_apk_packages(raw: str) -> List[InstalledPackage]:
    """Parse `apk info -v` output into Alpine InstalledPackage objects."""
    packages: List[InstalledPackage] = []
    for line in raw.splitlines():
        parsed = _parse_apk_line(line)
        if parsed is not None:
            name, version = parsed
            packages.append(
                InstalledPackage(ecosystem="Alpine", name=name, version=version)
            )
    return packages


def _parse_pip_packages(raw: str) -> List[InstalledPackage]:
    """Parse `pip list --format=json` output into PyPI InstalledPackage objects."""
    if not raw.strip():
        return []
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return []
    if not isinstance(payload, list):
        return []

    packages: List[InstalledPackage] = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        version = str(item.get("version") or "").strip()
        if name and version:
            packages.append(
                InstalledPackage(ecosystem="PyPI", name=name, version=version)
            )
    return packages


def _parse_npm_packages(raw: str) -> List[InstalledPackage]:
    """Parse `npm list -g --depth=0 --json` output into npm InstalledPackage objects."""
    if not raw.strip():
        return []
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return []
    if not isinstance(payload, dict):
        return []

    deps = payload.get("dependencies")
    if not isinstance(deps, dict):
        return []

    packages: List[InstalledPackage] = []
    for name, info in deps.items():
        if not isinstance(info, dict):
            continue
        version = str(info.get("version") or "").strip()
        if name and version:
            packages.append(
                InstalledPackage(ecosystem="npm", name=str(name), version=version)
            )
    return packages


def parse_probe_output(output: str) -> List[InstalledPackage]:
    """Parse combined shell probe output into a deduplicated list of packages."""
    sections = _split_sections(output)
    dpkg_ecosystem = _detect_dpkg_ecosystem(sections["===OS_RELEASE==="])

    combined: List[InstalledPackage] = []
    combined.extend(_parse_dpkg_packages(sections["===DPKG==="], dpkg_ecosystem))
    combined.extend(_parse_apk_packages(sections["===APK==="]))
    combined.extend(_parse_pip_packages(sections["===PIP==="]))
    combined.extend(_parse_npm_packages(sections["===NPM==="]))

    # Deduplicate while preserving deterministic order.
    seen = set()
    unique: List[InstalledPackage] = []
    for pkg in combined:
        if pkg not in seen:
            seen.add(pkg)
            unique.append(pkg)
    return unique


def extract_packages(metadata: ImageMetadata) -> List[InstalledPackage]:
    """Extract installed packages from a Docker image or running container.

    Uses `docker exec` for running containers and `docker run --rm --entrypoint /bin/sh`
    for images. Stopped containers are not started automatically.
    """
    if metadata.is_container and not metadata.is_running:
        raise PackageExtractionError(
            f"Container '{metadata.target}' is not running; start it or scan its image to extract packages."
        )

    if metadata.is_running:
        cmd = ["docker", "exec", metadata.target, "/bin/sh", "-c", _PROBE_SCRIPT]
    else:
        cmd = [
            "docker",
            "run",
            "--rm",
            "--entrypoint",
            "/bin/sh",
            metadata.target,
            "-c",
            _PROBE_SCRIPT,
        ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    except FileNotFoundError as exc:
        raise PackageExtractionError(
            "Docker CLI ('docker') was not found in PATH."
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise PackageExtractionError(
            f"Package extraction timed out for '{metadata.target}'."
        ) from exc

    if result.returncode != 0:
        stderr = result.stderr.strip() or f"exit code {result.returncode}"
        raise PackageExtractionError(
            f"Could not inspect packages inside '{metadata.target}': {stderr}"
        )

    return parse_probe_output(result.stdout)
