"""Runs `docker inspect` and parses image/container metadata."""

import json
import subprocess
from typing import Any, Dict, List

from scanner.models import Capabilities, ImageMetadata


class DockerInspectError(RuntimeError):
    """Raised when `docker inspect` fails or returns unexpected output."""


def _parse_env(raw_env: Any) -> Dict[str, str]:
    """Convert Docker's `KEY=VALUE` env list into a dictionary."""
    if not isinstance(raw_env, list):
        return {}

    parsed: Dict[str, str] = {}
    for entry in raw_env:
        if not isinstance(entry, str):
            continue
        if "=" in entry:
            key, value = entry.split("=", 1)
            parsed[key] = value
        else:
            parsed[entry] = ""
    return parsed


def _parse_entrypoint(raw_entrypoint: Any) -> List[str]:
    """Normalize Entrypoint (list, string, or None) to a list of strings."""
    if raw_entrypoint is None:
        return []
    if isinstance(raw_entrypoint, list):
        return [str(item) for item in raw_entrypoint]
    if isinstance(raw_entrypoint, str):
        return [raw_entrypoint]
    return []


def _parse_exposed_ports(raw_ports: Any) -> List[str]:
    """Extract sorted port strings from Docker's ExposedPorts mapping."""
    if not isinstance(raw_ports, dict):
        return []
    return sorted(str(port) for port in raw_ports.keys())


def _parse_capabilities(host_config: Dict[str, Any]) -> Capabilities:
    """Extract CapAdd/CapDrop from HostConfig when present (e.g. containers)."""
    cap_add = host_config.get("CapAdd")
    cap_drop = host_config.get("CapDrop")
    return Capabilities(
        add=[str(c) for c in cap_add] if isinstance(cap_add, list) else [],
        drop=[str(c) for c in cap_drop] if isinstance(cap_drop, list) else [],
    )


def parse_inspect_output(raw_json: str, target: str) -> ImageMetadata:
    """Parse raw JSON output from `docker inspect` into `ImageMetadata`."""
    try:
        payload = json.loads(raw_json)
    except json.JSONDecodeError as exc:
        raise DockerInspectError(f"Failed to parse `docker inspect` JSON: {exc}") from exc

    if not isinstance(payload, list) or not payload:
        raise DockerInspectError(f"No inspect data returned for target '{target}'.")

    obj = payload[0]
    if not isinstance(obj, dict):
        raise DockerInspectError("Unexpected `docker inspect` entry format.")

    config = obj.get("Config") or {}
    host_config = obj.get("HostConfig") or {}

    raw_user = config.get("User")
    user = str(raw_user).strip() if raw_user is not None else ""

    return ImageMetadata(
        target=target,
        user=user,
        exposed_ports=_parse_exposed_ports(config.get("ExposedPorts")),
        env=_parse_env(config.get("Env")),
        entrypoint=_parse_entrypoint(config.get("Entrypoint")),
        capabilities=_parse_capabilities(host_config),
    )


def inspect_target(target: str) -> ImageMetadata:
    """Invoke `docker inspect <target>` and return parsed `ImageMetadata`."""
    try:
        result = subprocess.run(
            ["docker", "inspect", target],
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError as exc:
        raise DockerInspectError(
            "Docker CLI ('docker') was not found in PATH."
        ) from exc

    if result.returncode != 0:
        stderr = result.stderr.strip() or f"exit code {result.returncode}"
        raise DockerInspectError(f"`docker inspect {target}` failed: {stderr}")

    return parse_inspect_output(result.stdout, target=target)
