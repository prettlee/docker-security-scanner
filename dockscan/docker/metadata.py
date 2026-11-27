"""Extract image metadata (ENV, labels, build history) from a saved image archive."""

from dataclasses import dataclass, field
import json
from pathlib import Path
import tarfile
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class HistoryEntry:
    """Single Dockerfile build history step from image config."""

    index: int
    created_by: str
    comment: str = ""
    empty_layer: bool = False


@dataclass
class DockerMetadata:
    """Metadata extracted statically from a saved Docker image config JSON."""

    image_id: str = ""
    env: Dict[str, str] = field(default_factory=dict)
    labels: Dict[str, str] = field(default_factory=dict)
    history: List[HistoryEntry] = field(default_factory=list)
    user: str = ""
    entrypoint: List[str] = field(default_factory=list)
    cmd: List[str] = field(default_factory=list)


def _parse_env_list(raw_env: Any) -> Dict[str, str]:
    """Parse Docker Config.Env `KEY=VALUE` entries into a dict."""
    if not isinstance(raw_env, list):
        return {}
    parsed: Dict[str, str] = {}
    for entry in raw_env:
        if not isinstance(entry, str):
            continue
        if "=" in entry:
            key, val = entry.split("=", 1)
            parsed[key] = val
        else:
            parsed[entry] = ""
    return parsed


def _parse_str_list(raw_val: Any) -> List[str]:
    if isinstance(raw_val, list):
        return [str(x) for x in raw_val]
    if isinstance(raw_val, str):
        return [raw_val]
    return []


def parse_image_config_json(
    config_payload: Dict[str, Any], image_id: str = ""
) -> DockerMetadata:
    """Normalize an image config JSON dictionary into `DockerMetadata`."""
    cfg = config_payload.get("config") or config_payload.get("Config") or {}
    if not isinstance(cfg, dict):
        cfg = {}

    raw_labels = cfg.get("Labels")
    labels = (
        {str(k): str(v) for k, v in raw_labels.items()}
        if isinstance(raw_labels, dict)
        else {}
    )

    history_entries: List[HistoryEntry] = []
    raw_history = config_payload.get("history")
    if isinstance(raw_history, list):
        for idx, item in enumerate(raw_history):
            if not isinstance(item, dict):
                continue
            history_entries.append(
                HistoryEntry(
                    index=idx,
                    created_by=str(item.get("created_by") or ""),
                    comment=str(item.get("comment") or ""),
                    empty_layer=bool(item.get("empty_layer", False)),
                )
            )

    return DockerMetadata(
        image_id=image_id,
        env=_parse_env_list(cfg.get("Env")),
        labels=labels,
        history=history_entries,
        user=str(cfg.get("User") or ""),
        entrypoint=_parse_str_list(cfg.get("Entrypoint")),
        cmd=_parse_str_list(cfg.get("Cmd")),
    )


def extract_metadata_from_tar(
    tar_path: Path, config_member_path: Optional[str]
) -> DockerMetadata:
    """Read the image config JSON directly from a saved Docker image tarball."""
    if not config_member_path:
        return DockerMetadata()

    with tarfile.open(tar_path, "r:*") as archive:
        normalized = config_member_path.lstrip("./")
        member = None
        for candidate in (config_member_path, normalized, f"./{normalized}"):
            try:
                member = archive.getmember(candidate)
                break
            except KeyError:
                continue
        if member is None:
            return DockerMetadata()

        extracted = archive.extractfile(member)
        if extracted is None:
            return DockerMetadata()

        payload = json.loads(extracted.read().decode("utf-8", errors="replace"))
        if not isinstance(payload, dict):
            return DockerMetadata()

        image_id = Path(normalized).stem
        if image_id.endswith(".json"):
            image_id = image_id[:-5]
        return parse_image_config_json(payload, image_id=image_id)
