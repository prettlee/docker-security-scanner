"""Parse Docker image tarballs and stream text files from individual layers."""

from dataclasses import dataclass
import json
from pathlib import Path
import tarfile
from typing import Iterator, List, Optional, Tuple

DEFAULT_MAX_FILE_BYTES = 10 * 1024 * 1024  # 10 MB

_BINARY_EXTENSIONS = frozenset(
    {
        ".a",
        ".bin",
        ".bmp",
        ".class",
        ".db",
        ".deb",
        ".dll",
        ".dylib",
        ".elf",
        ".exe",
        ".gif",
        ".gz",
        ".ico",
        ".jar",
        ".jpeg",
        ".jpg",
        ".mo",
        ".o",
        ".otf",
        ".pdf",
        ".png",
        ".pyc",
        ".pyo",
        ".rpm",
        ".so",
        ".sqlite",
        ".tar",
        ".ttf",
        ".wasm",
        ".webp",
        ".whl",
        ".woff",
        ".woff2",
        ".zip",
    }
)


class LayerExtractionError(RuntimeError):
    """Raised when a Docker image archive or its layers cannot be parsed."""


@dataclass(frozen=True)
class LayerFile:
    """A decoded text file extracted from a single Docker image layer."""

    layer_index: int
    layer_id: str
    file_path: str
    content: str


@dataclass(frozen=True)
class ImageManifestInfo:
    """Parsed `manifest.json` metadata from a `docker image save` archive."""

    config_path: Optional[str]
    layer_paths: List[str]


def is_probably_text(sample: bytes) -> bool:
    """Heuristically determine whether a byte sample represents text."""
    if not sample or b"\x00" in sample:
        return False
    try:
        sample.decode("utf-8")
        return True
    except UnicodeDecodeError:
        printable = sum(
            1 for byte in sample if 32 <= byte <= 126 or byte in (9, 10, 13)
        )
        return (printable / len(sample)) >= 0.85


def _has_binary_extension(path: str) -> bool:
    return Path(path).suffix.lower() in _BINARY_EXTENSIONS


def _is_whiteout_file(path: str) -> bool:
    return Path(path).name.startswith(".wh.")


def _find_member(archive: tarfile.TarFile, member_path: str) -> Optional[tarfile.TarInfo]:
    """Locate a member with or without a leading `./`."""
    stripped = member_path.lstrip("./")
    for candidate in (member_path, stripped, f"./{stripped}"):
        try:
            return archive.getmember(candidate)
        except KeyError:
            continue
    return None


def read_image_manifest(tar_path: Path) -> ImageManifestInfo:
    """Read `manifest.json` from a saved Docker image archive."""
    try:
        with tarfile.open(tar_path, "r:*") as archive:
            manifest_member = _find_member(archive, "manifest.json")
            if manifest_member is None:
                raise LayerExtractionError(
                    f"Archive '{tar_path}' does not contain 'manifest.json'."
                )
            stream = archive.extractfile(manifest_member)
            if stream is None:
                raise LayerExtractionError("Unable to read 'manifest.json' from archive.")
            payload = json.loads(stream.read().decode("utf-8"))
    except (tarfile.TarError, json.JSONDecodeError, OSError) as exc:
        raise LayerExtractionError(
            f"Failed to parse Docker archive '{tar_path}': {exc}"
        ) from exc

    if not isinstance(payload, list) or not payload or not isinstance(payload[0], dict):
        raise LayerExtractionError("Unexpected 'manifest.json' format in Docker archive.")

    entry = payload[0]
    config_path = entry.get("Config")
    raw_layers = entry.get("Layers") or []
    layer_paths = [str(layer) for layer in raw_layers if isinstance(layer, str)]
    return ImageManifestInfo(
        config_path=str(config_path) if config_path else None,
        layer_paths=layer_paths,
    )


def _derive_layer_id(layer_path: str, index: int) -> str:
    """Derive a concise readable layer identifier from its archive path."""
    parts = Path(layer_path).parts
    if len(parts) >= 2 and parts[-1] == "layer.tar":
        return parts[-2][:12]
    stem = Path(layer_path).stem
    if stem:
        return stem[:12]
    return f"layer-{index}"


def iter_layer_text_files(
    tar_path: Path,
    layer_paths: List[str],
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
) -> Iterator[Tuple[int, str, Optional[LayerFile]]]:
    """Yield `(layer_index, layer_id, LayerFile | None)` for each layer in `tar_path`.

    Yields `(layer_index, layer_id, None)` once per layer so callers can track
    every layer visited, followed by `(layer_index, layer_id, LayerFile)` for
    each qualifying text file up to `max_file_bytes`.
    """
    try:
        with tarfile.open(tar_path, "r:*") as outer_tar:
            for idx, layer_path in enumerate(layer_paths):
                layer_id = _derive_layer_id(layer_path, idx)
                yield idx, layer_id, None

                layer_member = _find_member(outer_tar, layer_path)
                if layer_member is None:
                    continue
                layer_stream = outer_tar.extractfile(layer_member)
                if layer_stream is None:
                    continue

                try:
                    with tarfile.open(fileobj=layer_stream, mode="r:*") as layer_tar:
                        for member in layer_tar:
                            if not member.isfile():
                                continue
                            if member.size <= 0 or member.size > max_file_bytes:
                                continue

                            clean_path = "/" + member.name.lstrip("./")
                            if _is_whiteout_file(clean_path) or _has_binary_extension(clean_path):
                                continue

                            file_stream = layer_tar.extractfile(member)
                            if file_stream is None:
                                continue

                            raw_bytes = file_stream.read(max_file_bytes)
                            if not is_probably_text(raw_bytes[:8192]):
                                continue

                            content = raw_bytes.decode("utf-8", errors="replace")
                            yield idx, layer_id, LayerFile(
                                layer_index=idx,
                                layer_id=layer_id,
                                file_path=clean_path,
                                content=content,
                            )
                except tarfile.TarError:
                    continue
    except (tarfile.TarError, OSError) as exc:
        raise LayerExtractionError(f"Failed reading image tar '{tar_path}': {exc}") from exc
