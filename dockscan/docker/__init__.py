"""Docker image loading, layer extraction, and metadata parsing utilities."""

from dockscan.docker.image_loader import ImageLoadError, cleanup_temp_tar, load_image_tar
from dockscan.docker.layer_extractor import (
    DEFAULT_MAX_FILE_BYTES,
    ImageManifestInfo,
    LayerExtractionError,
    LayerFile,
    is_probably_text,
    iter_layer_text_files,
    read_image_manifest,
)
from dockscan.docker.metadata import (
    DockerMetadata,
    HistoryEntry,
    extract_metadata_from_tar,
    parse_image_config_json,
)

__all__ = [
    "DEFAULT_MAX_FILE_BYTES",
    "DockerMetadata",
    "HistoryEntry",
    "ImageLoadError",
    "ImageManifestInfo",
    "LayerExtractionError",
    "LayerFile",
    "cleanup_temp_tar",
    "extract_metadata_from_tar",
    "is_probably_text",
    "iter_layer_text_files",
    "load_image_tar",
    "parse_image_config_json",
    "read_image_manifest",
]
