"""Unit tests for Step 1: Docker image loading and layer extraction."""

import io
import json
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from typing import Dict, List
from unittest.mock import patch

from dockscan.docker.image_loader import ImageLoadError, load_image_tar
from dockscan.docker.layer_extractor import (
    LayerExtractionError,
    LayerFile,
    iter_layer_text_files,
    read_image_manifest,
)


def _add_bytes_to_tar(tar: tarfile.TarFile, name: str, data: bytes) -> None:
    info = tarfile.TarInfo(name=name)
    info.size = len(data)
    tar.addfile(info, io.BytesIO(data))


def _make_layer_tar(files: Dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as layer_tar:
        for path, content in files.items():
            _add_bytes_to_tar(layer_tar, path, content)
    return buf.getvalue()


def _build_synthetic_image_tar(dest_path: Path, layers: List[Dict[str, bytes]]) -> Path:
    config_name = "abcdef123456.json"
    layer_paths: List[str] = []
    with tarfile.open(dest_path, "w") as outer:
        _add_bytes_to_tar(outer, config_name, b"{}")
        for idx, layer_files in enumerate(layers):
            layer_tar_path = f"layer{idx:04d}digest/layer.tar"
            layer_paths.append(layer_tar_path)
            _add_bytes_to_tar(outer, layer_tar_path, _make_layer_tar(layer_files))

        manifest = [{"Config": config_name, "Layers": layer_paths}]
        _add_bytes_to_tar(outer, "manifest.json", json.dumps(manifest).encode("utf-8"))
    return dest_path


class ImageLoaderTests(unittest.TestCase):
    def test_load_existing_tar_file_directly(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tar_path = _build_synthetic_image_tar(
                Path(tmpdir) / "local.tar", layers=[{"app/a.txt": b"hello\n"}]
            )
            loaded = load_image_tar(str(tar_path), Path(tmpdir) / "out", prefer_sdk=False)
            self.assertEqual(loaded, tar_path)

    @patch("dockscan.docker.image_loader.subprocess.run")
    def test_load_image_uses_docker_image_save_never_runs_container(
        self, mock_run: unittest.mock.MagicMock
    ) -> None:
        def fake_save(cmd, **_kwargs):
            out_path = Path(cmd[cmd.index("-o") + 1])
            _build_synthetic_image_tar(out_path, layers=[{"app/a.txt": b"ok\n"}])
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

        mock_run.side_effect = fake_save
        with tempfile.TemporaryDirectory() as tmpdir:
            loaded = load_image_tar("alpine:3.19", Path(tmpdir), prefer_sdk=False)
            self.assertTrue(loaded.exists())
            called_cmd = mock_run.call_args.args[0]
            self.assertEqual(called_cmd[:3], ["docker", "image", "save"])

    @patch("dockscan.docker.image_loader.subprocess.run")
    def test_load_image_raises_on_cli_failure(
        self, mock_run: unittest.mock.MagicMock
    ) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            args=["docker", "image", "save"],
            returncode=1,
            stdout="",
            stderr="No such image",
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            with self.assertRaises(ImageLoadError):
                load_image_tar("missing:latest", Path(tmpdir), prefer_sdk=False)


class LayerExtractorTests(unittest.TestCase):
    def test_extracts_text_files_across_layers_and_skips_binary_oversized_whiteouts(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tar_path = _build_synthetic_image_tar(
                Path(tmpdir) / "image.tar",
                layers=[
                    {
                        "app/.env": b"SECRET=val\n",
                        "app/logo.png": b"\x89PNG\r\n\x1a\n\x00\x00",
                        "app/huge.txt": ("X" * 4096).encode("utf-8"),
                    },
                    {
                        "app/.wh..env": b"",
                        "app/notes.txt": b"safe text\n",
                    },
                ],
            )
            manifest = read_image_manifest(tar_path)
            self.assertEqual(manifest.config_path, "abcdef123456.json")
            self.assertEqual(len(manifest.layer_paths), 2)

            files: List[LayerFile] = [
                lf
                for _idx, _lid, lf in iter_layer_text_files(
                    tar_path, manifest.layer_paths, max_file_bytes=1024
                )
                if lf is not None
            ]
            paths = [f.file_path for f in files]
            self.assertIn("/app/.env", paths)
            self.assertIn("/app/notes.txt", paths)
            self.assertNotIn("/app/logo.png", paths)
            self.assertNotIn("/app/huge.txt", paths)
            self.assertNotIn("/app/.wh..env", paths)

    def test_missing_manifest_raises_layer_extraction_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            bad_tar = Path(tmpdir) / "bad.tar"
            with tarfile.open(bad_tar, "w") as tar:
                _add_bytes_to_tar(tar, "other.txt", b"hi")
            with self.assertRaises(LayerExtractionError):
                read_image_manifest(bad_tar)


if __name__ == "__main__":
    unittest.main()
