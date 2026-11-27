"""Unit tests for Step 4: Docker metadata extraction and secret scanning."""

import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path

from dockscan.docker.metadata import extract_metadata_from_tar
from dockscan.secrets.metadata_scanner import scan_metadata

FAKE_AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"
FAKE_GH_TOKEN = "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyzABCD"
FAKE_LABEL_SECRET = "MyLabelSecretValue12345"


def _add_bytes_to_tar(tar: tarfile.TarFile, name: str, data: bytes) -> None:
    info = tarfile.TarInfo(name=name)
    info.size = len(data)
    tar.addfile(info, io.BytesIO(data))


class MetadataScannerTests(unittest.TestCase):
    def test_extracts_and_scans_env_labels_and_build_history(self) -> None:
        config_name = "deadbeef123456.json"
        config_payload = {
            "config": {
                "User": "1000",
                "Env": [
                    f"AWS_ACCESS_KEY_ID={FAKE_AWS_KEY}",
                    "APP_ENV=production",
                ],
                "Labels": {
                    "com.example.secret": FAKE_LABEL_SECRET,
                    "maintainer": "team@example.com",
                },
            },
            "history": [
                {
                    "created_by": f"/bin/sh -c echo {FAKE_GH_TOKEN} > /tmp/tok",
                    "empty_layer": False,
                },
                {
                    "created_by": "/bin/sh -c apk add --no-cache curl",
                    "empty_layer": False,
                },
            ],
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            tar_path = Path(tmpdir) / "meta.tar"
            with tarfile.open(tar_path, "w") as outer:
                _add_bytes_to_tar(
                    outer, config_name, json.dumps(config_payload).encode("utf-8")
                )

            meta = extract_metadata_from_tar(tar_path, config_name)
            self.assertEqual(meta.image_id, "deadbeef123456")
            self.assertEqual(meta.user, "1000")
            self.assertEqual(len(meta.history), 2)

            findings = scan_metadata(meta)
            locations = [f.location for f in findings]
            self.assertIn("metadata:env:AWS_ACCESS_KEY_ID", locations)
            self.assertIn("metadata:label:com.example.secret", locations)
            self.assertIn("metadata:history:step_0", locations)

            redacted_blob = " ".join(f.redacted_secret for f in findings)
            for secret in (FAKE_AWS_KEY, FAKE_GH_TOKEN, FAKE_LABEL_SECRET):
                self.assertNotIn(secret, redacted_blob)


if __name__ == "__main__":
    unittest.main()
