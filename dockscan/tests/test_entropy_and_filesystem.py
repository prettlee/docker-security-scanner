"""Unit tests for Step 3: entropy-based detection and filesystem layer scanning."""

import unittest

from dockscan.docker.layer_extractor import LayerFile
from dockscan.secrets.entropy_detector import (
    detect_high_entropy_in_text,
    shannon_entropy,
)
from dockscan.secrets.filesystem_scanner import scan_layer_file

FAKE_GH_TOKEN = "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyzABCD"
FAKE_ENTROPY_TOKEN = "Qm9zX3Rva2VuXzlLJHZQc1d4TTRuUTJ6TjhxUjV2WTd6WA=="


class EntropyDetectorTests(unittest.TestCase):
    def test_shannon_entropy_and_contextual_severity_confidence(self) -> None:
        self.assertGreater(shannon_entropy(FAKE_ENTROPY_TOKEN), 4.5)
        self.assertEqual(shannon_entropy(""), 0.0)

        text = "\n".join(
            [
                f"service_auth_token = {FAKE_ENTROPY_TOKEN}",
                f"opaque_blob = {FAKE_ENTROPY_TOKEN}",
                "sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "request_id = 550e8400-e29b-41d4-a716-446655440000",
            ]
        )
        findings = detect_high_entropy_in_text(
            text,
            source="filesystem",
            location_prefix="layer:123:/app/config.py",
        )
        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0].severity, "High")
        self.assertEqual(findings[0].confidence, "Medium")
        self.assertEqual(findings[1].severity, "Low")
        self.assertEqual(findings[1].confidence, "Low")
        for f in findings:
            self.assertNotIn(FAKE_ENTROPY_TOKEN, f.redacted_secret)


class FilesystemScannerTests(unittest.TestCase):
    def test_scan_layer_file_combines_regex_and_entropy_without_duplicate_span(
        self,
    ) -> None:
        lf = LayerFile(
            layer_index=0,
            layer_id="layer0",
            file_path="/app/settings.py",
            content=(
                f"GITHUB_TOKEN = '{FAKE_GH_TOKEN}'\n"
                f"signing_secret = '{FAKE_ENTROPY_TOKEN}'\n"
            ),
        )
        findings = scan_layer_file(lf)
        detectors = [f.detector for f in findings]
        self.assertIn("regex", detectors)
        self.assertIn("entropy", detectors)
        # GITHUB_TOKEN line should only be flagged by regex, not duplicated by entropy
        self.assertEqual(
            [f for f in findings if f.line_number == 1 and f.detector == "entropy"],
            [],
        )


if __name__ == "__main__":
    unittest.main()
