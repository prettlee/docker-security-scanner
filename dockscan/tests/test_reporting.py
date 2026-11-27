"""Unit tests for Phase 5: reporting, severity classification, confidence scoring, and aggregation."""

import io
import json
import tarfile
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from dockscan.models.finding import Finding, ScanReport
from dockscan.reporting import (
    aggregate_findings,
    classify_severity,
    convert_legacy_finding,
    format_json_report,
    format_terminal_report,
    score_confidence,
)
from dockscan.scanner import main, scan_image
from scanner.models import Finding as LegacyFinding
from scanner.models import InstalledPackage


def _add_bytes(tar: tarfile.TarFile, name: str, data: bytes) -> None:
    info = tarfile.TarInfo(name=name)
    info.size = len(data)
    tar.addfile(info, io.BytesIO(data))


class SeverityAndConfidenceTests(unittest.TestCase):
    def test_classify_severity_cvss_and_normalization(self) -> None:
        self.assertEqual(classify_severity(cvss_score=9.8), "Critical")
        self.assertEqual(classify_severity(cvss_score=7.5), "High")
        self.assertEqual(classify_severity(cvss_score=5.0), "Medium")
        self.assertEqual(classify_severity(cvss_score=2.1), "Low")
        self.assertEqual(classify_severity(raw_severity="MODERATE"), "Medium")
        self.assertEqual(classify_severity(raw_severity="critical"), "Critical")

    def test_score_confidence_across_detectors(self) -> None:
        self.assertEqual(score_confidence(detector="config"), ("High", 1.0))
        self.assertEqual(score_confidence(detector="vulnerability"), ("High", 0.9))
        self.assertEqual(
            score_confidence(detector="regex", confidence="High"), ("High", 0.95)
        )
        label_ctx, score_ctx = score_confidence(
            detector="entropy", has_context=True, entropy=4.6
        )
        self.assertEqual(label_ctx, "Medium")
        self.assertGreater(score_ctx, 0.5)

        label_raw, score_raw = score_confidence(
            detector="entropy", has_context=False, entropy=4.7
        )
        self.assertEqual(label_raw, "Low")
        self.assertLess(score_raw, 0.5)


class UnifiedReportingTests(unittest.TestCase):
    def test_converts_legacy_config_and_vuln_findings_and_renders_report(self) -> None:
        secret_finding = Finding(
            rule_id="SEC-003",
            title="Private Key Detected",
            severity="Critical",
            confidence="High",
            confidence_score=0.98,
            source="filesystem",
            location="layer:abc:/app/credentials/private.pem:1",
            redacted_secret="-----***REDACTED*** (31 chars)",
            description="PEM private key found.",
            remediation="Remove private key.",
            detector="regex",
            category="secret",
            file_path="/app/credentials/private.pem",
        )
        root_legacy = LegacyFinding(
            rule_id="DOCKER-001",
            severity="HIGH",
            title="Container Runs as Root",
            description="Runs as UID 0.",
            remediation="Use USER appuser.",
            evidence="Config.User = ''",
        )
        vuln_legacy = LegacyFinding(
            rule_id="DOCKER-004",
            severity="HIGH",
            title="Vulnerable Debian package 'openssl==3.0.11-1~deb12u2': DSA-5555 (CVE-2024-0727)",
            description="OpenSSL DoS.",
            remediation="Upgrade openssl.",
            evidence="Debian openssl@3.0.11-1~deb12u2",
        )

        findings = aggregate_findings(
            [
                convert_legacy_finding(vuln_legacy),
                convert_legacy_finding(root_legacy),
                secret_finding,
            ]
        )
        report = ScanReport(
            target="my-app:latest",
            image_id="abc123",
            layers_scanned=3,
            files_scanned=10,
            packages_scanned=42,
            findings=findings,
        )

        terminal = format_terminal_report(report)
        self.assertIn("DOCKSCAN SECURITY REPORT", terminal)
        self.assertIn("Image: my-app:latest", terminal)
        self.assertIn("CRITICAL: 1", terminal)
        self.assertIn("HIGH: 2", terminal)
        self.assertIn("MEDIUM: 0", terminal)
        self.assertIn("LOW: 0", terminal)
        self.assertIn("[CRITICAL] Private Key Detected", terminal)
        self.assertIn("Location: /app/credentials/private.pem", terminal)
        self.assertIn("[HIGH] Container Runs as Root", terminal)
        self.assertIn("Location: Image Configuration", terminal)
        self.assertIn("[HIGH] Vulnerable openssl Package", terminal)
        self.assertIn("Package: openssl", terminal)
        self.assertIn("Detected Version: 3.0.11-1~deb12u2", terminal)
        self.assertIn("CVE: CVE-2024-0727", terminal)

        parsed = json.loads(format_json_report(report))
        self.assertEqual(parsed["report_version"], "1.0")
        self.assertEqual(parsed["summary"]["total_findings"], 3)
        self.assertEqual(parsed["summary"]["by_severity"]["Critical"], 1)
        self.assertEqual(parsed["summary"]["by_severity"]["High"], 2)
        self.assertEqual(parsed["summary"]["by_category"]["vulnerability"], 1)
        self.assertEqual(parsed["summary"]["by_category"]["misconfiguration"], 1)
        self.assertEqual(parsed["summary"]["by_category"]["secret"], 1)

    def test_scan_image_runs_static_config_checks_alongside_secrets(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tar_path = Path(tmpdir) / "root_and_port.tar"
            config_name = "cfg123.json"
            config_payload = {
                "config": {
                    "User": "",
                    "ExposedPorts": {"22/tcp": {}},
                    "Env": [],
                    "Labels": {},
                },
                "history": [],
            }
            layer_buf = io.BytesIO()
            with tarfile.open(fileobj=layer_buf, mode="w") as ltar:
                _add_bytes(ltar, "app/ok.txt", b"hello\n")

            with tarfile.open(tar_path, "w") as outer:
                _add_bytes(
                    outer, config_name, json.dumps(config_payload).encode("utf-8")
                )
                _add_bytes(outer, "layer0/layer.tar", layer_buf.getvalue())
                _add_bytes(
                    outer,
                    "manifest.json",
                    json.dumps(
                        [{"Config": config_name, "Layers": ["layer0/layer.tar"]}]
                    ).encode("utf-8"),
                )

            report = scan_image(str(tar_path))
            rule_ids = {f.rule_id for f in report.findings}
            self.assertIn("DOCKER-001", rule_ids)
            self.assertIn("DOCKER-002", rule_ids)

            secrets_only_report = scan_image(str(tar_path), include_config=False)
            self.assertEqual(secrets_only_report.findings, [])

    @patch("dockscan.scanner.check_vulnerabilities")
    @patch("dockscan.scanner.extract_packages")
    @patch("dockscan.scanner.load_image_tar")
    def test_cli_with_vulns_aggregates_all_sources(
        self,
        mock_load: unittest.mock.MagicMock,
        mock_extract: unittest.mock.MagicMock,
        mock_vulns: unittest.mock.MagicMock,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tar_path = Path(tmpdir) / "app.tar"
            config_name = "cfg123.json"
            config_payload = {
                "config": {"User": "root", "Env": [], "Labels": {}},
                "history": [],
            }
            layer_buf = io.BytesIO()
            with tarfile.open(fileobj=layer_buf, mode="w") as ltar:
                _add_bytes(
                    ltar,
                    "app/key.pem",
                    b"-----BEGIN RSA PRIVATE KEY-----\nFAKE\n",
                )
            with tarfile.open(tar_path, "w") as outer:
                _add_bytes(
                    outer, config_name, json.dumps(config_payload).encode("utf-8")
                )
                _add_bytes(outer, "layer0/layer.tar", layer_buf.getvalue())
                _add_bytes(
                    outer,
                    "manifest.json",
                    json.dumps(
                        [{"Config": config_name, "Layers": ["layer0/layer.tar"]}]
                    ).encode("utf-8"),
                )

            mock_load.return_value = tar_path
            mock_extract.return_value = [
                InstalledPackage("Debian", "openssl", "3.0.11-1~deb12u2")
            ]
            mock_vulns.return_value = [
                LegacyFinding(
                    rule_id="DOCKER-004",
                    severity="HIGH",
                    title="Vulnerable Debian package 'openssl==3.0.11-1~deb12u2': CVE-2024-0727",
                    description="OpenSSL issue.",
                    remediation="Upgrade openssl.",
                )
            ]

            buf = io.StringIO()
            with redirect_stdout(buf):
                code = main(["my-app:latest", "--with-vulns"])
            self.assertEqual(code, 1)
            out = buf.getvalue()
            self.assertIn("DOCKSCAN SECURITY REPORT", out)
            self.assertIn("CRITICAL: 1", out)
            self.assertIn("HIGH: 2", out)
            self.assertIn("Package: openssl", out)


if __name__ == "__main__":
    unittest.main()
