"""Unit tests for the interactive HTML security dashboard report generator."""

import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from dockscan.dockerfile.cli import main as dockerfile_main
from dockscan.models.finding import Finding, ScanReport
from dockscan.reporting import format_html_report, write_html_report
from dockscan.scanner import main as dockscan_main

REPO_ROOT = Path(__file__).resolve().parents[2]


class HtmlReportTests(unittest.TestCase):
    def test_renders_findings_severity_bar_and_package_fields(self) -> None:
        report = ScanReport(
            target="my-app:latest",
            image_id="sha256deadbeef",
            layers_scanned=3,
            files_scanned=12,
            packages_scanned=40,
            warnings=["OSV lookup partially skipped"],
            findings=[
                Finding(
                    rule_id="SEC-003",
                    title="Private Key Detected",
                    severity="Critical",
                    confidence="High",
                    confidence_score=0.98,
                    source="filesystem",
                    location="layer:abc:/app/private.pem:1",
                    redacted_secret="-----***REDACTED*** (31 chars)",
                    description="PEM private key found.",
                    remediation="Remove key from image.",
                    category="secret",
                    file_path="/app/private.pem",
                    line_number=1,
                ),
                Finding(
                    rule_id="DOCKER-004",
                    title="Vulnerable openssl Package",
                    severity="High",
                    confidence="High",
                    confidence_score=0.90,
                    source="package",
                    location="Package Database (Debian)",
                    redacted_secret="Debian openssl@3.0.11",
                    description="OpenSSL DoS vulnerability.",
                    remediation="Upgrade openssl.",
                    detector="vulnerability",
                    category="vulnerability",
                    package="openssl",
                    detected_version="3.0.11",
                    fixed_version="3.0.13",
                    cve="CVE-2024-0727",
                ),
            ],
        )

        rendered = format_html_report(report)
        self.assertIn("<!DOCTYPE html>", rendered)
        self.assertIn("DOCKSCAN SECURITY REPORT", rendered)
        self.assertIn("my-app:latest", rendered)
        self.assertIn("Private Key Detected", rendered)
        self.assertIn("/app/private.pem:1", rendered)
        self.assertIn("openssl", rendered)
        self.assertIn("CVE-2024-0727", rendered)
        self.assertIn("OSV lookup partially skipped", rendered)
        self.assertIn('data-severity="critical"', rendered)
        self.assertIn('data-category="vulnerability"', rendered)

    def test_escapes_html_to_prevent_xss(self) -> None:
        xss_payload = '<script>alert("xss")</script>'
        report = ScanReport(
            target=xss_payload,
            findings=[
                Finding(
                    rule_id="SEC-001",
                    title=xss_payload,
                    severity="High",
                    confidence="High",
                    source="filesystem",
                    location=xss_payload,
                    redacted_secret=xss_payload,
                    description=xss_payload,
                    remediation=xss_payload,
                )
            ],
        )
        rendered = format_html_report(report)
        self.assertNotIn(xss_payload, rendered)
        self.assertIn("&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;", rendered)

    def test_clean_report_renders_pass_banner(self) -> None:
        report = ScanReport(target="clean:latest", findings=[])
        rendered = format_html_report(report)
        self.assertIn("PASS — No security issues detected", rendered)
        self.assertIn("seg-pass", rendered)

    def test_write_html_report_and_cli_flags(self) -> None:
        fixture = REPO_ROOT / "dockscan" / "tests" / "fixtures" / "Dockerfile.insecure"
        with tempfile.TemporaryDirectory() as tmpdir:
            direct_html = Path(tmpdir) / "nested" / "direct.html"
            write_html_report(ScanReport(target="demo"), direct_html)
            self.assertTrue(direct_html.is_file())

            cli_html_1 = Path(tmpdir) / "dockscan.html"
            buf1 = io.StringIO()
            with redirect_stdout(buf1):
                code1 = dockscan_main(
                    ["--dockerfile", str(fixture), "--html", str(cli_html_1)]
                )
            self.assertEqual(code1, 1)
            self.assertTrue(cli_html_1.is_file())
            self.assertIn("DOCKSCAN SECURITY REPORT", cli_html_1.read_text(encoding="utf-8"))

            cli_html_2 = Path(tmpdir) / "df.html"
            buf2 = io.StringIO()
            with redirect_stdout(buf2):
                code2 = dockerfile_main([str(fixture), "--html", str(cli_html_2)])
            self.assertEqual(code2, 1)
            self.assertTrue(cli_html_2.is_file())


if __name__ == "__main__":
    unittest.main()
