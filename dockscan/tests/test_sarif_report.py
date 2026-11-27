"""Unit tests for SARIF v2.1.0 report generation and CLI integration."""

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from dockscan.dockerfile.cli import main as dockerfile_main
from dockscan.models.finding import Finding, ScanReport
from dockscan.reporting import build_sarif_dict, format_sarif_report, write_sarif_report
from dockscan.scanner import main as dockscan_main

REPO_ROOT = Path(__file__).resolve().parents[2]


class SarifReportTests(unittest.TestCase):
    def test_builds_valid_sarif_2_1_0_with_rules_levels_and_locations(self) -> None:
        report = ScanReport(
            target="my-app:latest",
            findings=[
                Finding(
                    rule_id="SEC-003",
                    title="Private Key Detected",
                    severity="Critical",
                    confidence="High",
                    confidence_score=0.95,
                    source="filesystem",
                    location="layer:abc:/app/credentials/private.pem:1",
                    redacted_secret="-----***REDACTED*** (31 chars)",
                    description="PEM private key exposed.",
                    remediation="Remove private key from image.",
                    category="secret",
                    file_path="/app/credentials/private.pem",
                    line_number=1,
                ),
                Finding(
                    rule_id="DF-005",
                    title="Unpinned pip dependencies",
                    severity="Medium",
                    confidence="High",
                    confidence_score=0.90,
                    source="dockerfile",
                    location="Dockerfile:9",
                    redacted_secret="pip: requests",
                    description="Unpinned pip install.",
                    remediation="Pin versions.",
                    category="misconfiguration",
                    file_path="Dockerfile",
                    line_number=9,
                ),
                Finding(
                    rule_id="DF-007",
                    title="Missing HEALTHCHECK instruction",
                    severity="Low",
                    confidence="High",
                    confidence_score=1.0,
                    source="dockerfile",
                    location="Dockerfile:1",
                    redacted_secret="No HEALTHCHECK",
                    description="No healthcheck configured.",
                    remediation="Add HEALTHCHECK.",
                    category="misconfiguration",
                    file_path="Dockerfile",
                    line_number=1,
                ),
                Finding(
                    rule_id="DF-007",
                    title="Missing HEALTHCHECK instruction",
                    severity="Low",
                    confidence="High",
                    confidence_score=1.0,
                    source="dockerfile",
                    location="Dockerfile:20",
                    redacted_secret="No HEALTHCHECK",
                    description="No healthcheck configured.",
                    remediation="Add HEALTHCHECK.",
                    category="misconfiguration",
                    file_path="Dockerfile",
                    line_number=20,
                ),
            ],
        )

        sarif = build_sarif_dict(report)
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertIn("sarif-schema-2.1.0.json", sarif["$schema"])
        run = sarif["runs"][0]
        driver = run["tool"]["driver"]
        self.assertEqual(driver["name"], "dockscan")

        # Rules should be deduplicated by rule_id (SEC-003, DF-005, DF-007 -> 3 rules)
        self.assertEqual([r["id"] for r in driver["rules"]], ["SEC-003", "DF-005", "DF-007"])
        self.assertEqual(driver["rules"][0]["properties"]["security-severity"], "9.5")

        results = run["results"]
        self.assertEqual(len(results), 4)
        self.assertEqual(results[0]["level"], "error")
        self.assertEqual(results[1]["level"], "warning")
        self.assertEqual(results[2]["level"], "note")

        loc0 = results[0]["locations"][0]["physicalLocation"]
        self.assertEqual(loc0["artifactLocation"]["uri"], "app/credentials/private.pem")
        self.assertEqual(loc0["region"]["startLine"], 1)
        self.assertIn("dockscan/v1", results[0]["partialFingerprints"])

    def test_sarif_handles_empty_findings_and_cli_flags(self) -> None:
        empty_sarif = json.loads(format_sarif_report(ScanReport(target="clean:latest")))
        self.assertEqual(empty_sarif["runs"][0]["results"], [])
        self.assertEqual(empty_sarif["runs"][0]["tool"]["driver"]["rules"], [])

        fixture = REPO_ROOT / "dockscan" / "tests" / "fixtures" / "Dockerfile.insecure"
        with tempfile.TemporaryDirectory() as tmpdir:
            sarif_out_1 = Path(tmpdir) / "nested" / "dockscan.sarif"
            write_sarif_report(ScanReport(target="demo"), sarif_out_1)
            self.assertTrue(sarif_out_1.is_file())

            sarif_cli = Path(tmpdir) / "cli.sarif"
            buf1 = io.StringIO()
            with redirect_stdout(buf1):
                code1 = dockscan_main(
                    ["--dockerfile", str(fixture), "--sarif", str(sarif_cli)]
                )
            self.assertEqual(code1, 1)
            parsed1 = json.loads(sarif_cli.read_text(encoding="utf-8"))
            self.assertEqual(parsed1["version"], "2.1.0")
            self.assertGreaterEqual(len(parsed1["runs"][0]["results"]), 8)
            self.assertNotIn("SuperInsecureBuildPassword99", sarif_cli.read_text(encoding="utf-8"))

            sarif_df = Path(tmpdir) / "df.sarif"
            buf2 = io.StringIO()
            with redirect_stdout(buf2):
                code2 = dockerfile_main([str(fixture), "--sarif", str(sarif_df)])
            self.assertEqual(code2, 1)
            self.assertTrue(sarif_df.is_file())


if __name__ == "__main__":
    unittest.main()
