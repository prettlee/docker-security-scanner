"""Unit tests for GitHub Action helpers, --fail-on thresholds, and Step Summary."""

import io
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from dockscan.models.finding import Finding, ScanReport
from dockscan.reporting import format_github_summary, should_fail_ci, write_github_summary
from dockscan.scanner import main

REPO_ROOT = Path(__file__).resolve().parents[2]


def _sample_finding(severity: str) -> Finding:
    return Finding(
        rule_id="SEC-001",
        title=f"{severity} test finding",
        severity=severity,
        confidence="High",
        confidence_score=0.95,
        source="filesystem",
        location="layer:abc:/app/.env:1",
        redacted_secret="AKIA***REDACTED*** (20 chars)",
        description="Test finding",
        remediation="Rotate credential.",
    )


class GitHubActionHelpersTests(unittest.TestCase):
    def test_should_fail_ci_respects_severity_threshold(self) -> None:
        report_med = ScanReport(target="img", findings=[_sample_finding("Medium")])
        self.assertFalse(should_fail_ci(report_med, "critical"))
        self.assertFalse(should_fail_ci(report_med, "high"))
        self.assertTrue(should_fail_ci(report_med, "medium"))
        self.assertTrue(should_fail_ci(report_med, "low"))
        self.assertFalse(should_fail_ci(report_med, "none"))

        report_crit = ScanReport(target="img", findings=[_sample_finding("Critical")])
        self.assertTrue(should_fail_ci(report_crit, "critical"))
        self.assertFalse(should_fail_ci(report_crit, "none"))

    def test_format_and_write_github_summary(self) -> None:
        report = ScanReport(
            target="my-app:latest",
            layers_scanned=2,
            files_scanned=5,
            packages_scanned=10,
            findings=[_sample_finding("Critical"), _sample_finding("Low")],
        )
        md = format_github_summary(report)
        self.assertIn("## Dockscan Security Report", md)
        self.assertIn("| 1 | 0 | 0 | 1 | 2 |", md)
        self.assertIn("**CRITICAL**", md)

        with tempfile.TemporaryDirectory() as tmpdir:
            summary_file = Path(tmpdir) / "summary.md"
            written = write_github_summary(report, summary_file)
            self.assertEqual(written, summary_file)
            self.assertIn("## Dockscan Security Report", summary_file.read_text(encoding="utf-8"))

    def test_cli_fail_on_and_github_summary_flags(self) -> None:
        fixture = REPO_ROOT / "dockscan" / "tests" / "fixtures" / "Dockerfile.insecure"
        with tempfile.TemporaryDirectory() as tmpdir:
            summary_path = Path(tmpdir) / "gh_summary.md"
            out_json = Path(tmpdir) / "report.json"
            buf = io.StringIO()
            with patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": str(summary_path)}):
                with redirect_stdout(buf):
                    code = main(
                        [
                            "--dockerfile",
                            str(fixture),
                            "--fail-on",
                            "none",
                            "--github-summary",
                            "--output",
                            str(out_json),
                        ]
                    )
            self.assertEqual(code, 0)
            self.assertTrue(out_json.exists())
            self.assertTrue(summary_path.exists())
            self.assertIn("Dockscan Security Report", summary_path.read_text(encoding="utf-8"))

    def test_action_and_workflow_files_exist_with_expected_structure(self) -> None:
        action_yml = REPO_ROOT / "action.yml"
        workflow_yml = REPO_ROOT / ".github" / "workflows" / "ci.yml"
        self.assertTrue(action_yml.is_file())
        self.assertTrue(workflow_yml.is_file())

        action_text = action_yml.read_text(encoding="utf-8")
        self.assertIn('using: "composite"', action_text)
        self.assertIn("total-findings:", action_text)
        self.assertIn("python3 -m dockscan", action_text)

        workflow_text = workflow_yml.read_text(encoding="utf-8")
        self.assertIn("uses: ./", workflow_text)
        self.assertIn("actions/upload-artifact@v4", workflow_text)


if __name__ == "__main__":
    unittest.main()
