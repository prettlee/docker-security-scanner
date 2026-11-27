"""End-to-end tests for Step 5: finding aggregation, reporting, and `dockscan` CLI."""

import io
import json
import tarfile
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Dict, List
from unittest.mock import patch

from dockscan.docker.image_loader import ImageLoadError
from dockscan.models.finding import Finding
from dockscan.reporting import format_json_report, format_terminal_report
from dockscan.scanner import main, scan_image
from dockscan.secrets.aggregator import aggregate_findings

FAKE_AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"
FAKE_GH_TOKEN = "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyzABCD"
FAKE_STRIPE_KEY = "sk_live_" + "1234567890abcdefghijklmn"
FAKE_DB_PASS = "Tr0ub4dorAnd3_SecretPass"
FAKE_LABEL_SECRET = "LabelPassword123456"


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


def _build_synthetic_image_tar(
    dest_path: Path,
    layers: List[Dict[str, bytes]],
    *,
    env: List[str] = None,
    labels: Dict[str, str] = None,
    history: List[Dict[str, str]] = None,
) -> Path:
    config_id = "abcdef1234567890abcdef1234567890"
    config_name = f"{config_id}.json"
    config_payload = {
        "config": {
            "User": "1000",
            "Env": env or [],
            "Labels": labels or {},
        },
        "history": history or [],
    }

    layer_paths: List[str] = []
    with tarfile.open(dest_path, "w") as outer:
        _add_bytes_to_tar(outer, config_name, json.dumps(config_payload).encode("utf-8"))
        for idx, layer_files in enumerate(layers):
            layer_tar_path = f"layer{idx:04d}digest/layer.tar"
            layer_paths.append(layer_tar_path)
            _add_bytes_to_tar(outer, layer_tar_path, _make_layer_tar(layer_files))

        manifest = [{"Config": config_name, "Layers": layer_paths}]
        _add_bytes_to_tar(outer, "manifest.json", json.dumps(manifest).encode("utf-8"))

    return dest_path


class AggregatorAndReportingTests(unittest.TestCase):
    def test_aggregator_deduplicates_and_sorts_by_severity_and_confidence(self) -> None:
        low = Finding(
            rule_id="ENT-001",
            title="Low entropy",
            severity="Low",
            confidence="Low",
            source="filesystem",
            location="layer:1:/b:1",
            redacted_secret="abcd***REDACTED*** (20 chars)",
            description="d",
            remediation="r",
        )
        crit1 = Finding(
            rule_id="SEC-001",
            title="AWS",
            severity="Critical",
            confidence="High",
            source="filesystem",
            location="layer:1:/a:1",
            redacted_secret="AKIA***REDACTED*** (20 chars)",
            description="d",
            remediation="r",
        )
        crit2 = Finding(
            rule_id="SEC-001",
            title="AWS",
            severity="Critical",
            confidence="High",
            source="filesystem",
            location="layer:1:/a:1",
            redacted_secret="AKIA***REDACTED*** (20 chars)",
            description="d",
            remediation="r",
        )
        agg = aggregate_findings([low, crit1, crit2])
        self.assertEqual(len(agg), 2)
        self.assertEqual(agg[0].severity, "Critical")
        self.assertEqual(agg[0].occurrences, 2)
        self.assertEqual(agg[1].severity, "Low")

    def test_scan_image_end_to_end_and_redacts_terminal_and_json_reports(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tar_path = _build_synthetic_image_tar(
                Path(tmpdir) / "vuln.tar",
                layers=[
                    {
                        "app/.env": (
                            f"STRIPE_KEY={FAKE_STRIPE_KEY}\n"
                            f"DB_URL=mysql://root:{FAKE_DB_PASS}@db:3306/app\n"
                        ).encode("utf-8"),
                        "app/id_rsa": b"-----BEGIN RSA PRIVATE KEY-----\nFAKE\n",
                    },
                    {"app/.wh..env": b""},
                ],
                env=[f"GITHUB_TOKEN={FAKE_GH_TOKEN}"],
                labels={"build_password": FAKE_LABEL_SECRET},
                history=[{"created_by": f"RUN curl -u u:{FAKE_DB_PASS} https://x"}],
            )

            report = scan_image(str(tar_path))
            self.assertEqual(report.layers_scanned, 2)
            self.assertEqual(report.files_scanned, 2)
            self.assertGreaterEqual(len(report.findings), 5)
            self.assertEqual(report.findings[0].severity, "Critical")

            terminal_out = format_terminal_report(report)
            json_out = format_json_report(report)
            for secret in (FAKE_STRIPE_KEY, FAKE_DB_PASS, FAKE_GH_TOKEN, FAKE_LABEL_SECRET):
                self.assertNotIn(secret, terminal_out)
                self.assertNotIn(secret, json_out)

    def test_cli_exit_codes_and_json_output_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            clean_tar = _build_synthetic_image_tar(
                Path(tmpdir) / "clean.tar",
                layers=[{"app/readme.txt": b"hello world\n"}],
            )
            vuln_tar = _build_synthetic_image_tar(
                Path(tmpdir) / "vuln.tar",
                layers=[{"app/.env": f"AWS_ACCESS_KEY_ID={FAKE_AWS_KEY}\n".encode("utf-8")}],
            )
            out_json = Path(tmpdir) / "report.json"

            clean_buf = io.StringIO()
            with redirect_stdout(clean_buf):
                self.assertEqual(main([str(clean_tar)]), 0)
            self.assertIn("[PASS]", clean_buf.getvalue())

            vuln_buf = io.StringIO()
            with redirect_stdout(vuln_buf):
                self.assertEqual(
                    main([str(vuln_tar), "--json", "--output", str(out_json)]), 1
                )
            parsed = json.loads(vuln_buf.getvalue())
            self.assertGreaterEqual(parsed["summary"]["total_findings"], 1)
            self.assertTrue(out_json.exists())

        err_buf = io.StringIO()
        with patch("dockscan.scanner.scan_image", side_effect=ImageLoadError("bad tar")):
            with redirect_stderr(err_buf):
                self.assertEqual(main(["missing:latest"]), 2)
        self.assertIn("Error: bad tar", err_buf.getvalue())


if __name__ == "__main__":
    unittest.main()
