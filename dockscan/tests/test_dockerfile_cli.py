"""End-to-end CLI tests for Phase 6 Step 4: Dockerfile analyzer CLI and fixtures."""

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from dockscan.dockerfile import analyze_dockerfile_file
from dockscan.dockerfile.cli import main as dockerfile_main
from dockscan.scanner import main as dockscan_main

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"

HARDENED_DOCKERFILE = """
FROM python:3.11.8-slim AS builder
WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

FROM python:3.11.8-slim
RUN groupadd -r app && useradd -r -g app appuser
WORKDIR /app
COPY --from=builder /usr/local /usr/local
COPY app.py .
USER appuser
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health')"
CMD ["python", "app.py"]
""".strip()


class DockerfileCliTests(unittest.TestCase):
    def test_analyzes_insecure_fixture_and_cli_modes(self) -> None:
        fixture = FIXTURES_DIR / "Dockerfile.insecure"
        report = analyze_dockerfile_file(fixture)
        rule_ids = {f.rule_id for f in report.findings}
        for expected in ("DF-001", "DF-002", "DF-004", "DF-005", "DF-006", "DF-007", "SEC-001", "SEC-010"):
            self.assertIn(expected, rule_ids)

        with tempfile.TemporaryDirectory() as tmpdir:
            out_json = Path(tmpdir) / "df-report.json"
            buf = io.StringIO()
            with redirect_stdout(buf):
                code = dockerfile_main([str(fixture), "--json", "--output", str(out_json)])
            self.assertEqual(code, 1)
            payload = json.loads(buf.getvalue())
            self.assertGreaterEqual(payload["summary"]["total_findings"], 8)
            self.assertTrue(out_json.exists())

            buf2 = io.StringIO()
            with redirect_stdout(buf2):
                code2 = dockscan_main(["--dockerfile", str(fixture)])
            self.assertEqual(code2, 1)
            self.assertIn("DOCKSCAN SECURITY REPORT", buf2.getvalue())

            hardened = Path(tmpdir) / "Dockerfile.clean"
            hardened.write_text(HARDENED_DOCKERFILE, encoding="utf-8")
            buf3 = io.StringIO()
            with redirect_stdout(buf3):
                self.assertEqual(dockerfile_main([str(hardened)]), 0)
            self.assertIn("[PASS]", buf3.getvalue())

        err_buf = io.StringIO()
        with redirect_stderr(err_buf):
            self.assertEqual(dockerfile_main(["/nonexistent/Dockerfile"]), 2)
        self.assertIn("Dockerfile not found", err_buf.getvalue())


if __name__ == "__main__":
    unittest.main()
