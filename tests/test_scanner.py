"""Unit tests for `docker inspect` parsing, security checks, reports, and CLI."""

import io
import json
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from scanner.checks import (
    check_dangerous_ports,
    check_root_user,
    check_suspicious_env,
    run_checks,
)
from scanner.cli import main
from scanner.models import ImageMetadata, PortBinding
from scanner.reports import write_report
from scanner.scanner import scan_inspect_json
from scanner.utils.docker import (
    DockerInspectError,
    inspect_target,
    parse_inspect_output,
)


SAMPLE_IMAGE_INSPECT = json.dumps(
    [
        {
            "Id": "sha256:abc123",
            "Config": {
                "User": "",
                "ExposedPorts": {"22/tcp": {}, "80/tcp": {}, "5432/tcp": {}},
                "Env": [
                    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                    "APP_ENV=production=strict",
                    "STRIPE_API_KEY=sk_test_supersecret123",
                ],
                "Entrypoint": ["/docker-entrypoint.sh"],
            },
        }
    ]
)

SAMPLE_CONTAINER_INSPECT = json.dumps(
    [
        {
            "Id": "container123",
            "Config": {
                "User": "1000:1000",
                "ExposedPorts": {"5432/tcp": {}},
                "Env": ["APP_ENV=production"],
                "Entrypoint": None,
            },
            "HostConfig": {
                "CapAdd": ["NET_ADMIN"],
                "CapDrop": ["ALL"],
                "PortBindings": {
                    "5432/tcp": [{"HostIp": "127.0.0.1", "HostPort": "5432"}]
                },
            },
        }
    ]
)


class DockerUtilsTests(unittest.TestCase):
    def test_parse_image_inspect_extracts_fields(self) -> None:
        meta = parse_inspect_output(SAMPLE_IMAGE_INSPECT, target="nginx:latest")
        self.assertEqual(meta.target, "nginx:latest")
        self.assertEqual(meta.user, "")
        self.assertEqual(meta.exposed_ports, ["22/tcp", "5432/tcp", "80/tcp"])
        self.assertEqual(meta.port_bindings, [])
        self.assertEqual(
            meta.env,
            {
                "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                "APP_ENV": "production=strict",
                "STRIPE_API_KEY": "sk_test_supersecret123",
            },
        )
        self.assertEqual(meta.entrypoint, ["/docker-entrypoint.sh"])
        self.assertEqual(meta.capabilities.add, [])
        self.assertEqual(meta.capabilities.drop, [])

    def test_parse_container_inspect_extracts_capabilities_and_bindings(self) -> None:
        meta = parse_inspect_output(SAMPLE_CONTAINER_INSPECT, target="web-1")
        self.assertEqual(meta.user, "1000:1000")
        self.assertEqual(meta.exposed_ports, ["5432/tcp"])
        self.assertEqual(
            meta.port_bindings,
            [PortBinding(container_port="5432/tcp", host_ip="127.0.0.1", host_port="5432")],
        )
        self.assertEqual(meta.capabilities.add, ["NET_ADMIN"])
        self.assertEqual(meta.capabilities.drop, ["ALL"])

    def test_parse_invalid_json_raises(self) -> None:
        with self.assertRaises(DockerInspectError):
            parse_inspect_output("{not valid json", target="bad")

    def test_parse_empty_list_raises(self) -> None:
        with self.assertRaises(DockerInspectError):
            parse_inspect_output("[]", target="missing")

    @patch("scanner.utils.docker.subprocess.run")
    def test_inspect_target_success(self, mock_run: unittest.mock.MagicMock) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            args=["docker", "inspect", "nginx:latest"],
            returncode=0,
            stdout=SAMPLE_IMAGE_INSPECT,
            stderr="",
        )
        meta = inspect_target("nginx:latest")
        mock_run.assert_called_once_with(
            ["docker", "inspect", "nginx:latest"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(meta.entrypoint, ["/docker-entrypoint.sh"])

    @patch("scanner.utils.docker.subprocess.run")
    def test_inspect_target_nonzero_exit_raises(
        self, mock_run: unittest.mock.MagicMock
    ) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            args=["docker", "inspect", "nope"],
            returncode=1,
            stdout="",
            stderr="Error: No such object: nope",
        )
        with self.assertRaises(DockerInspectError) as ctx:
            inspect_target("nope")
        self.assertIn("No such object: nope", str(ctx.exception))


class CheckRootUserTests(unittest.TestCase):
    def test_flags_empty_user(self) -> None:
        findings = check_root_user(ImageMetadata(target="img", user=""))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "DOCKER-001")

    def test_flags_explicit_root_user(self) -> None:
        for user_val in ("root", "root:root", "0", "0:0"):
            with self.subTest(user_val=user_val):
                findings = check_root_user(ImageMetadata(target="img", user=user_val))
                self.assertEqual(len(findings), 1)

    def test_allows_non_root_user(self) -> None:
        for user_val in ("appuser", "1000", "1000:1000", "nobody:nogroup"):
            with self.subTest(user_val=user_val):
                self.assertEqual(
                    run_checks(ImageMetadata(target="img", user=user_val)), []
                )


class CheckDangerousPortsTests(unittest.TestCase):
    def test_flags_ssh_docker_api_and_database_ports_in_image(self) -> None:
        meta = ImageMetadata(
            target="img",
            user="1000",
            exposed_ports=["22/tcp", "2375/tcp", "3306/tcp", "8080/tcp"],
        )
        findings = check_dangerous_ports(meta)
        self.assertEqual(len(findings), 3)
        severities = {f.title: f.severity for f in findings}
        self.assertEqual(severities["Dangerous port 22 (SSH) exposed"], "HIGH")
        self.assertEqual(
            severities["Dangerous port 2375 (Docker Daemon API (unencrypted)) exposed"],
            "CRITICAL",
        )
        self.assertEqual(
            severities["Database port 3306 (MySQL / MariaDB) exposed publicly"],
            "HIGH",
        )

    def test_ignores_localhost_bound_database_port_on_container(self) -> None:
        meta = ImageMetadata(
            target="db",
            user="1000",
            exposed_ports=["5432/tcp"],
            port_bindings=[
                PortBinding(
                    container_port="5432/tcp", host_ip="127.0.0.1", host_port="5432"
                )
            ],
        )
        self.assertEqual(check_dangerous_ports(meta), [])

    def test_flags_publicly_bound_database_port_on_container(self) -> None:
        meta = ImageMetadata(
            target="db",
            user="1000",
            exposed_ports=["6379/tcp"],
            port_bindings=[
                PortBinding(
                    container_port="6379/tcp", host_ip="0.0.0.0", host_port="6379"
                )
            ],
        )
        findings = check_dangerous_ports(meta)
        self.assertEqual(len(findings), 1)
        self.assertIn("0.0.0.0:6379->6379/tcp", findings[0].evidence or "")


class CheckSuspiciousEnvTests(unittest.TestCase):
    def test_flags_suspicious_keys_and_redacts_values(self) -> None:
        meta = ImageMetadata(
            target="app",
            user="1000",
            env={
                "PORT": "8000",
                "STRIPE_API_KEY": "sk_live_secretvalue",
                "JWT_SECRET": "supersecret",
                "DB_PASSWORD": "hunter2",
                "github_token": "",
            },
        )
        findings = check_suspicious_env(meta)
        self.assertEqual(len(findings), 4)
        all_evidence = "\n".join(f.evidence or "" for f in findings)
        self.assertNotIn("sk_live_secretvalue", all_evidence)
        self.assertNotIn("supersecret", all_evidence)
        self.assertNotIn("hunter2", all_evidence)
        self.assertIn("***REDACTED***", all_evidence)

        by_title = {f.title: f for f in findings}
        self.assertEqual(
            by_title["Suspicious secret-like environment variable 'github_token'"].severity,
            "MEDIUM",
        )
        self.assertEqual(
            by_title["Hardcoded secret-like environment variable 'DB_PASSWORD'"].severity,
            "HIGH",
        )


class ScannerAndCliTests(unittest.TestCase):
    def test_scan_inspect_json_runs_all_checks(self) -> None:
        result = scan_inspect_json(SAMPLE_IMAGE_INSPECT, target="demo:latest")
        rule_ids = [f.rule_id for f in result.findings]
        self.assertIn("DOCKER-001", rule_ids)
        self.assertEqual(rule_ids.count("DOCKER-002"), 2)  # 22/tcp and 5432/tcp
        self.assertIn("DOCKER-003", rule_ids)

    @patch("scanner.scanner.inspect_target")
    def test_cli_json_output_with_findings_and_report_file(
        self, mock_inspect: unittest.mock.MagicMock
    ) -> None:
        mock_inspect.return_value = parse_inspect_output(
            SAMPLE_IMAGE_INSPECT, target="nginx:latest"
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            report_path = Path(tmpdir) / "report.json"
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                code = main(["nginx:latest", "--json", "--output", str(report_path)])
            self.assertEqual(code, 1)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["metadata"]["target"], "nginx:latest")
            self.assertTrue(report_path.exists())
            saved = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertEqual(len(saved["findings"]), 4)

    @patch("scanner.scanner.inspect_target")
    def test_cli_clean_target_returns_0(
        self, mock_inspect: unittest.mock.MagicMock
    ) -> None:
        mock_inspect.return_value = parse_inspect_output(
            SAMPLE_CONTAINER_INSPECT, target="web-1"
        )
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            code = main(["web-1"])
        self.assertEqual(code, 0)
        self.assertIn("[PASS] No issues detected.", stdout.getvalue())

    @patch("scanner.scanner.inspect_target", side_effect=DockerInspectError("boom"))
    def test_cli_inspect_error_returns_2(
        self, _mock_inspect: unittest.mock.MagicMock
    ) -> None:
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            code = main(["broken"])
        self.assertEqual(code, 2)
        self.assertIn("Error: boom", stderr.getvalue())

    def test_write_report_text(self) -> None:
        result = scan_inspect_json(SAMPLE_CONTAINER_INSPECT, target="web-1")
        with tempfile.TemporaryDirectory() as tmpdir:
            out = write_report(result, Path(tmpdir) / "nested" / "scan.txt")
            self.assertTrue(out.exists())
            self.assertIn("Target: web-1", out.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
