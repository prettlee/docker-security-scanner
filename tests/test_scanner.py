"""Unit tests for Docker inspection, package extraction, OSV lookup, checks, and CLI."""

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
    check_vulnerabilities,
    run_checks,
)
from scanner.cli import main
from scanner.models import ImageMetadata, InstalledPackage, PortBinding
from scanner.reports import write_report
from scanner.scanner import scan_inspect_json, scan_target
from scanner.utils.docker import (
    DockerInspectError,
    inspect_target,
    parse_inspect_output,
)
from scanner.utils.osv import (
    OSVApiError,
    VulnerabilityDetail,
    fetch_vuln_details,
    parse_vuln_detail,
    query_batch,
)
from scanner.utils.packages import (
    PackageExtractionError,
    extract_packages,
    parse_probe_output,
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
            "State": {"Running": True},
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

SAMPLE_PROBE_OUTPUT = """
===OS_RELEASE===
PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
ID=debian
===DPKG===
openssl\t3.0.11-1~deb12u2
ca-certificates\t20230311
===APK===
busybox-1.36.1-r15
libcrypto3-3.1.4-r5
===PIP===
[{"name": "requests", "version": "2.31.0"}, {"name": "jinja2", "version": "2.4.1"}]
===NPM===
{"dependencies": {"axios": {"version": "0.21.1"}}}
""".strip()


class DockerUtilsTests(unittest.TestCase):
    def test_parse_image_inspect_extracts_fields(self) -> None:
        meta = parse_inspect_output(SAMPLE_IMAGE_INSPECT, target="nginx:latest")
        self.assertEqual(meta.target, "nginx:latest")
        self.assertEqual(meta.user, "")
        self.assertFalse(meta.is_container)
        self.assertFalse(meta.is_running)
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

    def test_parse_container_inspect_extracts_state_capabilities_and_bindings(self) -> None:
        meta = parse_inspect_output(SAMPLE_CONTAINER_INSPECT, target="web-1")
        self.assertEqual(meta.user, "1000:1000")
        self.assertTrue(meta.is_container)
        self.assertTrue(meta.is_running)
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


class PackageExtractionTests(unittest.TestCase):
    def test_parse_probe_output_extracts_all_ecosystems(self) -> None:
        packages = parse_probe_output(SAMPLE_PROBE_OUTPUT)
        self.assertEqual(
            packages,
            [
                InstalledPackage("Debian", "openssl", "3.0.11-1~deb12u2"),
                InstalledPackage("Debian", "ca-certificates", "20230311"),
                InstalledPackage("Alpine", "busybox", "1.36.1-r15"),
                InstalledPackage("Alpine", "libcrypto3", "3.1.4-r5"),
                InstalledPackage("PyPI", "requests", "2.31.0"),
                InstalledPackage("PyPI", "jinja2", "2.4.1"),
                InstalledPackage("npm", "axios", "0.21.1"),
            ],
        )

    def test_parse_probe_output_detects_ubuntu_for_dpkg(self) -> None:
        ubuntu_probe = "===OS_RELEASE===\nID=ubuntu\n===DPKG===\nzlib1g\t1:1.2.11\n"
        packages = parse_probe_output(ubuntu_probe)
        self.assertEqual(
            packages, [InstalledPackage("Ubuntu", "zlib1g", "1:1.2.11")]
        )

    @patch("scanner.utils.packages.subprocess.run")
    def test_extract_packages_uses_docker_run_for_image(
        self, mock_run: unittest.mock.MagicMock
    ) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            args=["docker", "run"],
            returncode=0,
            stdout=SAMPLE_PROBE_OUTPUT,
            stderr="",
        )
        meta = ImageMetadata(target="python:3.11-slim", user="root")
        packages = extract_packages(meta)
        self.assertEqual(len(packages), 7)
        called_cmd = mock_run.call_args.args[0]
        self.assertEqual(called_cmd[:4], ["docker", "run", "--rm", "--entrypoint"])

    @patch("scanner.utils.packages.subprocess.run")
    def test_extract_packages_uses_docker_exec_for_running_container(
        self, mock_run: unittest.mock.MagicMock
    ) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            args=["docker", "exec"],
            returncode=0,
            stdout=SAMPLE_PROBE_OUTPUT,
            stderr="",
        )
        meta = ImageMetadata(
            target="web-1", user="1000", is_container=True, is_running=True
        )
        extract_packages(meta)
        called_cmd = mock_run.call_args.args[0]
        self.assertEqual(called_cmd[:3], ["docker", "exec", "web-1"])

    def test_extract_packages_stopped_container_raises(self) -> None:
        meta = ImageMetadata(
            target="stopped-1", user="1000", is_container=True, is_running=False
        )
        with self.assertRaises(PackageExtractionError):
            extract_packages(meta)


class OsvClientTests(unittest.TestCase):
    @patch("scanner.utils.osv._post_json")
    def test_query_batch_handles_pagination(
        self, mock_post: unittest.mock.MagicMock
    ) -> None:
        pkg1 = InstalledPackage("PyPI", "jinja2", "2.4.1")
        pkg2 = InstalledPackage("npm", "axios", "0.21.1")

        mock_post.side_effect = [
            {
                "results": [
                    {
                        "vulns": [{"id": "GHSA-1111"}],
                        "next_page_token": "tok-2",
                    },
                    {"vulns": []},
                ]
            },
            {
                "results": [
                    {"vulns": [{"id": "GHSA-2222"}]},
                ]
            },
        ]

        matches = query_batch([pkg1, pkg2])
        self.assertEqual(matches, {pkg1: ["GHSA-1111", "GHSA-2222"]})
        self.assertEqual(mock_post.call_count, 2)
        second_payload = mock_post.call_args_list[1].args[1]
        self.assertEqual(len(second_payload["queries"]), 1)
        self.assertEqual(second_payload["queries"][0]["page_token"], "tok-2")

    def test_parse_vuln_detail_extracts_severity_aliases_and_fixed(self) -> None:
        raw = {
            "id": "GHSA-cph5-m8f7-6c5x",
            "summary": "Axios SSRF vulnerability",
            "aliases": ["CVE-2021-3749"],
            "database_specific": {"severity": "HIGH"},
            "affected": [
                {
                    "ranges": [
                        {"events": [{"introduced": "0"}, {"fixed": "0.21.2"}]}
                    ]
                }
            ],
        }
        detail = parse_vuln_detail(raw, fallback_id="GHSA-cph5-m8f7-6c5x")
        self.assertEqual(detail.severity, "HIGH")
        self.assertEqual(detail.aliases, ["CVE-2021-3749"])
        self.assertEqual(detail.fixed_versions, ["0.21.2"])
        self.assertEqual(detail.summary, "Axios SSRF vulnerability")

    @patch("scanner.utils.osv._get_json")
    def test_fetch_vuln_details_degrades_gracefully_on_single_error(
        self, mock_get: unittest.mock.MagicMock
    ) -> None:
        def side_effect(url: str, timeout: float) -> dict:
            if url.endswith("GHSA-bad"):
                raise OSVApiError("404")
            return {"id": "GHSA-good", "summary": "Good record"}

        mock_get.side_effect = side_effect
        details = fetch_vuln_details(["GHSA-good", "GHSA-bad"])
        self.assertEqual(details["GHSA-good"].summary, "Good record")
        self.assertEqual(details["GHSA-bad"].vuln_id, "GHSA-bad")


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


class CheckVulnerabilitiesTests(unittest.TestCase):
    def test_check_vulnerabilities_formats_and_sorts_findings(self) -> None:
        pkg_npm = InstalledPackage("npm", "axios", "0.21.1")
        pkg_pip = InstalledPackage("PyPI", "jinja2", "2.4.1")
        meta = ImageMetadata(target="app", user="1000", packages=[pkg_npm, pkg_pip])

        findings = check_vulnerabilities(
            meta,
            batch_query_fn=lambda _pkgs: {
                pkg_pip: ["PYSEC-2019-1"],
                pkg_npm: ["GHSA-cph5"],
            },
            detail_fetch_fn=lambda _ids: {
                "PYSEC-2019-1": VulnerabilityDetail(
                    vuln_id="PYSEC-2019-1",
                    summary="Jinja2 sandbox escape",
                    severity="CRITICAL",
                    aliases=["CVE-2019-10906"],
                    fixed_versions=["2.10.1"],
                ),
                "GHSA-cph5": VulnerabilityDetail(
                    vuln_id="GHSA-cph5",
                    summary="Axios SSRF",
                    severity="HIGH",
                    aliases=["CVE-2021-3749"],
                    fixed_versions=["0.21.2"],
                ),
            },
        )

        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0].rule_id, "DOCKER-004")
        self.assertEqual(findings[0].severity, "CRITICAL")
        self.assertIn("CVE-2019-10906", findings[0].title)
        self.assertIn("2.10.1", findings[0].remediation)
        self.assertEqual(findings[1].severity, "HIGH")


class ScannerAndCliTests(unittest.TestCase):
    def test_scan_inspect_json_runs_config_checks(self) -> None:
        result = scan_inspect_json(SAMPLE_IMAGE_INSPECT, target="demo:latest")
        rule_ids = [f.rule_id for f in result.findings]
        self.assertIn("DOCKER-001", rule_ids)
        self.assertEqual(rule_ids.count("DOCKER-002"), 2)
        self.assertIn("DOCKER-003", rule_ids)

    @patch("scanner.scanner.check_vulnerabilities")
    @patch("scanner.scanner.extract_packages")
    @patch("scanner.scanner.inspect_target")
    def test_scan_target_records_warning_when_osv_unreachable(
        self,
        mock_inspect: unittest.mock.MagicMock,
        mock_extract: unittest.mock.MagicMock,
        mock_vuln_check: unittest.mock.MagicMock,
    ) -> None:
        mock_inspect.return_value = parse_inspect_output(
            SAMPLE_CONTAINER_INSPECT, target="web-1"
        )
        mock_extract.return_value = [InstalledPackage("PyPI", "jinja2", "2.4.1")]
        mock_vuln_check.side_effect = OSVApiError("offline")

        result = scan_target("web-1")
        self.assertEqual(result.findings, [])
        self.assertEqual(len(result.warnings), 1)
        self.assertIn("offline", result.warnings[0])

    @patch("scanner.scanner.extract_packages")
    @patch("scanner.scanner.inspect_target")
    def test_cli_no_vuln_skips_package_extraction(
        self,
        mock_inspect: unittest.mock.MagicMock,
        mock_extract: unittest.mock.MagicMock,
    ) -> None:
        mock_inspect.return_value = parse_inspect_output(
            SAMPLE_CONTAINER_INSPECT, target="web-1"
        )
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            code = main(["web-1", "--no-vuln"])
        self.assertEqual(code, 0)
        mock_extract.assert_not_called()
        self.assertIn("[PASS] No issues detected.", stdout.getvalue())

    @patch("scanner.scanner.extract_packages", return_value=[])
    @patch("scanner.scanner.inspect_target")
    def test_cli_json_output_with_findings_and_report_file(
        self,
        mock_inspect: unittest.mock.MagicMock,
        _mock_extract: unittest.mock.MagicMock,
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
