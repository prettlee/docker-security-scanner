"""Unit tests for `docker inspect` parsing, checks, and CLI."""

import io
import json
import subprocess
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

from scanner.checks import check_root_user, run_checks
from scanner.cli import main
from scanner.inspector import DockerInspectError, inspect_target, parse_inspect_output
from scanner.models import ImageMetadata


SAMPLE_IMAGE_INSPECT = json.dumps(
    [
        {
            "Id": "sha256:abc123",
            "Config": {
                "User": "",
                "ExposedPorts": {"80/tcp": {}, "443/tcp": {}},
                "Env": [
                    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                    "APP_ENV=production=strict",
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
                "ExposedPorts": None,
                "Env": None,
                "Entrypoint": None,
            },
            "HostConfig": {
                "CapAdd": ["NET_ADMIN"],
                "CapDrop": ["ALL"],
            },
        }
    ]
)


class InspectorTests(unittest.TestCase):
    def test_parse_image_inspect_extracts_fields(self) -> None:
        meta = parse_inspect_output(SAMPLE_IMAGE_INSPECT, target="nginx:latest")
        self.assertEqual(meta.target, "nginx:latest")
        self.assertEqual(meta.user, "")
        self.assertEqual(meta.exposed_ports, ["443/tcp", "80/tcp"])
        self.assertEqual(
            meta.env,
            {
                "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                "APP_ENV": "production=strict",
            },
        )
        self.assertEqual(meta.entrypoint, ["/docker-entrypoint.sh"])
        self.assertEqual(meta.capabilities.add, [])
        self.assertEqual(meta.capabilities.drop, [])

    def test_parse_container_inspect_extracts_capabilities(self) -> None:
        meta = parse_inspect_output(SAMPLE_CONTAINER_INSPECT, target="web-1")
        self.assertEqual(meta.user, "1000:1000")
        self.assertEqual(meta.exposed_ports, [])
        self.assertEqual(meta.env, {})
        self.assertEqual(meta.entrypoint, [])
        self.assertEqual(meta.capabilities.add, ["NET_ADMIN"])
        self.assertEqual(meta.capabilities.drop, ["ALL"])

    def test_parse_invalid_json_raises(self) -> None:
        with self.assertRaises(DockerInspectError):
            parse_inspect_output("{not valid json", target="bad")

    def test_parse_empty_list_raises(self) -> None:
        with self.assertRaises(DockerInspectError):
            parse_inspect_output("[]", target="missing")

    @patch("scanner.inspector.subprocess.run")
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

    @patch("scanner.inspector.subprocess.run")
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
        finding = check_root_user(ImageMetadata(target="img", user=""))
        self.assertIsNotNone(finding)
        assert finding is not None
        self.assertEqual(finding.rule_id, "DOCKER-001")

    def test_flags_explicit_root_user(self) -> None:
        for user_val in ("root", "root:root", "0", "0:0"):
            with self.subTest(user_val=user_val):
                finding = check_root_user(ImageMetadata(target="img", user=user_val))
                self.assertIsNotNone(finding)

    def test_allows_non_root_user(self) -> None:
        for user_val in ("appuser", "1000", "1000:1000", "nobody:nogroup"):
            with self.subTest(user_val=user_val):
                self.assertEqual(
                    run_checks(ImageMetadata(target="img", user=user_val)), []
                )


class CliTests(unittest.TestCase):
    @patch("scanner.cli.inspect_target")
    def test_cli_json_output_with_finding_returns_1(
        self, mock_inspect: unittest.mock.MagicMock
    ) -> None:
        mock_inspect.return_value = parse_inspect_output(
            SAMPLE_IMAGE_INSPECT, target="nginx:latest"
        )
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            code = main(["nginx:latest", "--json"])
        self.assertEqual(code, 1)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["metadata"]["target"], "nginx:latest")
        self.assertEqual(payload["findings"][0]["rule_id"], "DOCKER-001")

    @patch("scanner.cli.inspect_target")
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

    @patch("scanner.cli.inspect_target", side_effect=DockerInspectError("boom"))
    def test_cli_inspect_error_returns_2(
        self, _mock_inspect: unittest.mock.MagicMock
    ) -> None:
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            code = main(["broken"])
        self.assertEqual(code, 2)
        self.assertIn("Error: boom", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
