"""Unit tests for Phase 6 Step 1: Dockerfile parser."""

import tempfile
import unittest
from pathlib import Path

from dockscan.dockerfile import parse_dockerfile_file, parse_dockerfile_text


class DockerfileParserTests(unittest.TestCase):
    def test_parses_continuations_comments_and_multistage_builds(self) -> None:
        df = """
        # syntax=docker/dockerfile:1
        FROM --platform=linux/amd64 python:3.11-slim AS builder
        RUN apt-get update && \\
            # inline comment inside continuation
            apt-get install -y curl=7.88.1-10
        FROM alpine:3.19
        USER 1000
        """
        parsed = parse_dockerfile_text(df, path="Dockerfile")
        self.assertEqual(len(parsed.stages), 2)
        self.assertEqual(parsed.stages[0].base_image, "python:3.11-slim")
        self.assertEqual(parsed.stages[0].alias, "builder")
        self.assertEqual(parsed.stages[0].from_line, 3)
        self.assertEqual(parsed.stages[1].base_image, "alpine:3.19")
        self.assertIsNone(parsed.stages[1].alias)

        run_instr = parsed.stages[0].instructions[1]
        self.assertEqual(run_instr.instruction, "RUN")
        self.assertEqual(run_instr.line_number, 4)
        self.assertIn("apt-get install -y curl=7.88.1-10", run_instr.arguments)

    def test_parse_dockerfile_file_reads_from_disk(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            df_path = Path(tmpdir) / "Dockerfile"
            df_path.write_text("FROM alpine:3.19\nUSER app\n", encoding="utf-8")
            parsed = parse_dockerfile_file(df_path)
            self.assertEqual(parsed.path, str(df_path))
            self.assertEqual(len(parsed.instructions), 2)


if __name__ == "__main__":
    unittest.main()
