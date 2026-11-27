"""Unit tests for Phase 6 Step 2: base image, USER, ADD, and HEALTHCHECK checks."""

import unittest

from dockscan.dockerfile import analyze_dockerfile_text


class DockerfileStructureChecksTests(unittest.TestCase):
    def test_detects_latest_untagged_missing_user_add_and_missing_healthcheck(self) -> None:
        df = """
        FROM ubuntu
        FROM python:latest
        ADD https://example.com/app.tar.gz /tmp/
        ADD local.tar.gz /app/
        CMD ["python", "app.py"]
        """
        report = analyze_dockerfile_text(df, path="Dockerfile")
        rule_ids = {f.rule_id for f in report.findings}
        self.assertEqual(rule_ids, {"DF-001", "DF-002", "DF-004", "DF-007"})

        df001_titles = [f.title for f in report.findings if f.rule_id == "DF-001"]
        self.assertEqual(len(df001_titles), 2)

        df004_severities = sorted(
            f.severity for f in report.findings if f.rule_id == "DF-004"
        )
        self.assertEqual(df004_severities, ["High", "Medium"])

    def test_flags_explicit_root_user_and_disabled_healthcheck(self) -> None:
        df = """
        FROM alpine:3.19
        USER root
        HEALTHCHECK NONE
        """
        report = analyze_dockerfile_text(df, path="Dockerfile")
        rule_ids = {f.rule_id for f in report.findings}
        self.assertEqual(rule_ids, {"DF-002", "DF-007"})

    def test_allows_digest_pinned_multistage_nonroot_with_healthcheck(self) -> None:
        df = """
        FROM python:3.11.8-slim AS builder
        WORKDIR /build

        FROM ubuntu@sha256:0123456789abcdef
        COPY --from=builder /build /app
        COPY app.py /app/
        USER 10001
        HEALTHCHECK CMD true
        """
        report = analyze_dockerfile_text(df, path="Dockerfile")
        self.assertEqual(report.findings, [])


if __name__ == "__main__":
    unittest.main()
