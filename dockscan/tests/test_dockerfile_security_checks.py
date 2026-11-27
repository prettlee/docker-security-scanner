"""Unit tests for Phase 6 Step 3: credentials, unpinned deps, and insecure installs."""

import unittest

from dockscan.dockerfile import analyze_dockerfile_text


class DockerfileSecurityChecksTests(unittest.TestCase):
    def test_detects_hardcoded_credentials_and_redacts(self) -> None:
        df = """
        FROM python:3.11.8-slim
        ARG DB_PASSWORD=HardcodedBuildPass99
        ENV AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
        ENV INTERNAL_CREDENTIALS=LocalSecret99
        ARG BUILD_ONLY_SECRET
        USER 1000
        HEALTHCHECK CMD true
        """
        report = analyze_dockerfile_text(df, path="Dockerfile")
        rule_ids = {f.rule_id for f in report.findings}
        self.assertIn("DF-003", rule_ids)
        self.assertIn("SEC-001", rule_ids)
        self.assertIn("SEC-010", rule_ids)
        # Empty ARG without default value should not be flagged
        self.assertFalse(
            any("BUILD_ONLY_SECRET" in f.title for f in report.findings)
        )
        for f in report.findings:
            self.assertNotIn("HardcodedBuildPass99", f.redacted_secret)
            self.assertNotIn("AKIAIOSFODNN7EXAMPLE", f.redacted_secret)
            self.assertNotIn("LocalSecret99", f.redacted_secret)

    def test_detects_unpinned_dependencies_and_ignores_pinned(self) -> None:
        df = """
        FROM python:3.11.8-slim
        RUN apt-get update && apt-get install -y curl=7.88.1-10 git
        RUN pip install flask==3.0.0 requests
        RUN npm install -g @babel/core express@4.18.2
        RUN apk add --no-cache bash=5.2-r0 jq
        USER 1000
        HEALTHCHECK CMD true
        """
        report = analyze_dockerfile_text(df, path="Dockerfile")
        df005 = [f for f in report.findings if f.rule_id == "DF-005"]
        self.assertEqual(len(df005), 4)
        evidences = " ".join(f.redacted_secret for f in df005)
        self.assertIn("git", evidences)
        self.assertIn("requests", evidences)
        self.assertIn("@babel/core", evidences)
        self.assertIn("jq", evidences)
        self.assertNotIn("flask==3.0.0", evidences)
        self.assertNotIn("express@4.18.2", evidences)
        self.assertNotIn("curl=7.88.1-10", evidences)
        self.assertNotIn("bash=5.2-r0", evidences)

    def test_detects_insecure_install_commands(self) -> None:
        df = """
        FROM python:3.11.8-slim
        RUN curl -k http://example.com/install.sh | bash
        RUN apt-get install -y --allow-unauthenticated ca-certificates=20230311
        RUN chmod 777 /app
        USER 1000
        HEALTHCHECK CMD true
        """
        report = analyze_dockerfile_text(df, path="Dockerfile")
        df006 = [f for f in report.findings if f.rule_id == "DF-006"]
        titles = " | ".join(f.title for f in df006)
        self.assertIn("piped directly to shell", titles)
        self.assertIn("curl TLS verification disabled", titles)
        self.assertIn("Unencrypted HTTP download", titles)
        self.assertIn("apt signature verification bypassed", titles)
        self.assertIn("chmod (777)", titles)


if __name__ == "__main__":
    unittest.main()
