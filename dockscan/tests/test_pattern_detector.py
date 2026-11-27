"""Unit tests for Step 2: regex and contextual secret detection."""

import unittest

from dockscan.models.finding import redact_secret
from dockscan.secrets.pattern_detector import detect_patterns_in_text

FAKE_AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"
FAKE_GH_TOKEN = "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyzABCD"
FAKE_STRIPE_KEY = "sk_live_" + "1234567890abcdefghijklmn"
FAKE_DB_PASS = "Tr0ub4dorAnd3_SecretPass"


class RedactionTests(unittest.TestCase):
    def test_redact_secret_never_leaks_raw_value(self) -> None:
        self.assertNotIn(FAKE_AWS_KEY, redact_secret(FAKE_AWS_KEY))
        self.assertNotIn(FAKE_GH_TOKEN, redact_secret(FAKE_GH_TOKEN))
        self.assertIn("***REDACTED***", redact_secret("tiny"))
        self.assertEqual(redact_secret(""), "<empty>")


class PatternDetectorTests(unittest.TestCase):
    def test_detects_known_secrets_and_ignores_placeholders(self) -> None:
        sample = "\n".join(
            [
                f"aws_id = {FAKE_AWS_KEY}",
                f"GITHUB_TOKEN={FAKE_GH_TOKEN}",
                f"STRIPE={FAKE_STRIPE_KEY}",
                "-----BEGIN RSA PRIVATE KEY-----",
                f"DATABASE_URL=postgres://app:{FAKE_DB_PASS}@db.local:5432/prod",
                "API_KEY=${REPLACE_FROM_ENV}",
                "PASSWORD=changeme",
            ]
        )
        matches = detect_patterns_in_text(
            sample,
            source="filesystem",
            location_prefix="layer:abc:/app/.env",
            layer_id="abc",
            file_path="/app/.env",
        )
        rule_ids = [m.finding.rule_id for m in matches]
        self.assertIn("SEC-001", rule_ids)
        self.assertIn("SEC-003", rule_ids)
        self.assertIn("SEC-004", rule_ids)
        self.assertIn("SEC-005", rule_ids)
        self.assertIn("SEC-008", rule_ids)

        redacted_blob = " ".join(m.finding.redacted_secret for m in matches)
        for secret in (FAKE_AWS_KEY, FAKE_GH_TOKEN, FAKE_STRIPE_KEY, FAKE_DB_PASS, "changeme"):
            self.assertNotIn(secret, redacted_blob)


if __name__ == "__main__":
    unittest.main()
