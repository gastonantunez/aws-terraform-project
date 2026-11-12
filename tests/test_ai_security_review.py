import importlib.util
from pathlib import Path
import unittest


SCRIPT_PATH = (
    Path(__file__).resolve().parents[1]
    / ".github"
    / "scripts"
    / "ai_security_review.py"
)
SPEC = importlib.util.spec_from_file_location("ai_security_review", SCRIPT_PATH)
review = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(review)


def valid_report():
    return {
        "risk_score": 5,
        "risk_level": "LOW",
        "summary": "No material security issues found.",
        "findings": [],
        "decision": "PASS",
    }


def valid_finding(severity="MEDIUM"):
    return {
        "severity": severity,
        "category": "configuration",
        "file": "main.tf",
        "line": "12",
        "title": "Example finding",
        "evidence": "An insecure setting was detected.",
        "impact": "It may increase exposure.",
        "recommendation": "Use a more restrictive setting.",
    }


class ValidateReportTests(unittest.TestCase):
    def test_accepts_valid_report_without_findings(self):
        report = valid_report()
        self.assertIs(review.validate_report(report), report)

    def test_rejects_non_object(self):
        with self.assertRaises(ValueError):
            review.validate_report([])

    def test_rejects_missing_required_field(self):
        report = valid_report()
        del report["decision"]
        with self.assertRaises(ValueError):
            review.validate_report(report)

    def test_rejects_boolean_score(self):
        report = valid_report()
        report["risk_score"] = True
        with self.assertRaises(ValueError):
            review.validate_report(report)

    def test_rejects_score_outside_range(self):
        for score in (-1, 101):
            with self.subTest(score=score):
                report = valid_report()
                report["risk_score"] = score
                with self.assertRaises(ValueError):
                    review.validate_report(report)

    def test_rejects_invalid_risk_level_and_decision(self):
        for field, value in (("risk_level", "SEVERE"), ("decision", "ALLOW")):
            with self.subTest(field=field):
                report = valid_report()
                report[field] = value
                with self.assertRaises(ValueError):
                    review.validate_report(report)

    def test_rejects_pass_with_medium_finding(self):
        report = valid_report()
        report["findings"] = [valid_finding("MEDIUM")]
        with self.assertRaises(ValueError):
            review.validate_report(report)

    def test_rejects_block_without_high_finding(self):
        report = valid_report()
        report.update(risk_score=80, risk_level="HIGH", decision="BLOCK")
        report["findings"] = [valid_finding("MEDIUM")]
        with self.assertRaises(ValueError):
            review.validate_report(report)

    def test_rejects_high_finding_with_lower_risk_level(self):
        report = valid_report()
        report["findings"] = [valid_finding("HIGH")]
        report["decision"] = "REVIEW_REQUIRED"
        with self.assertRaises(ValueError):
            review.validate_report(report)

    def test_rejects_more_than_30_findings(self):
        report = valid_report()
        report["findings"] = [valid_finding("LOW") for _ in range(31)]
        with self.assertRaises(ValueError):
            review.validate_report(report)

    def test_rejects_oversized_summary(self):
        report = valid_report()
        report["summary"] = "x" * 4001
        with self.assertRaises(ValueError):
            review.validate_report(report)

    def test_rejects_malformed_finding(self):
        report = valid_report()
        report["findings"] = [{"severity": "LOW"}]
        with self.assertRaises(ValueError):
            review.validate_report(report)


class SecretRedactionTests(unittest.TestCase):
    def test_redacts_common_secret_formats(self):
        samples = [
            "AKIA1234567890ABCDEF",
            "ASIA1234567890ABCDEF",
            "AIza" + "A" * 35,
            "Bearer " + "a" * 25,
            "ghp_" + "a" * 25,
            "xoxb-" + "a" * 15,
            "password=SuperSecret123",
            "client_secret: SuperSecret123",
            "-----BEGIN RSA PRIVATE KEY-----\\nprivate-material\\n-----END RSA PRIVATE KEY-----",
        ]
        for secret in samples:
            with self.subTest(secret_type=secret.split("=")[0][:12]):
                redacted = review.redact_sensitive(secret)
                self.assertNotIn(secret, redacted)
                self.assertIn("REDACTED", redacted)


class ScannerNormalizationTests(unittest.TestCase):
    def test_accepts_json_object_and_array(self):
        self.assertIn('"status":"ok"', review.normalize_scanner_report('{"status":"ok"}', "trivy"))
        self.assertIn('[1,2]', review.normalize_scanner_report('[1, 2]', "checkov"))

    def test_compacts_json(self):
        result = review.normalize_scanner_report('{ "a": 1 }', "scanner")
        self.assertIn('{"a":1}', result)

    def test_excludes_invalid_json_and_scalar_values(self):
        for raw in ("{broken", '"text"', "42", "true", "null"):
            with self.subTest(raw=raw):
                result = review.normalize_scanner_report(raw, "scanner")
                self.assertIn("excluded", result)


class MarkdownSafetyTests(unittest.TestCase):
    def test_escapes_markup_and_neutralizes_mentions(self):
        result = review.markdown_text("<script>@here</script> **hello**")
        self.assertNotIn("<script>", result)
        self.assertIn("@\u200bhere", result)
        self.assertIn(r"\*\*hello\*\*", result)

    def test_limits_output_length(self):
        self.assertEqual(len(review.markdown_text("x" * 100, limit=12)), 12)

    def test_render_report_includes_marker_and_escaped_finding(self):
        report = valid_report()
        report["findings"] = [valid_finding("LOW")]
        report["findings"][0]["title"] = "<img src=x>"
        rendered = review.render_report(report)
        self.assertIn(review.MARKER, rendered)
        self.assertNotIn("<img", rendered)
        self.assertIn("AI Security Review", rendered)


if __name__ == "__main__":
    unittest.main()
