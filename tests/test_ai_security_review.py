import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


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



class ReadTextSafetyTests(unittest.TestCase):
    def test_reads_only_the_requested_number_of_characters(self):
        with tempfile.TemporaryDirectory() as directory:
            file_path = Path(directory) / "input.txt"
            file_path.write_text("abcdefghij", encoding="utf-8")
            self.assertEqual(review.read_text(file_path, 4), "abcd")

    def test_returns_empty_for_missing_file(self):
        with tempfile.TemporaryDirectory() as directory:
            file_path = Path(directory) / "missing.txt"
            self.assertEqual(review.read_text(file_path, 100), "")

    def test_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target.txt"
            link = Path(directory) / "link.txt"
            target.write_text("sensitive-data", encoding="utf-8")
            try:
                link.symlink_to(target)
            except (OSError, NotImplementedError):
                self.skipTest("Symlinks are not available in this environment.")
            self.assertEqual(review.read_text(link, 100), "")

    def test_rejects_invalid_limits(self):
        with tempfile.TemporaryDirectory() as directory:
            file_path = Path(directory) / "input.txt"
            file_path.write_text("content", encoding="utf-8")
            for limit in (0, -1, True, "10"):
                with self.subTest(limit=limit):
                    self.assertEqual(review.read_text(file_path, limit), "")


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

    def test_rejects_score_inconsistent_with_risk_level(self):
        report = valid_report()
        report["risk_score"] = 90
        with self.assertRaises(ValueError):
            review.validate_report(report)

    def test_accepts_score_band_boundaries(self):
        cases = [
            (0, "LOW"),
            (24, "LOW"),
            (25, "MEDIUM"),
            (49, "MEDIUM"),
            (50, "HIGH"),
            (79, "HIGH"),
            (80, "CRITICAL"),
            (100, "CRITICAL"),
        ]
        for score, level in cases:
            with self.subTest(score=score, level=level):
                report = valid_report()
                report["risk_score"] = score
                report["risk_level"] = level
                if level in {"HIGH", "CRITICAL"}:
                    report["decision"] = "REVIEW_REQUIRED"
                elif level == "MEDIUM":
                    report["decision"] = "REVIEW_REQUIRED"
                self.assertIs(review.validate_report(report), report)

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
            'password = "a secret value with spaces"',
            'secret_access_key: "another secret with spaces"',
            '{"password":"json secret value","client_secret":"another json secret"}',
            "github_pat_" + "a" * 30,
            "glpat-" + "a" * 25,
            "npm_" + "a" * 25,
            "pypi-" + "a" * 25,
            "sk_live_" + "a" * 20,
            "eyJ" + "A" * 15 + "." + "B" * 15 + "." + "C" * 15,
            "-----BEGIN RSA PRIVATE KEY-----\\nprivate-material\\n-----END RSA PRIVATE KEY-----",
        ]
        for secret in samples:
            with self.subTest(secret_type=secret.split("=")[0][:12]):
                redacted = review.redact_sensitive(secret)
                self.assertNotIn(secret, redacted)
                self.assertIn("REDACTED", redacted)



    def test_redacts_json_secret_fields_and_preserves_valid_json(self):
        raw = '{"password":"json secret value","client_secret":"another json secret"}'
        redacted = review.redact_sensitive(raw)
        parsed = __import__("json").loads(redacted)
        self.assertEqual(parsed["password"], "[REDACTED]")
        self.assertEqual(parsed["client_secret"], "[REDACTED]")
        self.assertNotIn("json secret value", redacted)


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


class BoundedResponseTests(unittest.TestCase):
    class FakeResponse:
        def __init__(self, payload):
            self.payload = payload

        def read(self, limit=-1):
            return self.payload[:limit] if limit >= 0 else self.payload

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    def test_accepts_response_at_limit(self):
        response = self.FakeResponse(b"1234")
        self.assertEqual(review.read_limited_response(response, 4), b"1234")

    def test_rejects_response_over_limit(self):
        response = self.FakeResponse(b"12345")
        with self.assertRaises(ValueError):
            review.read_limited_response(response, 4)

    def test_rejects_malformed_gemini_candidate(self):
        payload = b'{"candidates":["not-an-object"]}'
        with patch.object(review.urllib.request, "urlopen", return_value=self.FakeResponse(payload)):
            with self.assertRaises(ValueError):
                review.gemini_review("diff", "scanner")

    def test_rejects_non_object_gemini_response(self):
        payload = b'["unexpected"]'
        with patch.object(review.urllib.request, "urlopen", return_value=self.FakeResponse(payload)):
            with self.assertRaises(ValueError):
                review.gemini_review("diff", "scanner")


class ReportSizeTests(unittest.TestCase):
    def test_rendered_comment_stays_under_github_limit(self):
        report = valid_report()
        report["findings"] = [valid_finding("LOW") for _ in range(30)]
        for finding in report["findings"]:
            finding["evidence"] = "<" * 1500
        rendered = review.render_report(report)
        self.assertLessEqual(len(rendered), review.MAX_GITHUB_COMMENT_CHARS)
        self.assertIn("Report truncated", rendered)


if __name__ == "__main__":
    unittest.main()
