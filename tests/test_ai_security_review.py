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


class DiffCompletenessTests(unittest.TestCase):
    def test_reports_when_diff_exceeds_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            file_path = Path(directory) / "pr.diff"
            file_path.write_text("x" * 11, encoding="utf-8")
            content, truncated = review.read_text_with_truncation(file_path, 10)
            self.assertEqual(content, "x" * 10)
            self.assertTrue(truncated)

    def test_does_not_mark_diff_at_limit_as_truncated(self):
        with tempfile.TemporaryDirectory() as directory:
            file_path = Path(directory) / "pr.diff"
            file_path.write_text("x" * 10, encoding="utf-8")
            content, truncated = review.read_text_with_truncation(file_path, 10)
            self.assertEqual(content, "x" * 10)
            self.assertFalse(truncated)

    def test_missing_diff_prevents_pass(self):
        result = review.enforce_manual_review_when_diff_incomplete(valid_report())
        self.assertEqual(result["risk_score"], 25)
        self.assertEqual(result["risk_level"], "MEDIUM")
        self.assertEqual(result["decision"], "REVIEW_REQUIRED")
        self.assertIn("pull-request diff", result["summary"])

    def test_incomplete_diff_does_not_downgrade_high_risk(self):
        report = valid_report()
        report.update(risk_score=75, risk_level="HIGH", decision="REVIEW_REQUIRED")
        result = review.enforce_manual_review_when_diff_incomplete(report)
        self.assertEqual(result["risk_score"], 75)
        self.assertEqual(result["risk_level"], "HIGH")
        self.assertEqual(result["decision"], "REVIEW_REQUIRED")


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
            '{"password":"json secret value","client_secret":"another json secret","AWS_SECRET_ACCESS_KEY":"aws credential value"}',
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
        raw = '{"password":"json secret value","client_secret":"another json secret","AWS_SECRET_ACCESS_KEY":"aws credential value"}'
        redacted = review.redact_sensitive(raw)
        parsed = __import__("json").loads(redacted)
        self.assertEqual(parsed["password"], "[REDACTED]")
        self.assertEqual(parsed["client_secret"], "[REDACTED]")
        self.assertEqual(parsed["AWS_SECRET_ACCESS_KEY"], "[REDACTED]")
        self.assertNotIn("json secret value", redacted)


class ScannerCoverageTests(unittest.TestCase):
    def test_missing_scanner_report_prevents_pass(self):
        report = valid_report()
        result = review.enforce_manual_review_when_scanners_incomplete(report)
        self.assertEqual(result["risk_score"], 25)
        self.assertEqual(result["risk_level"], "MEDIUM")
        self.assertEqual(result["decision"], "REVIEW_REQUIRED")
        self.assertIn("static scanner reports", result["summary"])

    def test_incomplete_scanners_do_not_downgrade_high_risk(self):
        report = valid_report()
        report.update(risk_score=75, risk_level="HIGH", decision="REVIEW_REQUIRED")
        result = review.enforce_manual_review_when_scanners_incomplete(report)
        self.assertEqual(result["risk_score"], 75)
        self.assertEqual(result["risk_level"], "HIGH")
        self.assertEqual(result["decision"], "REVIEW_REQUIRED")

    def test_complete_scanner_reports_are_not_subject_to_override(self):
        report = valid_report()
        self.assertEqual(report["decision"], "PASS")


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
        self.assertIn(r"\<img", rendered)
        self.assertNotIn("<img", rendered.replace(r"\<img", ""))
        self.assertIn("AI Security Review", rendered)


class CommitStatusTests(unittest.TestCase):
    class FakeResponse:
        def read(self, limit=-1):
            return b"{}"[:limit] if limit >= 0 else b"{}"

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    def test_pass_publishes_success_status(self):
        captured = {}

        def fake_urlopen(request, timeout):
            captured["request"] = request
            return self.FakeResponse()

        with patch.object(review.urllib.request, "urlopen", side_effect=fake_urlopen):
            review.publish_commit_status("a" * 40, "PASS", "LOW", 10)

        request = captured["request"]
        payload = __import__("json").loads(request.data.decode("utf-8"))
        self.assertEqual(request.get_method(), "POST")
        self.assertEqual(payload["state"], "success")
        self.assertEqual(payload["context"], "AI Security Review")

    def test_review_required_and_block_publish_failure_status(self):
        for decision, level, score in (
            ("REVIEW_REQUIRED", "MEDIUM", 30),
            ("BLOCK", "HIGH", 70),
        ):
            with self.subTest(decision=decision):
                captured = {}

                def fake_urlopen(request, timeout):
                    captured["request"] = request
                    return self.FakeResponse()

                with patch.object(review.urllib.request, "urlopen", side_effect=fake_urlopen):
                    review.publish_commit_status("b" * 40, decision, level, score)

                payload = __import__("json").loads(
                    captured["request"].data.decode("utf-8")
                )
                self.assertEqual(payload["state"], "failure")

    def test_rejects_invalid_commit_sha(self):
        with self.assertRaises(ValueError):
            review.publish_commit_status("not-a-sha", "PASS", "LOW", 10)

    def test_rejects_invalid_decision(self):
        with self.assertRaises(ValueError):
            review.publish_commit_status("c" * 40, "APPROVE", "LOW", 10)


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


class GeminiRetryTests(unittest.TestCase):
    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, traceback):
            return False

    def test_retries_timeout_with_exponential_backoff_and_extended_timeout(self):
        with patch.object(
            review.urllib.request,
            "urlopen",
            side_effect=[TimeoutError("temporary timeout"), self.FakeResponse()],
        ) as mocked:
            with patch.object(review.time, "sleep") as sleep:
                with patch.object(review.random, "uniform", return_value=0):
                    response = review.open_gemini_request(object())
        self.assertIsInstance(response, self.FakeResponse)
        self.assertEqual(mocked.call_count, 2)
        self.assertEqual(mocked.call_args_list[0].kwargs["timeout"], 180)
        sleep.assert_called_once_with(2)

    def test_retries_transient_http_503_with_exponential_backoff(self):
        temporary_error = review.urllib.error.HTTPError(
            "https://example.invalid", 503, "service unavailable", {}, None
        )
        success = self.FakeResponse()
        with patch.object(
            review.urllib.request, "urlopen", side_effect=[temporary_error, success]
        ) as mocked:
            with patch.object(review.time, "sleep") as sleep:
                with patch.object(review.random, "uniform", return_value=0):
                    response = review.open_gemini_request(object())
        self.assertIs(response, success)
        self.assertEqual(mocked.call_count, 2)
        sleep.assert_called_once_with(2)

    def test_retries_explicit_short_term_rate_limit_429(self):
        import io
        body = b'{"error":{"code":"rate_limit_exceeded","message":"Requests per minute exceeded"}}'
        temporary_error = review.urllib.error.HTTPError(
            "https://example.invalid", 429, "rate limited", {"Retry-After": "3"}, io.BytesIO(body)
        )
        with patch.object(
            review.urllib.request, "urlopen",
            side_effect=[temporary_error, self.FakeResponse()],
        ) as mocked:
            with patch.object(review.time, "sleep") as sleep:
                with patch.object(review.random, "uniform", return_value=0):
                    response = review.open_gemini_request(object())
        self.assertIsInstance(response, self.FakeResponse)
        self.assertEqual(mocked.call_count, 2)
        sleep.assert_called_once_with(3)

    def test_does_not_retry_daily_quota_429(self):
        import io
        body = b'{"error":{"code":"quota_exceeded","message":"Daily quota exceeded"}}'
        quota_error = review.urllib.error.HTTPError(
            "https://example.invalid", 429, "quota exhausted", {}, io.BytesIO(body)
        )
        with patch.object(review.urllib.request, "urlopen", side_effect=quota_error) as mocked:
            with patch.object(review.time, "sleep") as sleep:
                with self.assertRaises(review.GeminiQuotaError) as raised:
                    review.open_gemini_request(object())
        self.assertEqual(raised.exception.category, "daily quota exhausted")
        mocked.assert_called_once()
        sleep.assert_not_called()

    def test_does_not_retry_unclassified_429(self):
        import io
        quota_error = review.urllib.error.HTTPError(
            "https://example.invalid", 429, "resource exhausted", {},
            io.BytesIO(b'{"error":{"status":"RESOURCE_EXHAUSTED"}}')
        )
        with patch.object(review.urllib.request, "urlopen", side_effect=quota_error) as mocked:
            with patch.object(review.time, "sleep") as sleep:
                with self.assertRaises(review.GeminiQuotaError) as raised:
                    review.open_gemini_request(object())
        self.assertIn("stopped to avoid wasting quota", raised.exception.category)
        mocked.assert_called_once()
        sleep.assert_not_called()

    def test_classifies_nested_daily_quota_reason(self):
        body = b'{"error":{"status":"RESOURCE_EXHAUSTED","details":[{"reason":"QUOTA_EXCEEDED","metadata":{"quotaMetric":"requests_per_day"}}]}}'
        self.assertEqual(review.classify_gemini_429(body), "daily quota exhausted")

    def test_does_not_retry_permanent_http_errors(self):
        for status in (400, 401, 403, 404):
            error = review.urllib.error.HTTPError(
                "https://example.invalid", status, "permanent error", {}, None
            )
            with self.subTest(status=status):
                with patch.object(
                    review.urllib.request, "urlopen", side_effect=error
                ) as mocked:
                    with self.assertRaises(review.urllib.error.HTTPError):
                        review.open_gemini_request(object())
                mocked.assert_called_once()

    def test_stops_after_configured_timeout_attempts(self):
        with patch.object(
            review.urllib.request, "urlopen", side_effect=TimeoutError("timeout")
        ) as mocked:
            with patch.object(review.time, "sleep") as sleep:
                with patch.object(review.random, "uniform", return_value=0):
                    with self.assertRaises(TimeoutError):
                        review.open_gemini_request(object(), attempts=2)
        self.assertEqual(mocked.call_count, 2)
        self.assertEqual([call.args[0] for call in sleep.call_args_list], [2])


class FailureStatusTests(unittest.TestCase):
    class FakeResponse:
        def read(self, limit=-1):
            return b"{}"[:limit] if limit >= 0 else b"{}"

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    def test_failure_status_publishes_error_state(self):
        captured = {}

        def fake_urlopen(request, timeout):
            captured["request"] = request
            return self.FakeResponse()

        with patch.object(review, "TOKEN", "test-token"):
            with patch.object(review, "REPOSITORY", "owner/repo"):
                with patch.object(review.urllib.request, "urlopen", side_effect=fake_urlopen):
                    self.assertTrue(review.publish_failure_status("d" * 40))

        payload = __import__("json").loads(captured["request"].data.decode("utf-8"))
        self.assertEqual(captured["request"].get_method(), "POST")
        self.assertEqual(payload["state"], "error")
        self.assertEqual(payload["context"], "AI Security Review")

    def test_failure_status_rejects_invalid_sha_without_network_call(self):
        with patch.object(review.urllib.request, "urlopen") as mocked:
            self.assertFalse(review.publish_failure_status("invalid-sha"))
        mocked.assert_not_called()

    def test_failure_status_returns_false_when_github_is_unavailable(self):
        with patch.object(
            review.urllib.request, "urlopen",
            side_effect=review.urllib.error.URLError("network unavailable"),
        ):
            self.assertFalse(review.publish_failure_status("e" * 40))

    def test_missing_gemini_key_attempts_failure_status(self):
        with patch.object(review, "API_KEY", ""):
            with patch.object(review, "publish_failure_status", return_value=True) as publish_failure:
                with patch.dict(review.os.environ, {"REVIEWED_SHA": "f" * 40}):
                    with patch("sys.stderr"):
                        result = review.main()

        self.assertEqual(result, 1)
        publish_failure.assert_called_once_with("f" * 40)

    def test_unexpected_runtime_error_attempts_failure_status(self):
        with patch.object(review, "API_KEY", "configured"):
            with patch.object(review, "TOKEN", "test-token"):
                with patch.object(review, "REPOSITORY", "owner/repo"):
                    with patch.object(review, "PR_NUMBER", "2"):
                        with patch.object(review, "gemini_review", side_effect=RuntimeError("unexpected")):
                            with patch.object(review, "publish_failure_status", return_value=True) as publish_failure:
                                with patch.dict(review.os.environ, {"REVIEWED_SHA": "a" * 40}):
                                    with patch("sys.stderr"):
                                        result = review.main()

        self.assertEqual(result, 1)
        publish_failure.assert_called_once_with("a" * 40)


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
