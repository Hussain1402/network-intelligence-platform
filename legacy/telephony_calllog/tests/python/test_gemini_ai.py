
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from google.genai import errors

from python.gemini_ai import (
    build_observed_evidence,
    generate_with_retry,
    investigate_with_gemini,
    validate_ai_findings,
    write_json_atomically,
)


class GeminiInvestigatorTests(unittest.TestCase):

    def setUp(self):
        self.evidence = {
            "source": "call_log_csv",
            "summary": {
                "total_calls": 15,
                "successful_calls": 9,
                "failed_calls": 6,
                "failure_rate_percent": 40.0,
                "average_success_duration_ms": 1333.33,
            },
            "failure_codes": [
                {"code": "NETWORK_TIMEOUT", "count": 6}
            ],
            "anomalies": [
                {
                    "window_start": "2026-10-14T10:01:00",
                    "total_calls": 10,
                    "failed_calls": 6,
                    "failure_rate_percent": 60.0,
                }
            ],
        }

        self.valid_findings = {
            "root_cause_hypotheses": [
                {
                    "hypothesis": "Possible upstream service latency",
                    "confidence": "medium",
                    "status": "unconfirmed",
                    "reasoning": (
                        "The evidence records repeated timeouts. "
                        "Upstream latency is one possible explanation, "
                        "but no server telemetry was supplied."
                    ),
                }
            ],
            "recommended_diagnostic_checks": [
                {
                    "priority": "high",
                    "check": "Inspect upstream service metrics",
                    "purpose": (
                        "Determine whether the service was slow "
                        "during the affected window."
                    ),
                }
            ],
        }

    @patch("python.gemini_ai.genai.Client")
    def test_accepts_valid_gemini_response(self, client_class):
        client = MagicMock()
        client_class.return_value = client

        response = MagicMock()
        response.text = json.dumps(self.valid_findings)
        client.models.generate_content.return_value = response

        with patch.dict("os.environ", {"GEMINI_API_KEY": "test-key"}):
            report = investigate_with_gemini(self.evidence)

        self.assertEqual(
            report["report_type"],
            "gemini_ai_network_investigation",
        )
        self.assertEqual(report["summary"], self.evidence["summary"])
        self.assertEqual(
            report["root_cause_hypotheses"][0]["status"],
            "unconfirmed",
        )
        self.assertTrue(report["observed_evidence"])
        self.assertIn(
            "NETWORK_TIMEOUT",
            " ".join(report["observed_evidence"]),
        )
        client.models.generate_content.assert_called_once()

    @patch("python.gemini_ai.genai.Client")
    def test_observed_evidence_is_built_locally(self, client_class):
        client = MagicMock()
        client_class.return_value = client

        response = MagicMock()
        response.text = json.dumps(self.valid_findings)
        client.models.generate_content.return_value = response

        with patch.dict("os.environ", {"GEMINI_API_KEY": "test-key"}):
            report = investigate_with_gemini(self.evidence)

        evidence_text = " ".join(report["observed_evidence"])

        self.assertIn("15", evidence_text)
        self.assertIn("40.00%", evidence_text)
        self.assertIn("NETWORK_TIMEOUT", evidence_text)
        self.assertIn("60.0", evidence_text)

        # Gemini cannot replace factual evidence with its own statements.
        self.assertNotIn("observed_evidence", self.valid_findings)

    def test_rejects_invalid_json(self):
        with self.assertRaises(json.JSONDecodeError):
            json.loads("not JSON")

    @patch("python.gemini_ai.genai.Client")
    def test_rejects_confirmed_hypothesis(self, client_class):
        client = MagicMock()
        client_class.return_value = client

        findings = json.loads(json.dumps(self.valid_findings))
        findings["root_cause_hypotheses"][0]["status"] = "confirmed"

        response = MagicMock()
        response.text = json.dumps(findings)
        client.models.generate_content.return_value = response

        with patch.dict("os.environ", {"GEMINI_API_KEY": "test-key"}):
            with self.assertRaisesRegex(
                ValueError,
                "must remain unconfirmed",
            ):
                investigate_with_gemini(self.evidence)

    def test_rejects_invalid_hypothesis_confidence(self):
        findings = json.loads(json.dumps(self.valid_findings))
        findings["root_cause_hypotheses"][0]["confidence"] = "very high"

        with self.assertRaisesRegex(ValueError, "invalid confidence"):
            validate_ai_findings(findings)

    def test_rejects_incomplete_diagnostic_check(self):
        findings = json.loads(json.dumps(self.valid_findings))
        del findings["recommended_diagnostic_checks"][0]["purpose"]

        with self.assertRaisesRegex(ValueError, "invalid 'purpose'"):
            validate_ai_findings(findings)

    def test_rejects_missing_required_fields(self):
        with self.assertRaisesRegex(ValueError, "missing fields"):
            validate_ai_findings({})

    def test_rejects_non_list_hypotheses(self):
        findings = json.loads(json.dumps(self.valid_findings))
        findings["root_cause_hypotheses"] = "not a list"

        with self.assertRaisesRegex(ValueError, "must be a list"):
            validate_ai_findings(findings)

    @patch.dict("os.environ", {}, clear=True)
    @patch("python.gemini_ai.genai.Client")
    def test_rejects_missing_api_key(self, client_class):
        with self.assertRaisesRegex(
            ValueError,
            "GEMINI_API_KEY is not configured",
        ):
            investigate_with_gemini(self.evidence)

        client_class.assert_not_called()

    @patch("python.gemini_ai.genai.Client")
    def test_propagates_gemini_api_error(self, client_class):
        client = MagicMock()
        client_class.return_value = client

        client.models.generate_content.side_effect = RuntimeError(
            "Simulated Gemini service failure"
        )

        with patch.dict("os.environ", {"GEMINI_API_KEY": "test-key"}):
            with self.assertRaisesRegex(
                RuntimeError,
                "Simulated Gemini service failure",
            ):
                investigate_with_gemini(self.evidence)

    @patch("python.gemini_ai.time.sleep")
    def test_retries_temporary_api_error(self, sleep_mock):
        client = MagicMock()

        temporary_error = errors.ServerError(
            503,
            {"error": {"message": "Temporary outage"}},
        )

        successful_response = MagicMock()
        successful_response.text = json.dumps(self.valid_findings)

        client.models.generate_content.side_effect = [
            temporary_error,
            successful_response,
        ]

        response = generate_with_retry(
            client,
            "test prompt",
            "test instructions",
        )

        self.assertEqual(response.text, json.dumps(self.valid_findings))
        self.assertEqual(
            client.models.generate_content.call_count,
            2,
        )
        sleep_mock.assert_called_once_with(2)

    @patch("python.gemini_ai.time.sleep")
    def test_does_not_retry_permanent_api_error(self, sleep_mock):
        client = MagicMock()

        permanent_error = errors.ClientError(
            400,
            {"error": {"message": "Invalid request"}},
        )

        client.models.generate_content.side_effect = permanent_error

        with self.assertRaises(errors.ClientError):
            generate_with_retry(
                client,
                "test prompt",
                "test instructions",
            )

        client.models.generate_content.assert_called_once()
        sleep_mock.assert_not_called()

    def test_atomic_write_creates_valid_report(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "report.json"
            report = {"status": "valid", "count": 3}

            write_json_atomically(destination, report)

            with destination.open("r", encoding="utf-8") as file:
                loaded = json.load(file)

            self.assertEqual(loaded, report)

    def test_atomic_write_preserves_previous_report_on_serialization_error(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "report.json"
            original_content = '{"previous": true}\n'
            destination.write_text(original_content, encoding="utf-8")

            invalid_report = {"bad_value": object()}

            with self.assertRaises(TypeError):
                write_json_atomically(destination, invalid_report)

            self.assertEqual(
                destination.read_text(encoding="utf-8"),
                original_content,
            )


if __name__ == "__main__":
    unittest.main()
