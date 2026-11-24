import json
import tempfile
import unittest
import sys
from pathlib import Path
from unittest.mock import Mock, patch

PROJECT_PYTHON = Path(__file__).resolve().parents[2] / "python"
sys.path.insert(0, str(PROJECT_PYTHON))

from functionlog_gemini_ai import (
    investigate_with_gemini,
    validate_ai_findings,
    write_json_atomically,
)


def valid_findings():
    return {
        "root_cause_hypotheses": [
            {
                "hypothesis": "A function may be failing due to invalid input.",
                "confidence": "low",
                "status": "unconfirmed",
                "reasoning": "The supplied execution evidence contains a failure record."
            }
        ],
        "recommended_diagnostic_checks": [
            {
                "priority": "high",
                "check": "Inspect the failing function.",
                "purpose": "Identify the operation associated with the recorded error."
            }
        ]
    }


def make_evidence():
    return {
        "project": "Function Execution Test",
        "summary": {
            "total_executions": 1,
            "successful_executions": 1,
            "failed_executions": 0,
            "in_progress_executions": 0,
            "unique_functions": 1,
            "failure_rate_percent": 0.0
        },
        "performance": {
            "average_execution_time_ms": 2.5,
            "minimum_execution_time_ms": 2.5,
            "maximum_execution_time_ms": 2.5
        },
        "function_statistics": [
            {
                "function_name": "process_request",
                "total_executions": 1,
                "successful_executions": 1,
                "failed_executions": 0,
                "average_execution_time_ms": 2.5,
                "minimum_execution_time_ms": 2.5,
                "maximum_execution_time_ms": 2.5
            }
        ],
        "execution_records": [
            {
                "id": 1,
                "parent_id": 0,
                "function_name": "process_request",
                "caller_name": "main",
                "start_timestamp": "2026-10-14T10:00:00Z",
                "end_timestamp": "2026-10-14T10:00:00Z",
                "execution_time_ms": 2.5,
                "status": "SUCCESS",
                "error_code": 0,
                "error_message": ""
            }
        ]
    }


class FunctionLogGeminiTests(unittest.TestCase):

    def test_accepts_valid_response(self):
        result = validate_ai_findings(valid_findings())
        self.assertEqual(len(result["root_cause_hypotheses"]), 1)
        self.assertEqual(len(result["recommended_diagnostic_checks"]), 1)

    def test_rejects_confirmed_hypothesis(self):
        findings = valid_findings()
        findings["root_cause_hypotheses"][0]["status"] = "confirmed"

        with self.assertRaises(ValueError):
            validate_ai_findings(findings)

    def test_rejects_invalid_confidence(self):
        findings = valid_findings()
        findings["root_cause_hypotheses"][0]["confidence"] = "certain"

        with self.assertRaises(ValueError):
            validate_ai_findings(findings)

    def test_rejects_incomplete_diagnostic_check(self):
        findings = valid_findings()
        findings["recommended_diagnostic_checks"][0].pop("purpose")

        with self.assertRaises(ValueError):
            validate_ai_findings(findings)

    def test_rejects_missing_required_fields(self):
        with self.assertRaises(ValueError):
            validate_ai_findings({
                "root_cause_hypotheses": []
            })

    @patch.dict("os.environ", {}, clear=True)
    def test_rejects_missing_api_key(self):
        with self.assertRaisesRegex(ValueError, "GEMINI_API_KEY"):
            investigate_with_gemini(make_evidence())

    @patch("functionlog_gemini_ai.genai.Client")
    def test_builds_report_with_local_observed_evidence(self, client_class):
        response = Mock()
        response.text = json.dumps(valid_findings())

        client = client_class.return_value
        client.models.generate_content.return_value = response

        with patch.dict("os.environ", {"GEMINI_API_KEY": "test-key"}):
            report = investigate_with_gemini(make_evidence())

        self.assertEqual(
            report["report_type"],
            "function_execution_gemini_investigation"
        )
        self.assertEqual(report["summary"]["total_executions"], 1)
        self.assertTrue(report["observed_evidence"])
        self.assertEqual(
            report["root_cause_hypotheses"][0]["status"],
            "unconfirmed"
        )

    @patch("functionlog_gemini_ai.genai.Client")
    def test_rejects_invalid_gemini_json(self, client_class):
        response = Mock()
        response.text = "{invalid json"

        client = client_class.return_value
        client.models.generate_content.return_value = response

        with patch.dict("os.environ", {"GEMINI_API_KEY": "test-key"}):
            with self.assertRaisesRegex(ValueError, "invalid JSON"):
                investigate_with_gemini(make_evidence())

    def test_atomic_write_creates_valid_report(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            report = {"result": "success"}

            write_json_atomically(path, report)

            with path.open(encoding="utf-8") as file:
                self.assertEqual(json.load(file), report)

    def test_atomic_write_preserves_old_report_on_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            path.write_text('{"old": true}', encoding="utf-8")

            invalid_report = {"invalid": object()}

            with self.assertRaises(TypeError):
                write_json_atomically(path, invalid_report)

            with path.open(encoding="utf-8") as file:
                self.assertEqual(json.load(file), {"old": True})


if __name__ == "__main__":
    unittest.main()
