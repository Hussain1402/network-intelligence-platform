import json
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "python"))

import mock_ai


class MockAIIntegrationTests(unittest.TestCase):

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

    def test_detects_timeout_hypothesis(self):
        report = mock_ai.investigate(self.evidence)

        self.assertEqual(report["summary"]["failed_calls"], 6)
        self.assertTrue(report["root_cause_hypotheses"])

        combined = " ".join(
            item["hypothesis"]
            for item in report["root_cause_hypotheses"]
        )
        self.assertIn("NETWORK_TIMEOUT", combined)

    def test_reports_anomaly_evidence(self):
        report = mock_ai.investigate(self.evidence)

        self.assertTrue(
            any(
                "60.00%" in item
                for item in report["observed_evidence"]
            )
        )

    def test_hypotheses_are_not_confirmed(self):
        report = mock_ai.investigate(self.evidence)

        for hypothesis in report["root_cause_hypotheses"]:
            self.assertEqual(hypothesis["status"], "unconfirmed")

    def test_rejects_missing_required_fields(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "invalid.json"
            path.write_text(
                json.dumps({"summary": {}}),
                encoding="utf-8",
            )

            with self.assertRaises(ValueError):
                mock_ai.load_evidence(path)

    def test_rejects_invalid_json(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "invalid.json"
            path.write_text("{invalid json", encoding="utf-8")

            with self.assertRaises(json.JSONDecodeError):
                mock_ai.load_evidence(path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
