import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(
    0,
    str(Path(__file__).resolve().parents[2] / "python")
)

from network_mock_ai import investigate, load_evidence


def sample_evidence():
    return {
        "report_type": "ps2_network_investigation_evidence",
        "summary": {
            "total_measurements": 3,
            "normal_measurements": 1,
            "anomalous_measurements": 2,
            "anomaly_rate_percent": 66.67,
            "baseline_measurements": 1,
            "trend_analysis_measurements": 2,
        },
        "thresholds": {},
        "aggregate_statistics": {
            "latency_ms": {"minimum": 40, "maximum": 180, "average": 100},
            "packet_loss_percent": {"minimum": 0.1, "maximum": 4.5, "average": 2},
            "throughput_mbps": {"minimum": 48, "maximum": 95, "average": 70},
            "error_rate_percent": {"minimum": 0.5, "maximum": 12, "average": 5},
            "memory_used_mb": {"minimum": 512, "maximum": 780, "average": 650},
            "memory_usage_percent": {"minimum": 42, "maximum": 65, "average": 55},
        },
        "anomalous_measurements": [
            {
                "timestamp": "2026-10-15T10:01:00",
                "latency_ms": 180,
                "packet_loss_percent": 4.5,
                "throughput_mbps": 48,
                "error_rate_percent": 12,
                "memory_used_mb": 780,
                "memory_usage_percent": 65,
                "is_anomaly": True,
                "reasons": [
                    "high_latency",
                    "high_packet_loss",
                    "low_throughput",
                    "high_error_rate",
                    "high_memory_usage",
                ],
            },
            {
                "timestamp": "2026-10-15T10:02:00",
                "latency_ms": 160,
                "packet_loss_percent": 3,
                "throughput_mbps": 50,
                "error_rate_percent": 10,
                "memory_used_mb": 700,
                "memory_usage_percent": 62,
                "is_anomaly": True,
                "reasons": [
                    "high_latency",
                    "high_packet_loss",
                    "low_throughput",
                    "high_error_rate",
                    "high_memory_usage",
                ],
            },
        ],
        "historical_trends": [
            {
                "metric": "latency",
                "detected": True,
                "recovered": False,
                "baseline_average": 40,
                "observed_average": 170,
                "deviation_percent": 325,
                "consecutive_measurements": 2,
                "start_timestamp": "2026-10-15T10:01:00",
                "end_timestamp": "2026-10-15T10:02:00",
                "recovery_timestamp": "",
            },
            {
                "metric": "packet_loss",
                "detected": True,
                "recovered": True,
                "baseline_average": 0.1,
                "observed_average": 3.75,
                "deviation_percent": 3650,
                "consecutive_measurements": 2,
                "start_timestamp": "2026-10-15T10:01:00",
                "end_timestamp": "2026-10-15T10:02:00",
                "recovery_timestamp": "2026-10-15T10:03:00",
            },
            {
                "metric": "throughput",
                "detected": False,
                "recovered": False,
                "baseline_average": 95,
                "observed_average": 0,
                "deviation_percent": 0,
                "consecutive_measurements": 0,
                "start_timestamp": "",
                "end_timestamp": "",
                "recovery_timestamp": "",
            },
            {
                "metric": "error_rate",
                "detected": False,
                "recovered": False,
                "baseline_average": 0.5,
                "observed_average": 0,
                "deviation_percent": 0,
                "consecutive_measurements": 0,
                "start_timestamp": "",
                "end_timestamp": "",
                "recovery_timestamp": "",
            },
            {
                "metric": "memory_usage",
                "detected": False,
                "recovered": False,
                "baseline_average": 42,
                "observed_average": 0,
                "deviation_percent": 0,
                "consecutive_measurements": 0,
                "start_timestamp": "",
                "end_timestamp": "",
                "recovery_timestamp": "",
            },
        ],
        "analysis_guidance": [],
    }


class NetworkMockAITests(unittest.TestCase):

    def test_generates_investigation_report(self):
        report = investigate(sample_evidence())

        self.assertEqual(
            report["report_type"],
            "ps2_mock_ai_network_investigation",
        )
        self.assertTrue(report["observed_evidence"])
        self.assertTrue(report["root_cause_hypotheses"])
        self.assertTrue(report["recommended_diagnostic_checks"])

    def test_hypotheses_remain_unconfirmed(self):
        report = investigate(sample_evidence())

        for hypothesis in report["root_cause_hypotheses"]:
            self.assertEqual(hypothesis["status"], "unconfirmed")

    def test_detects_multi_metric_degradation(self):
        report = investigate(sample_evidence())

        text = " ".join(report["observed_evidence"]).lower()

        self.assertIn("all five", text)

    def test_distinguishes_recovered_and_unrecovered_trends(self):
        report = investigate(sample_evidence())

        assessment = report["historical_trend_assessment"]

        self.assertEqual(assessment["detected_trends"], 2)
        self.assertEqual(assessment["recovered_trends"], 1)
        self.assertEqual(assessment["unrecovered_trends"], 1)

    def test_zero_baseline_uses_absolute_evidence_not_percentage(self):
        data = sample_evidence()
        data["historical_trends"][0].update({
            "baseline_average": 0,
            "observed_average": 5,
            "deviation_percent": None,
        })

        report = investigate(data)

        self.assertIn(
            "relative percentage change is undefined",
            " ".join(report["observed_evidence"]),
        )

    def test_no_anomaly_case(self):
        data = sample_evidence()
        data["summary"]["normal_measurements"] = 3
        data["summary"]["anomalous_measurements"] = 0
        data["summary"]["anomaly_rate_percent"] = 0
        data["anomalous_measurements"] = []

        report = investigate(data)

        self.assertEqual(len(report["root_cause_hypotheses"]), 1)
        self.assertIn(
            "No anomalous measurements",
            " ".join(report["observed_evidence"]),
        )

    def test_rejects_inconsistent_evidence_counts(self):
        data = sample_evidence()
        data["summary"]["total_measurements"] = 99

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence.json"
            path.write_text(json.dumps(data), encoding="utf-8")

            with self.assertRaises(ValueError):
                load_evidence(path)

    def test_rejects_wrong_report_type(self):
        data = sample_evidence()
        data["report_type"] = "wrong_type"

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence.json"
            path.write_text(json.dumps(data), encoding="utf-8")

            with self.assertRaises(ValueError):
                load_evidence(path)


if __name__ == "__main__":
    unittest.main()
