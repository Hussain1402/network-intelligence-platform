import json
import tempfile
import unittest
from pathlib import Path

from python.network_evidence import build_evidence


def source_reports():
    measurement = {
        "timestamp": "2026-10-15T10:01:00",
        "latency_ms": 180,
        "packet_loss_percent": 4.5,
        "throughput_mbps": 48,
        "error_rate_percent": 12,
        "memory_used_mb": 780,
        "memory_usage_percent": 65,
        "is_anomaly": True,
        "reasons": ["high_latency"],
    }

    anomaly = {
        "report_type": "network_anomaly_report",
        "summary": {
            "total_measurements": 3,
            "anomaly_count": 1,
            "normal_count": 2,
        },
        "thresholds": {"max_latency_ms": 100},
        "measurements": [
            dict(measurement),
            {**measurement, "timestamp": "2026-10-15T10:02:00", "is_anomaly": False, "reasons": []},
            {**measurement, "timestamp": "2026-10-15T10:03:00", "is_anomaly": False, "reasons": []},
        ],
    }

    analytics = {
        "report_type": "network_analytics_report",
        "summary": {
            "total_measurements": 3,
            "anomaly_count": 1,
            "normal_count": 2,
            "anomaly_rate_percent": 100 / 3,
        },
        "statistics": {
            metric: {"minimum": 1, "maximum": 3, "average": 2}
            for metric in (
                "latency_ms",
                "packet_loss_percent",
                "throughput_mbps",
                "error_rate_percent",
                "memory_used_mb",
                "memory_usage_percent",
            )
        },
    }

    metrics = (
        "latency",
        "packet_loss",
        "throughput",
        "error_rate",
        "memory_usage",
    )
    trends = {
        "report_type": "network_trend_report",
        "summary": {
            "total_measurements": 3,
            "baseline_measurements": 1,
            "analyzed_measurements": 2,
        },
        "trends": [
            {
                "metric": metric,
                "detected": False,
                "recovered": False,
                "baseline_average": 1,
                "observed_average": 0,
                "deviation_percent": 0,
                "consecutive_measurements": 0,
                "start_timestamp": "",
                "end_timestamp": "",
                "recovery_timestamp": "",
            }
            for metric in metrics
        ],
    }
    return anomaly, analytics, trends


def build_from_reports(anomaly, analytics, trends):
    with tempfile.TemporaryDirectory() as directory:
        paths = []
        for name, report in zip(
            ("anomaly", "analytics", "trends"),
            (anomaly, analytics, trends),
        ):
            path = Path(directory) / f"{name}.json"
            path.write_text(json.dumps(report), encoding="utf-8")
            paths.append(path)
        return build_evidence(*paths)


class NetworkEvidenceTests(unittest.TestCase):

    def test_consolidates_anomalous_records_from_generated_evidence(self):
        anomaly, analytics, trends = source_reports()

        evidence = build_from_reports(anomaly, analytics, trends)

        self.assertEqual(evidence["summary"]["total_measurements"], 3)
        self.assertEqual(evidence["summary"]["anomalous_measurements"], 1)
        self.assertEqual(
            evidence["anomalous_measurements"][0]["timestamp"],
            "2026-10-15T10:01:00",
        )
        self.assertEqual(len(evidence["historical_trends"]), 5)

    def test_rejects_mismatched_counts_between_reports(self):
        anomaly, analytics, trends = source_reports()
        analytics["summary"]["anomaly_count"] = 2
        analytics["summary"]["normal_count"] = 1
        analytics["summary"]["anomaly_rate_percent"] = 200 / 3

        with self.assertRaisesRegex(ValueError, "anomaly_count"):
            build_from_reports(anomaly, analytics, trends)

    def test_accepts_undefined_percentage_for_zero_baseline(self):
        anomaly, analytics, trends = source_reports()
        trends["trends"][0].update({
            "detected": True,
            "baseline_average": 0,
            "observed_average": 2,
            "deviation_percent": None,
            "consecutive_measurements": 2,
        })

        evidence = build_from_reports(anomaly, analytics, trends)

        self.assertIsNone(evidence["historical_trends"][0]["deviation_percent"])


if __name__ == "__main__":
    unittest.main()
