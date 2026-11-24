import json
import math
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path


def load_json(path):
    with Path(path).open("r", encoding="utf-8") as file:
        data = json.load(file)

    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected a JSON object.")

    return data


def require_number(value, field, minimum=None, maximum=None):
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
    ):
        raise ValueError(f"Invalid numeric field: {field}")

    if minimum is not None and value < minimum:
        raise ValueError(f"{field} must be at least {minimum}.")

    if maximum is not None and value > maximum:
        raise ValueError(f"{field} must be at most {maximum}.")

    return value


def require_count(value, field):
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"Invalid count field: {field}")

    return value


def validate_anomaly_report(data):
    if data.get("report_type") != "network_anomaly_report":
        raise ValueError("Invalid anomaly report type.")

    summary = data.get("summary")
    thresholds = data.get("thresholds")
    measurements = data.get("measurements")

    if not isinstance(summary, dict):
        raise ValueError("Anomaly report summary must be an object.")

    if not isinstance(thresholds, dict):
        raise ValueError("Anomaly report thresholds must be an object.")

    if not isinstance(measurements, list) or not measurements:
        raise ValueError("Anomaly report measurements must be a non-empty list.")

    total = require_count(
        summary.get("total_measurements"), "anomaly.total_measurements"
    )
    anomalies = require_count(
        summary.get("anomaly_count"), "anomaly.anomaly_count"
    )
    normal = require_count(
        summary.get("normal_count"), "anomaly.normal_count"
    )

    if total != len(measurements):
        raise ValueError("Anomaly measurement count does not match summary.")

    if anomalies + normal != total:
        raise ValueError("Anomaly summary counts are inconsistent.")

    actual_anomalies = 0

    for index, item in enumerate(measurements):
        if not isinstance(item, dict):
            raise ValueError(f"Invalid anomaly measurement at index {index}.")

        required = (
            "timestamp",
            "latency_ms",
            "packet_loss_percent",
            "throughput_mbps",
            "error_rate_percent",
            "memory_used_mb",
            "memory_usage_percent",
            "is_anomaly",
            "reasons",
        )

        for field in required:
            if field not in item:
                raise ValueError(
                    f"Measurement {index} is missing field {field}."
                )

        if not isinstance(item["timestamp"], str) or not item["timestamp"]:
            raise ValueError(f"Measurement {index} has an invalid timestamp.")

        if not isinstance(item["is_anomaly"], bool):
            raise ValueError(f"Measurement {index} has an invalid anomaly flag.")

        if not isinstance(item["reasons"], list) or not all(
            isinstance(reason, str) for reason in item["reasons"]
        ):
            raise ValueError(f"Measurement {index} has invalid reasons.")

        for field in (
            "latency_ms",
            "packet_loss_percent",
            "throughput_mbps",
            "error_rate_percent",
            "memory_used_mb",
            "memory_usage_percent",
        ):
            require_number(item[field], f"measurements[{index}].{field}", 0)

        require_number(
            item["packet_loss_percent"],
            f"measurements[{index}].packet_loss_percent",
            0,
            100,
        )
        require_number(
            item["error_rate_percent"],
            f"measurements[{index}].error_rate_percent",
            0,
            100,
        )
        require_number(
            item["memory_usage_percent"],
            f"measurements[{index}].memory_usage_percent",
            0,
            100,
        )

        if item["is_anomaly"]:
            actual_anomalies += 1
            if not item["reasons"]:
                raise ValueError(
                    f"Anomalous measurement {index} has no recorded reasons."
                )

    if actual_anomalies != anomalies:
        raise ValueError("Anomaly flags do not match anomaly summary.")

    return summary, thresholds, measurements


def validate_analytics_report(data):
    if data.get("report_type") != "network_analytics_report":
        raise ValueError("Invalid analytics report type.")

    summary = data.get("summary")
    statistics = data.get("statistics")

    if not isinstance(summary, dict) or not isinstance(statistics, dict):
        raise ValueError("Analytics summary and statistics must be objects.")

    total = require_count(
        summary.get("total_measurements"), "analytics.total_measurements"
    )
    anomalies = require_count(
        summary.get("anomaly_count"), "analytics.anomaly_count"
    )
    normal = require_count(
        summary.get("normal_count"), "analytics.normal_count"
    )

    if anomalies + normal != total:
        raise ValueError("Analytics summary counts are inconsistent.")

    rate = require_number(
        summary.get("anomaly_rate_percent"),
        "analytics.anomaly_rate_percent",
        0,
        100,
    )

    expected_rate = 100.0 * anomalies / total if total else 0.0
    if not math.isclose(rate, expected_rate, rel_tol=1e-4, abs_tol=1e-4):
        raise ValueError("Analytics anomaly rate does not match its counts.")

    expected_metrics = (
        "latency_ms",
        "packet_loss_percent",
        "throughput_mbps",
        "error_rate_percent",
        "memory_used_mb",
        "memory_usage_percent",
    )

    for metric in expected_metrics:
        stat = statistics.get(metric)

        if not isinstance(stat, dict):
            raise ValueError(f"Missing analytics statistics: {metric}")

        minimum = require_number(stat.get("minimum"), f"{metric}.minimum", 0)
        maximum = require_number(stat.get("maximum"), f"{metric}.maximum", 0)
        average = require_number(stat.get("average"), f"{metric}.average", 0)

        if minimum > maximum or not minimum <= average <= maximum:
            raise ValueError(f"Inconsistent analytics statistics: {metric}")

    return summary, statistics


def validate_trend_report(data):
    if data.get("report_type") != "network_trend_report":
        raise ValueError("Invalid trend report type.")

    summary = data.get("summary")
    trends = data.get("trends")

    if not isinstance(summary, dict) or not isinstance(trends, list):
        raise ValueError("Trend summary or trends list is invalid.")

    total = require_count(
        summary.get("total_measurements"), "trends.total_measurements"
    )
    baseline = require_count(
        summary.get("baseline_measurements"), "trends.baseline_measurements"
    )
    analyzed = require_count(
        summary.get("analyzed_measurements"), "trends.analyzed_measurements"
    )

    if baseline + analyzed != total:
        raise ValueError("Trend measurement counts are inconsistent.")

    if baseline == 0 or analyzed == 0:
        raise ValueError("Trend report requires baseline and analyzed measurements.")

    expected_metrics = {
        "latency",
        "packet_loss",
        "throughput",
        "error_rate",
        "memory_usage",
    }

    actual_metrics = set()

    for index, item in enumerate(trends):
        if not isinstance(item, dict):
            raise ValueError(f"Invalid trend entry at index {index}.")

        metric = item.get("metric")

        if metric not in expected_metrics or metric in actual_metrics:
            raise ValueError(f"Invalid or duplicate trend metric: {metric}")

        actual_metrics.add(metric)

        if not isinstance(item.get("detected"), bool):
            raise ValueError(f"Invalid detected flag for {metric}.")

        if not isinstance(item.get("recovered"), bool):
            raise ValueError(f"Invalid recovered flag for {metric}.")

        for field in (
            "baseline_average",
            "observed_average",
        ):
            require_number(item.get(field), f"{metric}.{field}")

        baseline = item["baseline_average"]
        observed = item["observed_average"]
        deviation = item.get("deviation_percent")

        if deviation is None:
            if baseline != 0 or observed <= 0 or not item["detected"]:
                raise ValueError(
                    f"Undefined percentage deviation is inconsistent for {metric}."
                )
        else:
            require_number(deviation, f"{metric}.deviation_percent")
            if baseline == 0 and observed > 0 and item["detected"]:
                raise ValueError(
                    f"{metric} must use a null percentage deviation from zero."
                )

        require_count(
            item.get("consecutive_measurements"),
            f"{metric}.consecutive_measurements",
        )

        for field in (
            "start_timestamp",
            "end_timestamp",
            "recovery_timestamp",
        ):
            if not isinstance(item.get(field), str):
                raise ValueError(f"Invalid {field} for {metric}.")

        if item["recovered"] and not item["detected"]:
            raise ValueError(f"{metric} cannot recover without a detected trend.")

    if actual_metrics != expected_metrics:
        raise ValueError("Trend report does not contain all five metrics.")

    return summary, trends


def write_json_atomically(output_path, data):
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            dir=output_path.parent,
            prefix=f".{output_path.name}.",
            suffix=".tmp",
            delete=False,
        ) as file:
            temporary_path = Path(file.name)
            json.dump(data, file, indent=4, ensure_ascii=False)
            file.write("\n")
            file.flush()
            os.fsync(file.fileno())

        os.replace(temporary_path, output_path)
        temporary_path = None

    finally:
        if temporary_path is not None:
            try:
                temporary_path.unlink(missing_ok=True)
            except OSError:
                pass


def build_evidence(anomaly_path, analytics_path, trend_path):
    anomaly_data = load_json(anomaly_path)
    analytics_data = load_json(analytics_path)
    trend_data = load_json(trend_path)

    anomaly_summary, thresholds, measurements = (
        validate_anomaly_report(anomaly_data)
    )
    analytics_summary, statistics = validate_analytics_report(analytics_data)
    trend_summary, trends = validate_trend_report(trend_data)

    totals = {
        anomaly_summary["total_measurements"],
        analytics_summary["total_measurements"],
        trend_summary["total_measurements"],
    }

    if len(totals) != 1:
        raise ValueError("The three reports contain different measurement counts.")

    for field in ("anomaly_count", "normal_count"):
        if anomaly_summary[field] != analytics_summary[field]:
            raise ValueError(f"Anomaly and analytics {field} values disagree.")

    if trend_summary["total_measurements"] != anomaly_summary["total_measurements"]:
        raise ValueError("Trend and anomaly measurement totals disagree.")

    anomalous_measurements = [
        item for item in measurements if item["is_anomaly"]
    ]

    return {
        "report_type": "ps2_network_investigation_evidence",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "sources": {
            "anomaly_report": str(anomaly_path),
            "analytics_report": str(analytics_path),
            "trend_report": str(trend_path),
        },
        "summary": {
            "total_measurements": anomaly_summary["total_measurements"],
            "normal_measurements": anomaly_summary["normal_count"],
            "anomalous_measurements": anomaly_summary["anomaly_count"],
            "anomaly_rate_percent": analytics_summary["anomaly_rate_percent"],
            "baseline_measurements": trend_summary["baseline_measurements"],
            "trend_analysis_measurements": trend_summary["analyzed_measurements"],
        },
        "thresholds": thresholds,
        "aggregate_statistics": statistics,
        "anomalous_measurements": anomalous_measurements,
        "historical_trends": trends,
        "analysis_guidance": [
            "Treat recorded measurements and calculated statistics as observed evidence.",
            "Anomaly thresholds and historical baseline thresholds are different rules.",
            "A measurement can return below an anomaly threshold while remaining outside its historical baseline range.",
            "A detected trend is not proof of its underlying cause.",
            "Do not claim recovery unless the trend report explicitly records recovery.",
            "Memory usage percentage is used for threshold analysis; memory_used_mb describes consumption.",
            "Root-cause hypotheses must remain unconfirmed until independently corroborated.",
            "No live network, server, CPU, deployment, or external telemetry checks were performed.",
        ],
    }


def main():
    if len(sys.argv) != 5:
        print(
            "Usage: python network_evidence.py "
            "<anomaly.json> <analytics.json> <trends.json> <evidence.json>",
            file=sys.stderr,
        )
        return 2

    anomaly_path = Path(sys.argv[1])
    analytics_path = Path(sys.argv[2])
    trend_path = Path(sys.argv[3])
    output_path = Path(sys.argv[4])

    try:
        evidence = build_evidence(
            anomaly_path,
            analytics_path,
            trend_path,
        )
        write_json_atomically(output_path, evidence)

        summary = evidence["summary"]

        print("PS2 evidence generated successfully.")
        print(f"Measurements: {summary['total_measurements']}")
        print(f"Anomalies: {summary['anomalous_measurements']}")
        print(f"Anomaly rate: {summary['anomaly_rate_percent']:.2f}%")
        print(f"Trend indicators: {len(evidence['historical_trends'])}")
        print(f"Output: {output_path}")

        return 0

    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        print(f"PS2 evidence generation failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
