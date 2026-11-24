
import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path


def load_json(path):
    """Load a JSON file and require a JSON object at the root."""

    with Path(path).open("r", encoding="utf-8") as file:
        data = json.load(file)

    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected a JSON object.")

    return data


def require_number(value, field):
    """Require a finite numeric value, excluding booleans."""

    import math

    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
    ):
        raise ValueError(f"Invalid numeric field: {field}")


def validate_call_log(data):
    """Validate the call-log evidence needed for combined analysis."""

    summary = data.get("summary")
    failures = data.get("failure_codes")
    anomalies = data.get("anomalies")

    if not isinstance(summary, dict):
        raise ValueError("Call-log evidence has no valid summary.")

    for field in (
        "total_calls",
        "successful_calls",
        "failed_calls",
        "failure_rate_percent",
    ):
        if field not in summary:
            raise ValueError(f"Call-log summary is missing {field}.")

    for field in (
        "total_calls",
        "successful_calls",
        "failed_calls",
    ):
        value = summary[field]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f"Invalid call-log summary field: {field}")

    if summary["successful_calls"] + summary["failed_calls"] != summary["total_calls"]:
        raise ValueError("Call-log summary counts are inconsistent.")

    require_number(
        summary["failure_rate_percent"],
        "failure_rate_percent",
    )

    if not 0 <= summary["failure_rate_percent"] <= 100:
        raise ValueError("Call-log failure rate must be between 0 and 100.")

    if not isinstance(failures, list):
        raise ValueError("Call-log failure_codes must be a list.")

    if not isinstance(anomalies, list):
        raise ValueError("Call-log anomalies must be a list.")

    for index, item in enumerate(failures):
        if not isinstance(item, dict):
            raise ValueError(f"Invalid failure-code entry at index {index}.")

        if not isinstance(item.get("code"), str):
            raise ValueError(f"Failure-code entry {index} has no valid code.")

        count = item.get("count")
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise ValueError(f"Failure-code entry {index} has an invalid count.")

    return summary, failures, anomalies


def validate_network_report(data):
    """Validate the network anomaly report."""

    summary = data.get("summary")
    measurements = data.get("measurements")
    thresholds = data.get("thresholds")

    if not isinstance(summary, dict):
        raise ValueError("Network report has no valid summary.")

    if not isinstance(measurements, list):
        raise ValueError("Network report measurements must be a list.")

    if not isinstance(thresholds, dict):
        raise ValueError("Network report thresholds must be an object.")

    for field in (
        "total_measurements",
        "anomaly_count",
        "normal_count",
    ):
        value = summary.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f"Invalid network summary field: {field}")

    if (
        summary["anomaly_count"] + summary["normal_count"]
        != summary["total_measurements"]
    ):
        raise ValueError("Network report summary counts are inconsistent.")

    if len(measurements) != summary["total_measurements"]:
        raise ValueError("Network report measurement count does not match summary.")

    actual_anomalies = 0

    for index, item in enumerate(measurements):
        if not isinstance(item, dict):
            raise ValueError(f"Invalid measurement at index {index}.")

        for field in (
            "timestamp",
            "latency_ms",
            "packet_loss_percent",
            "throughput_mbps",
            "error_rate_percent",
            "is_anomaly",
            "reasons",
        ):
            if field not in item:
                raise ValueError(
                    f"Measurement {index} is missing field {field}."
                )

        if not isinstance(item["timestamp"], str):
            raise ValueError(f"Measurement {index} has an invalid timestamp.")

        if not isinstance(item["is_anomaly"], bool):
            raise ValueError(f"Measurement {index} has an invalid anomaly flag.")

        if not isinstance(item["reasons"], list):
            raise ValueError(f"Measurement {index} reasons must be a list.")

        for field in (
            "latency_ms",
            "packet_loss_percent",
            "throughput_mbps",
            "error_rate_percent",
        ):
            require_number(item[field], f"measurements[{index}].{field}")

        if item["is_anomaly"]:
            actual_anomalies += 1

    if actual_anomalies != summary["anomaly_count"]:
        raise ValueError("Network anomaly count does not match measurements.")

    return summary, measurements, thresholds


def write_json_atomically(output_path, data):
    """Write the complete JSON document before replacing the destination."""

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


def combine_evidence(call_log_path, network_report_path):
    """Validate and combine call-log and network anomaly evidence."""

    call_log = load_json(call_log_path)
    network_report = load_json(network_report_path)

    call_summary, failure_codes, call_anomalies = validate_call_log(call_log)

    network_summary, measurements, thresholds = validate_network_report(
        network_report
    )

    anomalous_measurements = [
        item for item in measurements if item["is_anomaly"]
    ]

    return {
        "report_type": "combined_network_investigation_evidence",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "sources": {
            "call_log": str(call_log_path),
            "network_metrics": str(network_report_path),
        },
        "cross_source_summary": {
            "total_calls": call_summary["total_calls"],
            "failed_calls": call_summary["failed_calls"],
            "call_failure_rate_percent": call_summary[
                "failure_rate_percent"
            ],
            "call_log_anomaly_windows": len(call_anomalies),
            "network_measurements": network_summary["total_measurements"],
            "network_anomalies": network_summary["anomaly_count"],
            "normal_network_measurements": network_summary["normal_count"],
        },
        "call_log_evidence": {
            "summary": call_summary,
            "failure_codes": failure_codes,
            "anomalies": call_anomalies,
        },
        "network_evidence": {
            "summary": network_summary,
            "thresholds": thresholds,
            "anomalous_measurements": anomalous_measurements,
        },
        "analysis_guidance": [
            "Treat supplied measurements and counts as observed evidence.",
            "Compare timestamps only where the available time ranges overlap.",
            "Do not assume that correlation proves causation.",
            "Keep root-cause explanations unconfirmed until corroborated.",
            "No live network or server telemetry is included unless supplied "
            "in the input evidence.",
        ],
    }


def main():
    if len(sys.argv) != 4:
        print(
            "Usage: python combined_evidence.py "
            "<call_log.json> <network_report.json> <combined.json>",
            file=sys.stderr,
        )
        return 2

    call_log_path = Path(sys.argv[1])
    network_report_path = Path(sys.argv[2])
    output_path = Path(sys.argv[3])

    try:
        combined = combine_evidence(call_log_path, network_report_path)
        write_json_atomically(output_path, combined)

        print("Combined evidence created successfully.")
        print(f"Call-log source: {call_log_path}")
        print(f"Network source: {network_report_path}")
        print(
            "Network anomalies: "
            f"{combined['cross_source_summary']['network_anomalies']}"
        )
        print(f"Output: {output_path}")
        return 0

    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        print(f"Combined evidence generation failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
