import json
import sys
from datetime import datetime, timezone
from pathlib import Path


def load_evidence(path):
    with Path(path).open("r", encoding="utf-8") as file:
        data = json.load(file)

    if not isinstance(data, dict):
        raise ValueError("Evidence root must be a JSON object.")

    if data.get("report_type") != "ps2_network_investigation_evidence":
        raise ValueError("Invalid PS2 evidence report type.")

    required = (
        "summary",
        "thresholds",
        "aggregate_statistics",
        "anomalous_measurements",
        "historical_trends",
        "analysis_guidance",
    )

    for field in required:
        if field not in data:
            raise ValueError(f"Evidence is missing required field: {field}")

    if not isinstance(data["summary"], dict):
        raise ValueError("Evidence summary must be an object.")

    if not isinstance(data["thresholds"], dict):
        raise ValueError("Evidence thresholds must be an object.")

    if not isinstance(data["aggregate_statistics"], dict):
        raise ValueError("Aggregate statistics must be an object.")

    if not isinstance(data["anomalous_measurements"], list):
        raise ValueError("Anomalous measurements must be a list.")

    if not isinstance(data["historical_trends"], list):
        raise ValueError("Historical trends must be a list.")

    if not isinstance(data["analysis_guidance"], list):
        raise ValueError("Analysis guidance must be a list.")

    summary = data["summary"]

    for field in (
        "total_measurements",
        "normal_measurements",
        "anomalous_measurements",
        "anomaly_rate_percent",
        "baseline_measurements",
        "trend_analysis_measurements",
    ):
        if field not in summary:
            raise ValueError(f"Summary is missing field: {field}")

    total = summary["total_measurements"]
    normal = summary["normal_measurements"]
    anomalous = summary["anomalous_measurements"]

    for field, value in (
        ("total_measurements", total),
        ("normal_measurements", normal),
        ("anomalous_measurements", anomalous),
    ):
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f"Invalid summary count: {field}")

    if normal + anomalous != total:
        raise ValueError("Evidence summary counts are inconsistent.")

    if len(data["anomalous_measurements"]) != anomalous:
        raise ValueError("Anomalous measurement list does not match summary.")

    return data


def investigate(data):
    """Generate deterministic, explainable PS2 network findings."""

    summary = data["summary"]
    statistics = data["aggregate_statistics"]
    anomalous = data["anomalous_measurements"]
    trends = data["historical_trends"]
    thresholds = data["thresholds"]

    evidence = []
    hypotheses = []
    checks = []

    total = summary["total_measurements"]
    anomaly_count = summary["anomalous_measurements"]
    anomaly_rate = summary["anomaly_rate_percent"]

    evidence.append(
        f"{anomaly_count} of {total} network measurements were anomalous "
        f"({anomaly_rate:.2f}%)."
    )

    if total:
        evidence.append(
            f"{summary['normal_measurements']} measurements were classified "
            "as normal by the configured anomaly detector."
        )

    # Identify the time interval containing anomalous measurements.
    if anomalous:
        timestamps = [item["timestamp"] for item in anomalous]
        first_timestamp = min(timestamps)
        last_timestamp = max(timestamps)

        evidence.append(
            f"Anomalous measurements occurred from {first_timestamp} "
            f"through {last_timestamp}."
        )

        reason_counts = {}

        for item in anomalous:
            for reason in item["reasons"]:
                reason_counts[reason] = reason_counts.get(reason, 0) + 1

        reason_labels = {
            "high_latency": "high latency",
            "high_packet_loss": "high packet loss",
            "low_throughput": "low throughput",
            "high_error_rate": "high error rate",
            "high_memory_usage": "high memory usage",
        }

        for reason, count in sorted(
            reason_counts.items(),
            key=lambda pair: (-pair[1], pair[0]),
        ):
            label = reason_labels.get(reason, reason.replace("_", " "))
            evidence.append(
                f"{label.capitalize()} was recorded in {count} "
                f"anomalous measurement(s)."
            )

        # Check whether all five indicators overlap in the anomalous records.
        expected_reasons = {
            "high_latency",
            "high_packet_loss",
            "low_throughput",
            "high_error_rate",
            "high_memory_usage",
        }

        multi_metric_count = sum(
            1 for item in anomalous
            if expected_reasons.issubset(set(item["reasons"]))
        )

        if multi_metric_count:
            evidence.append(
                f"{multi_metric_count} anomalous measurement(s) contained "
                "all five recorded anomaly indicators simultaneously."
            )

        latency = statistics["latency_ms"]
        packet_loss = statistics["packet_loss_percent"]
        throughput = statistics["throughput_mbps"]
        error_rate = statistics["error_rate_percent"]
        memory = statistics["memory_usage_percent"]

        evidence.append(
            f"Across the full dataset, latency ranged from "
            f"{latency['minimum']:.2f} to {latency['maximum']:.2f} ms "
            f"(average {latency['average']:.2f} ms)."
        )

        evidence.append(
            f"Packet loss ranged from {packet_loss['minimum']:.2f}% "
            f"to {packet_loss['maximum']:.2f}% "
            f"(average {packet_loss['average']:.2f}%)."
        )

        evidence.append(
            f"Throughput ranged from {throughput['minimum']:.2f} to "
            f"{throughput['maximum']:.2f} Mbps "
            f"(average {throughput['average']:.2f} Mbps)."
        )

        evidence.append(
            f"Error rate ranged from {error_rate['minimum']:.2f}% "
            f"to {error_rate['maximum']:.2f}% "
            f"(average {error_rate['average']:.2f}%)."
        )

        evidence.append(
            f"Memory usage ranged from {memory['minimum']:.2f}% "
            f"to {memory['maximum']:.2f}% "
            f"(average {memory['average']:.2f}%)."
        )

        # Broad multi-metric degradation hypothesis.
        if multi_metric_count:
            hypotheses.append({
                "id": "H1",
                "hypothesis": (
                    "A network congestion event or transport-path "
                    "impairment may have contributed to the simultaneous "
                    "increase in latency and packet loss and the reduction "
                    "in throughput."
                ),
                "confidence": "medium",
                "status": "unconfirmed",
                "supporting_evidence": [
                    "High latency and packet loss were recorded together.",
                    "Throughput decreased during the same anomalous measurements.",
                    "The anomaly detector flagged these indicators concurrently.",
                ],
                "alternative_explanations": [
                    "An upstream service slowdown.",
                    "A network interface or routing problem.",
                    "A workload spike or resource contention.",
                ],
            })

            hypotheses.append({
                "id": "H2",
                "hypothesis": (
                    "The elevated error rate may be associated with the "
                    "observed network degradation or an upstream service "
                    "failure."
                ),
                "confidence": "medium",
                "status": "unconfirmed",
                "supporting_evidence": [
                    "The error-rate threshold was exceeded in anomalous measurements.",
                    "Elevated latency and packet loss occurred in the same interval.",
                ],
                "alternative_explanations": [
                    "Application-level failures unrelated to the network.",
                    "Invalid requests or service configuration problems.",
                    "Upstream dependency failures.",
                ],
            })

            if any("high_memory_usage" in item["reasons"] for item in anomalous):
                hypotheses.append({
                    "id": "H3",
                    "hypothesis": (
                        "Elevated memory utilization may have contributed "
                        "to resource pressure during the anomalous interval."
                    ),
                    "confidence": "low",
                    "status": "unconfirmed",
                    "supporting_evidence": [
                        "Memory usage exceeded the configured anomaly threshold.",
                        "Memory utilization increased during the multi-metric event.",
                    ],
                    "alternative_explanations": [
                        "A temporary workload increase.",
                        "A memory-intensive application task.",
                        "Memory pressure may be a consequence rather than a cause.",
                    ],
                })

        # Diagnostic recommendations.
        checks.extend([
            {
                "priority": "high",
                "check": "Inspect network interface and transport-path health",
                "purpose": (
                    "Review interface errors, dropped packets, retransmissions, "
                    "link utilization, routing changes, and packet loss."
                ),
            },
            {
                "priority": "high",
                "check": "Correlate latency, packet loss, and throughput",
                "purpose": (
                    "Compare time-aligned network measurements to determine "
                    "whether degradation affected the same interval and path."
                ),
            },
            {
                "priority": "high",
                "check": "Investigate application and upstream service errors",
                "purpose": (
                    "Inspect service logs, dependency health, request failures, "
                    "and response-time distributions."
                ),
            },
            {
                "priority": "medium",
                "check": "Inspect memory and process utilization",
                "purpose": (
                    "Compare process-level memory consumption, available memory, "
                    "and workload activity during the anomalous interval."
                ),
            },
            {
                "priority": "medium",
                "check": "Review deployment and configuration changes",
                "purpose": (
                    "Check whether routing, application, timeout, or infrastructure "
                    "changes occurred near the start of the degradation."
                ),
            },
        ])

    else:
        evidence.append("No anomalous measurements were supplied.")

        hypotheses.append({
            "id": "H1",
            "hypothesis": (
                "No anomaly-based root-cause hypothesis can be established "
                "from the supplied measurements."
            ),
            "confidence": "low",
            "status": "unconfirmed",
            "supporting_evidence": [],
            "alternative_explanations": [],
        })

        checks.append({
            "priority": "medium",
            "check": "Continue collecting network telemetry",
            "purpose": (
                "Collect additional measurements to establish whether "
                "degradation occurs outside the supplied observation window."
            ),
        })

    # Historical trend interpretation.
    detected_trends = [item for item in trends if item["detected"]]
    recovered_trends = [item for item in detected_trends if item["recovered"]]
    unrecovered_trends = [item for item in detected_trends if not item["recovered"]]

    evidence.append(
        f"{len(detected_trends)} of {len(trends)} historical trend indicators "
        "were detected."
    )

    for trend in detected_trends:
        direction = (
            "decrease"
            if trend["metric"] == "throughput"
            else "increase"
        )

        article = "a" if direction == "decrease" else "an"

        if trend["deviation_percent"] is None:
            evidence.append(
                f"The {trend['metric']} trend moved from a zero baseline "
                f"to an observed average of {trend['observed_average']:.4g}; "
                "a relative percentage change is undefined."
            )
        else:
            evidence.append(
                f"The {trend['metric']} trend showed {article} {direction} of "
                f"{trend['deviation_percent']:.2f}% relative to its baseline "
                f"average of {trend['baseline_average']:.4g}."
            )

        if trend["recovered"]:
            evidence.append(
                f"The {trend['metric']} trend was marked recovered at "
                f"{trend['recovery_timestamp']}."
            )
        else:
            evidence.append(
                f"The {trend['metric']} trend was not marked recovered "
                "by the trend detector."
            )

    # Explicitly distinguish anomaly thresholds from baseline thresholds.
    if unrecovered_trends and anomalous:
        last_anomaly_timestamp = max(
            item["timestamp"] for item in anomalous
        )

        evidence.append(
            "The anomaly detector and historical trend detector use "
            "different criteria. A measurement may no longer exceed an "
            "absolute anomaly threshold while remaining outside its "
            "baseline-relative trend threshold."
        )

        if any(
            item["timestamp"] > last_anomaly_timestamp
            for item in data.get("anomalous_measurements", [])
        ):
            evidence.append(
                "A later anomalous measurement was also present in the supplied evidence."
            )

    if detected_trends:
        checks.append({
            "priority": "medium",
            "check": "Verify recovery against the historical baseline",
            "purpose": (
                "Collect additional consecutive measurements and compare "
                "them with the configured baseline and recovery criteria."
            ),
        })

    if not checks:
        checks.append({
            "priority": "medium",
            "check": "Collect additional network telemetry",
            "purpose": "Gather time-aligned measurements for further investigation.",
        })

    return {
        "report_type": "ps2_mock_ai_network_investigation",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "investigation_mode": "deterministic_rule_based",
        "source": data.get("report_type", "unknown"),
        "summary": summary,
        "observed_evidence": evidence,
        "root_cause_hypotheses": hypotheses,
        "historical_trend_assessment": {
            "total_trends": len(trends),
            "detected_trends": len(detected_trends),
            "recovered_trends": len(recovered_trends),
            "unrecovered_trends": len(unrecovered_trends),
        },
        "recommended_diagnostic_checks": checks,
        "limitations": [
            "This is a deterministic, rule-based Mock AI investigator, not a trained machine-learning model.",
            "Root-cause hypotheses are unconfirmed and require independent verification.",
            "The investigation uses only the supplied PS2 evidence JSON.",
            "No live network devices, servers, application services, or external telemetry were queried.",
            "Historical trend results depend on the configured baseline and thresholds.",
            "Correlation between metrics does not establish causation.",
        ],
    }


def main():
    if len(sys.argv) != 3:
        print(
            "Usage: python network_mock_ai.py <evidence.json> <report.json>",
            file=sys.stderr,
        )
        return 2

    input_path = Path(sys.argv[1])
    output_path = Path(sys.argv[2])

    try:
        data = load_evidence(input_path)
        report = investigate(data)

        output_path.parent.mkdir(parents=True, exist_ok=True)

        with output_path.open("w", encoding="utf-8") as file:
            json.dump(report, file, indent=4, ensure_ascii=False)
            file.write("\n")

        print("PS2 Mock AI investigation completed.")
        print(f"Evidence source: {input_path}")
        print(f"Report: {output_path}")

        print("\nObserved evidence:")
        for item in report["observed_evidence"]:
            print(f"- {item}")

        print("\nRoot-cause hypotheses:")
        for item in report["root_cause_hypotheses"]:
            print(
                f"- [{item['confidence']}] {item['hypothesis']}"
            )
            print(f"  Status: {item['status']}")

        print("\nRecommended diagnostic checks:")
        for item in report["recommended_diagnostic_checks"]:
            print(f"- [{item['priority']}] {item['check']}")

        return 0

    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        print(f"PS2 Mock AI investigation failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
