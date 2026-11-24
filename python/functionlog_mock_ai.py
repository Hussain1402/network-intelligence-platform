import json
import sys
from pathlib import Path
from datetime import datetime, timezone


def load_evidence(path):
    with path.open("r", encoding="utf-8") as file:
        data = json.load(file)

    required = {
        "summary",
        "performance",
        "function_statistics",
        "execution_records",
    }

    missing = required - data.keys()
    if missing:
        raise ValueError(f"Missing evidence fields: {sorted(missing)}")

    summary = data["summary"]
    records = data["execution_records"]
    functions = data["function_statistics"]

    if not isinstance(records, list) or not isinstance(functions, list):
        raise ValueError("Execution records and function statistics must be lists.")

    required_summary = {
        "total_executions",
        "successful_executions",
        "failed_executions",
        "in_progress_executions",
        "unique_functions",
        "failure_rate_percent",
    }

    if not required_summary.issubset(summary):
        raise ValueError("Function execution summary is incomplete.")

    if summary["total_executions"] != len(records):
        raise ValueError("Total execution count does not match execution records.")

    status_counts = {
        "SUCCESS": 0,
        "FAILED": 0,
        "IN_PROGRESS": 0,
    }

    record_ids = set()

    for record in records:
        required_record = {
            "id", "parent_id", "function_name", "caller_name",
            "start_timestamp", "end_timestamp", "execution_time_ms",
            "status", "error_code", "error_message",
        }

        if not required_record.issubset(record):
            raise ValueError("An execution record is missing required fields.")

        if record["status"] not in status_counts:
            raise ValueError(f"Invalid execution status: {record['status']}")

        if record["id"] in record_ids:
            raise ValueError("Duplicate execution ID detected.")

        record_ids.add(record["id"])
        status_counts[record["status"]] += 1

    if status_counts["SUCCESS"] != summary["successful_executions"]:
        raise ValueError("Successful execution count mismatch.")

    if status_counts["FAILED"] != summary["failed_executions"]:
        raise ValueError("Failed execution count mismatch.")

    if status_counts["IN_PROGRESS"] != summary["in_progress_executions"]:
        raise ValueError("In-progress execution count mismatch.")

    for record in records:
        parent_id = record["parent_id"]

        if parent_id != 0 and parent_id not in record_ids:
            raise ValueError(
                f"Execution {record['id']} references missing parent {parent_id}."
            )

    return data


def investigate(data):
    summary = data["summary"]
    performance = data["performance"]
    records = data["execution_records"]
    function_stats = data["function_statistics"]

    evidence = []
    hypotheses = []
    checks = []

    total = summary["total_executions"]
    successful = summary["successful_executions"]
    failed = summary["failed_executions"]
    in_progress = summary["in_progress_executions"]

    evidence.append(
        f"{total} function executions were recorded: "
        f"{successful} successful, {failed} failed, "
        f"and {in_progress} still in progress."
    )

    evidence.append(
        f"Completed-execution failure rate: "
        f"{summary['failure_rate_percent']:.2f}%."
    )

    evidence.append(
        f"{summary['unique_functions']} unique functions were observed."
    )

    if total == 0:
        evidence.append("No function execution records are available.")

    completed = [
        record for record in records
        if record["status"] in {"SUCCESS", "FAILED"}
    ]

    failed_records = [
        record for record in records
        if record["status"] == "FAILED"
    ]

    record_by_id = {record["id"]: record for record in records}

    # Identify failed parents that have a directly failed child.
    failed_parent_ids = {
        record["parent_id"]
        for record in failed_records
        if record["parent_id"] != 0
        and record["parent_id"] in record_by_id
        and record_by_id[record["parent_id"]]["status"] == "FAILED"
    }

    # Identify failed functions and their execution context.
    for record in failed_records:
        function_name = record["function_name"]

        evidence.append(
            f"Function '{function_name}' failed with error code "
            f"{record['error_code']}: {record['error_message'] or 'No error message supplied'}."
        )

        parent_id = record["parent_id"]

        if parent_id != 0:
            parent = record_by_id[parent_id]

            evidence.append(
                f"Failed execution {record['id']} was nested inside "
                f"'{parent['function_name']}' (execution ID {parent_id}), "
                f"whose recorded status is {parent['status']}."
            )

        if record["id"] in failed_parent_ids:
            evidence.append(
                f"Failure in '{function_name}' may be propagated from "
                "a failed child execution. Its own failure is recorded, "
                "but it is not treated as an independent originating failure."
            )

            checks.append({
                "priority": "medium",
                "check": f"Trace failure propagation in '{function_name}'",
                "purpose": (
                    "Determine whether this function propagated the "
                    "child failure or encountered an additional independent error."
                ),
            })

            continue

        hypotheses.append({
            "hypothesis": (
                f"The failure in '{function_name}' may originate from "
                "an application error or an unsuccessful operation "
                "within that function."
            ),
            "confidence": "low",
            "status": "unconfirmed",
            "reasoning": (
                f"The execution record contains error code "
                f"{record['error_code']} and message "
                f"'{record['error_message']}'. These identify the "
                "reported failure but do not establish its underlying cause."
            ),
        })

        checks.append({
            "priority": "high",
            "check": f"Inspect the implementation of '{function_name}'",
            "purpose": (
                "Trace the failing operation, validate its inputs, "
                "and inspect the code path that generated the recorded error."
            ),
        })

        if parent_id != 0:
            checks.append({
                "priority": "medium",
                "check": f"Trace the caller '{parent['function_name']}'",
                "purpose": (
                    "Inspect the arguments and execution path passed "
                    "from the parent function to the failed function."
                ),
            })

    # Aggregate failures by function.
    failures_by_function = {}

    for record in failed_records:
        name = record["function_name"]
        failures_by_function[name] = failures_by_function.get(name, 0) + 1

    for name, count in failures_by_function.items():
        evidence.append(
            f"Function '{name}' accounts for {count} recorded failure(s)."
        )

    # Performance observations.
    if completed:
        evidence.append(
            f"Average completed execution duration: "
            f"{performance['average_execution_time_ms']:.6f} ms."
        )

        evidence.append(
            f"Minimum completed execution duration: "
            f"{performance['minimum_execution_time_ms']:.6f} ms."
        )

        evidence.append(
            f"Maximum completed execution duration: "
            f"{performance['maximum_execution_time_ms']:.6f} ms."
        )

    if function_stats:
        completed_functions = [
            item for item in function_stats
            if item["successful_executions"] + item["failed_executions"] > 0
        ]

        if completed_functions:
            slowest = max(
                completed_functions,
                key=lambda item: item["maximum_execution_time_ms"]
            )

            evidence.append(
                f"Highest observed maximum execution duration was for "
                f"'{slowest['function_name']}': "
                f"{slowest['maximum_execution_time_ms']:.6f} ms."
            )

            checks.append({
                "priority": "medium",
                "check": f"Profile function '{slowest['function_name']}'",
                "purpose": (
                    "Compare repeated execution durations and establish "
                    "a baseline before deciding whether performance "
                    "optimization is necessary."
                ),
            })

    if in_progress:
        evidence.append(
            f"{in_progress} execution(s) are still in progress and "
            "were excluded from completed-duration analysis."
        )

        checks.append({
            "priority": "medium",
            "check": "Investigate executions still in progress",
            "purpose": (
                "Determine whether these executions are legitimately "
                "running or are blocked by an unfinished operation."
            ),
        })

    if not hypotheses:
        hypotheses.append({
            "hypothesis": (
                "The supplied execution evidence does not identify "
                "a confirmed function failure."
            ),
            "confidence": "low",
            "status": "unconfirmed",
            "reasoning": (
                "No failed execution records were supplied. "
                "This does not prove that the application is free of defects."
            ),
        })

    if not checks:
        checks.append({
            "priority": "medium",
            "check": "Collect additional execution evidence",
            "purpose": (
                "Capture representative function executions, errors, "
                "and performance measurements for further investigation."
            ),
        })

    return {
        "report_type": "function_execution_mock_investigation",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "source": data.get("project", "Function Execution Analysis"),
        "summary": summary,
        "observed_evidence": evidence,
        "root_cause_hypotheses": hypotheses,
        "recommended_diagnostic_checks": checks,
        "limitations": [
            "This is a deterministic, rule-based mock investigator.",
            "Root-cause hypotheses are unconfirmed.",
            "Only supplied function execution evidence was analyzed.",
            "No source code, live application, or external telemetry was inspected.",
            "A performance baseline or threshold is required to establish anomalies.",
        ],
    }


def main():
    if len(sys.argv) != 3:
        print(
            "Usage: python functionlog_mock_ai.py <evidence.json> <report.json>",
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

        print(f"Function investigation report written to: {output_path}")

        print("\nObserved evidence:")
        for item in report["observed_evidence"]:
            print(f"- {item}")

        print("\nRoot-cause hypotheses:")
        for item in report["root_cause_hypotheses"]:
            print(f"- [{item['confidence']}] {item['hypothesis']}")
            print(f"  Status: {item['status']}")

        print("\nRecommended diagnostic checks:")
        for item in report["recommended_diagnostic_checks"]:
            print(f"- [{item['priority']}] {item['check']}")
            print(f"  Purpose: {item['purpose']}")

        return 0

    except (OSError, json.JSONDecodeError, ValueError, TypeError, KeyError) as exc:
        print(f"Investigation failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
