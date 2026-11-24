import unittest

from python.functionlog_mock_ai import load_evidence, investigate


def make_evidence():
    return {
        "project": "Function Execution Analysis",
        "summary": {
            "total_executions": 2,
            "successful_executions": 2,
            "failed_executions": 0,
            "in_progress_executions": 0,
            "unique_functions": 2,
            "failure_rate_percent": 0.0,
        },
        "performance": {
            "average_execution_time_ms": 5.0,
            "minimum_execution_time_ms": 2.0,
            "maximum_execution_time_ms": 8.0,
        },
        "function_statistics": [
            {
                "function_name": "process_request",
                "total_executions": 1,
                "successful_executions": 1,
                "failed_executions": 0,
                "average_execution_time_ms": 8.0,
                "minimum_execution_time_ms": 8.0,
                "maximum_execution_time_ms": 8.0,
            },
            {
                "function_name": "validate_input",
                "total_executions": 1,
                "successful_executions": 1,
                "failed_executions": 0,
                "average_execution_time_ms": 2.0,
                "minimum_execution_time_ms": 2.0,
                "maximum_execution_time_ms": 2.0,
            },
        ],
        "execution_records": [
            {
                "id": 1,
                "parent_id": 0,
                "function_name": "process_request",
                "caller_name": "main",
                "start_timestamp": "2026-11-04T10:00:00Z",
                "end_timestamp": "2026-11-04T10:00:01Z",
                "execution_time_ms": 8.0,
                "status": "SUCCESS",
                "error_code": 0,
                "error_message": "",
            },
            {
                "id": 2,
                "parent_id": 1,
                "function_name": "validate_input",
                "caller_name": "process_request",
                "start_timestamp": "2026-11-04T10:00:00Z",
                "end_timestamp": "2026-11-04T10:00:00Z",
                "execution_time_ms": 2.0,
                "status": "SUCCESS",
                "error_code": 0,
                "error_message": "",
            },
        ],
    }


class FunctionLogMockAITests(unittest.TestCase):

    def test_successful_execution_analysis(self):
        data = make_evidence()
        report = investigate(data)

        self.assertEqual(report["summary"]["successful_executions"], 2)
        self.assertEqual(report["summary"]["failed_executions"], 0)
        self.assertTrue(report["observed_evidence"])
        self.assertEqual(
            report["report_type"],
            "function_execution_mock_investigation",
        )

    def test_nested_failure_propagation(self):
        data = make_evidence()

        parent = data["execution_records"][0]
        child = data["execution_records"][1]

        parent.update({
            "status": "FAILED",
            "error_code": 1002,
            "error_message": "Validation failure propagated",
        })

        child.update({
            "status": "FAILED",
            "error_code": 1002,
            "error_message": "Input validation failed",
        })

        data["summary"].update({
            "successful_executions": 0,
            "failed_executions": 2,
            "failure_rate_percent": 100.0,
        })

        for stats in data["function_statistics"]:
            stats["successful_executions"] = 0
            stats["failed_executions"] = 1

        report = investigate(data)

        hypotheses = report["root_cause_hypotheses"]

        self.assertEqual(len(hypotheses), 1)
        self.assertIn("validate_input", hypotheses[0]["hypothesis"])

        evidence_text = " ".join(report["observed_evidence"])
        self.assertIn("propagated from a failed child", evidence_text)

        self.assertEqual(report["summary"]["failed_executions"], 2)

    def test_in_progress_execution(self):
        data = make_evidence()

        record = data["execution_records"][1]
        record.update({
            "end_timestamp": None,
            "execution_time_ms": None,
            "status": "IN_PROGRESS",
        })

        data["summary"].update({
            "successful_executions": 1,
            "in_progress_executions": 1,
        })

        report = investigate(data)

        evidence_text = " ".join(report["observed_evidence"])
        self.assertIn("still in progress", evidence_text)
        self.assertIn(
            "excluded from completed-duration analysis",
            evidence_text,
        )

    def test_missing_required_fields(self):
        data = make_evidence()
        del data["execution_records"]

        with self.assertRaises(ValueError):
            # Write through a temporary file to exercise the actual loader.
            import json
            import tempfile
            from pathlib import Path

            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "invalid.json"
                path.write_text(json.dumps(data), encoding="utf-8")
                load_evidence(path)

    def test_duplicate_execution_ids(self):
        data = make_evidence()
        data["execution_records"][1]["id"] = 1

        import json
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.json"
            path.write_text(json.dumps(data), encoding="utf-8")

            with self.assertRaises(ValueError):
                load_evidence(path)


if __name__ == "__main__":
    unittest.main()
