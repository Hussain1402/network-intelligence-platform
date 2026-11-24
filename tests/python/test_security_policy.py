import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from devsecops.agent.policy_engine import evaluate_security_report


def make_report(severities):
    return {
        "report_type": "devsecops_security_scan",
        "findings": [
            {
                "rule_id": f"TEST_RULE_{index}",
                "file": "fixture.py",
                "line": index + 1,
                "severity": severity,
            }
            for index, severity in enumerate(severities)
        ],
    }


class TestSecurityPolicy(unittest.TestCase):

    def test_critical_finding_blocks(self):
        result = evaluate_security_report(make_report(["critical"]))
        self.assertEqual(
            result["summary"]["overall_decision"], "blocked"
        )
        self.assertEqual(result["summary"]["blocked_findings"], 1)

    def test_high_finding_blocks(self):
        result = evaluate_security_report(make_report(["high"]))
        self.assertEqual(
            result["summary"]["overall_decision"], "blocked"
        )

    def test_medium_finding_warns_without_blocking(self):
        result = evaluate_security_report(make_report(["medium"]))
        self.assertEqual(
            result["summary"]["overall_decision"],
            "passed_with_warnings",
        )
        self.assertEqual(result["summary"]["warnings"], 1)
        self.assertEqual(result["summary"]["blocked_findings"], 0)

    def test_low_finding_is_informational(self):
        result = evaluate_security_report(make_report(["low"]))
        self.assertEqual(
            result["summary"]["overall_decision"], "passed"
        )
        self.assertEqual(result["summary"]["informational"], 1)

    def test_mixed_findings(self):
        result = evaluate_security_report(
            make_report(["high", "medium", "low"])
        )
        summary = result["summary"]

        self.assertEqual(summary["total_findings"], 3)
        self.assertEqual(summary["blocked_findings"], 1)
        self.assertEqual(summary["warnings"], 1)
        self.assertEqual(summary["informational"], 1)
        self.assertEqual(summary["overall_decision"], "blocked")

    def test_rejects_unknown_severity(self):
        with self.assertRaises(ValueError):
            evaluate_security_report(make_report(["unknown"]))

    def test_rejects_wrong_report_type(self):
        report = make_report([])
        report["report_type"] = "something_else"

        with self.assertRaises(ValueError):
            evaluate_security_report(report)


if __name__ == "__main__":
    unittest.main()
