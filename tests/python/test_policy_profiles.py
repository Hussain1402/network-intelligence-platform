import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from devsecops.agent.policy_engine import (
    evaluate_security_report,
    load_policy_config,
)


class TestPolicyProfiles(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.config = load_policy_config(
            PROJECT_ROOT
            / "devsecops"
            / "config"
            / "security_policy.json"
        )

    def make_report(self):
        return {
            "report_type": "devsecops_security_scan",
            "findings": [
                {"rule_id": "R1", "file": "a.py", "line": 1,
                 "severity": "critical"},
                {"rule_id": "R2", "file": "b.py", "line": 2,
                 "severity": "high"},
                {"rule_id": "R3", "file": "c.py", "line": 3,
                 "severity": "medium"},
                {"rule_id": "R4", "file": "d.py", "line": 4,
                 "severity": "low"},
            ],
        }

    def test_balanced_profile(self):
        result = evaluate_security_report(
            self.make_report(),
            self.config["profiles"]["balanced"],
            "balanced",
        )
        summary = result["summary"]

        self.assertEqual(summary["blocked_findings"], 2)
        self.assertEqual(summary["warnings"], 1)
        self.assertEqual(summary["informational"], 1)
        self.assertEqual(summary["overall_decision"], "blocked")

    def test_strict_profile(self):
        result = evaluate_security_report(
            self.make_report(),
            self.config["profiles"]["strict"],
            "strict",
        )
        summary = result["summary"]

        self.assertEqual(summary["blocked_findings"], 3)
        self.assertEqual(summary["warnings"], 1)
        self.assertEqual(summary["overall_decision"], "blocked")

    def test_report_only_profile(self):
        result = evaluate_security_report(
            self.make_report(),
            self.config["profiles"]["report_only"],
            "report_only",
        )
        summary = result["summary"]

        self.assertEqual(summary["blocked_findings"], 0)
        self.assertEqual(summary["warnings"], 0)
        self.assertEqual(summary["informational"], 4)
        self.assertEqual(summary["overall_decision"], "passed")

    def test_report_records_selected_profile(self):
        result = evaluate_security_report(
            self.make_report(),
            self.config["profiles"]["strict"],
            "strict",
        )
        self.assertEqual(result["policy_mode"], "strict")

    def test_default_profile_is_balanced(self):
        self.assertEqual(self.config["default_profile"], "balanced")


if __name__ == "__main__":
    unittest.main()
