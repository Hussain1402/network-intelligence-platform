import unittest

from devsecops.agent.security_investigator import (
    build_investigation_report,
    investigate_finding,
)


class SecurityInvestigatorTests(unittest.TestCase):

    def setUp(self):
        self.scan_report = {
            "report_type": "devsecops_security_scan",
            "summary": {"total_findings": 2},
            "findings": [
                {
                    "rule_id": "C_UNSAFE_STRCPY",
                    "severity": "high",
                    "file": "demo.c",
                    "line": 9,
                    "description": "Potentially unsafe strcpy usage.",
                    "evidence": "strcpy(buffer, input);"
                },
                {
                    "rule_id": "PY_EVAL",
                    "severity": "high",
                    "file": "demo.py",
                    "line": 5,
                    "description": "Dynamic evaluation can execute untrusted expressions.",
                    "evidence": "return eval(expression)"
                }
            ],
            "scan_errors": []
        }

    def test_generates_investigation_for_each_finding(self):
        report = build_investigation_report(self.scan_report)

        self.assertEqual(
            report["summary"]["total_investigated"], 2
        )
        self.assertEqual(len(report["investigations"]), 2)

    def test_identifies_strcpy_risk(self):
        result = investigate_finding(self.scan_report["findings"][0])

        self.assertIn("memory", result["potential_impact"].lower())
        self.assertIn("bounded", result["recommended_remediation"].lower())

    def test_identifies_eval_risk(self):
        result = investigate_finding(self.scan_report["findings"][1])

        self.assertIn("execute", result["potential_impact"].lower())
        self.assertIn("eval", result["rule_id"].lower())

    def test_requires_human_review(self):
        report = build_investigation_report(self.scan_report)

        for item in report["investigations"]:
            self.assertTrue(item["requires_human_review"])

    def test_rejects_inconsistent_finding_count(self):
        self.scan_report["summary"]["total_findings"] = 10

        with self.assertRaises(ValueError):
            build_investigation_report(self.scan_report)

    def test_rejects_wrong_report_type(self):
        self.scan_report["report_type"] = "unknown"

        with self.assertRaises(ValueError):
            build_investigation_report(self.scan_report)

    def test_handles_unknown_rule_safely(self):
        finding = {
            "rule_id": "UNKNOWN_RULE",
            "severity": "low",
            "file": "example.py",
            "line": 3,
            "description": "Unknown pattern."
        }

        result = investigate_finding(finding)

        self.assertEqual(result["title"], "Unclassified security finding")
        self.assertTrue(result["requires_human_review"])


if __name__ == "__main__":
    unittest.main()
