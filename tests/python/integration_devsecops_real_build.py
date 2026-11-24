import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

from devsecops.agent import orchestrator
from devsecops.agent.security_scanner import scan_directory


class DevSecOpsRealBuildIntegrationTests(unittest.TestCase):

    def test_real_build_and_ctest_after_approved_remediation(self):
        project_root = Path(__file__).resolve().parents[2]
        scan_target = (
            project_root
            / "devsecops"
            / "fixtures"
            / "vulnerable_app"
        )

        self.assertTrue(scan_target.is_dir())
        self.assertTrue((project_root / "CMakeLists.txt").is_file())

        original_hashes = orchestrator.source_file_hashes(scan_target)

        scan_report = scan_directory(scan_target)
        findings = scan_report["findings"]
        self.assertGreater(len(findings), 0)

        investigations = [
            {
                "rule_id": finding["rule_id"],
                "severity": finding["severity"],
                "location": {
                    "file": finding["file"],
                    "line": finding["line"],
                },
                "explanation": "Real-build integration test.",
                "potential_impact": "Potential security exposure.",
                "recommended_remediation": finding["recommendation"],
            }
            for finding in findings
        ]

        investigation_report = {
            "report_type": "devsecops_security_investigation",
            "summary": {
                "total_investigated": len(investigations),
            },
            "investigations": investigations,
        }

        real_run_step = orchestrator.run_step

        def run_real_steps_except_nested_python_tests(
            name, command, working_root, timeout=600
        ):
            if name == "Remediation Python Tests":
                return {
                    "name": name,
                    "command": command,
                    "status": "passed",
                    "return_code": 0,
                    "duration_seconds": 0,
                    "stdout": "Nested Python test execution intentionally mocked.",
                    "stderr": "",
                }

            return real_run_step(
                name, command, working_root, timeout
            )

        with patch.object(
            orchestrator,
            "run_step",
            side_effect=run_real_steps_except_nested_python_tests,
        ):
            result, steps = orchestrator.verify_approved_remediation(
                project_root,
                scan_target,
                scan_report,
                investigation_report,
            )

        statuses = {
            step["name"]: step["status"]
            for step in steps
        }

        self.assertEqual(
            statuses["Remediation CMake Configure"], "passed"
        )
        self.assertEqual(
            statuses["Remediation CMake Build"], "passed"
        )
        self.assertEqual(
            statuses["Remediation C/C++ Tests"], "passed"
        )
        self.assertEqual(
            statuses["Remediation Python Tests"], "passed"
        )
        self.assertEqual(
            statuses["Post-remediation Security Rescan"], "passed"
        )

        self.assertGreater(len(result["applied_changes"]), 0)
        self.assertIsNotNone(result["post_remediation_scan"])

        remaining_findings = result["post_remediation_findings"]

        print("\nPOST-REMEDIATION SECURITY FINDINGS")
        print("=" * 60)

        for finding in remaining_findings:
            print(f"Rule           : {finding['rule_id']}")
            print(f"Severity       : {finding['severity']}")
            print(f"File           : {finding['file']}")
            print(f"Line           : {finding['line']}")
            print(f"Recommendation : {finding.get('recommendation', 'Not provided')}")
            print("-" * 60)

        print("\nREMEDIATION SUMMARY")
        print("=" * 60)
        print("Initial findings:", result["summary"]["original_findings"])
        print("Resolved findings:", result["summary"]["resolved_findings"])
        print("Unresolved findings:", result["summary"]["unresolved_findings"])
        print("New findings:", result["summary"]["new_findings"])
        print("Remaining scan findings:", len(remaining_findings))
        print("Remediation status:", result["status"])

        self.assertEqual(
            result["post_remediation_scan"]["total_findings"],
            len(remaining_findings),
        )
        summary = result["summary"]
        post_scan = result["post_remediation_scan"]

        # Validate finding accounting.
        self.assertEqual(summary["original_findings"], len(findings))
        self.assertEqual(
            summary["resolved_findings"] + summary["unresolved_findings"],
            summary["original_findings"],
        )
        self.assertEqual(summary["new_findings"], 0)

        # The post-scan contains unresolved original findings plus new findings.
        self.assertEqual(
            post_scan["total_findings"],
            len(remaining_findings),
        )
        self.assertEqual(
            len(remaining_findings),
            summary["unresolved_findings"] + summary["new_findings"],
        )

        self.assertGreater(summary["resolved_findings"], 0)
        self.assertGreater(len(remaining_findings), 0)
        self.assertEqual(result["status"], "partially_verified")


        self.assertTrue(result["original_source_unchanged"])
        self.assertEqual(
            original_hashes,
            orchestrator.source_file_hashes(scan_target),
        )

        self.assertTrue(
            result["working_copy"]["removed_after_verification"]
        )
        self.assertFalse(
            Path(result["working_copy"]["path"]).exists()
        )

        print("\nREAL BUILD VERIFICATION RESULTS")
        for name, status in statuses.items():
            print(f"{name}: {status}")
        print(f"Remediation status: {result['status']}")


if __name__ == "__main__":
    unittest.main()
