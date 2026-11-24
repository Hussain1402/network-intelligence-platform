import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from devsecops.agent import orchestrator
from devsecops.agent.security_scanner import scan_directory


class DevSecOpsIntegrationTests(unittest.TestCase):

    def test_approved_remediation_runs_in_copy_and_rescans(self):
        repository_root = Path(__file__).resolve().parents[2]
        fixture_source = (
            repository_root
            / "devsecops"
            / "fixtures"
            / "vulnerable_app"
        )

        with tempfile.TemporaryDirectory() as directory:
            project_root = Path(directory)
            scan_target = (
                project_root
                / "devsecops"
                / "fixtures"
                / "vulnerable_app"
            )
            scan_target.parent.mkdir(parents=True)

            shutil.copytree(fixture_source, scan_target)

            scanner_destination = (
                project_root / "devsecops" / "agent"
                / "security_scanner.py"
            )
            scanner_destination.parent.mkdir(parents=True)
            shutil.copy2(
                repository_root
                / "devsecops"
                / "agent"
                / "security_scanner.py",
                scanner_destination,
            )

            original_files = {
                path.relative_to(scan_target): path.read_bytes()
                for path in scan_target.rglob("*")
                if path.is_file()
            }

            scan_report = scan_directory(scan_target)

            findings = scan_report["findings"]
            self.assertGreater(len(findings), 0)

            investigations = []
            for finding in findings:
                investigations.append({
                    "rule_id": finding["rule_id"],
                    "severity": finding["severity"],
                    "location": {
                        "file": finding["file"],
                        "line": finding["line"],
                    },
                    "explanation": "Integration test investigation.",
                    "potential_impact": "Potential security exposure.",
                    "recommended_remediation": finding["recommendation"],
                })

            investigation_report = {
                "report_type": "devsecops_security_investigation",
                "summary": {
                    "total_investigated": len(investigations),
                },
                "investigations": investigations,
            }

            def fake_run_step(
                name, command, working_root, timeout=600
            ):
                if name == "Post-remediation Security Rescan":
                    try:
                        completed = subprocess.run(
                            command,
                            cwd=working_root,
                            capture_output=True,
                            text=True,
                            timeout=timeout,
                            check=False,
                        )
                        status = (
                            "passed"
                            if completed.returncode == 0
                            else "failed"
                        )
                        return {
                            "name": name,
                            "command": command,
                            "status": status,
                            "return_code": completed.returncode,
                            "duration_seconds": 0,
                            "stdout": completed.stdout,
                            "stderr": completed.stderr,
                        }
                    except subprocess.TimeoutExpired:
                        return {
                            "name": name,
                            "command": command,
                            "status": "timed_out",
                            "return_code": None,
                            "duration_seconds": timeout,
                            "stdout": "",
                            "stderr": "Rescan timed out.",
                        }

                return {
                    "name": name,
                    "command": command,
                    "status": "passed",
                    "return_code": 0,
                    "duration_seconds": 0,
                    "stdout": "Simulated successful verification.",
                    "stderr": "",
                }

            with (
                patch.object(
                    orchestrator,
                    "run_step",
                    side_effect=fake_run_step,
                ),
                patch.object(
                    orchestrator,
                    "cmake_configure_command",
                    return_value=["cmake", "-S", ".", "-B", "build"],
                ),
            ):
                result, steps = (
                    orchestrator.verify_approved_remediation(
                        project_root,
                        scan_target,
                        scan_report,
                        investigation_report,
                    )
                )

            # The real source fixture must remain unchanged.
            final_files = {
                path.relative_to(scan_target): path.read_bytes()
                for path in scan_target.rglob("*")
                if path.is_file()
            }
            self.assertEqual(original_files, final_files)
            self.assertTrue(result["original_source_unchanged"])

            # The temporary verification copy must be removed.
            self.assertTrue(result["working_copy"]["temporary"])
            self.assertTrue(
                result["working_copy"]["removed_after_verification"]
            )
            self.assertFalse(
                Path(result["working_copy"]["path"]).exists()
            )

            # Real remediation and real post-remediation scanning occurred.
            self.assertGreater(len(result["applied_changes"]), 0)
            self.assertIsNotNone(result["post_remediation_scan"])

            step_statuses = {
                step["name"]: step["status"]
                for step in steps
            }
            self.assertEqual(
                step_statuses["Remediation CMake Configure"],
                "passed",
            )
            self.assertEqual(
                step_statuses["Remediation CMake Build"],
                "passed",
            )
            self.assertEqual(
                step_statuses["Remediation C/C++ Tests"],
                "passed",
            )
            self.assertEqual(
                step_statuses["Remediation Python Tests"],
                "passed",
            )
            self.assertEqual(
                step_statuses["Post-remediation Security Rescan"],
                "passed",
            )

            # Some supported findings should be resolved.
            self.assertGreater(
                result["summary"]["resolved_findings"],
                0,
            )

            # Manual-review findings should remain unresolved.
            self.assertGreater(
                result["summary"]["unresolved_findings"],
                0,
            )
            self.assertEqual(result["status"], "partially_verified")
            self.assertEqual(result["execution_status"], "passed")


if __name__ == "__main__":
    unittest.main()
