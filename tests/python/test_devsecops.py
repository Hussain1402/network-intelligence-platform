import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from devsecops.agent import orchestrator


class DevSecOpsOrchestratorTests(unittest.TestCase):

    def test_build_failure_skips_build_and_cpp_tests_and_fails_pipeline(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "devsecops" / "reports").mkdir(parents=True)
            calls = []

            def fake_run_step(name, command, project_root, timeout=600):
                calls.append(name)
                status = "failed" if name in {
                    "CMake Configure",
                    "Security Scan",
                } else "passed"
                return {
                    "name": name,
                    "command": command,
                    "status": status,
                    "return_code": 1 if status == "failed" else 0,
                    "duration_seconds": 0,
                    "stdout": "",
                    "stderr": "simulated failure" if status == "failed" else "",
                }

            with patch.object(orchestrator, "run_step", side_effect=fake_run_step):
                result = orchestrator.run_pipeline(root)

            self.assertEqual(result, 1)
            self.assertNotIn("CMake Build", calls)
            self.assertNotIn("C/C++ Unit Tests", calls)

            report_path = root / "devsecops" / "reports" / "pipeline_report.json"
            report = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertEqual(report["overall_status"], "failed")
            self.assertEqual(report["execution_status"], "failed")
            self.assertTrue(
                any(
                    step["name"] == "C/C++ Unit Tests"
                    and step["status"] == "skipped"
                    for step in report["steps"]
                )
            )

    def test_finding_comparison_does_not_mark_remaining_rule_as_resolved(self):
        before = [{
            "rule_id": "PY_EVAL",
            "file": "app.py",
            "evidence": "eval(value)",
        }]
        after = [dict(before[0])]

        comparisons, new_findings = orchestrator.compare_findings(before, after)

        self.assertEqual(comparisons[0]["status"], "unresolved")
        self.assertEqual(comparisons[0]["resolved_count"], 0)
        self.assertEqual(new_findings, [])

    def test_blocked_policy_prevents_approved_remediation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "devsecops" / "reports").mkdir(parents=True)

            def fake_run_step(name, command, project_root, timeout=600):
                return {
                    "name": name,
                    "command": command,
                    "status": "passed",
                    "return_code": 0,
                    "duration_seconds": 0,
                    "stdout": "",
                    "stderr": "",
                }

            with (
                patch.object(orchestrator, "run_step", side_effect=fake_run_step),
                patch.object(
                    orchestrator,
                    "load_security_summary",
                    return_value={
                        "execution_status": "passed",
                        "security_status": "findings_detected",
                        "total_findings": 2,
                    },
                ),
                patch.object(
                    orchestrator,
                    "load_policy_summary",
                    return_value={
                        "execution_status": "passed",
                        "decision": "blocked",
                    },
                ),
                patch.object(
                    orchestrator,
                    "load_investigation_summary",
                    return_value={
                        "execution_status": "passed",
                        "total_investigated": 2,
                    },
                ),
                patch.object(
                    orchestrator,
                    "load_remediation_summary",
                    return_value={
                        "execution_status": "passed",
                        "proposals_generated": 2,
                    },
                ),
                patch.object(
                    orchestrator,
                    "verify_approved_remediation",
                ) as verify,
            ):
                result = orchestrator.run_pipeline(
                    root,
                    approve_remediation=True,
                )

            report_path = (
                root / "devsecops" / "reports" / "pipeline_report.json"
            )
            report = json.loads(report_path.read_text(encoding="utf-8"))

            self.assertEqual(result, 1)
            self.assertEqual(report["overall_status"], "blocked")
            self.assertEqual(report["investigation"]["execution_status"], "passed")
            self.assertEqual(report["remediation"]["execution_status"], "passed")
            self.assertEqual(
                report["remediation"]["verification"]["status"],
                "blocked_by_policy",
            )
            verify.assert_not_called()

    def test_partial_verification_is_reported_when_policy_allows_delivery(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "devsecops" / "reports").mkdir(parents=True)
            reports_dir = root / 'devsecops' / 'reports'

            (reports_dir / 'security_scan_report.json').write_text(
                json.dumps({'report_type': 'devsecops_security_scan'}),
                encoding='utf-8',
            )

            (reports_dir / 'security_investigation_report.json').write_text(
                json.dumps({'report_type': 'devsecops_security_investigation'}),
                encoding='utf-8',
            )

            def fake_run_step(name, command, project_root, timeout=600):
                return {
                    "name": name,
                    "command": command,
                    "status": "passed",
                    "return_code": 0,
                    "duration_seconds": 0,
                    "stdout": "",
                    "stderr": "",
                }

            with (
                patch.object(orchestrator, "run_step", side_effect=fake_run_step),
                patch.object(
                    orchestrator,
                    "load_security_summary",
                    return_value={
                        "execution_status": "passed",
                        "security_status": "findings_detected",
                        "total_findings": 1,
                    },
                ),
                patch.object(
                    orchestrator,
                    "load_policy_summary",
                    return_value={
                        "execution_status": "passed",
                        "decision": "passed",
                    },
                ),
                patch.object(
                    orchestrator,
                    "load_investigation_summary",
                    return_value={
                        "execution_status": "passed",
                        "total_investigated": 1,
                    },
                ),
                patch.object(
                    orchestrator,
                    "load_remediation_summary",
                    return_value={
                        "execution_status": "passed",
                        "proposals_generated": 1,
                    },
                ),
                patch.object(
                    orchestrator,
                    "verify_approved_remediation",
                    return_value=(
                        {
                            "execution_status": "passed",
                            "status": "partially_verified",
                        },
                        [],
                    ),
                ),
            ):
                result = orchestrator.run_pipeline(
                    root,
                    approve_remediation=True,
                )

            report = json.loads(
                (
                    root / "devsecops" / "reports" / "pipeline_report.json"
                ).read_text(encoding="utf-8")
            )

            self.assertEqual(result, 1)
            self.assertEqual(report["overall_status"], "partially_verified")


    def test_successful_pipeline_waits_for_explicit_remediation_approval(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "devsecops" / "reports").mkdir(parents=True)

            def fake_run_step(name, command, project_root, timeout=600):
                return {
                    "name": name,
                    "command": command,
                    "status": "passed",
                    "return_code": 0,
                    "duration_seconds": 0,
                    "stdout": "",
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
                    "load_security_summary",
                    return_value={
                        "execution_status": "passed",
                        "security_status": "findings_detected",
                        "total_findings": 1,
                    },
                ),
                patch.object(
                    orchestrator,
                    "load_policy_summary",
                    return_value={
                        "execution_status": "passed",
                        "decision": "passed",
                    },
                ),
                patch.object(
                    orchestrator,
                    "load_investigation_summary",
                    return_value={
                        "execution_status": "passed",
                        "total_investigated": 1,
                    },
                ),
                patch.object(
                    orchestrator,
                    "load_remediation_summary",
                    return_value={
                        "execution_status": "passed",
                        "proposals_generated": 1,
                    },
                ),
                patch.object(
                    orchestrator,
                    "verify_approved_remediation",
                ) as verify,
            ):
                result = orchestrator.run_pipeline(root)

            report_path = (
                root / "devsecops" / "reports" / "pipeline_report.json"
            )
            self.assertTrue(report_path.exists())

            report = json.loads(
                report_path.read_text(encoding="utf-8")
            )

            self.assertEqual(result, 0)
            self.assertEqual(report["overall_status"], "passed")
            self.assertEqual(report["execution_status"], "passed")
            self.assertEqual(report["policy"]["decision"], "passed")
            self.assertEqual(
                report["remediation"]["execution_status"],
                "passed",
            )
            self.assertEqual(
                report["remediation"]["verification"]["status"],
                "awaiting_explicit_approval",
            )
            self.assertEqual(
                report["remediation"]["verification"]["execution_status"],
                "not_run",
            )
            self.assertEqual(
                report["remediation"]["verification"]["human_approval"],
                "not_granted",
            )
            self.assertTrue(
                all(step["status"] == "passed" for step in report["steps"])
            )
            verify.assert_not_called()



    def test_security_scan_failure_skips_all_downstream_security_stages(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "devsecops" / "reports").mkdir(parents=True)

            executed_steps = []

            def fake_run_step(name, command, project_root, timeout=600):
                executed_steps.append(name)

                status = "failed" if name == "Security Scan" else "passed"

                return {
                    "name": name,
                    "command": command,
                    "status": status,
                    "return_code": 1 if status == "failed" else 0,
                    "duration_seconds": 0,
                    "stdout": "",
                    "stderr": (
                        "Simulated security scanner failure."
                        if status == "failed"
                        else ""
                    ),
                }

            with (
                patch.object(
                    orchestrator,
                    "run_step",
                    side_effect=fake_run_step,
                ),
                patch.object(
                    orchestrator,
                    "load_policy_summary",
                ) as load_policy,
                patch.object(
                    orchestrator,
                    "load_investigation_summary",
                ) as load_investigation,
                patch.object(
                    orchestrator,
                    "load_remediation_summary",
                ) as load_remediation,
                patch.object(
                    orchestrator,
                    "verify_approved_remediation",
                ) as verify,
            ):
                result = orchestrator.run_pipeline(
                    root,
                    approve_remediation=True,
                )

            report_path = (
                root / "devsecops" / "reports" / "pipeline_report.json"
            )
            self.assertTrue(report_path.exists())

            report = json.loads(
                report_path.read_text(encoding="utf-8")
            )

            self.assertEqual(result, 1)
            self.assertEqual(report["overall_status"], "failed")
            self.assertEqual(report["execution_status"], "failed")
            self.assertEqual(
                report["security"]["execution_status"],
                "failed",
            )
            self.assertEqual(
                report["policy"]["execution_status"],
                "skipped",
            )
            self.assertEqual(
                report["investigation"]["execution_status"],
                "skipped",
            )
            self.assertEqual(
                report["remediation"]["execution_status"],
                "skipped",
            )

            self.assertIn("Security Scan", executed_steps)
            self.assertNotIn("Security Policy Evaluation", executed_steps)
            self.assertNotIn("Security Investigation", executed_steps)
            self.assertNotIn("Security Remediation Planning", executed_steps)

            load_policy.assert_not_called()
            load_investigation.assert_not_called()
            load_remediation.assert_not_called()
            verify.assert_not_called()



    def test_invalid_security_report_skips_all_downstream_security_stages(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            reports_dir = root / "devsecops" / "reports"
            reports_dir.mkdir(parents=True)

            executed_steps = []

            def fake_run_step(name, command, project_root, timeout=600):
                executed_steps.append(name)

                if name == "Security Scan":
                    (reports_dir / "security_scan_report.json").write_text(
                        json.dumps({
                            "report_type": "wrong_report_type",
                            "summary": {},
                        }),
                        encoding="utf-8",
                    )

                return {
                    "name": name,
                    "command": command,
                    "status": "passed",
                    "return_code": 0,
                    "duration_seconds": 0,
                    "stdout": "",
                    "stderr": "",
                }

            with (
                patch.object(orchestrator, "run_step", side_effect=fake_run_step),
                patch.object(orchestrator, "load_policy_summary") as load_policy,
                patch.object(orchestrator, "load_investigation_summary") as load_investigation,
                patch.object(orchestrator, "load_remediation_summary") as load_remediation,
                patch.object(orchestrator, "verify_approved_remediation") as verify,
            ):
                result = orchestrator.run_pipeline(
                    root,
                    approve_remediation=True,
                )

            report_path = reports_dir / "pipeline_report.json"
            self.assertTrue(report_path.exists())

            report = json.loads(report_path.read_text(encoding="utf-8"))

            self.assertEqual(result, 1)
            self.assertEqual(report["overall_status"], "failed")
            self.assertEqual(report["execution_status"], "failed")
            self.assertEqual(
                report["security"]["execution_status"],
                "invalid_report",
            )
            self.assertEqual(
                report["security"]["security_status"],
                "unavailable",
            )
            self.assertEqual(report["policy"]["execution_status"], "skipped")
            self.assertEqual(report["investigation"]["execution_status"], "skipped")
            self.assertEqual(report["remediation"]["execution_status"], "skipped")

            self.assertIn("Security Scan", executed_steps)
            self.assertNotIn("Security Policy Evaluation", executed_steps)
            self.assertNotIn("Security Investigation", executed_steps)
            self.assertNotIn("Security Remediation Planning", executed_steps)

            load_policy.assert_not_called()
            load_investigation.assert_not_called()
            load_remediation.assert_not_called()
            verify.assert_not_called()


    def test_incomplete_security_report_skips_downstream_stages(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            reports_dir = root / "devsecops" / "reports"
            reports_dir.mkdir(parents=True)

            def fake_run_step(name, command, project_root, timeout=600):
                if name == "Security Scan":
                    (reports_dir / "security_scan_report.json").write_text(
                        json.dumps({
                            "report_type": "devsecops_security_scan",
                            "summary": {
                                "scanned_files": 2,
                                "total_findings": 1,
                                "scan_errors": 0,
                            },
                        }),
                        encoding="utf-8",
                    )

                return {
                    "name": name,
                    "command": command,
                    "status": "passed",
                    "return_code": 0,
                    "duration_seconds": 0,
                    "stdout": "",
                    "stderr": "",
                }

            with (
                patch.object(orchestrator, "run_step", side_effect=fake_run_step),
                patch.object(orchestrator, "load_policy_summary") as load_policy,
                patch.object(orchestrator, "load_investigation_summary") as load_investigation,
                patch.object(orchestrator, "load_remediation_summary") as load_remediation,
                patch.object(orchestrator, "verify_approved_remediation") as verify,
            ):
                result = orchestrator.run_pipeline(
                    root,
                    approve_remediation=True,
                )

            report = json.loads(
                (reports_dir / "pipeline_report.json").read_text(encoding="utf-8")
            )

            self.assertEqual(result, 1)
            self.assertEqual(report["overall_status"], "failed")
            self.assertEqual(
                report["security"]["execution_status"],
                "invalid_report",
            )
            self.assertIn(
                "summary is incomplete",
                report["security"]["error"],
            )

            self.assertEqual(report["policy"]["execution_status"], "skipped")
            self.assertEqual(report["investigation"]["execution_status"], "skipped")
            self.assertEqual(report["remediation"]["execution_status"], "skipped")

            load_policy.assert_not_called()
            load_investigation.assert_not_called()
            load_remediation.assert_not_called()
            verify.assert_not_called()


    def test_security_report_with_scan_errors_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            reports_dir = root / "devsecops" / "reports"
            reports_dir.mkdir(parents=True)

            def fake_run_step(name, command, project_root, timeout=600):
                if name == "Security Scan":
                    (reports_dir / "security_scan_report.json").write_text(
                        json.dumps({
                            "report_type": "devsecops_security_scan",
                            "summary": {
                                "scanned_files": 2,
                                "total_findings": 1,
                                "severity_counts": {
                                    "critical": 0,
                                    "high": 1,
                                    "medium": 0,
                                    "low": 0,
                                },
                                "scan_errors": 1,
                            },
                        }),
                        encoding="utf-8",
                    )

                return {
                    "name": name,
                    "command": command,
                    "status": "passed",
                    "return_code": 0,
                    "duration_seconds": 0,
                    "stdout": "",
                    "stderr": "",
                }

            with (
                patch.object(orchestrator, "run_step", side_effect=fake_run_step),
                patch.object(orchestrator, "load_policy_summary") as load_policy,
                patch.object(orchestrator, "load_investigation_summary") as load_investigation,
                patch.object(orchestrator, "load_remediation_summary") as load_remediation,
                patch.object(orchestrator, "verify_approved_remediation") as verify,
            ):
                result = orchestrator.run_pipeline(
                    root,
                    approve_remediation=True,
                )

            report = json.loads(
                (reports_dir / "pipeline_report.json").read_text(encoding="utf-8")
            )

            self.assertEqual(result, 1)
            self.assertEqual(report["overall_status"], "failed")
            self.assertEqual(
                report["security"]["execution_status"],
                "invalid_report",
            )
            self.assertIn(
                "scan errors",
                report["security"]["error"],
            )

            self.assertEqual(report["policy"]["execution_status"], "skipped")
            self.assertEqual(report["investigation"]["execution_status"], "skipped")
            self.assertEqual(report["remediation"]["execution_status"], "skipped")

            load_policy.assert_not_called()
            load_investigation.assert_not_called()
            load_remediation.assert_not_called()
            verify.assert_not_called()
    def test_security_report_rejects_non_integer_total_findings(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            reports_dir = root / "devsecops" / "reports"
            reports_dir.mkdir(parents=True)

            def fake_run_step(name, command, project_root, timeout=600):
                if name == "Security Scan":
                    (reports_dir / "security_scan_report.json").write_text(
                        json.dumps({
                            "report_type": "devsecops_security_scan",
                            "summary": {
                                "scanned_files": 2,
                                "total_findings": "five",
                                "severity_counts": {
                                    "critical": 0,
                                    "high": 0,
                                    "medium": 0,
                                    "low": 0,
                                },
                                "scan_errors": 0,
                            },
                        }),
                        encoding="utf-8",
                    )

                return {
                    "name": name,
                    "command": command,
                    "status": "passed",
                    "return_code": 0,
                    "duration_seconds": 0,
                    "stdout": "",
                    "stderr": "",
                }

            with (
                patch.object(orchestrator, "run_step", side_effect=fake_run_step),
                patch.object(orchestrator, "load_policy_summary") as load_policy,
                patch.object(orchestrator, "load_investigation_summary") as load_investigation,
                patch.object(orchestrator, "load_remediation_summary") as load_remediation,
                patch.object(orchestrator, "verify_approved_remediation") as verify,
            ):
                result = orchestrator.run_pipeline(
                    root,
                    approve_remediation=True,
                )

            report = json.loads(
                (reports_dir / "pipeline_report.json").read_text(encoding="utf-8")
            )

            self.assertEqual(result, 1)
            self.assertEqual(report["overall_status"], "failed")
            self.assertEqual(
                report["security"]["execution_status"],
                "invalid_report",
            )
            self.assertIn(
                "Invalid total_findings value",
                report["security"]["error"],
            )

            self.assertEqual(report["policy"]["execution_status"], "skipped")
            self.assertEqual(report["investigation"]["execution_status"], "skipped")
            self.assertEqual(report["remediation"]["execution_status"], "skipped")

            load_policy.assert_not_called()
            load_investigation.assert_not_called()
            load_remediation.assert_not_called()
            verify.assert_not_called()


    def test_security_report_rejects_non_integer_scan_errors(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            reports_dir = root / "devsecops" / "reports"
            reports_dir.mkdir(parents=True)

            def fake_run_step(name, command, project_root, timeout=600):
                if name == "Security Scan":
                    (reports_dir / "security_scan_report.json").write_text(
                        json.dumps({
                            "report_type": "devsecops_security_scan",
                            "summary": {
                                "scanned_files": 2,
                                "total_findings": 0,
                                "severity_counts": {
                                    "critical": 0,
                                    "high": 0,
                                    "medium": 0,
                                    "low": 0,
                                },
                                "scan_errors": "zero",
                            },
                        }),
                        encoding="utf-8",
                    )

                return {
                    "name": name,
                    "command": command,
                    "status": "passed",
                    "return_code": 0,
                    "duration_seconds": 0,
                    "stdout": "",
                    "stderr": "",
                }

            with (
                patch.object(orchestrator, "run_step", side_effect=fake_run_step),
                patch.object(orchestrator, "load_policy_summary") as load_policy,
                patch.object(orchestrator, "load_investigation_summary") as load_investigation,
                patch.object(orchestrator, "load_remediation_summary") as load_remediation,
                patch.object(orchestrator, "verify_approved_remediation") as verify,
            ):
                result = orchestrator.run_pipeline(
                    root,
                    approve_remediation=True,
                )

            report = json.loads(
                (reports_dir / "pipeline_report.json").read_text(encoding="utf-8")
            )

            self.assertEqual(result, 1)
            self.assertEqual(report["overall_status"], "failed")
            self.assertEqual(
                report["security"]["execution_status"],
                "invalid_report",
            )
            self.assertIn(
                "Invalid scan_errors value",
                report["security"]["error"],
            )

            self.assertEqual(report["policy"]["execution_status"], "skipped")
            self.assertEqual(report["investigation"]["execution_status"], "skipped")
            self.assertEqual(report["remediation"]["execution_status"], "skipped")

            load_policy.assert_not_called()
            load_investigation.assert_not_called()
            load_remediation.assert_not_called()
            verify.assert_not_called()


    def test_security_report_rejects_boolean_total_findings(self):
        self._assert_boolean_security_count_rejected(
            total_findings=True,
            scan_errors=0,
            expected_error="Invalid total_findings value",
        )

    def test_security_report_rejects_boolean_scan_errors(self):
        self._assert_boolean_security_count_rejected(
            total_findings=0,
            scan_errors=False,
            expected_error="Invalid scan_errors value",
        )

    def _assert_boolean_security_count_rejected(
        self, total_findings, scan_errors, expected_error
    ):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            reports_dir = root / "devsecops" / "reports"
            reports_dir.mkdir(parents=True)

            def fake_run_step(name, command, project_root, timeout=600):
                if name == "Security Scan":
                    (reports_dir / "security_scan_report.json").write_text(
                        json.dumps({
                            "report_type": "devsecops_security_scan",
                            "summary": {
                                "scanned_files": 2,
                                "total_findings": total_findings,
                                "severity_counts": {
                                    "critical": 0,
                                    "high": 0,
                                    "medium": 0,
                                    "low": 0,
                                },
                                "scan_errors": scan_errors,
                            },
                        }),
                        encoding="utf-8",
                    )

                return {
                    "name": name,
                    "command": command,
                    "status": "passed",
                    "return_code": 0,
                    "duration_seconds": 0,
                    "stdout": "",
                    "stderr": "",
                }

            with (
                patch.object(orchestrator, "run_step", side_effect=fake_run_step),
                patch.object(orchestrator, "load_policy_summary") as load_policy,
                patch.object(orchestrator, "load_investigation_summary") as load_investigation,
                patch.object(orchestrator, "load_remediation_summary") as load_remediation,
                patch.object(orchestrator, "verify_approved_remediation") as verify,
            ):
                result = orchestrator.run_pipeline(
                    root,
                    approve_remediation=True,
                )

            report = json.loads(
                (reports_dir / "pipeline_report.json").read_text(encoding="utf-8")
            )

            self.assertEqual(result, 1)
            self.assertEqual(report["overall_status"], "failed")
            self.assertEqual(
                report["security"]["execution_status"],
                "invalid_report",
            )
            self.assertIn(expected_error, report["security"]["error"])

            self.assertEqual(report["policy"]["execution_status"], "skipped")
            self.assertEqual(report["investigation"]["execution_status"], "skipped")
            self.assertEqual(report["remediation"]["execution_status"], "skipped")

            load_policy.assert_not_called()
            load_investigation.assert_not_called()
            load_remediation.assert_not_called()
            verify.assert_not_called()


if __name__ == "__main__":
    unittest.main()
