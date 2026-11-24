import json
import tempfile
import unittest
from pathlib import Path

from devsecops.agent.remediation_planner import (
    apply_approved_plan,
    build_plan,
    safe_source_path,
)


class RemediationPlannerTests(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "demo.py").write_text(
            'API_KEY = "demo_secret"\n'
            'def calculate(expression):\n'
            '    return eval(expression)\n'
            'def run(command):\n'
            '    return subprocess.run(command, shell=True)\n',
            encoding="utf-8",
        )

        self.findings = [
            {
                "rule_id": "HARDCODED_SECRET",
                "severity": "high",
                "file": "demo.py",
                "line": 1,
                "description": "Hardcoded secret",
                "evidence": "[REDACTED_SECRET]",
            },
            {
                "rule_id": "PY_EVAL",
                "severity": "high",
                "file": "demo.py",
                "line": 3,
                "description": "Unsafe eval",
                "evidence": "eval(expression)",
            },
            {
                "rule_id": "PY_SUBPROCESS_SHELL",
                "severity": "high",
                "file": "demo.py",
                "line": 5,
                "description": "Shell execution",
                "evidence": "shell=True",
            },
        ]

        self.investigations = []
        for finding in self.findings:
            self.investigations.append({
                "rule_id": finding["rule_id"],
                "severity": finding["severity"],
                "location": {
                    "file": finding["file"],
                    "line": finding["line"],
                },
                "explanation": "Test explanation",
                "potential_impact": "Test impact",
                "recommended_remediation": "Test recommendation",
            })

        self.scan = {
            "report_type": "devsecops_security_scan",
            "summary": {"total_findings": 3},
            "findings": self.findings,
        }

        self.investigation = {
            "report_type": "devsecops_security_investigation",
            "summary": {"total_investigated": 3},
            "investigations": self.investigations,
        }

    def tearDown(self):
        self.temp.cleanup()

    def test_generates_proposal_for_each_finding(self):
        plan, patch = build_plan(
            self.scan, self.investigation, self.root
        )
        self.assertEqual(plan["proposals_generated"], 3)
        self.assertEqual(plan["human_review_required"], 3)

    def test_generates_patch_preview(self):
        plan, patch = build_plan(
            self.scan, self.investigation, self.root
        )
        self.assertIn("ast", patch)
        self.assertNotIn("shell=False", patch)
        self.assertIn("shell=True", patch)
        self.assertIn("literal_eval", patch)

    def test_multiline_c_patch_has_valid_diff_lines(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            c_source = (
                "#include <string.h>\n"
                "void copy_user_input(const char *input) {\n"
                "    char buffer[16];\n"
                "    strcpy(buffer, input);\n"
                "}\n"
            )
            source_path = root / "demo.c"
            source_path.write_text(c_source, encoding="utf-8")

            findings = [{
                "rule_id": "C_UNSAFE_STRCPY",
                "severity": "high",
                "file": "demo.c",
                "line": 4,
                "description": "Unsafe string copy",
                "evidence": "strcpy(buffer, input)",
            }]

            investigations = [{
                "rule_id": "C_UNSAFE_STRCPY",
                "severity": "high",
                "location": {"file": "demo.c", "line": 4},
                "explanation": "Test explanation",
                "potential_impact": "Test impact",
                "recommended_remediation": "Use a bounded copy",
            }]

            scan = {
                "report_type": "devsecops_security_scan",
                "summary": {"total_findings": 1},
                "findings": findings,
            }

            investigation = {
                "report_type": "devsecops_security_investigation",
                "summary": {"total_investigated": 1},
                "investigations": investigations,
            }

            original = source_path.read_text(encoding="utf-8")
            plan, patch = build_plan(scan, investigation, root)

            added_lines = [
                line for line in patch.splitlines()
                if line.startswith("+") and not line.startswith("+++")
            ]

            self.assertEqual(plan["patches_generated"], 1)
            self.assertIn(
                "+    if (strlen(input) >= sizeof(buffer)) { return; }",
                added_lines,
            )
            self.assertIn(
                "+    memcpy(buffer, input, strlen(input) + 1);",
                added_lines,
            )
            self.assertNotIn(r"\n", patch)
            self.assertEqual(
                source_path.read_text(encoding="utf-8"),
                original,
            )

    def test_never_modifies_source(self):
        source = (self.root / "demo.py").read_text(encoding="utf-8")
        build_plan(self.scan, self.investigation, self.root)
        self.assertEqual(
            (self.root / "demo.py").read_text(encoding="utf-8"),
            source,
        )

    def test_application_requires_approval_and_records_changes(self):
        source_path = self.root / "demo.py"
        original = source_path.read_bytes()

        with self.assertRaises(PermissionError):
            apply_approved_plan(
                self.scan,
                self.investigation,
                self.root,
            )
        self.assertEqual(source_path.read_bytes(), original)

        result = apply_approved_plan(
            self.scan,
            self.investigation,
            self.root,
            approved=True,
        )

        updated = source_path.read_text(encoding="utf-8")
        self.assertNotIn("return eval(expression)", updated)
        self.assertIn("shell=True", updated)
        self.assertTrue(result["source_modified"])
        self.assertEqual(result["patches_applied"], 2)
        self.assertEqual(len(result["applied_changes"]), 1)
        self.assertNotEqual(
            result["applied_changes"][0]["before_sha256"],
            result["applied_changes"][0]["after_sha256"],
        )

    def test_all_proposals_require_review(self):
        plan, _ = build_plan(
            self.scan, self.investigation, self.root
        )
        self.assertTrue(
            all(p["requires_human_review"] for p in plan["proposals"])
        )

    def test_rejects_inconsistent_finding_count(self):
        self.scan["summary"]["total_findings"] = 99
        with self.assertRaises(ValueError):
            build_plan(self.scan, self.investigation, self.root)

    def test_rejects_missing_investigation(self):
        self.investigation["investigations"].pop()
        self.investigation["summary"]["total_investigated"] = 2
        with self.assertRaises(ValueError):
            build_plan(self.scan, self.investigation, self.root)

    def test_rejects_path_traversal(self):
        with self.assertRaises(ValueError):
            safe_source_path(self.root, "../outside.py")


if __name__ == "__main__":
    unittest.main()
