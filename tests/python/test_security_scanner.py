import json
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from devsecops.agent.security_scanner import scan_directory


def write_vulnerable_fixture(root):
    (root / "demo.c").write_text(
        '#include <stdio.h>\n'
        '#include <string.h>\n'
        '#include <stdlib.h>\n'
        '#define API_TOKEN "DEMO_SECRET_TOKEN_123456789"\n'
        'void copy_user_input(const char *input) {\n'
        '    char buffer[16];\n'
        '    strcpy(buffer, input);\n'
        '}\n'
        'int main(void) {\n'
        '    char command[128];\n'
        '    sprintf(command, "echo %s", "demo");\n'
        '    system(command);\n'
        '    return 0;\n'
        '}\n',
        encoding="utf-8",
    )
    (root / "demo.py").write_text(
        'API_KEY = "DEMO_API_KEY_123456789"\n'
        'DATABASE_PASSWORD = "demo_password_12345"\n'
        'def calculate(expression):\n'
        '    return eval(expression)\n'
        'def run_command(command):\n'
        '    import subprocess\n'
        '    return subprocess.run(command, shell=True)\n',
        encoding="utf-8",
    )


class TestSecurityScanner(unittest.TestCase):

    def test_detects_expected_fixture_findings(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            write_vulnerable_fixture(Path(temp_dir))
            report = scan_directory(Path(temp_dir))

            self.assertEqual(report["summary"]["scanned_files"], 2)
            self.assertEqual(report["summary"]["total_findings"], 8)
            self.assertEqual(report["summary"]["scan_errors"], 0)

            rule_ids = {item["rule_id"] for item in report["findings"]}

            expected_rules = {
                "HARDCODED_SECRET",
                "C_UNSAFE_STRCPY",
                "C_UNSAFE_SPRINTF",
                "C_SYSTEM_CALL",
                "PY_EVAL",
                "PY_SUBPROCESS_SHELL",
            }

            self.assertTrue(expected_rules.issubset(rule_ids))

            secret_findings = [
                item for item in report["findings"]
                if item["rule_id"] == "HARDCODED_SECRET"
            ]
            self.assertEqual(len(secret_findings), 3)

    def test_does_not_flag_clean_code(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)

            (root / "clean.py").write_text(
                'username = "demo-user"\n'
                'def add(a, b):\n'
                '    return a + b\n',
                encoding="utf-8",
            )

            (root / "clean.c").write_text(
                '#include <stdio.h>\n'
                'int main(void) {\n'
                '    printf("Hello world");\n'
                '    return 0;\n'
                '}\n',
                encoding="utf-8",
            )

            report = scan_directory(root)

            self.assertEqual(report["summary"]["scanned_files"], 2)
            self.assertEqual(report["summary"]["total_findings"], 0)

    def test_ignores_build_virtualenv_cache_and_legacy_sources(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            for directory in ("build", ".venv", "__pycache__", "legacy"):
                nested = root / directory
                nested.mkdir()
                (nested / "ignored.py").write_text(
                    "eval(user_input)\n",
                    encoding="utf-8",
                )

            report = scan_directory(root)

            self.assertEqual(report["summary"]["scanned_files"], 0)
            self.assertEqual(report["summary"]["total_findings"], 0)

    def test_secret_values_are_redacted(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            write_vulnerable_fixture(Path(temp_dir))
            report = scan_directory(Path(temp_dir))
            serialized_report = json.dumps(report)

            self.assertNotIn("DEMO_SECRET_TOKEN_123456789", serialized_report)
            self.assertNotIn("DEMO_API_KEY_123456789", serialized_report)
            self.assertNotIn("demo_password_12345", serialized_report)


if __name__ == "__main__":
    unittest.main()
