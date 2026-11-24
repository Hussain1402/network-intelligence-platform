import argparse
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path


RULE_KNOWLEDGE = {
    "HARDCODED_SECRET": {
        "title": "Hardcoded credential exposure",
        "explanation": (
            "A credential or secret appears to be embedded directly in source code. "
            "Anyone with access to the source or its history may be able to retrieve it."
        ),
        "impact": (
            "An exposed credential could allow unauthorized access to services, "
            "databases, or other protected resources if it is genuine and still valid."
        ),
        "root_cause": (
            "Sensitive configuration appears to have been stored directly in "
            "application source instead of being supplied through a secure mechanism."
        ),
        "remediation": (
            "Load secrets from environment variables or a managed secret store. "
            "Rotate any genuine exposed credential and remove it from repository history "
            "where appropriate."
        ),
        "verification": [
            "Confirm that no credential is embedded in source code.",
            "Confirm that the application obtains secrets from a secure configuration source.",
            "Run the secret scanner again."
        ]
    },
    "C_UNSAFE_STRCPY": {
        "title": "Potential C buffer overflow",
        "explanation": (
            "strcpy copies a source string without checking whether the destination "
            "buffer has sufficient capacity."
        ),
        "impact": (
            "An oversized input may overwrite adjacent memory, potentially causing "
            "a crash, memory corruption, or exploitable behaviour."
        ),
        "root_cause": (
            "The copy operation does not enforce a destination buffer size limit."
        ),
        "remediation": (
            "Use a bounded copy strategy, explicitly validate input length, "
            "and ensure that the destination is correctly null-terminated. "
            "Consider redesigning the function to receive the destination capacity."
        ),
        "verification": [
            "Test empty, normal, maximum-length, and oversized inputs.",
            "Verify that the destination buffer is never overrun.",
            "Run the C/C++ unit tests and security scanner again."
        ]
    },
    "C_UNSAFE_SPRINTF": {
        "title": "Potential C formatted-output buffer overflow",
        "explanation": (
            "sprintf writes formatted output without knowing the destination buffer capacity."
        ),
        "impact": (
            "Output exceeding the destination capacity may corrupt memory or crash "
            "the application."
        ),
        "root_cause": (
            "The formatting operation does not enforce a maximum output size."
        ),
        "remediation": (
            "Use snprintf with the actual destination buffer size and check its return "
            "value to detect truncation or formatting errors."
        ),
        "verification": [
            "Test output that fits and output that exceeds the destination capacity.",
            "Check the snprintf return value and truncation handling.",
            "Run the C/C++ unit tests and security scanner again."
        ]
    },
    "C_SYSTEM_CALL": {
        "title": "Shell command execution",
        "explanation": (
            "system() passes a command string to a system shell. If untrusted data "
            "reaches that string, shell metacharacters may change the executed command."
        ),
        "impact": (
            "Unsafe command construction can potentially lead to command injection "
            "and execution of unintended commands."
        ),
        "root_cause": (
            "The application invokes a shell through system() instead of using a "
            "more controlled process-execution interface."
        ),
        "remediation": (
            "Avoid shell execution where possible. Use a process API that accepts "
            "separate arguments, validate inputs, and avoid constructing commands "
            "by concatenating untrusted strings."
        ),
        "verification": [
            "Check whether shell execution can be eliminated.",
            "Test inputs containing shell metacharacters.",
            "Verify that only intended executable arguments can be passed."
        ]
    },
    "PY_EVAL": {
        "title": "Dynamic expression evaluation",
        "explanation": (
            "Python eval evaluates a string as a Python expression. Evaluating "
            "untrusted input can execute unintended code."
        ),
        "impact": (
            "An attacker may be able to execute code with the application's "
            "permissions if untrusted expressions reach eval."
        ),
        "root_cause": (
            "The application uses a general-purpose expression evaluator instead "
            "of validating and parsing the expected input format."
        ),
        "remediation": (
            "Avoid eval for untrusted input. Use a strict parser for the expected "
            "data format or implement an explicit allowlist of supported operations."
        ),
        "verification": [
            "Test valid and invalid input formats.",
            "Confirm that arbitrary Python expressions are not executed.",
            "Run the Python unit tests and security scanner again."
        ]
    },
    "PY_SUBPROCESS_SHELL": {
        "title": "Python subprocess shell execution",
        "explanation": (
            "subprocess is configured with shell=True. This sends a command through "
            "a shell and can create command-injection risk when input is untrusted."
        ),
        "impact": (
            "Untrusted command input may alter the executed shell command and "
            "cause unintended operations."
        ),
        "root_cause": (
            "The process invocation uses shell interpretation instead of passing "
            "the executable and its arguments separately."
        ),
        "remediation": (
            "Prefer subprocess.run with an argument list and shell=False. "
            "Validate arguments and use a fixed executable where possible."
        ),
        "verification": [
            "Verify that commands are passed as separate arguments.",
            "Test inputs containing shell metacharacters.",
            "Confirm that shell=True is not required."
        ]
    }
}


def validate_scan_report(report):
    if not isinstance(report, dict):
        raise ValueError("Security scan report must be a JSON object.")

    if report.get("report_type") != "devsecops_security_scan":
        raise ValueError("Unexpected security scan report type.")

    summary = report.get("summary")
    findings = report.get("findings")

    if not isinstance(summary, dict):
        raise ValueError("Missing or invalid summary.")

    if not isinstance(findings, list):
        raise ValueError("Missing or invalid findings list.")

    if not isinstance(report.get("scan_errors"), list):
        raise ValueError("Missing or invalid scan_errors list.")

    if summary.get("total_findings") != len(findings):
        raise ValueError("Finding count does not match the summary.")

    for index, finding in enumerate(findings):
        if not isinstance(finding, dict):
            raise ValueError(f"Finding {index} must be an object.")

        for field in ("rule_id", "severity", "file", "line", "description"):
            if field not in finding:
                raise ValueError(
                    f"Finding {index} is missing required field: {field}"
                )

        if finding["severity"] not in ("critical", "high", "medium", "low"):
            raise ValueError(f"Finding {index} has an invalid severity.")

        if not isinstance(finding["line"], int) or finding["line"] < 1:
            raise ValueError(f"Finding {index} has an invalid line number.")

    return report


def investigate_finding(finding):
    rule_id = finding["rule_id"]
    knowledge = RULE_KNOWLEDGE.get(rule_id)

    if knowledge is None:
        knowledge = {
            "title": "Unclassified security finding",
            "explanation": (
                "The scanner detected a pattern that requires further investigation. "
                "No rule-specific analysis is available."
            ),
            "impact": (
                "The potential impact cannot be determined from the available "
                "rule information alone."
            ),
            "root_cause": (
                "The underlying cause has not been established. Manual code review "
                "is required."
            ),
            "remediation": (
                "Review the affected source code and scanner recommendation. "
                "Do not apply an automatic fix without validating the context."
            ),
            "verification": [
                "Review the affected source code manually.",
                "Determine whether the finding is a true positive.",
                "Run appropriate tests and repeat the security scan."
            ]
        }

    return {
        "rule_id": rule_id,
        "title": knowledge["title"],
        "severity": finding["severity"],
        "location": {
            "file": finding["file"],
            "line": finding["line"]
        },
        "scanner_description": finding["description"],
        "evidence": finding.get("evidence", "[NOT PROVIDED]"),
        "explanation": knowledge["explanation"],
        "potential_impact": knowledge["impact"],
        "likely_root_cause": knowledge["root_cause"],
        "recommended_remediation": knowledge["remediation"],
        "verification_steps": knowledge["verification"],
        "confidence": "rule_based",
        "requires_human_review": True
    }


def build_investigation_report(scan_report):
    validate_scan_report(scan_report)

    investigations = [
        investigate_finding(finding)
        for finding in scan_report["findings"]
    ]

    severity_counts = {
        severity: sum(
            1 for item in investigations if item["severity"] == severity
        )
        for severity in ("critical", "high", "medium", "low")
    }

    return {
        "report_type": "devsecops_security_investigation",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "investigator": "deterministic_mock_security_investigator",
        "source_report": "devsecops_security_scan",
        "summary": {
            "total_investigated": len(investigations),
            "severity_counts": severity_counts,
            "human_review_required": len(investigations)
        },
        "investigations": investigations,
        "limitations": [
            "This is a deterministic rule-based investigator, not a trained AI model.",
            "Root causes are inferred from scanner rules and require manual confirmation.",
            "The investigator does not inspect the full application context.",
            "No source files are modified.",
            "Remediation suggestions must be reviewed and tested by a human."
        ]
    }


def atomic_write_json(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            suffix=".tmp",
            delete=False
        ) as temporary_file:
            temporary_path = Path(temporary_file.name)
            json.dump(data, temporary_file, indent=4)
            temporary_file.write("\n")

        os.replace(temporary_path, path)

    finally:
        if temporary_path and temporary_path.exists():
            temporary_path.unlink()


def main():
    parser = argparse.ArgumentParser(
        description="Generate a security investigation report."
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=Path("devsecops/reports/security_scan_report.json")
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("devsecops/reports/security_investigation_report.json")
    )
    args = parser.parse_args()

    try:
        with args.input.open("r", encoding="utf-8-sig") as file:
            scan_report = json.load(file)

        investigation_report = build_investigation_report(scan_report)
        atomic_write_json(args.output, investigation_report)

    except (OSError, json.JSONDecodeError, ValueError) as error:
        parser.exit(1, f"Investigation failed: {error}\n")

    summary = investigation_report["summary"]
    print("\nDEVSECOPS SECURITY INVESTIGATION")
    print("--------------------------------")
    print(f"Findings investigated : {summary['total_investigated']}")
    print(f"Human review required : {summary['human_review_required']}")
    print(f"Report                : {args.output.resolve()}")


if __name__ == "__main__":
    main()
