import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path


SECRET_PATTERNS = [
    (
    "HARDCODED_SECRET",
    re.compile(
        r"""(?i)\b[A-Za-z0-9_]*"""
        r"""(?:api[_-]?key|secret|password|passwd|token)"""
        r"""[A-Za-z0-9_]*\b\s*(?:[:=]\s*)?"""
        r"""["'][^"'\s]{8,}["']"""
    ),
    "Potential hardcoded credential or secret.",
    "high",
    ),
    (
        "PRIVATE_KEY",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        "Private key material found in source.",
        "critical",
    ),
    (
        "AWS_ACCESS_KEY",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "Possible AWS access key identifier.",
        "critical",
    ),
]

CODE_RULES = {
    ".c": [
        ("C_UNSAFE_STRCPY", re.compile(r"\bstrcpy\s*\("), "Potentially unsafe strcpy usage.", "high"),
        ("C_UNSAFE_SPRINTF", re.compile(r"\bsprintf\s*\("), "Potentially unsafe sprintf usage.", "high"),
        ("C_UNSAFE_GETS", re.compile(r"\bgets\s*\("), "Unsafe gets usage.", "critical"),
        ("C_SYSTEM_CALL", re.compile(r"\bsystem\s*\("), "Shell command execution through system(). Review input handling.", "medium"),
    ],
    ".h": [
        ("C_UNSAFE_STRCPY", re.compile(r"\bstrcpy\s*\("), "Potentially unsafe strcpy usage.", "high"),
        ("C_UNSAFE_SPRINTF", re.compile(r"\bsprintf\s*\("), "Potentially unsafe sprintf usage.", "high"),
        ("C_UNSAFE_GETS", re.compile(r"\bgets\s*\("), "Unsafe gets usage.", "critical"),
        ("C_SYSTEM_CALL", re.compile(r"\bsystem\s*\("), "Shell command execution through system(). Review input handling.", "medium"),
    ],
    ".cpp": [
        ("CPP_UNSAFE_STRCPY", re.compile(r"\bstrcpy\s*\("), "Potentially unsafe strcpy usage.", "high"),
        ("CPP_UNSAFE_SPRINTF", re.compile(r"\bsprintf\s*\("), "Potentially unsafe sprintf usage.", "high"),
        ("CPP_SYSTEM_CALL", re.compile(r"\bsystem\s*\("), "Shell command execution through system(). Review input handling.", "medium"),
    ],
    ".hpp": [
        ("CPP_UNSAFE_STRCPY", re.compile(r"\bstrcpy\s*\("), "Potentially unsafe strcpy usage.", "high"),
        ("CPP_UNSAFE_SPRINTF", re.compile(r"\bsprintf\s*\("), "Potentially unsafe sprintf usage.", "high"),
        ("CPP_SYSTEM_CALL", re.compile(r"\bsystem\s*\("), "Shell command execution through system(). Review input handling.", "medium"),
    ],
    ".py": [
        ("PY_EVAL", re.compile(r"\beval\s*\("), "Dynamic evaluation can execute untrusted expressions.", "high"),
        ("PY_EXEC", re.compile(r"\bexec\s*\("), "Dynamic code execution can execute untrusted code.", "high"),
        ("PY_SUBPROCESS_SHELL", re.compile(r"\bshell\s*=\s*True\b"), "Subprocess shell execution requires careful input validation.", "high"),
        ("PY_PICKLE", re.compile(r"\bpickle\.loads\s*\("), "Unpickling untrusted data can execute arbitrary code.", "critical"),
    ],
}

EXCLUDED_DIRECTORIES = {
    ".git",
    ".venv",
    "build",
    "__pycache__",
    "legacy",
}

RECOMMENDATIONS = {
    "HARDCODED_SECRET": "Move credentials to environment variables or a managed secret store; rotate any real exposed credential.",
    "PRIVATE_KEY": "Remove private key material from source control and rotate the exposed key.",
    "AWS_ACCESS_KEY": "Remove the key from source control and rotate it through the cloud provider.",
    "C_UNSAFE_STRCPY": "Use a bounded alternative and validate destination capacity.",
    "C_UNSAFE_SPRINTF": "Use snprintf with an explicit destination size and check truncation.",
    "C_UNSAFE_GETS": "Replace gets with a bounded input function.",
    "C_SYSTEM_CALL": "Avoid shell invocation where possible; use a safe process API and validate arguments.",
    "CPP_UNSAFE_STRCPY": "Use a bounded alternative and validate destination capacity.",
    "CPP_UNSAFE_SPRINTF": "Use snprintf with an explicit destination size and check truncation.",
    "CPP_SYSTEM_CALL": "Avoid shell invocation where possible; use a safe process API and validate arguments.",
    "PY_EVAL": "Avoid eval on untrusted input; parse the expected data format instead.",
    "PY_EXEC": "Avoid dynamic execution of untrusted input.",
    "PY_SUBPROCESS_SHELL": "Prefer argument lists with shell=False and validate each argument.",
    "PY_PICKLE": "Do not unpickle untrusted data; use a safer serialization format.",
}


def redact_evidence(line, pattern):
    """Avoid copying the full credential value into the report."""
    return pattern.sub("[REDACTED_SECRET]", line.strip())


def scan_file(file_path, scan_root):
    findings = []

    try:
        content = file_path.read_text(encoding="utf-8-sig", errors="replace")
    except OSError as error:
        return findings, str(error)

    extension = file_path.suffix.lower()
    relative_path = file_path.relative_to(scan_root).as_posix()

    for line_number, line in enumerate(content.splitlines(), start=1):
        for rule_id, pattern, description, severity in SECRET_PATTERNS:
            match = pattern.search(line)
            if match:
                findings.append({
                    "rule_id": rule_id,
                    "category": "secrets",
                    "severity": severity,
                    "file": relative_path,
                    "line": line_number,
                    "description": description,
                    "evidence": redact_evidence(line, pattern),
                    "recommendation": RECOMMENDATIONS[rule_id],
                })

        for rule_id, pattern, description, severity in CODE_RULES.get(extension, []):
            if pattern.search(line):
                findings.append({
                    "rule_id": rule_id,
                    "category": "static_code",
                    "severity": severity,
                    "file": relative_path,
                    "line": line_number,
                    "description": description,
                    "evidence": line.strip()[:240],
                    "recommendation": RECOMMENDATIONS[rule_id],
                })

    return findings, None


def scan_directory(scan_root):
    supported_extensions = {".c", ".h", ".cpp", ".hpp", ".py"}
    findings = []
    scan_errors = []
    scanned_files = 0

    for file_path in sorted(scan_root.rglob("*")):
        if not file_path.is_file() or file_path.suffix.lower() not in supported_extensions:
            continue
        relative_parts = file_path.relative_to(scan_root).parts[:-1]
        if any(part in EXCLUDED_DIRECTORIES for part in relative_parts):
            continue

        scanned_files += 1
        file_findings, error = scan_file(file_path, scan_root)
        findings.extend(file_findings)

        if error:
            scan_errors.append({
                "file": file_path.relative_to(scan_root).as_posix(),
                "error": error,
            })

    severity_counts = {
        severity: sum(item["severity"] == severity for item in findings)
        for severity in ("critical", "high", "medium", "low")
    }

    return {
        "report_type": "devsecops_security_scan",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scan_root": str(scan_root),
        "scanner": "local_rule_based_scanner",
        "limitations": [
            "This is a basic pattern-based scanner, not a complete security audit.",
            "Findings may include false positives and require manual review.",
            "Dependency vulnerability analysis is not included yet.",
            "No files are modified by this scanner.",
        ],
        "summary": {
            "scanned_files": scanned_files,
            "total_findings": len(findings),
            "severity_counts": severity_counts,
            "scan_errors": len(scan_errors),
        },
        "findings": findings,
        "scan_errors": scan_errors,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Local DevSecOps secret and static-code scanner."
    )
    parser.add_argument(
        "--target",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "fixtures" / "vulnerable_app",
        help="Directory to scan. Defaults to the controlled vulnerable fixture.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "reports" / "security_scan_report.json",
        help="Path for the JSON security report.",
    )

    args = parser.parse_args()
    scan_root = args.target.resolve()
    output_path = args.output.resolve()

    if not scan_root.is_dir():
        print(f"Error: scan target is not a directory: {scan_root}")
        return 2

    report = scan_directory(scan_root)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = output_path.with_suffix(output_path.suffix + ".tmp")
    temporary_path.write_text(json.dumps(report, indent=4), encoding="utf-8")
    temporary_path.replace(output_path)

    print("\nDEVSECOPS SECURITY SCAN")
    print(f"Target          : {scan_root}")
    print(f"Files scanned   : {report['summary']['scanned_files']}")
    print(f"Total findings  : {report['summary']['total_findings']}")
    print(f"Severity counts : {report['summary']['severity_counts']}")
    print(f"Report          : {output_path}")

    return 1 if report["summary"]["scan_errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
