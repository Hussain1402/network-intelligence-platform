import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

try:
    from .remediation_planner import apply_approved_plan
except ImportError:
    from remediation_planner import apply_approved_plan


def run_step(name, command, project_root, timeout=600):
    print(f"\n{'=' * 65}")
    print(f"Running: {name}")
    print(f"Command: {' '.join(command)}")
    print("=" * 65)

    start_time = time.perf_counter()

    try:
        result = subprocess.run(
            command,
            cwd=project_root,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )

        duration = round(time.perf_counter() - start_time, 3)

        step_result = {
            "name": name,
            "command": command,
            "status": "passed" if result.returncode == 0 else "failed",
            "return_code": result.returncode,
            "duration_seconds": duration,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }

    except subprocess.TimeoutExpired as error:
        duration = round(time.perf_counter() - start_time, 3)
        step_result = {
            "name": name,
            "command": command,
            "status": "timed_out",
            "return_code": None,
            "duration_seconds": duration,
            "stdout": error.stdout or "",
            "stderr": error.stderr or "",
        }

    except OSError as error:
        duration = round(time.perf_counter() - start_time, 3)
        step_result = {
            "name": name,
            "command": command,
            "status": "error",
            "return_code": None,
            "duration_seconds": duration,
            "stdout": "",
            "stderr": str(error),
        }

    print(f"Status: {step_result['status']}")
    print(f"Duration: {step_result['duration_seconds']} seconds")

    if step_result["stdout"]:
        print(step_result["stdout"])

    if step_result["stderr"]:
        print(step_result["stderr"])

    return step_result


def skipped_step(name, reason):
    return {
        "name": name,
        "command": [],
        "status": "skipped",
        "return_code": None,
        "duration_seconds": 0,
        "stdout": "",
        "stderr": reason,
    }


def failed_step(name, error):
    return {
        "name": name,
        "command": [],
        "status": "failed",
        "return_code": None,
        "duration_seconds": 0,
        "stdout": "",
        "stderr": str(error),
    }


def load_security_summary(project_root, scanner_step):
    report_path = (
        project_root
        / "devsecops"
        / "reports"
        / "security_scan_report.json"
    )

    if scanner_step["status"] != "passed":
        return {
            "execution_status": scanner_step["status"],
            "security_status": "unavailable",
            "report_path": str(report_path),
            "error": "Security scanner did not complete successfully.",
        }

    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))

        if report.get("report_type") != "devsecops_security_scan":
            raise ValueError("Unexpected security scanner report type.")

        summary = report["summary"]

        required_fields = {
            "scanned_files",
            "total_findings",
            "severity_counts",
            "scan_errors",
        }

        if not required_fields.issubset(summary):
            raise ValueError("Security report summary is incomplete.")

        if type(summary["total_findings"]) is not int:
            raise ValueError("Invalid total_findings value.")

        if type(summary["scan_errors"]) is not int:
            raise ValueError("Invalid scan_errors value.")

        if summary["scan_errors"] != 0:
            raise ValueError("Security scanner reported scan errors.")

        return {
            "execution_status": "passed",
            "security_status": (
                "findings_detected"
                if summary["total_findings"] > 0
                else "no_findings"
            ),
            "scanned_files": summary["scanned_files"],
            "total_findings": summary["total_findings"],
            "severity_counts": summary["severity_counts"],
            "scan_errors": summary["scan_errors"],
            "report_path": str(report_path),
        }

    except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as error:
        return {
            "execution_status": "invalid_report",
            "security_status": "unavailable",
            "report_path": str(report_path),
            "error": str(error),
        }


def load_policy_summary(project_root, policy_step):
    report_path = (
        project_root
        / "devsecops"
        / "reports"
        / "security_policy_report.json"
    )

    if policy_step["status"] != "passed":
        return {
            "execution_status": policy_step["status"],
            "decision": "unavailable",
            "report_path": str(report_path),
            "error": "Security policy engine did not complete successfully.",
        }

    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))

        if report.get("report_type") != "devsecops_security_policy":
            raise ValueError("Unexpected security policy report type.")

        summary = report["summary"]

        required_fields = {
            "total_findings",
            "severity_counts",
            "blocked_findings",
            "warnings",
            "informational",
            "overall_decision",
        }

        if not required_fields.issubset(summary):
            raise ValueError("Security policy summary is incomplete.")

        decision = summary["overall_decision"]

        if decision not in {
            "blocked",
            "passed_with_warnings",
            "passed",
        }:
            raise ValueError(f"Unsupported policy decision: {decision}")

        if not isinstance(summary["total_findings"], int):
            raise ValueError("Invalid policy total_findings value.")

        if not isinstance(summary["blocked_findings"], int):
            raise ValueError("Invalid blocked_findings value.")

        return {
            "execution_status": "passed",
            "decision": decision,
            "policy_mode": report.get("policy_mode"),
            "total_findings": summary["total_findings"],
            "severity_counts": summary["severity_counts"],
            "blocked_findings": summary["blocked_findings"],
            "warnings": summary["warnings"],
            "informational": summary["informational"],
            "report_path": str(report_path),
        }

    except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as error:
        return {
            "execution_status": "invalid_report",
            "decision": "unavailable",
            "report_path": str(report_path),
            "error": str(error),
        }



def load_investigation_summary(project_root, investigation_step, expected_findings):
    report_path = (
        project_root
        / "devsecops"
        / "reports"
        / "security_investigation_report.json"
    )

    if investigation_step["status"] != "passed":
        return {
            "execution_status": investigation_step["status"],
            "total_investigated": 0,
            "report_path": str(report_path),
            "error": "Security investigator did not complete successfully.",
        }

    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))

        if report.get("report_type") != "devsecops_security_investigation":
            raise ValueError("Unexpected security investigation report type.")

        summary = report.get("summary")
        investigations = report.get("investigations")

        if not isinstance(summary, dict):
            raise ValueError("Investigation summary is missing or invalid.")

        if not isinstance(investigations, list):
            raise ValueError("Investigation findings list is missing or invalid.")

        total = summary.get("total_investigated")

        if not isinstance(total, int) or isinstance(total, bool):
            raise ValueError("Invalid total_investigated value.")

        if total != len(investigations):
            raise ValueError("Investigation count does not match its findings.")

        if total != expected_findings:
            raise ValueError(
                "Investigation count does not match the current security scan."
            )

        if summary.get("human_review_required") != total:
            raise ValueError("Human review count does not match investigated findings.")

        return {
            "execution_status": "passed",
            "total_investigated": total,
            "severity_counts": summary.get("severity_counts", {}),
            "human_review_required": summary["human_review_required"],
            "report_path": str(report_path),
        }

    except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as error:
        return {
            "execution_status": "invalid_report",
            "total_investigated": 0,
            "report_path": str(report_path),
            "error": str(error),
        }



def load_remediation_summary(project_root, remediation_step, expected_findings):
    report_path = (
        project_root / "devsecops" / "reports" / "remediation_plan.json"
    )
    patch_path = (
        project_root / "devsecops" / "reports" / "remediation_preview.patch"
    )

    if remediation_step["status"] != "passed":
        return {
            "execution_status": remediation_step["status"],
            "report_path": str(report_path),
            "patch_path": str(patch_path),
            "error": "Remediation planner did not complete successfully.",
        }

    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))

        if report.get("report_type") != "devsecops_remediation_plan":
            raise ValueError("Unexpected remediation plan report type.")

        if report.get("mode") != "preview_only":
            raise ValueError("Remediation plan is not preview-only.")

        if report.get("source_modified") is not False:
            raise ValueError("Remediation planner must not modify source files.")

        proposals = report.get("proposals")
        if not isinstance(proposals, list):
            raise ValueError("Remediation proposals are missing or invalid.")

        findings = report.get("source_findings")
        generated = report.get("proposals_generated")
        review_required = report.get("human_review_required")
        patches = report.get("patches_generated")

        for name, value in [
            ("source_findings", findings),
            ("proposals_generated", generated),
            ("human_review_required", review_required),
            ("patches_generated", patches),
        ]:
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValueError(f"Invalid {name} value.")

        if findings != expected_findings:
            raise ValueError(
                "Remediation plan does not match the current security scan."
            )

        if generated != findings or len(proposals) != findings:
            raise ValueError("Not every security finding has a remediation proposal.")

        if review_required != generated:
            raise ValueError("Every remediation proposal must require human review.")

        if any(
            proposal.get("requires_human_review") is not True
            or proposal.get("status") != "preview_only"
            for proposal in proposals
        ):
            raise ValueError("A proposal does not satisfy the human-review policy.")

        if not patch_path.is_file():
            raise ValueError("Remediation patch preview was not generated.")

        return {
            "execution_status": "passed",
            "mode": report["mode"],
            "source_findings": findings,
            "proposals_generated": generated,
            "patches_generated": patches,
            "human_review_required": review_required,
            "source_modified": False,
            "report_path": str(report_path),
            "patch_path": str(patch_path),
        }

    except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as error:
        return {
            "execution_status": "invalid_report",
            "report_path": str(report_path),
            "patch_path": str(patch_path),
            "error": str(error),
        }


def write_pipeline_report(project_root, report):
    report_directory = project_root / "devsecops" / "reports"
    report_directory.mkdir(parents=True, exist_ok=True)

    report_path = report_directory / "pipeline_report.json"
    temporary_path = report_path.with_suffix(".json.tmp")

    temporary_path.write_text(
        json.dumps(report, indent=4),
        encoding="utf-8",
    )
    temporary_path.replace(report_path)

    return report_path


def cmake_configure_command(project_root, reference_root=None):
    command = ["cmake", "-S", ".", "-B", "build"]
    cache_path = (
        (reference_root or project_root) / "build" / "CMakeCache.txt"
    )

    if not cache_path.is_file():
        return command

    settings = {}
    for line in cache_path.read_text(encoding="utf-8", errors="replace").splitlines():
        for key in (
            "CMAKE_GENERATOR",
            "CMAKE_C_COMPILER",
            "CMAKE_CXX_COMPILER",
        ):
            prefix = f"{key}:"
            if line.startswith(prefix) and "=" in line:
                settings[key] = line.split("=", 1)[1]

    if settings.get("CMAKE_GENERATOR"):
        command.extend(["-G", settings["CMAKE_GENERATOR"]])
    for key in ("CMAKE_C_COMPILER", "CMAKE_CXX_COMPILER"):
        compiler = settings.get(key)
        if compiler and Path(compiler).is_file():
            command.append(f"-D{key}={compiler}")

    return command


def source_file_hashes(scan_root):
    supported_extensions = {".c", ".h", ".cpp", ".hpp", ".py"}
    excluded_directories = {
        ".git", ".venv", "build", "__pycache__", "legacy"
    }
    hashes = {}

    for path in sorted(scan_root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in supported_extensions:
            continue
        relative = path.relative_to(scan_root)
        if any(part in excluded_directories for part in relative.parts[:-1]):
            continue
        hashes[relative.as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()

    return hashes


def controlled_project_copy(project_root, workspace):
    excluded = shutil.ignore_patterns(
        ".git",
        ".venv",
        "build",
        "__pycache__",
        "*.pyc",
        "network-intelligence-platform-audit.zip",
    )
    destination = workspace / "project"
    shutil.copytree(project_root, destination, ignore=excluded)
    return destination


def compare_findings(before_findings, after_findings):
    def key_for(finding):
        return (
            finding.get("rule_id"),
            finding.get("file"),
            finding.get("evidence", ""),
        )

    before = Counter(key_for(item) for item in before_findings)
    after = Counter(key_for(item) for item in after_findings)
    comparisons = []

    for key, original_count in sorted(before.items()):
        remaining_count = after[key]
        comparisons.append({
            "rule_id": key[0],
            "file": key[1],
            "original_evidence": key[2],
            "original_count": original_count,
            "remaining_count": remaining_count,
            "resolved_count": max(0, original_count - remaining_count),
            "status": "resolved" if remaining_count == 0 else "unresolved",
        })

    newly_detected = [
        {
            "rule_id": key[0],
            "file": key[1],
            "evidence": key[2],
            "count": count - before[key],
        }
        for key, count in sorted(after.items())
        if count > before[key]
    ]

    return comparisons, newly_detected


def verify_approved_remediation(
    project_root,
    scan_target,
    scan_report,
    investigation_report,
):
    original_hashes = source_file_hashes(scan_target)
    verification_steps = []
    applied_changes = []
    post_scan = None
    workspace_path = None

    with tempfile.TemporaryDirectory(prefix="nip-remediation-") as directory:
        workspace = Path(directory)
        workspace_path = str(workspace)
        project_copy = controlled_project_copy(project_root, workspace)

        try:
            relative_target = scan_target.relative_to(project_root)
            work_target = project_copy / relative_target
            if not work_target.is_dir():
                raise ValueError(
                    "The scan target is not present in the controlled project copy."
                )
        except ValueError as error:
            if scan_target.is_relative_to(project_root):
                raise
            work_target = workspace / "scan-target"
            shutil.copytree(scan_target, work_target)

        application = apply_approved_plan(
            scan_report,
            investigation_report,
            work_target,
            approved=True,
        )
        applied_changes = application["applied_changes"]

        configure = run_step(
            "Remediation CMake Configure",
            cmake_configure_command(project_copy, project_root),
            project_copy,
        )
        verification_steps.append(configure)

        if configure["status"] == "passed":
            build = run_step(
                "Remediation CMake Build",
                ["cmake", "--build", "build"],
                project_copy,
            )
        else:
            build = skipped_step(
                "Remediation CMake Build",
                "Skipped because CMake configuration failed.",
            )
        verification_steps.append(build)

        if build["status"] == "passed":
            c_tests = run_step(
                "Remediation C/C++ Tests",
                ["ctest", "--test-dir", "build", "--output-on-failure"],
                project_copy,
            )
        else:
            c_tests = skipped_step(
                "Remediation C/C++ Tests",
                "Skipped because the controlled-copy build did not pass.",
            )
        verification_steps.append(c_tests)

        python_tests = run_step(
            "Remediation Python Tests",
            [
                sys.executable,
                "-m",
                "unittest",
                "discover",
                "-s",
                "tests/python",
                "-p",
                "test_*.py",
                "-v",
            ],
            project_copy,
        )
        verification_steps.append(python_tests)

        post_scan_path = (
            project_copy
            / "devsecops"
            / "reports"
            / "post_remediation_scan_report.json"
        )
        rescan = run_step(
            "Post-remediation Security Rescan",
            [
                sys.executable,
                "devsecops/agent/security_scanner.py",
                "--target",
                str(work_target),
                "--output",
                str(post_scan_path),
            ],
            project_copy,
        )
        verification_steps.append(rescan)

        if rescan["status"] == "passed":
            try:
                post_scan = json.loads(
                    post_scan_path.read_text(encoding="utf-8")
                )
                if (
                    post_scan.get("report_type") != "devsecops_security_scan"
                    or not isinstance(post_scan.get("findings"), list)
                    or post_scan.get("summary", {}).get("scan_errors") != 0
                    or post_scan.get("summary", {}).get("total_findings")
                    != len(post_scan["findings"])
                ):
                    raise ValueError("Post-remediation scan report is invalid.")
            except (OSError, json.JSONDecodeError, TypeError, ValueError) as error:
                rescan["status"] = "failed"
                rescan["stderr"] += f"\nPost-remediation report validation failed: {error}"
                post_scan = None

    final_hashes = source_file_hashes(scan_target)
    source_unchanged = original_hashes == final_hashes
    if not source_unchanged:
        verification_steps.append(
            failed_step(
                "Original Source Integrity",
                "Source files changed during controlled-copy remediation.",
            )
        )

    if post_scan is None:
        comparisons = []
        newly_detected = []
        unresolved = len(scan_report.get("findings", []))
        post_scan_summary = None
    else:
        comparisons, newly_detected = compare_findings(
            scan_report.get("findings", []),
            post_scan["findings"],
        )
        unresolved = sum(
            item["remaining_count"] for item in comparisons
        )
        post_scan_summary = post_scan["summary"]

    failed_steps = [
        step for step in verification_steps
        if step["status"] in {"failed", "timed_out", "error", "skipped"}
    ]

    if failed_steps:
        status = "failed"
    elif unresolved or newly_detected:
        status = "partially_verified"
    else:
        status = "verified"

    return {
        "execution_status": "failed" if failed_steps else "passed",
        "status": status,
        "human_approval": "explicit_cli_approval",
        "working_copy": {
            "path": workspace_path,
            "temporary": True,
            "removed_after_verification": True,
        },
        "original_source_unchanged": source_unchanged,
        "applied_changes": applied_changes,
        "post_remediation_scan": post_scan_summary,
        "post_remediation_findings": (
            post_scan["findings"] if post_scan is not None else []
        ),
        "original_finding_verification": comparisons,
        "newly_detected_findings": newly_detected,
        "summary": {
            "original_findings": len(scan_report.get("findings", [])),
            "resolved_findings": sum(
                item["resolved_count"] for item in comparisons
            ),
            "unresolved_findings": unresolved,
            "new_findings": sum(item["count"] for item in newly_detected),
        },
        "verification_steps": [
            {
                "name": step["name"],
                "status": step["status"],
                "return_code": step["return_code"],
            }
            for step in verification_steps
        ],
        "limitations": [
            "Only deterministic previewed replacements were applied.",
            "Manual remediation proposals remain unapplied.",
            "A finding is marked resolved only when absent from the post-remediation scan.",
            "Rule-based rescanning is not a substitute for manual security review.",
        ],
    }, verification_steps


def run_pipeline(
    project_root,
    profile="balanced",
    scan_target=None,
    approve_remediation=False,
):
    results = []

    configure = run_step(
        "CMake Configure",
        cmake_configure_command(project_root),
        project_root,
    )
    results.append(configure)

    if configure["status"] == "passed":
        build = run_step(
            "CMake Build",
            ["cmake", "--build", "build"],
            project_root,
        )
    else:
        build = skipped_step(
            "CMake Build",
            "Skipped because CMake configuration failed.",
        )
    results.append(build)

    if build["status"] == "passed":
        c_tests = run_step(
            "C/C++ Unit Tests",
            ["ctest", "--test-dir", "build", "--output-on-failure"],
            project_root,
        )
    else:
        c_tests = skipped_step(
            "C/C++ Unit Tests",
            "Skipped because the current build did not pass.",
        )
    results.append(c_tests)

    python_tests = run_step(
        "Python Unit Tests",
        [
            sys.executable,
            "-m",
            "unittest",
            "discover",
            "-s",
            "tests/python",
            "-p",
            "test_*.py",
            "-v",
        ],
        project_root,
    )
    results.append(python_tests)

    scanner_command = [
        sys.executable,
        "devsecops/agent/security_scanner.py",
    ]
    if scan_target is not None:
        scanner_command.extend(["--target", str(scan_target)])
    scanner_step = run_step("Security Scan", scanner_command, project_root)
    results.append(scanner_step)

    security = load_security_summary(project_root, scanner_step)

    # A scanner report validation error is an execution failure.
    if security["execution_status"] == "invalid_report":
        scanner_step["status"] = "failed"
        scanner_step["stderr"] += (
            "\nSecurity report validation failed: "
            + security["error"]
        )

    policy = {
        "execution_status": "skipped",
        "decision": "unavailable",
        "error": "Policy evaluation was not run.",
    }

    # Never evaluate a stale report if this run's scanner did not succeed.
    if security["execution_status"] == "passed":
        policy_command = [
            sys.executable,
            "devsecops/agent/policy_engine.py",
            "--profile",
            profile,
        ]

        policy_step = run_step(
            "Security Policy Evaluation",
            policy_command,
            project_root,
        )
        results.append(policy_step)

        policy = load_policy_summary(project_root, policy_step)

        if policy["execution_status"] == "invalid_report":
            policy_step["status"] = "failed"
            policy_step["stderr"] += (
                "\nSecurity policy report validation failed: "
                + policy["error"]
            )

    else:
        results.append(
            skipped_step(
                "Security Policy Evaluation",
                "Skipped because the current security scan was unsuccessful "
                "or its report was invalid.",
            )
        )

    investigation = {
        "execution_status": "skipped",
        "total_investigated": 0,
        "error": "Investigation was not run.",
    }

    # Investigation is allowed even when policy blocks delivery.
    # It must use the current successful scan, never a stale report.
    if security["execution_status"] == "passed":
        investigation_command = [
            sys.executable,
            "devsecops/agent/security_investigator.py",
        ]

        investigation_step = run_step(
            "Security Investigation",
            investigation_command,
            project_root,
        )
        results.append(investigation_step)

        investigation = load_investigation_summary(
            project_root,
            investigation_step,
            security["total_findings"],
        )

        if investigation["execution_status"] == "invalid_report":
            investigation_step["status"] = "failed"
            investigation_step["stderr"] += (
                "\\nSecurity investigation report validation failed: "
                + investigation["error"]
            )
    else:
        results.append(
            skipped_step(
                "Security Investigation",
                "Skipped because the current security scan was unsuccessful "
                "or its report was invalid.",
            )
        )


    remediation = {
        "execution_status": "skipped",
        "proposals_generated": 0,
        "error": "Remediation planning was not run.",
    }

    # Plan remediations only from the current validated scan and investigation.
    if (
        security["execution_status"] == "passed"
        and investigation["execution_status"] == "passed"
    ):
        effective_scan_target = (
            scan_target
            if scan_target is not None
            else project_root / "devsecops" / "fixtures" / "vulnerable_app"
        )

        remediation_command = [
            sys.executable,
            "devsecops/agent/remediation_planner.py",
            "--target",
            str(effective_scan_target),
            "--scan-report",
            str(project_root / "devsecops/reports/security_scan_report.json"),
            "--investigation-report",
            str(project_root / "devsecops/reports/security_investigation_report.json"),
            "--output",
            str(project_root / "devsecops/reports/remediation_plan.json"),
            "--patch",
            str(project_root / "devsecops/reports/remediation_preview.patch"),
        ]

        remediation_step = run_step(
            "Security Remediation Planning",
            remediation_command,
            project_root,
        )
        results.append(remediation_step)

        remediation = load_remediation_summary(
            project_root,
            remediation_step,
            security["total_findings"],
        )

        if remediation["execution_status"] == "invalid_report":
            remediation_step["status"] = "failed"
            remediation_step["stderr"] += (
                "\nRemediation plan validation failed: "
                + remediation["error"]
            )

        if remediation["execution_status"] == "passed":
            if policy["decision"] == "blocked":
                remediation["verification"] = {
                    "execution_status": "not_run",
                    "status": "blocked_by_policy",
                    "human_approval": "not_applied_policy_block",
                    "original_source_unchanged": True,
                    "applied_changes": [],
                    "message": (
                        "Remediation application was prevented because "
                        "the security policy blocked delivery."
                    ),
                }
            elif approve_remediation:
                try:
                    verification, verification_steps = (
                        verify_approved_remediation(
                            project_root,
                            Path(effective_scan_target).resolve(),
                            json.loads(
                                (
                                    project_root
                                    / "devsecops/reports/security_scan_report.json"
                                ).read_text(encoding="utf-8")
                            ),
                            json.loads(
                                (
                                    project_root
                                    / "devsecops/reports/security_investigation_report.json"
                                ).read_text(encoding="utf-8")
                            ),
                        )
                    )
                    remediation["verification"] = verification
                    results.extend(verification_steps)
                except (OSError, json.JSONDecodeError, TypeError, ValueError) as error:
                    remediation["verification"] = {
                        "execution_status": "failed",
                        "status": "failed",
                        "human_approval": "explicit_cli_approval",
                        "original_source_unchanged": None,
                        "error": str(error),
                    }
                    results.append(
                        failed_step("Remediation Verification", error)
                    )
            else:
                remediation["verification"] = {
                    "execution_status": "not_run",
                    "status": "awaiting_explicit_approval",
                    "human_approval": "not_granted",
                    "original_source_unchanged": True,
                    "applied_changes": [],
                    "message": (
                        "Patch previews were generated but not applied. "
                        "Pass --approve-remediation to test them in a temporary copy."
                    ),
                }
    else:
        results.append(
            skipped_step(
                "Security Remediation Planning",
                "Skipped because the current security scan or investigation "
                "was unsuccessful or its report was invalid.",
            )
        )


    execution_failures = [
        step for step in results
        if step["status"] in {"failed", "timed_out", "error"}
    ]

    if execution_failures:
        overall_status = "failed"
    elif policy["execution_status"] != "passed":
        overall_status = "failed"
    elif policy["decision"] == "blocked":
        overall_status = "blocked"
    elif (
        remediation.get("verification", {}).get("execution_status") == "failed"
    ):
        overall_status = "failed"
    elif remediation.get("verification", {}).get("status") == "partially_verified":
        overall_status = "partially_verified"
    else:
        overall_status = "passed"

    passed = sum(step["status"] == "passed" for step in results)
    failed = sum(
        step["status"] in {"failed", "timed_out", "error"}
        for step in results
    )
    skipped = sum(step["status"] == "skipped" for step in results)

    report = {
        "report_type": "devsecops_ci_pipeline",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "project_root": str(project_root),
        "overall_status": overall_status,
        "execution_status": (
            "passed" if not execution_failures else "failed"
        ),
        "security_policy": {
            "mode": profile,
            "description": (
                "Security findings are evaluated using the selected "
                "configurable policy profile."
            ),
        },
        "security": security,
        "policy": policy,
        "investigation": investigation,
        "remediation": remediation,
        "summary": {
            "total_steps": len(results),
            "passed": passed,
            "failed": failed,
            "skipped": skipped,
        },
        "steps": results,
    }

    report_path = write_pipeline_report(project_root, report)

    print("\n" + "=" * 65)
    print("DEVSECOPS PIPELINE SUMMARY")
    print("=" * 65)
    print(f"Overall status       : {overall_status}")
    print(f"Execution status     : {report['execution_status']}")
    print(f"Passed steps         : {passed}")
    print(f"Failed steps         : {failed}")
    print(f"Skipped steps        : {skipped}")
    print(f"Security status      : {security['security_status']}")
    print(f"Security findings    : {security.get('total_findings', 'unavailable')}")
    print(f"Policy execution     : {policy['execution_status']}")
    print(f"Policy decision      : {policy['decision']}")
    print(
        "Investigated findings: "
        f"{investigation.get('total_investigated', 'unavailable')}"
    )
    print(f"Investigation status : {investigation['execution_status']}")
    print(f"Remediation status   : {remediation['execution_status']}")
    print(f"Proposals generated  : {remediation.get('proposals_generated', 'unavailable')}")
    print(f"Patch previews       : {remediation.get('patches_generated', 'unavailable')}")
    print(f"Pipeline report      : {report_path}")

    # A policy block is a rejected delivery, not a tool execution error.
    return 1 if overall_status != "passed" else 0


def main():
    parser = argparse.ArgumentParser(
        description="Local DevSecOps CI pipeline orchestrator."
    )
    parser.add_argument(
        "--project-root",
        type=Path,
        default=Path(__file__).resolve().parents[2],
        help="Path to the network-intelligence-platform root directory.",
    )

    parser.add_argument(
        "--profile",
        choices=["strict", "balanced", "report_only"],
        default="balanced",
        help="Security policy profile.",
    )
    parser.add_argument(
        "--scan-target",
        type=Path,
        default=None,
        help="Directory to scan. Defaults to the vulnerable demonstration fixture.",
    )
    parser.add_argument(
        "--approve-remediation",
        action="store_true",
        help=(
            "Approve generated patches for application only in a temporary "
            "controlled copy, followed by build, tests, and rescan."
        ),
    )

    args = parser.parse_args()
    project_root = args.project_root.resolve()

    scan_target = None
    if args.scan_target is not None:
        scan_target = args.scan_target
        if not scan_target.is_absolute():
            scan_target = project_root / scan_target
        scan_target = scan_target.resolve()

        if not scan_target.is_dir():
            print(f"Error: scan target is not a directory: {scan_target}")
            return 2

    if not (project_root / "CMakeLists.txt").is_file():
        print("Error: CMakeLists.txt was not found in the project root.")
        return 2

    return run_pipeline(
        project_root,
        args.profile,
        scan_target,
        approve_remediation=args.approve_remediation,
    )


if __name__ == "__main__":
    raise SystemExit(main())
