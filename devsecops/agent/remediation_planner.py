import argparse
import difflib
import hashlib
import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path


RULES = {
    "HARDCODED_SECRET": {
        "title": "Move hardcoded secret to secure configuration",
        "replacement": "Replace the embedded value with an environment-variable lookup.",
        "review": "A real secret must be rotated and configured securely.",
    },
    "C_UNSAFE_STRCPY": {
        "title": "Replace unbounded string copy",
        "replacement": "Check the input length and use a bounded copy.",
        "review": "Confirm the buffer size and input contract.",
    },
    "C_UNSAFE_SPRINTF": {
        "title": "Replace unbounded string formatting",
        "replacement": "Use snprintf with the destination buffer size.",
        "review": "Check the return value and handle truncation.",
    },
    "C_SYSTEM_CALL": {
        "title": "Remove shell-based command execution",
        "replacement": "Use an explicit executable and argument list through a safer process API.",
        "review": "Review the intended command and its arguments before replacing this call.",
    },
    "PY_EVAL": {
        "title": "Replace dynamic eval",
        "replacement": "Use ast.literal_eval for literal-only input, or implement an explicit parser for supported expressions.",
        "review": "Confirm the accepted input grammar and required functionality.",
    },
    "PY_SUBPROCESS_SHELL": {
        "title": "Disable shell execution",
        "replacement": "Pass an argument list to subprocess.run and set shell=False.",
        "review": "Handle quoting and platform-specific command arguments.",
    },
}


def atomic_write(path, content):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    fd, temporary = tempfile.mkstemp(
        prefix=path.name,
        suffix=".tmp",
        dir=str(path.parent),
    )

    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            handle.write(content)
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def load_json(path, expected_type):
    with Path(path).open("r", encoding="utf-8-sig") as handle:
        data = json.load(handle)

    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a JSON object")

    if data.get("report_type") != expected_type:
        raise ValueError(f"Unexpected report type in {path}")

    return data


def safe_source_path(target_root, relative_path):
    root = Path(target_root).resolve()
    candidate = (root / relative_path).resolve()

    if candidate == root or root not in candidate.parents:
        raise ValueError(f"Source path escapes scan target: {relative_path}")

    if not candidate.is_file():
        raise ValueError(f"Source file does not exist: {relative_path}")

    return candidate


def propose_replacement(rule_id, line):
    stripped = line.strip()
    rule = RULES.get(rule_id)
    indent = line[:len(line) - len(line.lstrip())]

    if rule_id == "HARDCODED_SECRET":
        match = re.match(
            r'^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*["\\\'].*["\\\']\s*$',
            stripped,
        )

        if match:
            variable = match.group(1)
            replacement = (
                f'{indent}{variable} = __import__("os").environ.get("{variable}")\n'
                f'{indent}if not {variable}:\n'
                f'{indent}    raise RuntimeError("Required environment variable '
                f'{variable} is not set")\n'
            )
            return (
                replacement,
                "Load the secret from the environment and fail explicitly if it is missing.",
            )

        if re.match(
            r'^#define\s+[A-Za-z_][A-Za-z0-9_]*\s+["\\\'].*["\\\']\s*$',
            stripped,
        ):
            return (
                None,
                "Manual remediation: retrieve the secret at runtime and validate "
                "the returned pointer before use.",
            )

    elif rule_id == "C_UNSAFE_STRCPY" and "strcpy(" in stripped:
        return (
            indent + "if (strlen(input) >= sizeof(buffer)) { return; }\n"
            + indent + "memcpy(buffer, input, strlen(input) + 1);\n",
            "Check input length before copying. This proposal assumes the demo function's input and buffer names.",
        )

    elif (
        rule_id == "C_UNSAFE_SPRINTF"
        and stripped == 'sprintf(command, "echo %s", "demo");'
    ):
        return (
            indent
            + 'int format_result = snprintf(command, sizeof(command), "echo %s", "demo");\n'
            + indent
            + 'if (format_result < 0 || (size_t)format_result >= sizeof(command)) { return 1; }\n',
            "Check snprintf errors and truncation. This proposal is specific to the demo fixture.",
        )

    elif rule_id == "C_SYSTEM_CALL" and "system(" in stripped:
        return (
            None,
            "Manual remediation: replace system() with a platform-appropriate process API and explicit arguments.",
        )

    elif rule_id == "PY_EVAL" and "eval(" in stripped:
        return (
            line.replace("eval(", "__import__('ast').literal_eval("),
            "Use literal_eval only when the input is expected to contain Python literals.",
        )

    elif rule_id == "PY_SUBPROCESS_SHELL" and "shell=True" in stripped:
        return (
            None,
            "Manual remediation: identify the executable and construct a validated argument list; use shell=False.",
        )

    if rule:
        return None, rule["review"]

    return None, "Unknown rule. Manual remediation required."

def build_plan(scan_report, investigation_report, target_root):
    findings = scan_report.get("findings")
    investigations = investigation_report.get("investigations")

    if not isinstance(findings, list) or not isinstance(investigations, list):
        raise ValueError("Findings and investigations must be lists")

    scan_total = scan_report.get("summary", {}).get("total_findings")
    investigation_total = investigation_report.get("summary", {}).get(
        "total_investigated"
    )

    if scan_total != len(findings):
        raise ValueError("Scanner finding count is inconsistent")

    if investigation_total != len(investigations):
        raise ValueError("Investigation count is inconsistent")

    if scan_total != investigation_total:
        raise ValueError("Scanner and investigation counts do not match")

    investigation_index = {}
    for item in investigations:
        location = item.get("location", {})
        key = (
            item.get("rule_id"),
            location.get("file"),
            location.get("line"),
        )
        if key in investigation_index:
            raise ValueError(f"Duplicate investigation record: {key}")
        investigation_index[key] = item

    edits_by_file = {}
    proposals = []

    for finding in findings:
        rule_id = finding.get("rule_id")
        relative_file = finding.get("file")
        line_number = finding.get("line")

        if not isinstance(relative_file, str) or not isinstance(line_number, int):
            raise ValueError("Finding has invalid file or line information")

        key = (rule_id, relative_file, line_number)
        investigation = investigation_index.get(key)

        if investigation is None:
            raise ValueError(f"Missing investigation for finding: {key}")

        source_path = safe_source_path(target_root, relative_file)
        source_lines = source_path.read_text(encoding="utf-8-sig").splitlines(
            keepends=True
        )

        if line_number < 1 or line_number > len(source_lines):
            raise ValueError(f"Finding line is outside source file: {key}")

        original = source_lines[line_number - 1]
        replacement, replacement_note = propose_replacement(rule_id, original)

        proposal = {
            "rule_id": rule_id,
            "severity": finding.get("severity"),
            "file": relative_file,
            "line": line_number,
            "title": RULES.get(rule_id, {}).get("title", "Manual review required"),
            "investigation": investigation.get("explanation", ""),
            "potential_impact": investigation.get("potential_impact", ""),
            "recommended_remediation": investigation.get(
                "recommended_remediation", ""
            ),
            "proposed_change": replacement_note,
            "patch_generated": replacement is not None,
            "requires_human_review": True,
            "status": "preview_only",
        }

        proposals.append(proposal)

        if replacement is not None:
            edits_by_file.setdefault(relative_file, []).append(
                (line_number - 1, original, replacement)
            )

    patch_parts = []

    for relative_file, edits in sorted(edits_by_file.items()):
        source_path = safe_source_path(target_root, relative_file)
        original_lines = source_path.read_text(
            encoding="utf-8-sig"
        ).splitlines(keepends=True)

        updated_lines = list(original_lines)

        for index, original, replacement in sorted(edits, reverse=True):
            if updated_lines[index] != original:
                raise ValueError(
                    f"Source changed while planning: {relative_file}:{index + 1}"
                )
            updated_lines[index:index + 1] = replacement.splitlines(keepends=True)

        diff = difflib.unified_diff(
            original_lines,
            updated_lines,
            fromfile=f"a/{relative_file}",
            tofile=f"b/{relative_file}",
        )
        patch_parts.extend(diff)

    return {
        "report_type": "devsecops_remediation_plan",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "mode": "preview_only",
        "source_findings": len(findings),
        "proposals_generated": len(proposals),
        "patches_generated": sum(p["patch_generated"] for p in proposals),
        "human_review_required": len(proposals),
        "source_modified": False,
        "proposals": proposals,
        "limitations": [
            "Remediation proposals are deterministic rule-based suggestions.",
            "Generated diffs have not been applied to source files.",
            "Some changes require application-specific decisions.",
            "All proposals require human review and testing.",
        ],
    }, "".join(patch_parts)


def apply_approved_plan(
    scan_report,
    investigation_report,
    target_root,
    approved=False,
):
    if approved is not True:
        raise PermissionError("Explicit approval is required to apply patches.")

    plan, _ = build_plan(scan_report, investigation_report, target_root)
    operations_by_file = {}

    for proposal in plan["proposals"]:
        source_path = safe_source_path(target_root, proposal["file"])
        lines = source_path.read_text(
            encoding="utf-8-sig"
        ).splitlines(keepends=True)
        line_index = proposal["line"] - 1
        replacement, _ = propose_replacement(
            proposal["rule_id"],
            lines[line_index],
        )

        if replacement is not None:
            operations_by_file.setdefault(proposal["file"], []).append(
                (line_index, lines[line_index], replacement, proposal["rule_id"])
            )

    applied_changes = []

    for relative_file, operations in sorted(operations_by_file.items()):
        source_path = safe_source_path(target_root, relative_file)
        original_bytes = source_path.read_bytes()
        original_lines = source_path.read_text(
            encoding="utf-8-sig"
        ).splitlines(keepends=True)
        updated_lines = list(original_lines)

        for line_index, expected, replacement, _ in sorted(
            operations,
            key=lambda operation: operation[0],
            reverse=True,
        ):
            if updated_lines[line_index] != expected:
                raise ValueError(
                    f"Source changed while applying plan: "
                    f"{relative_file}:{line_index + 1}"
                )
            updated_lines[line_index:line_index + 1] = (
                replacement.splitlines(keepends=True)
            )

        atomic_write(source_path, "".join(updated_lines))
        applied_changes.append({
            "file": relative_file,
            "rule_ids": sorted({operation[3] for operation in operations}),
            "lines": sorted({operation[0] + 1 for operation in operations}),
            "before_sha256": hashlib.sha256(original_bytes).hexdigest(),
            "after_sha256": hashlib.sha256(source_path.read_bytes()).hexdigest(),
            "status": "applied_to_controlled_copy",
        })

    return {
        "applied_changes": applied_changes,
        "source_modified": bool(applied_changes),
        "previewed_proposals": plan["proposals_generated"],
        "patches_applied": sum(
            proposal["patch_generated"] for proposal in plan["proposals"]
        ),
    }


def main():
    parser = argparse.ArgumentParser(description="Generate safe remediation previews")
    parser.add_argument(
        "--target",
        default="devsecops/fixtures/vulnerable_app",
    )
    parser.add_argument(
        "--scan-report",
        default="devsecops/reports/security_scan_report.json",
    )
    parser.add_argument(
        "--investigation-report",
        default="devsecops/reports/security_investigation_report.json",
    )
    parser.add_argument(
        "--output",
        default="devsecops/reports/remediation_plan.json",
    )
    parser.add_argument(
        "--patch",
        default="devsecops/reports/remediation_preview.patch",
    )
    args = parser.parse_args()

    try:
        scan = load_json(
            args.scan_report,
            "devsecops_security_scan",
        )
        investigation = load_json(
            args.investigation_report,
            "devsecops_security_investigation",
        )

        plan, patch = build_plan(scan, investigation, args.target)

        atomic_write(
            args.output,
            json.dumps(plan, indent=2) + "\n",
        )
        atomic_write(args.patch, patch)

        print("\nDEVSECOPS REMEDIATION PLANNER")
        print("-----------------------------")
        print(f"Findings received    : {plan['source_findings']}")
        print(f"Proposals generated  : {plan['proposals_generated']}")
        print(f"Patch previews       : {plan['patches_generated']}")
        print(f"Human reviews needed : {plan['human_review_required']}")
        print("Source files modified: No")
        print(f"Plan                 : {Path(args.output).resolve()}")
        print(f"Patch preview        : {Path(args.patch).resolve()}")

        return 0

    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        print(f"Remediation planning failed: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
