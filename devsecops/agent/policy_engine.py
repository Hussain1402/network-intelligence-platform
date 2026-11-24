import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG_PATH = (
    PROJECT_ROOT / "devsecops" / "config" / "security_policy.json"
)
DEFAULT_REPORT_PATH = (
    PROJECT_ROOT / "devsecops" / "reports" / "security_scan_report.json"
)
DEFAULT_OUTPUT_PATH = (
    PROJECT_ROOT / "devsecops" / "reports" / "security_policy_report.json"
)

VALID_SEVERITIES = {"critical", "high", "medium", "low"}
VALID_ACTIONS = {"block", "warn", "informational"}


def load_policy_config(config_path=DEFAULT_CONFIG_PATH):
    config = json.loads(Path(config_path).read_text(encoding="utf-8-sig"))

    profiles = config.get("profiles")
    default_profile = config.get("default_profile")

    if not isinstance(profiles, dict) or not profiles:
        raise ValueError("Policy configuration must contain profiles.")

    if default_profile not in profiles:
        raise ValueError("Default policy profile does not exist.")

    for profile_name, profile in profiles.items():
        if not isinstance(profile, dict):
            raise ValueError(f"Invalid policy profile: {profile_name}")

        if set(profile) != VALID_SEVERITIES:
            raise ValueError(
                f"Profile '{profile_name}' must define all four severities."
            )

        for severity, action in profile.items():
            if action not in VALID_ACTIONS:
                raise ValueError(
                    f"Invalid action '{action}' for {severity} "
                    f"in profile '{profile_name}'."
                )

    return config


def create_finding_id(finding):
    identity = "|".join([
        str(finding.get("rule_id", "")),
        str(finding.get("file", "")),
        str(finding.get("line", "")),
    ])
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]


def evaluate_security_report(report, policy=None, profile="balanced"):
    policy = policy or {
        "critical": "block",
        "high": "block",
        "medium": "warn",
        "low": "informational",
    }

    if report.get("report_type") != "devsecops_security_scan":
        raise ValueError("Unsupported security report type.")

    findings = report.get("findings")

    if not isinstance(findings, list):
        raise ValueError("Security report findings must be a list.")

    if set(policy) != VALID_SEVERITIES:
        raise ValueError("Policy must define all four severity levels.")

    for severity, action in policy.items():
        if severity not in VALID_SEVERITIES or action not in VALID_ACTIONS:
            raise ValueError(f"Invalid policy setting: {severity}={action}")

    decisions = []
    counts = {severity: 0 for severity in VALID_SEVERITIES}

    blocked = 0
    warnings = 0
    informational = 0

    for finding in findings:
        if not isinstance(finding, dict):
            raise ValueError("Each finding must be an object.")

        severity = finding.get("severity")

        if severity not in VALID_SEVERITIES:
            raise ValueError(f"Unsupported finding severity: {severity}")

        action = policy[severity]
        counts[severity] += 1

        if action == "block":
            blocked += 1
        elif action == "warn":
            warnings += 1
        else:
            informational += 1

        decisions.append({
            "finding_id": create_finding_id(finding),
            "rule_id": finding.get("rule_id"),
            "file": finding.get("file"),
            "line": finding.get("line"),
            "severity": severity,
            "decision": action,
            "reason": (
                f"{severity.capitalize()} severity findings "
                f"are configured to {action}."
            ),
        })

    if blocked:
        overall_decision = "blocked"
    elif warnings:
        overall_decision = "passed_with_warnings"
    else:
        overall_decision = "passed"

    return {
        "report_type": "devsecops_security_policy",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "policy_mode": profile,
        "policy": policy,
        "summary": {
            "total_findings": len(findings),
            "severity_counts": counts,
            "blocked_findings": blocked,
            "warnings": warnings,
            "informational": informational,
            "overall_decision": overall_decision,
        },
        "decisions": decisions,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Evaluate security findings against a configurable policy."
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=DEFAULT_REPORT_PATH,
        help="Input security scanner JSON report.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT_PATH,
        help="Output policy decision JSON report.",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=DEFAULT_CONFIG_PATH,
        help="Security policy configuration JSON.",
    )
    parser.add_argument(
        "--profile",
        choices=["strict", "balanced", "report_only"],
        default=None,
        help="Policy profile to apply. Defaults to configured default_profile.",
    )

    args = parser.parse_args()

    try:
        config = load_policy_config(args.config)
        selected_profile = args.profile or config["default_profile"]

        if selected_profile not in config["profiles"]:
            raise ValueError(
                f"Policy profile '{selected_profile}' is not configured."
            )

        report = json.loads(args.input.read_text(encoding="utf-8-sig"))

        policy_report = evaluate_security_report(
            report,
            policy=config["profiles"][selected_profile],
            profile=selected_profile,
        )

        args.output.parent.mkdir(parents=True, exist_ok=True)
        temporary_path = args.output.with_suffix(
            args.output.suffix + ".tmp"
        )
        temporary_path.write_text(
            json.dumps(policy_report, indent=4),
            encoding="utf-8",
        )
        temporary_path.replace(args.output)

    except (OSError, json.JSONDecodeError, ValueError) as error:
        print(f"Policy evaluation error: {error}")
        return 2

    summary = policy_report["summary"]

    print("\nDEVSECOPS SECURITY POLICY")
    print(f"Profile        : {selected_profile}")
    print(f"Findings       : {summary['total_findings']}")
    print(f"Blocked        : {summary['blocked_findings']}")
    print(f"Warnings       : {summary['warnings']}")
    print(f"Informational  : {summary['informational']}")
    print(f"Decision       : {summary['overall_decision']}")
    print(f"Report         : {args.output.resolve()}")

    # A blocked decision is valid policy output, not an execution error.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
