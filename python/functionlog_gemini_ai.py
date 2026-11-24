import json
import os
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

from google import genai
from google.genai import errors, types

try:
    from .functionlog_mock_ai import load_evidence, investigate
except ImportError:
    from functionlog_mock_ai import load_evidence, investigate


MODEL_NAME = "gemini-3.8-flash"
MAX_ATTEMPTS = 4
INITIAL_RETRY_DELAY_SECONDS = 2
RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}

REQUIRED_AI_FIELDS = {
    "root_cause_hypotheses",
    "recommended_diagnostic_checks",
}


def validate_ai_findings(findings):
    """Validate Gemini findings against the PS1 report schema."""

    if not isinstance(findings, dict):
        raise ValueError("Gemini response must be a JSON object.")

    missing = REQUIRED_AI_FIELDS - findings.keys()
    if missing:
        raise ValueError(
            f"Gemini response missing fields: {sorted(missing)}"
        )

    unexpected = findings.keys() - REQUIRED_AI_FIELDS
    if unexpected:
        raise ValueError(
            f"Gemini response has unexpected fields: {sorted(unexpected)}"
        )

    hypotheses = findings["root_cause_hypotheses"]

    if not isinstance(hypotheses, list) or not hypotheses:
        raise ValueError(
            "'root_cause_hypotheses' must be a non-empty list."
        )

    hypothesis_fields = {
        "hypothesis", "confidence", "status", "reasoning"
    }

    for index, hypothesis in enumerate(hypotheses):
        if not isinstance(hypothesis, dict):
            raise ValueError(f"Hypothesis {index} must be an object.")

        if hypothesis.keys() != hypothesis_fields:
            raise ValueError(
                f"Hypothesis {index} must contain exactly: "
                f"{sorted(hypothesis_fields)}"
            )

        for field in hypothesis_fields:
            value = hypothesis[field]
            if not isinstance(value, str) or not value.strip():
                raise ValueError(
                    f"Hypothesis {index} has an invalid '{field}'."
                )

        if hypothesis["confidence"] not in {"low", "medium", "high"}:
            raise ValueError(
                f"Hypothesis {index} has invalid confidence."
            )

        if hypothesis["status"] != "unconfirmed":
            raise ValueError(
                "Root-cause hypotheses must remain unconfirmed."
            )

    checks = findings["recommended_diagnostic_checks"]

    if not isinstance(checks, list) or not checks:
        raise ValueError(
            "'recommended_diagnostic_checks' must be a non-empty list."
        )

    check_fields = {"priority", "check", "purpose"}

    for index, check in enumerate(checks):
        if not isinstance(check, dict):
            raise ValueError(f"Diagnostic check {index} must be an object.")

        if check.keys() != check_fields:
            raise ValueError(
                f"Diagnostic check {index} must contain exactly: "
                f"{sorted(check_fields)}"
            )

        for field in check_fields:
            value = check[field]
            if not isinstance(value, str) or not value.strip():
                raise ValueError(
                    f"Diagnostic check {index} has an invalid '{field}'."
                )

        if check["priority"] not in {"low", "medium", "high"}:
            raise ValueError(
                f"Diagnostic check {index} has invalid priority."
            )

    return {
        "root_cause_hypotheses": hypotheses,
        "recommended_diagnostic_checks": checks,
    }


def generate_with_retry(client, prompt, instructions):
    """Retry temporary Gemini API failures with bounded backoff."""

    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            return client.models.generate_content(
                model=MODEL_NAME,
                contents=prompt,
                config=types.GenerateContentConfig(
                    system_instruction=instructions,
                    response_mime_type="application/json",
                    temperature=0.2,
                ),
            )

        except errors.APIError as exc:
            status_code = getattr(exc, "code", None)

            if status_code not in RETRYABLE_STATUS_CODES:
                raise

            if attempt == MAX_ATTEMPTS:
                raise

            delay = INITIAL_RETRY_DELAY_SECONDS * (2 ** (attempt - 1))

            print(
                f"Temporary Gemini API error ({status_code}). "
                f"Retrying in {delay} seconds "
                f"(attempt {attempt + 1}/{MAX_ATTEMPTS})...",
                file=sys.stderr,
            )

            time.sleep(delay)


def investigate_with_gemini(data):
    """Investigate C-generated function execution evidence using Gemini."""

    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        raise ValueError("GEMINI_API_KEY is not configured.")

    # Build factual observations locally using the existing PS1 analyzer.
    base_report = investigate(data)
    observed_evidence = base_report["observed_evidence"]

    instructions = """
You are an expert C/C++ application reliability and debugging assistant.

Analyze the supplied function execution evidence.

EVIDENCE RULES:
1. The supplied JSON is the only source of observed facts.
2. Never invent function names, execution IDs, durations, error codes,
   error messages, timestamps, or parent-child relationships.
3. Observed evidence is constructed locally by the application.
   Do not return or modify observed_evidence.
4. Distinguish observed failures from possible explanations.
5. Every root-cause hypothesis must have status "unconfirmed".
6. A failed parent with a failed child may indicate propagated failure.
   Do not automatically assume this proves causation.
7. Consider nested execution relationships when analyzing failures.
8. Do not treat the longest execution as an anomaly without a baseline.
9. Do not claim to have inspected source code, live processes,
   external telemetry, or diagnostic systems.
10. Recommend checks that could distinguish possible explanations.
11. Do not claim recommended checks have already been performed.
12. Explicitly acknowledge insufficient evidence.

CONFIDENCE:
- low: weak or indirect supporting evidence
- medium: meaningful but incomplete supporting evidence
- high: strong supporting evidence, but still unconfirmed

Return only valid JSON with this exact structure:

{
  "root_cause_hypotheses": [
    {
      "hypothesis": "string",
      "confidence": "low, medium, or high",
      "status": "unconfirmed",
      "reasoning": "string"
    }
  ],
  "recommended_diagnostic_checks": [
    {
      "priority": "low, medium, or high",
      "check": "string",
      "purpose": "string"
    }
  ]
}
"""

    prompt_data = {
        "summary": data["summary"],
        "performance": data["performance"],
        "function_statistics": data["function_statistics"],
        "execution_records": data["execution_records"],
        "locally_observed_evidence": observed_evidence,
    }

    prompt = (
        "Investigate this C/C++ function execution evidence. "
        "Consider failures, nested execution relationships, "
        "performance measurements, and in-progress executions. "
        "Return only the requested JSON structure.\n\n"
        + json.dumps(prompt_data, indent=2)
    )

    client = genai.Client(api_key=api_key)

    response = generate_with_retry(client, prompt, instructions)

    if not response.text:
        raise ValueError("Gemini returned an empty response.")

    try:
        raw_findings = json.loads(response.text)
    except json.JSONDecodeError as exc:
        raise ValueError("Gemini returned invalid JSON.") from exc

    findings = validate_ai_findings(raw_findings)

    return {
        "report_type": "function_execution_gemini_investigation",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "model": MODEL_NAME,
        "source": base_report["source"],
        "summary": data["summary"],
        "performance": data["performance"],
        "function_statistics": data["function_statistics"],
        "observed_evidence": observed_evidence,
        **findings,
        "limitations": [
            "Root-cause hypotheses are unconfirmed.",
            "Analysis is limited to supplied function execution evidence.",
            "Nested failure relationships do not independently prove causation.",
            "No source code, live application, or external telemetry was inspected.",
            "A performance baseline or threshold is required to establish anomalies.",
            "Confidence values are qualitative AI assessments, not probabilities.",
        ],
    }


def write_json_atomically(output_path, report):
    """Write a complete report without prematurely replacing an old report."""

    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            dir=output_path.parent,
            prefix=f".{output_path.name}.",
            suffix=".tmp",
            delete=False,
        ) as file:
            temporary_path = Path(file.name)
            json.dump(report, file, indent=4, ensure_ascii=False)
            file.write("\n")
            file.flush()
            os.fsync(file.fileno())

        os.replace(temporary_path, output_path)
        temporary_path = None

    finally:
        if temporary_path is not None:
            try:
                temporary_path.unlink(missing_ok=True)
            except OSError:
                pass


def main():
    if len(sys.argv) != 3:
        print(
            "Usage: python functionlog_gemini_ai.py "
            "<evidence.json> <report.json>",
            file=sys.stderr,
        )
        return 2

    input_path = Path(sys.argv[1])
    output_path = Path(sys.argv[2])

    try:
        data = load_evidence(input_path)
        report = investigate_with_gemini(data)
        write_json_atomically(output_path, report)

        print(f"Gemini function investigation written to: {output_path}")

        print("\nObserved evidence:")
        for item in report["observed_evidence"]:
            print(f"- {item}")

        print("\nRoot-cause hypotheses:")
        for item in report["root_cause_hypotheses"]:
            print(f"- [{item['confidence']}] {item['hypothesis']}")
            print(f"  Status: {item['status']}")

        print("\nRecommended diagnostic checks:")
        for item in report["recommended_diagnostic_checks"]:
            print(f"- [{item['priority']}] {item['check']}")
            print(f"  Purpose: {item['purpose']}")

        return 0

    except (OSError, ValueError, TypeError, KeyError) as exc:
        print(f"Investigation failed: {exc}", file=sys.stderr)
        return 1

    except Exception as exc:
        print(
            f"Gemini API request failed: {type(exc).__name__}: {exc}",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
