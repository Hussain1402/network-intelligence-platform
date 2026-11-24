
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
    from .mock_ai import load_evidence
except ImportError:
    from mock_ai import load_evidence


MODEL_NAME = "gemini-3.8-flash"
MAX_ATTEMPTS = 4
INITIAL_RETRY_DELAY_SECONDS = 2

RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}

REQUIRED_AI_FIELDS = {
    "root_cause_hypotheses",
    "recommended_diagnostic_checks",
}


def build_observed_evidence(data):
    """Build factual observations directly from C-generated evidence."""

    summary = data["summary"]
    failures = data["failure_codes"]
    anomalies = data["anomalies"]

    total = summary["total_calls"]
    successful = summary["successful_calls"]
    failed = summary["failed_calls"]
    failure_rate = summary["failure_rate_percent"]

    evidence = [
        (
            f"Total calls: {total}; successful calls: {successful}; "
            f"failed calls: {failed}."
        ),
        f"Overall failure rate: {failure_rate:.2f}%.",
    ]

    if "average_success_duration_ms" in summary:
        evidence.append(
            "Average successful call duration: "
            f"{summary['average_success_duration_ms']} ms."
        )

    for item in failures:
        code = item["code"]
        count = item["count"]
        evidence.append(
            f"Recorded failure code {code}: {count} occurrence(s)."
        )

    for anomaly in anomalies:
        evidence.append(
            "Detected anomaly window: "
            f"start={anomaly.get('window_start', 'unknown')}, "
            f"total_calls={anomaly.get('total_calls', 0)}, "
            f"failed_calls={anomaly.get('failed_calls', 0)}, "
            "failure_rate_percent="
            f"{anomaly.get('failure_rate_percent', 0)}."
        )

    return evidence


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



def validate_ai_findings(findings):
    """Validate the structure and required fields of AI-generated findings."""

    if not isinstance(findings, dict):
        raise ValueError("Gemini response must be a JSON object.")

    missing = REQUIRED_AI_FIELDS - findings.keys()
    if missing:
        raise ValueError(
            f"Gemini response missing fields: {sorted(missing)}"
        )

    allowed_top_level = REQUIRED_AI_FIELDS
    unexpected = findings.keys() - allowed_top_level
    if unexpected:
        raise ValueError(
            f"Gemini response has unexpected fields: {sorted(unexpected)}"
        )

    hypotheses = findings["root_cause_hypotheses"]

    if not isinstance(hypotheses, list):
        raise ValueError("'root_cause_hypotheses' must be a list.")

    if not hypotheses:
        raise ValueError("'root_cause_hypotheses' must not be empty.")

    hypothesis_fields = {
        "hypothesis", "confidence", "status", "reasoning"
    }

    for index, hypothesis in enumerate(hypotheses):
        if not isinstance(hypothesis, dict):
            raise ValueError(
                f"Hypothesis {index} must be a JSON object."
            )

        if hypothesis.keys() != hypothesis_fields:
            raise ValueError(
                f"Hypothesis {index} must contain exactly these fields: "
                f"{sorted(hypothesis_fields)}"
            )

        for field in hypothesis_fields:
            value = hypothesis[field]

            if not isinstance(value, str) or not value.strip():
                raise ValueError(
                    f"Hypothesis {index} has an invalid '{field}' field."
                )

        if hypothesis["confidence"] not in {"low", "medium", "high"}:
            raise ValueError(
                f"Hypothesis {index} has an invalid confidence value."
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
            raise ValueError(
                f"Diagnostic check {index} must be a JSON object."
            )

        missing_fields = check_fields - check.keys()
        if missing_fields:
            field = sorted(missing_fields)[0]
            raise ValueError(
                f"Diagnostic check {index} has an invalid '{field}' field."
            )

        unexpected_fields = check.keys() - check_fields
        if unexpected_fields:
            raise ValueError(
                f"Diagnostic check {index} has unexpected fields: "
                f"{sorted(unexpected_fields)}"
            )

        for field in check_fields:
            value = check[field]

            if not isinstance(value, str) or not value.strip():
                raise ValueError(
                    f"Diagnostic check {index} has an invalid "
                    f"'{field}' field."
                )

        if check["priority"] not in {"low", "medium", "high"}:
            raise ValueError(
                f"Diagnostic check {index} has an invalid priority."
            )

    return {
        "root_cause_hypotheses": hypotheses,
        "recommended_diagnostic_checks": checks,
    }



def investigate_with_gemini(data):
    """Use Gemini to interpret evidence produced by the C engine."""

    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        raise ValueError("GEMINI_API_KEY is not configured.")

    # These facts are constructed locally, not generated by Gemini.
    observed_evidence = build_observed_evidence(data)

    instructions = """
You are a network reliability investigation assistant.

Analyze the supplied call-log evidence conservatively.

EVIDENCE RULES:
1. The supplied JSON is the only source of observed facts.
2. Never invent call counts, failure codes, timestamps, metrics,
   timeout settings, network conditions, or service health.
3. Do not return an observed_evidence field. The application builds
   observed evidence directly from the C engine's measurements.
4. Put possible explanations only in root_cause_hypotheses.
5. Explain which supplied facts support each hypothesis.
6. Identify assumptions and missing information in the reasoning.
7. Every hypothesis must have status "unconfirmed".
8. Do not infer a timeout threshold from average call duration.
9. Do not claim to have inspected live systems or external telemetry.
10. Recommend practical checks that could distinguish hypotheses.
11. Do not claim a recommended check has already been performed.
12. If evidence is insufficient, explicitly acknowledge uncertainty.

CONFIDENCE:
- low: weak or indirect supporting evidence
- medium: meaningful but incomplete supporting evidence
- high: strong supporting evidence, but not confirmed

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

    prompt = (
        "Analyze this C-generated network call-log evidence. "
        "Suggest possible explanations and diagnostic checks. "
        "Do not invent facts or claim any cause is confirmed.\n\n"
        + json.dumps(data, indent=2)
    )

    client = genai.Client(api_key=api_key)

    response = generate_with_retry(
        client,
        prompt,
        instructions,
    )

    if not response.text:
        raise ValueError("Gemini returned an empty response.")

    try:
        raw_findings = json.loads(response.text)
    except json.JSONDecodeError as exc:
        raise ValueError(
            "Gemini returned invalid JSON."
        ) from exc

    findings = validate_ai_findings(raw_findings)

    return {
        "report_type": "gemini_ai_network_investigation",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "model": MODEL_NAME,
        "source": data.get("source", "unknown"),
        # Preserve the original C measurements.
        "summary": data["summary"],
        # Facts are constructed locally from the supplied evidence.
        "observed_evidence": observed_evidence,
        # These fields are generated by Gemini and validated above.
        **findings,
        "limitations": [
            "Root-cause hypotheses are unconfirmed.",
            "Analysis is limited to the supplied call-log evidence.",
            "No live network, server, or external telemetry was inspected.",
            "Confidence values are qualitative AI assessments, not "
            "statistical probabilities.",
        ],
    }


def write_json_atomically(output_path, report):
    """Write a complete report without replacing the old one prematurely."""

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

        # Replacement occurs only after the entire report is written.
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
            "Usage: python gemini_ai.py <evidence.json> <report.json>",
            file=sys.stderr,
        )
        return 2

    input_path = Path(sys.argv[1])
    output_path = Path(sys.argv[2])

    try:
        data = load_evidence(input_path)
        report = investigate_with_gemini(data)

        # Do not touch the previous report until investigation succeeds.
        write_json_atomically(output_path, report)

        print(f"Gemini investigation written to: {output_path}")
        return 0

    except (OSError, ValueError, TypeError) as exc:
        print(f"Investigation failed: {exc}", file=sys.stderr)
        return 1

    except Exception as exc:
        print(
            f"Gemini API request failed: "
            f"{type(exc).__name__}: {exc}",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
