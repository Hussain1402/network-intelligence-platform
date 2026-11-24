# Network Intelligence Platform

A multi-module engineering project combining systems programming, network analytics, artificial intelligence, and automated security engineering.

The platform is organized into three independent problem statements:

- **PS1 – FunctionLog:** A reusable C library for function execution logging, analytics, and AI-assisted root-cause investigation.
- **PS2 – Network Analytics:** Network metrics processing, anomaly detection, trend analysis, and evidence-based reporting.
- **PS3 – Autonomous DevSecOps Agent:** Security scanning, investigation, policy evaluation, controlled remediation, and verification.

The root CMake build includes PS1 and PS2. Historical telephone-call CSV analysis is maintained separately under `legacy/telephony_calllog/` and is not the definition of PS1.

---

## 1. Project Objectives

The project aims to demonstrate:

1. Reusable systems-level software development using C.
2. Structured analysis of execution logs and network metrics.
3. Detection and investigation of abnormal system behaviour.
4. AI-assisted explanations grounded in machine-generated evidence.
5. Automated source-code security analysis.
6. Policy-controlled remediation with explicit human approval.
7. Verification through builds, tests, and post-remediation scans.

---

## 2. System Architecture

### PS1 – FunctionLog

FunctionLog is a reusable C library designed to capture and analyse function execution behaviour.

```text
C/C++ Application
       |
       v
FunctionLog C Library
       |
       v
Execution Records
       |
       v
Timing, Status and Failure Analysis
       |
       v
JSON / CSV Evidence
       |
       v
Python Root-Cause Investigator
       |
       v
Mock AI / Optional Gemini Integration
       |
       v
Investigation Report
```

**Key capabilities:**

- Function execution tracking.
- Execution status and failure analysis.
- Nested execution and failure propagation.
- Duplicate execution ID detection.
- Execution analytics and structured evidence generation.
- Python-based investigation using generated evidence.
- Optional Gemini integration.

### PS2 – Network Analytics

The Network Analytics module processes network metrics and identifies abnormal behaviour across observations.

```text
Network Metrics CSV
       |
       v
C Metrics Parser
       |
       v
Metrics Processing
       |
       v
Anomaly Detection
       |
       v
Aggregate Analytics
       |
       v
Historical Trend Analysis
       |
       v
Evidence Validation
       |
       v
AI-Assisted Investigation
       |
       v
Network Analytics Report
```

**Key capabilities:**

- Network metrics ingestion and parsing.
- Counter and metric analysis.
- Threshold-based anomaly detection.
- Multi-metric degradation detection.
- Historical trend analysis.
- Identification of recovered and unrecovered trends.
- Evidence consistency validation.
- AI-assisted reporting based on observed evidence.

### PS3 – Autonomous DevSecOps Agent

The DevSecOps module implements a controlled security workflow that scans source code, investigates findings, evaluates policies, and verifies approved remediation.

```text
Source Code
    |
    v
Security Scanner
    |
    v
Security Findings
    |
    v
Security Investigator
    |
    v
Policy Engine
    |
    v
Remediation Planner
    |
    v
Patch Preview
    |
    v
Explicit Human Approval
    |
    v
Temporary Project Copy
    |
    v
Approved Remediation
    |
    v
Build and Test
    |
    v
Post-Remediation Security Scan
    |
    v
Verification Report
```

**Key capabilities:**

- Detection of potentially unsafe coding practices.
- Security finding classification and severity assignment.
- Secret redaction in security reports.
- Finding-specific investigation and recommendations.
- Configurable security policy profiles.
- Remediation planning and patch previews.
- Explicit human approval before applying changes.
- Temporary-copy remediation verification.
- Build, test, and post-remediation security scanning.
- Before-and-after SHA-256 integrity checks.

Remediation is approval-gated. Verification is performed on a temporary project copy so the original project source remains unchanged.

---

## 3. Project Structure

```text
network-intelligence-platform/
|
|-- include/                  Public C library headers
|
|-- src/                      C implementations and demonstration programs
|
|-- examples/                 C and C++ examples
|
|-- tests/
|   |-- c/                    C and C++ unit tests
|   |-- python/               Python unit and integration tests
|
|-- python/                   PS1 and PS2 Python investigation modules
|
|-- data/                     Sample metrics and input datasets
|
|-- scripts/                  PowerShell execution scripts
|
|-- devsecops/
|   |-- agent/                DevSecOps agent components
|   |-- config/               Security policy configuration
|   |-- fixtures/             Security testing fixtures
|   |-- reports/              Security reports and patch previews
|
|-- docs/                     Documentation and traceability
|
|-- output/                   Generated evidence and investigation reports
|
|-- legacy/                   Historical implementations
|
|-- CMakeLists.txt            Root CMake build configuration
|-- README.md                 Project documentation
|-- .gitignore                Git exclusion rules
```

---

## 4. Technologies Used

| Area | Technologies |
|---|---|
| Systems programming | C |
| Demonstrations | C++ |
| Build system | CMake |
| Compiler | GCC / MinGW |
| Scripting and investigation | Python |
| Data exchange | CSV and JSON |
| AI integration | Mock AI, optional Google Gemini |
| Security analysis | Python-based static scanning |
| Testing | CTest, Python unittest |
| Version control | Git |

---

## 5. Prerequisites

The development environment used for this project includes:

- Windows 11
- Visual Studio Code
- CMake
- MinGW / MSYS2 UCRT64 GCC and G++
- Python 3.13
- Git
- Python package `google-genai` for optional Gemini integration

The C and C++ build uses the MSYS2 UCRT64 toolchain. Python project tests use the Windows Python virtual environment.

---

## 6. Build Instructions

Open PowerShell in the project root.

### Configure the CMake project

```powershell
cmake -S . -B build -G "MinGW Makefiles" `
  -DCMAKE_C_COMPILER="C:/msys64/ucrt64/bin/gcc.exe" `
  -DCMAKE_CXX_COMPILER="C:/msys64/ucrt64/bin/g++.exe"
```

### Build the project

```powershell
cmake --build build
```

### Run C and C++ tests

```powershell
ctest --test-dir build --output-on-failure
```

The latest recorded CTest result was **8/8 tests passed**.

---

## 7. Python Test Instructions

The project uses a Windows Python virtual environment named `.venv-win`.

Run the complete Python test suite from the project root:

```powershell
.\.venv-win\Scripts\python.exe -m unittest discover -s tests\python -p "test_*.py" -v
```

The latest recorded full Python test result was **72/72 tests passed**.

The Gemini integration tests use a mocked client. Passing those tests does not establish that a live Gemini API request has been successfully executed.

---

## 8. DevSecOps Security Scanning

The security scanner checks for potentially unsafe coding patterns, including:

- Hardcoded secrets.
- Unsafe C functions such as `strcpy`, `sprintf`, and `gets`.
- Risky C system calls.
- Python `eval()` and `exec()`.
- Subprocess calls using `shell=True`.
- Potentially unsafe pickle usage.

Findings are classified by severity and accompanied by recommendations.

The scanner is rule-based. Findings should be treated as security indicators requiring appropriate review, not as proof that an application is exploitable.

---

## 9. Controlled Remediation and Verification

The remediation workflow follows a human-in-the-loop approach.

1. Scan the source code.
2. Investigate the identified findings.
3. Evaluate the findings against the configured security policy.
4. Generate remediation proposals and patch previews.
5. Require explicit approval before applying changes.
6. Create a temporary project copy.
7. Apply approved changes to the temporary copy.
8. Configure and build the temporary project.
9. Run CTest and perform a post-remediation security scan.
10. Compare the original and post-remediation findings.
11. Report resolved, unresolved, and newly detected findings.

The original source is checked for modification, and the temporary workspace is removed after verification.

### Recorded integration verification

A real-build DevSecOps integration test successfully performed:

- Security scanning.
- Investigation and remediation planning.
- Approved remediation on a temporary copy.
- CMake configuration.
- C and C++ compilation.
- Execution of all 8 CTest tests.
- Post-remediation security scanning.

The recorded result was:

| Metric | Result |
|---|---:|
| Initial findings | 8 |
| Resolved findings | 5 |
| Remaining findings | 3 |
| New findings | 0 |
| Final status | Partially verified |

The three remaining findings required further manual remediation.

The Python test stage inside this particular real-build integration test was mocked. The complete Python test suite was run separately and passed 72/72 tests.

---

## 10. AI-Assisted Investigation

AI-assisted investigation is designed to explain evidence generated by the underlying analysis modules.

The reports distinguish:

- Directly observed evidence.
- Possible root-cause hypotheses.
- Recommended verification steps.
- Investigation limitations.

The Mock AI implementation provides deterministic, rule-based explanations for development and testing.

Optional Gemini integration is available for PS1. API credentials should be supplied through environment variables and must never be committed to version control.

AI-generated hypotheses are not treated as confirmed root causes without supporting evidence.

---

## 11. Testing Summary

Latest recorded verification results:

| Test Category | Result |
|---|---:|
| C/C++ CTest suite | 8/8 passed |
| Complete Python unit test suite | 72/72 passed |
| Gemini mocked-client tests | 10/10 passed |
| Real-build DevSecOps integration test | 1/1 passed |

These results represent the latest recorded test runs and should be rerun after subsequent code changes.

---

## 12. Security and Project Limitations

- The security scanner uses predefined rules and does not replace a comprehensive commercial static-analysis platform.
- Security recommendations require engineering review.
- Remediation is not applied automatically without explicit approval.
- Some findings require manual remediation.
- Mock AI reports are deterministic and are not equivalent to live model-generated analysis.
- Gemini API integration requires valid credentials and a separate live API verification.
- Network anomaly detection depends on the quality and coverage of the supplied metrics.
- The project does not claim autonomous production deployment or unrestricted automatic remediation.

---

## 13. Future Enhancements

Potential future improvements include:

- Live network telemetry ingestion.
- More advanced statistical and machine-learning anomaly detection.
- Expanded network performance metrics.
- Improved root-cause correlation across multiple data sources.
- More security detection rules and language support.
- Additional safe remediation strategies.
- CI/CD integration.
- Container-based security testing.
- Improved dashboards and visualization.
- Expanded AI-assisted investigation with stronger evidence correlation.

---

## 14. Project Status

The project currently contains three implemented engineering modules:

- **PS1:** Function execution logging, analytics, and AI-assisted investigation.
- **PS2:** Network metrics analytics, anomaly detection, and trend reporting.
- **PS3:** Security scanning, policy evaluation, controlled remediation, and verification.

The project has automated C/C++ and Python test coverage, along with a real-build DevSecOps integration test.

---

## 15. Author

Developed as an engineering project exploring the integration of systems programming, network intelligence, artificial intelligence, and DevSecOps automation.
