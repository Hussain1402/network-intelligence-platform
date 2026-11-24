# Requirement-to-implementation traceability

This matrix describes the active implementation after excluding the historical
telephone-call CSV module from the root build. “Covered” means the current
automated tests exercise the listed behavior; it is not a production
certification.

| Requirement | Relevant implementation | Existing coverage | Missing / limitation | Action or status |
|---|---|---|---|---|
| PS1: reusable C function logging library | `include/functionlog.h`, `src/functionlog.c`, root `CMakeLists.txt` (`functionlog` target) | `tests/c/test_functionlog.c` | Fixed record/function limits; no install/export package; caller supplies instrumentation | Kept as a separate static library target |
| PS1: entry/exit, duration, success/failure, nested parent-child | `src/functionlog.c`; C/C++ examples | `test_functionlog.c`, `test_functionlog_analytics.c`, `test_functionlog_json.c`; Python evidence tests | Failures must be explicitly reported; same-thread LIFO exit contract | Documented in `docs/FUNCTIONLOG_API.md` |
| PS1: thread-safe operation | `src/functionlog.c` shared lock and thread-local execution stack | `tests/c/test_functionlog_concurrency.c` on Windows | Cleanup must not overlap logging; concurrency test is Windows-specific | Retained and built on Windows |
| PS1: structured evidence and analytics | `functionlog_export_json`, `functionlog_export_csv`, analytics API | `test_functionlog_analytics.c`, `test_functionlog_json.c` | No automatic performance baseline/anomaly threshold | Preserved; evidence remains JSON/CSV |
| PS1: AI investigation and meaningful reports | `python/functionlog_mock_ai.py`; optional `python/functionlog_gemini_ai.py` | `test_functionlog_mock_ai.py`, `test_functionlog_gemini_ai.py` | Mock is deterministic; live Gemini request/model/account not verified | Reports distinguish evidence and unconfirmed hypotheses |
| PS2: ingest network metrics | `include/network_metrics.h`, `src/network_metrics.c`, `data/network_metrics.csv` | `tests/c/test_network_metrics.c` | Batch CSV only; no live device/service adapter | PowerShell pipeline documented in README |
| PS2: latency, loss, throughput, error and memory anomalies | `src/network_anomaly.c`, `include/network_anomaly.h` | `tests/c/test_network_anomaly.c` | Fixed example thresholds | Preserved |
| PS2: aggregate analytics | `src/network_analytics.c`, `include/network_analytics.h` | `tests/c/test_network_analytics.c` | Aggregate statistics do not persist or provide quantiles | Preserved |
| PS2: historical trends and recovery | `src/network_trends.c`, `include/network_trends.h` | `tests/c/test_network_trends.c` | Initial-window baseline and configured thresholds; requires strictly increasing timestamps | Zero-baseline percentage is explicitly undefined (`null`); out-of-order data rejected |
| PS2: consolidated evidence and AI explanation | `python/network_evidence.py`, `python/network_mock_ai.py` | `tests/python/test_network_evidence.py`, `test_network_mock_ai.py` | Rule-based Mock AI only; no dedicated external model or live telemetry | Evidence cross-checks report counts and uses actual anomaly/trend records |
| PS2: structured JSON reports | C writers in `src/network_*.c`; Python evidence/report writers | C JSON assertions; Python evidence tests; run scripts parse JSON | C writers are direct file writes rather than transactional output | Sample pipeline validates the final evidence/report JSON |
| PS3: source scanner and security policies | `devsecops/agent/security_scanner.py`, `policy_engine.py`, `devsecops/config/security_policy.json` | `test_security_scanner.py`, `test_security_policy.py`, `test_policy_profiles.py` | Pattern-based scanning; no dependency analysis; false positives/negatives possible | Build/cache/legacy directories excluded from source scans |
| PS3: investigation and remediation proposals/previews | `security_investigator.py`, `remediation_planner.py` | `test_security_investigator.py`, `test_remediation_planner.py` | Deterministic investigation; only selected rules have automatic patch previews | Manual findings remain preview-only |
| PS3: human approval and controlled patch application | `remediation_planner.apply_approved_plan`; `orchestrator.py --approve-remediation` | `test_remediation_planner.py`; controlled-copy pipeline execution | Only deterministic replacements are applicable; explicit CLI flag approves generated replacements as a batch | Original source is not the patch destination |
| PS3: rebuild, C/C++ tests, Python tests, rescan, verify findings | `devsecops/agent/orchestrator.py` | `test_devsecops.py`; full pipeline run | Verification scope is the scanner's rules; test or rescan failures remain report failures | Run only in temporary project copy; hashes and per-rule results are reported |
| PS3: fail safely on earlier-stage errors | `devsecops/agent/orchestrator.py` | `test_devsecops.py` | Python tests/scanning remain independent stages for diagnostic output | Build failure prevents CTest from using stale binaries; overall result remains failed |

## Legacy boundary

`legacy/telephony_calllog/` contains the old telephone-call CSV library,
examples, tests, documentation, datasets, and historical outputs. Root CMake
and active PS1/PS2 code do not depend on it. It has its own CMake project and
README; it is not the official FunctionLog implementation.

## Current assessment

- **PS1 — Partially Complete:** the library, C and C++ examples, structured
  evidence, analytics, concurrency handling, and Mock AI pipeline are
  implemented and tested. A live external model integration has not been
  verified; production-scale limits and automatic instrumentation remain.
- **PS2 — Partially Complete:** batch metrics, threshold anomaly detection,
  aggregate statistics, historical trends, evidence consolidation, and
  Mock AI reports are implemented. Live telemetry and a dedicated real-model
  investigation path are absent.
- **PS3 — Partially Complete:** policy evaluation, rule-based investigation,
  previews, approval-gated temporary-copy application, rebuild/test/rescan,
  and evidence-based verification are implemented. Scanner/remediation coverage
  is narrow and not equivalent to a comprehensive autonomous DevSecOps agent.
