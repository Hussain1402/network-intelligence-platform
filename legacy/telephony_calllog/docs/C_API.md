# Public C API

The public interface is declared in `include/calllog.h`.

## Lifecycle

### `calllog_init()`

Initializes the call-log analysis library.

Returns a `CallLogStatus`. Initialize the library before calling other
stateful functions.

### `calllog_cleanup()`

Releases library-managed resources. Call this when finished.

## Loading input

### `calllog_load_file(const char *path)`

Loads and analyzes a call-log CSV file.

The CSV must follow the format expected by the current parser:

`timestamp,call_id,source,destination,status,failure_code,duration_ms`

Returns a `CallLogStatus` indicating success or failure.

## Summary

### `calllog_get_summary(CallLogSummary *summary)`

Writes aggregate statistics into the supplied structure.

The summary contains:

- `total_calls`
- `successful_calls`
- `failed_calls`
- `failure_rate_percent`
- `average_success_duration_ms`

Pass a non-null pointer to a valid `CallLogSummary`.

## Failure-code distribution

### `calllog_get_failure_codes(CallLogFailureCode *codes, size_t capacity, size_t *count)`

Retrieves failure-code counts.

- `codes`: destination array
- `capacity`: number of available array entries
- `count`: receives the number of entries reported by the API

Check the function's return status and the declared API behavior if the
destination capacity is insufficient.

## Anomaly configuration and retrieval

### `calllog_set_anomaly_config(const CallLogAnomalyConfig *config)`

Sets the time-window size, failure-rate threshold, and minimum number
of calls used by anomaly detection.

The current demo uses a 60-second window, a 20% threshold, and a
minimum of 5 calls. Reload the input file after changing the configuration
so that anomalies are recalculated.

### `calllog_get_anomalies(CallLogAnomaly *anomalies, size_t capacity, size_t *count)`

Retrieves the anomalies detected during the most recent analysis.

Each anomaly contains a window start timestamp, total calls, failed
calls, and failure rate.

## JSON export

### `calllog_generate_investigation(const char *path)`

Writes the analyzed summary, failure-code distribution, and anomalies
to a JSON file.

The library must be initialized and input must have been loaded first.

## Status codes

See `CallLogStatus` in `include/calllog.h` for the authoritative list.
The current API defines statuses for success, invalid arguments,
uninitialized use, file errors, invalid data, and memory errors.

Always check returned statuses rather than assuming a call succeeded.

## Example

See `examples/c_api_demo.c` for a separate C program that consumes the
public API. It can be compiled and linked against the `calllog` library.
