# Function Execution Monitoring API

This document describes the function execution monitoring library
declared in include/functionlog.h.

It is separate from the legacy call-log analysis API documented
in docs/C_API.md.

## 1. Purpose

The library records function execution activity in C and C++ applications.
It captures function identity, caller identity, nested execution
relationships, timing, completion status, and application-reported errors.

The library does not automatically detect every application error.
Applications must explicitly report failures through functionlog_exit().

## 2. Lifecycle

### functionlog_init()

Initializes the logger. Call before recording executions.

### functionlog_cleanup()

Clears logger state. Call only after every thread using the logger has
stopped and all logging operations have completed.

Concurrent cleanup and logging operations are not supported.

## 3. Recording executions

### functionlog_enter()

Starts a function execution record and returns its execution ID.
Nested calls receive the ID of their active parent as parent_id.

### functionlog_exit()

Completes a previously started execution.

The exit must occur on the same thread as the corresponding entry.
Nested executions must complete in reverse entry order (LIFO).

Use FUNCTIONLOG_SUCCESS for successful completion and
FUNCTIONLOG_FAILED when the application reports a failure.

## 4. Analytics

### functionlog_get_analytics()

Returns aggregate execution counts, failure rate, execution-time
statistics, and per-function statistics.

In-progress executions are counted separately and excluded from completed
execution duration and failure-rate calculations.

## 5. Export

### functionlog_export_csv()

Exports execution records to CSV, including IDs, parent IDs, function
names, timestamps, duration, status, and error details.

### functionlog_export_json()

Exports a structured JSON evidence document containing:
- Execution summary
- Performance statistics
- Per-function statistics
- Individual execution records
- Root-cause investigation status

AI investigation is performed by the separate Python pipeline.

## 6. Threading and limits

Each thread maintains its own active execution stack.

The current implementation has a maximum of 10,000 stored execution
records, 1,024 active nested executions per thread, and 256 unique
functions in analytics.

Stop all worker threads before calling cleanup.

## 7. Error handling

Check every FunctionLogResult returned by the API.

Important results include:
- FUNCTIONLOG_OK
- FUNCTIONLOG_ERROR_INVALID_ARGUMENT
- FUNCTIONLOG_ERROR_NOT_INITIALIZED
- FUNCTIONLOG_ERROR_IO
- FUNCTIONLOG_ERROR_NOT_FOUND
- FUNCTIONLOG_ERROR_LIMIT

## 8. Examples

- examples/functionlog_c_demo.c: C integration example.
- examples/functionlog_cpp_demo.cpp: C++ exception-aware integration example.

Both examples use the same C monitoring library.
