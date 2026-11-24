#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif

#include "functionlog.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
static SRWLOCK records_lock = SRWLOCK_INIT;
#define LOCK_RECORDS() AcquireSRWLockExclusive(&records_lock)
#define UNLOCK_RECORDS() ReleaseSRWLockExclusive(&records_lock)
#else
#include <stdatomic.h>
static atomic_flag records_lock = ATOMIC_FLAG_INIT;
#define LOCK_RECORDS() \
    while (atomic_flag_test_and_set_explicit(&records_lock, memory_order_acquire)) {}
#define UNLOCK_RECORDS() \
    atomic_flag_clear_explicit(&records_lock, memory_order_release)
#endif

#define FUNCTIONLOG_MAX_RECORDS 10000

static FunctionLogRecord records[FUNCTIONLOG_MAX_RECORDS];
static size_t record_count = 0;
static unsigned long long next_id = 1;
static int initialized = 0;

/* Each thread has its own active execution stack. */
static _Thread_local unsigned long long active_stack[FUNCTIONLOG_MAX_ACTIVE];
static _Thread_local size_t active_depth = 0;

static void copy_text(char *destination, size_t capacity, const char *source)
{
    if (capacity == 0) return;

    if (source == NULL) {
        destination[0] = '\0';
        return;
    }

    snprintf(destination, capacity, "%s", source);
}

static void get_timestamp(char *buffer, size_t capacity)
{
    time_t now = time(NULL);
    struct tm time_info;

#ifdef _WIN32
    gmtime_s(&time_info, &now);
#else
    gmtime_r(&now, &time_info);
#endif

    strftime(buffer, capacity, "%Y-%m-%dT%H:%M:%SZ", &time_info);
}

static double get_monotonic_time_ms(void)
{
#ifdef _WIN32
    LARGE_INTEGER counter;
    LARGE_INTEGER frequency;

    QueryPerformanceCounter(&counter);
    QueryPerformanceFrequency(&frequency);

    return ((double)counter.QuadPart * 1000.0) /
           (double)frequency.QuadPart;
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);

    return ((double)ts.tv_sec * 1000.0) +
           ((double)ts.tv_nsec / 1000000.0);
#endif
}



FunctionLogResult functionlog_init(void)
{
    LOCK_RECORDS();

    if (initialized) {
        UNLOCK_RECORDS();
        return FUNCTIONLOG_OK;
    }

    memset(records, 0, sizeof(records));
    record_count = 0;
    next_id = 1;
    initialized = 1;

    UNLOCK_RECORDS();

    active_depth = 0;
    return FUNCTIONLOG_OK;
}

void functionlog_cleanup(void)
{
    LOCK_RECORDS();

    memset(records, 0, sizeof(records));
    record_count = 0;
    next_id = 1;
    initialized = 0;

    UNLOCK_RECORDS();

    active_depth = 0;
}

FunctionLogResult functionlog_enter(
    const char *function_name,
    const char *caller_name,
    unsigned long long *execution_id)
{
    if (function_name == NULL || execution_id == NULL) {
        return FUNCTIONLOG_ERROR_INVALID_ARGUMENT;
    }

    if (active_depth >= FUNCTIONLOG_MAX_ACTIVE) {
        return FUNCTIONLOG_ERROR_LIMIT;
    }

    double start_ms = get_monotonic_time_ms();
    char timestamp[32];
    get_timestamp(timestamp, sizeof(timestamp));

    LOCK_RECORDS();

    if (!initialized) {
        UNLOCK_RECORDS();
        return FUNCTIONLOG_ERROR_NOT_INITIALIZED;
    }

    if (record_count >= FUNCTIONLOG_MAX_RECORDS) {
        UNLOCK_RECORDS();
        return FUNCTIONLOG_ERROR_LIMIT;
    }

    FunctionLogRecord *record = &records[record_count];

    memset(record, 0, sizeof(*record));

    record->id = next_id++;
    record->parent_id =
        active_depth > 0 ? active_stack[active_depth - 1] : 0;

    copy_text(record->function_name,
              sizeof(record->function_name),
              function_name);

    copy_text(record->caller_name,
              sizeof(record->caller_name),
              caller_name);

    copy_text(record->start_timestamp,
              sizeof(record->start_timestamp),
              timestamp);

    record->execution_time_ms = start_ms;

    *execution_id = record->id;
    active_stack[active_depth++] = record->id;
    record_count++;

    UNLOCK_RECORDS();

    return FUNCTIONLOG_OK;
}

FunctionLogResult functionlog_exit(
    unsigned long long execution_id,
    FunctionLogStatus status,
    int error_code,
    const char *error_message)
{
    if (status != FUNCTIONLOG_SUCCESS &&
        status != FUNCTIONLOG_FAILED) {
        return FUNCTIONLOG_ERROR_INVALID_ARGUMENT;
    }

    double end_ms = get_monotonic_time_ms();
    char timestamp[32];
    get_timestamp(timestamp, sizeof(timestamp));

    FunctionLogResult result = FUNCTIONLOG_ERROR_NOT_FOUND;

    LOCK_RECORDS();

    if (!initialized) {
        UNLOCK_RECORDS();
        return FUNCTIONLOG_ERROR_NOT_INITIALIZED;
    }

    for (size_t i = 0; i < record_count; i++) {
        FunctionLogRecord *record = &records[i];

        if (record->id == execution_id) {
            if (record->end_timestamp[0] != '\0') {
                result = FUNCTIONLOG_ERROR_INVALID_ARGUMENT;
                break;
            }

            /* Enforce same-thread completion and LIFO nesting. */
            if (active_depth == 0 ||
                active_stack[active_depth - 1] != execution_id) {
                result = FUNCTIONLOG_ERROR_INVALID_ARGUMENT;
                break;
            }

            record->execution_time_ms =
                end_ms - record->execution_time_ms;

            record->status = status;
            record->error_code = error_code;

            copy_text(record->error_message,
                      sizeof(record->error_message),
                      error_message);

            copy_text(record->end_timestamp,
                      sizeof(record->end_timestamp),
                      timestamp);

            result = FUNCTIONLOG_OK;
            break;
        }
    }

    UNLOCK_RECORDS();

    if (result == FUNCTIONLOG_OK) {
        active_stack[--active_depth] = 0;
    }

    return result;
}

/*
 * Calculate analytics while the caller holds records_lock.
 * This ensures analytics and exported records use the same snapshot.
 */
static FunctionLogResult calculate_analytics_locked(
    FunctionLogAnalytics *analytics)
{
    memset(analytics, 0, sizeof(*analytics));

    size_t completed_executions = 0;

    for (size_t i = 0; i < record_count; i++) {
        const FunctionLogRecord *record = &records[i];

        analytics->total_executions++;

        size_t function_index = 0;

        while (function_index < analytics->unique_functions &&
               strcmp(
                   analytics->functions[function_index].function_name,
                   record->function_name
               ) != 0) {
            function_index++;
        }

        if (function_index == analytics->unique_functions) {
            if (analytics->unique_functions >=
                FUNCTIONLOG_MAX_UNIQUE_FUNCTIONS) {
                return FUNCTIONLOG_ERROR_LIMIT;
            }

            FunctionLogFunctionStats *new_stats =
                &analytics->functions[analytics->unique_functions];

            memset(new_stats, 0, sizeof(*new_stats));

            copy_text(
                new_stats->function_name,
                sizeof(new_stats->function_name),
                record->function_name
            );

            analytics->unique_functions++;
        }

        FunctionLogFunctionStats *stats =
            &analytics->functions[function_index];

        stats->total_executions++;

        if (record->end_timestamp[0] == '\0') {
            analytics->in_progress_executions++;
            continue;
        }

        completed_executions++;

        if (record->status == FUNCTIONLOG_SUCCESS) {
            analytics->successful_executions++;
            stats->successful_executions++;
        } else if (record->status == FUNCTIONLOG_FAILED) {
            analytics->failed_executions++;
            stats->failed_executions++;
        }

        double duration = record->execution_time_ms;

        analytics->average_execution_time_ms += duration;
        stats->average_execution_time_ms += duration;

        if (completed_executions == 1 ||
            duration < analytics->minimum_execution_time_ms) {
            analytics->minimum_execution_time_ms = duration;
        }

        if (completed_executions == 1 ||
            duration > analytics->maximum_execution_time_ms) {
            analytics->maximum_execution_time_ms = duration;
        }

        size_t function_completed =
            stats->successful_executions + stats->failed_executions;

        if (function_completed == 1 ||
            duration < stats->minimum_execution_time_ms) {
            stats->minimum_execution_time_ms = duration;
        }

        if (function_completed == 1 ||
            duration > stats->maximum_execution_time_ms) {
            stats->maximum_execution_time_ms = duration;
        }
    }

    if (completed_executions > 0) {
        analytics->average_execution_time_ms /=
            (double)completed_executions;

        analytics->failure_rate_percent =
            ((double)analytics->failed_executions /
             (double)completed_executions) * 100.0;
    }

    for (size_t i = 0; i < analytics->unique_functions; i++) {
        FunctionLogFunctionStats *stats = &analytics->functions[i];

        size_t function_completed =
            stats->successful_executions + stats->failed_executions;

        if (function_completed > 0) {
            stats->average_execution_time_ms /=
                (double)function_completed;
        }
    }

    return FUNCTIONLOG_OK;
}


FunctionLogResult functionlog_get_analytics(
    FunctionLogAnalytics *analytics)
{
    if (analytics == NULL) {
        return FUNCTIONLOG_ERROR_INVALID_ARGUMENT;
    }

    LOCK_RECORDS();

    if (!initialized) {
        UNLOCK_RECORDS();
        return FUNCTIONLOG_ERROR_NOT_INITIALIZED;
    }

    FunctionLogResult result = calculate_analytics_locked(analytics);

    UNLOCK_RECORDS();

    return result;
}
static void write_json_string(FILE *file, const char *value)
{
    fputc('"', file);

    if (value != NULL) {
        const unsigned char *p = (const unsigned char *)value;

        while (*p != '\0') {
            switch (*p) {
                case '"':  fputs("\\\"", file); break;
                case '\\': fputs("\\\\", file); break;
                case '\b': fputs("\\b", file); break;
                case '\f': fputs("\\f", file); break;
                case '\n': fputs("\\n", file); break;
                case '\r': fputs("\\r", file); break;
                case '\t': fputs("\\t", file); break;

                default:
                    if (*p < 0x20) {
                        fprintf(file, "\\u%04x", (unsigned int)*p);
                    } else {
                        fputc(*p, file);
                    }
                    break;
            }

            p++;
        }
    }

    fputc('"', file);
}

FunctionLogResult functionlog_export_json(const char *output_path)
{
    if (output_path == NULL) {
        return FUNCTIONLOG_ERROR_INVALID_ARGUMENT;
    }

    LOCK_RECORDS();

    if (!initialized) {
        UNLOCK_RECORDS();
        return FUNCTIONLOG_ERROR_NOT_INITIALIZED;
    }

    FunctionLogAnalytics analytics;

    FunctionLogResult analytics_result =
        calculate_analytics_locked(&analytics);

    if (analytics_result != FUNCTIONLOG_OK) {
        UNLOCK_RECORDS();
        return analytics_result;
    }

    FILE *file = fopen(output_path, "w");

    if (file == NULL) {
        UNLOCK_RECORDS();
        return FUNCTIONLOG_ERROR_IO;
    }

    fprintf(file, "{\n");
    fprintf(file, "  \"project\": \"Function Execution Analysis\",\n");

    fprintf(file, "  \"summary\": {\n");
    fprintf(file, "    \"total_executions\": %zu,\n",
            analytics.total_executions);
    fprintf(file, "    \"successful_executions\": %zu,\n",
            analytics.successful_executions);
    fprintf(file, "    \"failed_executions\": %zu,\n",
            analytics.failed_executions);
    fprintf(file, "    \"in_progress_executions\": %zu,\n",
            analytics.in_progress_executions);
    fprintf(file, "    \"unique_functions\": %zu,\n",
            analytics.unique_functions);
    fprintf(file, "    \"failure_rate_percent\": %.6f\n",
            analytics.failure_rate_percent);
    fprintf(file, "  },\n");

    fprintf(file, "  \"performance\": {\n");
    fprintf(file, "    \"average_execution_time_ms\": %.6f,\n",
            analytics.average_execution_time_ms);
    fprintf(file, "    \"minimum_execution_time_ms\": %.6f,\n",
            analytics.minimum_execution_time_ms);
    fprintf(file, "    \"maximum_execution_time_ms\": %.6f\n",
            analytics.maximum_execution_time_ms);
    fprintf(file, "  },\n");

    fprintf(file, "  \"function_statistics\": [\n");

    for (size_t i = 0; i < analytics.unique_functions; i++) {
        const FunctionLogFunctionStats *stats =
            &analytics.functions[i];

        fprintf(file, "    {\n");
        fprintf(file, "      \"function_name\": ");
        write_json_string(file, stats->function_name);

        fprintf(file, ",\n      \"total_executions\": %zu,\n",
                stats->total_executions);
        fprintf(file, "      \"successful_executions\": %zu,\n",
                stats->successful_executions);
        fprintf(file, "      \"failed_executions\": %zu,\n",
                stats->failed_executions);
        fprintf(file, "      \"average_execution_time_ms\": %.6f,\n",
                stats->average_execution_time_ms);
        fprintf(file, "      \"minimum_execution_time_ms\": %.6f,\n",
                stats->minimum_execution_time_ms);
        fprintf(file, "      \"maximum_execution_time_ms\": %.6f\n",
                stats->maximum_execution_time_ms);
        fprintf(file, "    }%s\n",
                i + 1 < analytics.unique_functions ? "," : "");
    }

    fprintf(file, "  ],\n");

    fprintf(file, "  \"execution_records\": [\n");

    for (size_t i = 0; i < record_count; i++) {
        const FunctionLogRecord *record = &records[i];

        int in_progress = record->end_timestamp[0] == '\0';

        const char *status = in_progress
            ? "IN_PROGRESS"
            : (record->status == FUNCTIONLOG_SUCCESS
                ? "SUCCESS"
                : "FAILED");

        fprintf(file, "    {\n");
        fprintf(file, "      \"id\": %llu,\n", record->id);
        fprintf(file, "      \"parent_id\": %llu,\n",
                record->parent_id);

        fprintf(file, "      \"function_name\": ");
        write_json_string(file, record->function_name);

        fprintf(file, ",\n      \"caller_name\": ");
        write_json_string(file, record->caller_name);

        fprintf(file, ",\n      \"start_timestamp\": ");
        write_json_string(file, record->start_timestamp);

        fprintf(file, ",\n      \"end_timestamp\": ");

        if (in_progress) {
            fprintf(file, "null");
        } else {
            write_json_string(file, record->end_timestamp);
        }

        fprintf(file, ",\n      \"execution_time_ms\": ");

        if (in_progress) {
            fprintf(file, "null");
        } else {
            fprintf(file, "%.6f", record->execution_time_ms);
        }

        fprintf(file, ",\n      \"status\": ");
        write_json_string(file, status);

        fprintf(file, ",\n      \"error_code\": %d,\n",
                record->error_code);

        fprintf(file, "      \"error_message\": ");
        write_json_string(file, record->error_message);

        fprintf(file, "\n    }%s\n",
                i + 1 < record_count ? "," : "");
    }

    fprintf(file, "  ],\n");

    fprintf(file, "  \"root_cause_investigation\": {\n");
    fprintf(file, "    \"status\": \"pending\"\n");
    fprintf(file, "  }\n");

    fprintf(file, "}\n");

    int write_failed = ferror(file);
    int close_failed = fclose(file) != 0;

    UNLOCK_RECORDS();

    if (write_failed || close_failed) {
        return FUNCTIONLOG_ERROR_IO;
    }

    return FUNCTIONLOG_OK;
}
static void write_csv_field(FILE *file, const char *value)
{
    fputc('"', file);

    if (value != NULL) {
        while (*value != '\0') {
            if (*value == '"') {
                fputc('"', file);
            }

            fputc(*value, file);
            value++;
        }
    }

    fputc('"', file);
}

FunctionLogResult functionlog_export_csv(const char *output_path)
{
    if (output_path == NULL) {
        return FUNCTIONLOG_ERROR_INVALID_ARGUMENT;
    }

    LOCK_RECORDS();

    if (!initialized) {
        UNLOCK_RECORDS();
        return FUNCTIONLOG_ERROR_NOT_INITIALIZED;
    }

    FILE *file = fopen(output_path, "w");

    if (file == NULL) {
        UNLOCK_RECORDS();
        return FUNCTIONLOG_ERROR_IO;
    }

    fprintf(file,
        "id,parent_id,function_name,caller_name,start_timestamp,"
        "end_timestamp,execution_time_ms,status,error_code,error_message\n");

    for (size_t i = 0; i < record_count; i++) {
        const FunctionLogRecord *record = &records[i];

        const char *status =
            record->end_timestamp[0] == '\0'
                ? "IN_PROGRESS"
                : (record->status == FUNCTIONLOG_SUCCESS
                    ? "SUCCESS"
                    : "FAILED");

        fprintf(file, "%llu,%llu,",
                record->id,
                record->parent_id);

        write_csv_field(file, record->function_name);
        fputc(',', file);

        write_csv_field(file, record->caller_name);
        fputc(',', file);

        write_csv_field(file, record->start_timestamp);
        fputc(',', file);

        write_csv_field(file, record->end_timestamp);
        fputc(',', file);

        if (record->end_timestamp[0] == '\0') {
            /* Duration is not available until execution completes. */
            fprintf(file, ",%s,%d,",
                    status,
                    record->error_code);
        } else {
            fprintf(file, "%.6f,%s,%d,",
                    record->execution_time_ms,
                    status,
                    record->error_code);
        }

        write_csv_field(file, record->error_message);
        fputc('\n', file);
    }

    int write_failed = ferror(file);
    int close_failed = fclose(file) != 0;

    UNLOCK_RECORDS();

    if (write_failed || close_failed) {
        return FUNCTIONLOG_ERROR_IO;
    }

    return FUNCTIONLOG_OK;
}
