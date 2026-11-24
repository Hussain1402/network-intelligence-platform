
#include "calllog.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAX_LINE_LENGTH 4096
#define MAX_FIELD_LENGTH CALLLOG_FAILURE_CODE_MAX

#define DEFAULT_WINDOW_SECONDS 60UL
#define DEFAULT_FAILURE_THRESHOLD 20.0
#define DEFAULT_MINIMUM_CALLS 5UL

/* Internal representation of one time window. */
typedef struct {
    long long window_id;
    unsigned long total_calls;
    unsigned long failed_calls;
} CallLogWindow;

/* Library state. */
static int initialized = 0;

static CallLogSummary current_summary = {0};

static CallLogFailureCode *failure_codes = NULL;
static size_t failure_code_count = 0;

static CallLogWindow *windows = NULL;
static size_t window_count = 0;

static CallLogAnomaly *anomalies = NULL;
static size_t anomaly_count = 0;

static CallLogAnomalyConfig anomaly_config = {
    DEFAULT_WINDOW_SECONDS,
    DEFAULT_FAILURE_THRESHOLD,
    DEFAULT_MINIMUM_CALLS
};

/* Forward declarations. */
static void clear_failure_codes(void);
static void clear_anomalies(void);
static void reset_summary(void);
static int timestamp_to_seconds(
    const char *timestamp,
    long long *seconds
);
static int record_window(long long timestamp_seconds, int failed);
static CallLogStatus build_anomalies(void);

/* ---------------------------------------------------------
   Memory management and initialization
   --------------------------------------------------------- */

static void clear_failure_codes(void)
{
    free(failure_codes);
    failure_codes = NULL;
    failure_code_count = 0;
}

static void clear_anomalies(void)
{
    free(anomalies);
    anomalies = NULL;
    anomaly_count = 0;

    free(windows);
    windows = NULL;
    window_count = 0;
}

static void reset_summary(void)
{
    current_summary = (CallLogSummary){0};

    clear_failure_codes();
    clear_anomalies();
}

CallLogStatus calllog_init(void)
{
    reset_summary();

    anomaly_config.window_seconds = DEFAULT_WINDOW_SECONDS;
    anomaly_config.failure_rate_threshold_percent =
        DEFAULT_FAILURE_THRESHOLD;
    anomaly_config.minimum_calls = DEFAULT_MINIMUM_CALLS;

    initialized = 1;
    return CALLLOG_OK;
}

void calllog_cleanup(void)
{
    reset_summary();
    initialized = 0;
}

/* ---------------------------------------------------------
   CSV parsing helpers
   Supports simple CSV fields without quoted commas.
   --------------------------------------------------------- */

static void trim_field(char *field)
{
    char *start = field;
    char *end;

    while (isspace((unsigned char)*start)) {
        start++;
    }

    if (start != field) {
        memmove(field, start, strlen(start) + 1);
    }

    end = field + strlen(field);

    while (end > field && isspace((unsigned char)end[-1])) {
        end--;
    }

    *end = '\0';
}

static int split_csv_line(
    char *line,
    char fields[][MAX_FIELD_LENGTH],
    size_t expected_fields
)
{
    size_t count = 0;
    char *start = line;
    char *cursor = line;

    for (;;) {
        if (*cursor == ',' ||
            *cursor == '\0' ||
            *cursor == '\n' ||
            *cursor == '\r') {

            size_t length = (size_t)(cursor - start);

            if (count >= expected_fields ||
                length >= MAX_FIELD_LENGTH) {
                return 0;
            }

            memcpy(fields[count], start, length);
            fields[count][length] = '\0';

            trim_field(fields[count]);
            count++;

            if (*cursor == '\0' ||
                *cursor == '\n' ||
                *cursor == '\r') {
                break;
            }

            start = cursor + 1;
        }

        cursor++;
    }

    return count == expected_fields;
}

static int valid_timestamp(const char *value)
{
    int year, month, day, hour, minute, second;
    char extra;

    if (sscanf(
            value,
            "%4d-%2d-%2dT%2d:%2d:%2d%c",
            &year, &month, &day,
            &hour, &minute, &second, &extra
        ) != 6) {
        return 0;
    }

    return year >= 1900 &&
           month >= 1 && month <= 12 &&
           day >= 1 && day <= 31 &&
           hour >= 0 && hour <= 23 &&
           minute >= 0 && minute <= 59 &&
           second >= 0 && second <= 59;
}

static int valid_identifier(const char *value)
{
    size_t i;

    if (value[0] == '\0') {
        return 0;
    }

    for (i = 0; value[i] != '\0'; i++) {
        unsigned char c = (unsigned char)value[i];

        if (!isalnum(c) &&
            c != '_' &&
            c != '-' &&
            c != '.') {
            return 0;
        }
    }

    return 1;
}

static int parse_duration(
    const char *value,
    unsigned long *duration
)
{
    char *end = NULL;
    unsigned long parsed;

    if (value[0] == '\0' || value[0] == '-') {
        return 0;
    }

    errno = 0;
    parsed = strtoul(value, &end, 10);

    if (errno != 0 || end == value || *end != '\0') {
        return 0;
    }

    *duration = parsed;
    return 1;
}

/* ---------------------------------------------------------
   Failure-code distribution
   --------------------------------------------------------- */

static int add_failure_code(const char *code)
{
    size_t i;
    size_t new_count;
    CallLogFailureCode *grown;

    for (i = 0; i < failure_code_count; i++) {
        if (strcmp(failure_codes[i].code, code) == 0) {
            if (failure_codes[i].count == ULONG_MAX) {
                return 0;
            }

            failure_codes[i].count++;
            return 1;
        }
    }

    if (strlen(code) >= CALLLOG_FAILURE_CODE_MAX ||
        failure_code_count >=
            (size_t)-1 / sizeof(*failure_codes)) {
        return 0;
    }

    new_count = failure_code_count + 1;

    grown = realloc(
        failure_codes,
        new_count * sizeof(*failure_codes)
    );

    if (grown == NULL) {
        return 0;
    }

    failure_codes = grown;

    strcpy(failure_codes[failure_code_count].code, code);
    failure_codes[failure_code_count].count = 1;

    failure_code_count++;
    return 1;
}

/* ---------------------------------------------------------
   Timestamp conversion
   Converts YYYY-MM-DDTHH:MM:SS to Unix-style seconds.
   --------------------------------------------------------- */

static long long days_from_civil(
    int year,
    unsigned month,
    unsigned day
)
{
    int adjusted_year = year - (month <= 2);
    int era = (adjusted_year >= 0
        ? adjusted_year
        : adjusted_year - 399) / 400;

    unsigned year_of_era =
        (unsigned)(adjusted_year - era * 400);

    int adjusted_month =
        (int)month + (month > 2 ? -3 : 9);

    unsigned day_of_year =
        (unsigned)((153 * adjusted_month + 2) / 5)
        + day - 1;

    unsigned day_of_era =
        year_of_era * 365
        + year_of_era / 4
        - year_of_era / 100
        + day_of_year;

    return (long long)era * 146097LL
        + (long long)day_of_era
        - 719468LL;
}

static int timestamp_to_seconds(
    const char *timestamp,
    long long *seconds
)
{
    int year, month, day, hour, minute, second;
    char extra;

    if (timestamp == NULL || seconds == NULL) {
        return 0;
    }

    if (sscanf(
            timestamp,
            "%4d-%2d-%2dT%2d:%2d:%2d%c",
            &year, &month, &day,
            &hour, &minute, &second, &extra
        ) != 6) {
        return 0;
    }

    if (year < 1900 ||
        month < 1 || month > 12 ||
        day < 1 || day > 31 ||
        hour < 0 || hour > 23 ||
        minute < 0 || minute > 59 ||
        second < 0 || second > 59) {
        return 0;
    }

    *seconds =
        days_from_civil(year, (unsigned)month, (unsigned)day)
            * 86400LL
        + hour * 3600LL
        + minute * 60LL
        + second;

    return 1;
}

/* ---------------------------------------------------------
   Time-window tracking
   --------------------------------------------------------- */

static int record_window(
    long long timestamp_seconds,
    int failed
)
{
    long long window_id;
    size_t i;
    CallLogWindow *grown;

    if (anomaly_config.window_seconds == 0) {
        return 0;
    }

    window_id =
        timestamp_seconds /
        (long long)anomaly_config.window_seconds;

    for (i = 0; i < window_count; i++) {
        if (windows[i].window_id == window_id) {
            if (windows[i].total_calls == ULONG_MAX ||
                (failed &&
                 windows[i].failed_calls == ULONG_MAX)) {
                return 0;
            }

            windows[i].total_calls++;

            if (failed) {
                windows[i].failed_calls++;
            }

            return 1;
        }
    }

    if (window_count >=
        (size_t)-1 / sizeof(*windows)) {
        return 0;
    }

    grown = realloc(
        windows,
        (window_count + 1) * sizeof(*windows)
    );

    if (grown == NULL) {
        return 0;
    }

    windows = grown;

    windows[window_count].window_id = window_id;
    windows[window_count].total_calls = 1;
    windows[window_count].failed_calls = failed ? 1UL : 0UL;

    window_count++;
    return 1;
}

static int format_window_start(
    long long window_id,
    char *buffer,
    size_t buffer_size
)
{
    long long start_seconds =
        window_id * (long long)anomaly_config.window_seconds;

    time_t value = (time_t)start_seconds;
    struct tm result;

    if ((long long)value != start_seconds) {
        return 0;
    }

    /*
     * MinGW/UCRT64 provides the Microsoft-compatible gmtime_s
     * signature: gmtime_s(struct tm *, const time_t *).
     */
    if (gmtime_s(&result, &value) != 0) {
        return 0;
    }

    return strftime(
        buffer,
        buffer_size,
        "%Y-%m-%dT%H:%M:%S",
        &result
    ) != 0;
}

/* ---------------------------------------------------------
   Anomaly detection
   --------------------------------------------------------- */

static CallLogStatus build_anomalies(void)
{
    size_t i;
    size_t found = 0;
    CallLogAnomaly *result;

    free(anomalies);
    anomalies = NULL;
    anomaly_count = 0;

    for (i = 0; i < window_count; i++) {
        double rate;

        if (windows[i].total_calls <
            anomaly_config.minimum_calls) {
            continue;
        }

        rate =
            100.0 * (double)windows[i].failed_calls /
            (double)windows[i].total_calls;

        if (rate >=
            anomaly_config.failure_rate_threshold_percent) {
            found++;
        }
    }

    if (found == 0) {
        return CALLLOG_OK;
    }

    if (found > (size_t)-1 / sizeof(*result)) {
        return CALLLOG_ERROR_MEMORY;
    }

    result = calloc(found, sizeof(*result));

    if (result == NULL) {
        return CALLLOG_ERROR_MEMORY;
    }

    found = 0;

    for (i = 0; i < window_count; i++) {
        double rate;

        if (windows[i].total_calls <
            anomaly_config.minimum_calls) {
            continue;
        }

        rate =
            100.0 * (double)windows[i].failed_calls /
            (double)windows[i].total_calls;

        if (rate <
            anomaly_config.failure_rate_threshold_percent) {
            continue;
        }

        if (!format_window_start(
                windows[i].window_id,
                result[found].window_start,
                sizeof(result[found].window_start))) {
            free(result);
            return CALLLOG_ERROR_INVALID_DATA;
        }

        result[found].total_calls = windows[i].total_calls;
        result[found].failed_calls = windows[i].failed_calls;
        result[found].failure_rate_percent = rate;

        found++;
    }

    anomalies = result;
    anomaly_count = found;

    return CALLLOG_OK;
}

/* ---------------------------------------------------------
   Main CSV loading and analysis
   --------------------------------------------------------- */

CallLogStatus calllog_load_file(const char *path)
{
    FILE *file;
    char line[MAX_LINE_LENGTH];
    char fields[7][MAX_FIELD_LENGTH];

    unsigned long long duration_sum = 0;
    unsigned long line_number = 0;
    CallLogSummary new_summary = {0};

    const char *expected_header =
        "timestamp,call_id,source,destination,status,failure_code,duration_ms";

    if (!initialized) {
        return CALLLOG_ERROR_NOT_INITIALIZED;
    }

    if (path == NULL || path[0] == '\0') {
        return CALLLOG_ERROR_INVALID_ARGUMENT;
    }

    file = fopen(path, "r");

    if (file == NULL) {
        return CALLLOG_ERROR_FILE;
    }

    /*
     * Start a fresh analysis. Invalid input will leave the
     * published summary empty rather than showing partial data.
     */
    reset_summary();

    if (fgets(line, sizeof(line), file) == NULL) {
        fclose(file);
        return CALLLOG_ERROR_INVALID_DATA;
    }

    line_number++;

    /*
     * Accept LF and CRLF line endings for the CSV header.
     */
    line[strcspn(line, "\r\n")] = '\0';

    if (strcmp(line, expected_header) != 0) {
        fclose(file);
        return CALLLOG_ERROR_INVALID_DATA;
    }

    while (fgets(line, sizeof(line), file) != NULL) {
        unsigned long duration;
        long long timestamp_seconds;
        int failed;
        CallLogStatus result = CALLLOG_OK;

        line_number++;

        if (strchr(line, '\n') == NULL &&
            !feof(file)) {
            fprintf(stderr,
                    "CSV line %lu exceeds the maximum length.\n",
                    line_number);

            fclose(file);
            reset_summary();
            return CALLLOG_ERROR_INVALID_DATA;
        }

        if (line[0] == '\n' ||
            line[0] == '\r' ||
            line[0] == '\0') {
            continue;
        }

        if (!split_csv_line(line, fields, 7)) {
            result = CALLLOG_ERROR_INVALID_DATA;
        } else if (!valid_timestamp(fields[0]) ||
                   !valid_identifier(fields[1]) ||
                   !valid_identifier(fields[2]) ||
                   !valid_identifier(fields[3]) ||
                   !parse_duration(fields[6], &duration)) {
            result = CALLLOG_ERROR_INVALID_DATA;
        } else if (strcmp(fields[4], "SUCCESS") != 0 &&
                   strcmp(fields[4], "FAILED") != 0) {
            result = CALLLOG_ERROR_INVALID_DATA;
        } else if (strcmp(fields[4], "SUCCESS") == 0 &&
                   strcmp(fields[5], "NONE") != 0) {
            result = CALLLOG_ERROR_INVALID_DATA;
        } else if (strcmp(fields[4], "FAILED") == 0 &&
                   !valid_identifier(fields[5])) {
            result = CALLLOG_ERROR_INVALID_DATA;
        } else if (strcmp(fields[4], "FAILED") == 0 &&
                   duration != 0) {
            result = CALLLOG_ERROR_INVALID_DATA;
        } else if (strcmp(fields[4], "SUCCESS") == 0 &&
                   duration >
                       ULLONG_MAX - duration_sum) {
            result = CALLLOG_ERROR_INVALID_DATA;
        }

        if (result != CALLLOG_OK) {
            fprintf(stderr,
                    "Invalid CSV record at line %lu.\n",
                    line_number);

            fclose(file);
            reset_summary();
            return result;
        }

        if (!timestamp_to_seconds(
                fields[0],
                &timestamp_seconds)) {
            fclose(file);
            reset_summary();
            return CALLLOG_ERROR_INVALID_DATA;
        }

        failed = strcmp(fields[4], "FAILED") == 0;

        if (!record_window(timestamp_seconds, failed)) {
            fclose(file);
            reset_summary();
            return CALLLOG_ERROR_MEMORY;
        }

        if (new_summary.total_calls == ULONG_MAX) {
            fclose(file);
            reset_summary();
            return CALLLOG_ERROR_INVALID_DATA;
        }

        new_summary.total_calls++;

        if (!failed) {
            if (new_summary.successful_calls == ULONG_MAX) {
                fclose(file);
                reset_summary();
                return CALLLOG_ERROR_INVALID_DATA;
            }

            new_summary.successful_calls++;
            duration_sum += duration;
        } else {
            if (new_summary.failed_calls == ULONG_MAX) {
                fclose(file);
                reset_summary();
                return CALLLOG_ERROR_INVALID_DATA;
            }

            new_summary.failed_calls++;

            if (!add_failure_code(fields[5])) {
                fclose(file);
                reset_summary();
                return CALLLOG_ERROR_MEMORY;
            }
        }
    }

    if (ferror(file)) {
        fclose(file);
        reset_summary();
        return CALLLOG_ERROR_FILE;
    }

    fclose(file);

    if (new_summary.total_calls > 0) {
        new_summary.failure_rate_percent =
            100.0 * (double)new_summary.failed_calls /
            (double)new_summary.total_calls;
    }

    if (new_summary.successful_calls > 0) {
        new_summary.average_success_duration_ms =
            (double)duration_sum /
            (double)new_summary.successful_calls;
    }

    {
        CallLogStatus status = build_anomalies();

        if (status != CALLLOG_OK) {
            reset_summary();
            return status;
        }
    }

    current_summary = new_summary;

    return CALLLOG_OK;
}

/* ---------------------------------------------------------
   Public summary API
   --------------------------------------------------------- */

CallLogStatus calllog_get_summary(CallLogSummary *summary)
{
    if (summary == NULL) {
        return CALLLOG_ERROR_INVALID_ARGUMENT;
    }

    if (!initialized) {
        return CALLLOG_ERROR_NOT_INITIALIZED;
    }

    *summary = current_summary;
    return CALLLOG_OK;
}

/* ---------------------------------------------------------
   Public failure-code distribution API
   --------------------------------------------------------- */

CallLogStatus calllog_get_failure_codes(
    CallLogFailureCode *codes,
    size_t capacity,
    size_t *count
)
{
    if (count == NULL) {
        return CALLLOG_ERROR_INVALID_ARGUMENT;
    }

    if (!initialized) {
        return CALLLOG_ERROR_NOT_INITIALIZED;
    }

    *count = failure_code_count;

    if (codes == NULL && capacity == 0) {
        return CALLLOG_OK;
    }

    if (codes == NULL || capacity < failure_code_count) {
        return CALLLOG_ERROR_INVALID_ARGUMENT;
    }

    if (failure_code_count > 0) {
        memcpy(
            codes,
            failure_codes,
            failure_code_count * sizeof(*failure_codes)
        );
    }

    return CALLLOG_OK;
}

/* ---------------------------------------------------------
   Public anomaly configuration API
   --------------------------------------------------------- */



CallLogStatus calllog_set_anomaly_config(
    const CallLogAnomalyConfig *config
)
{
    if (!initialized) {
        return CALLLOG_ERROR_NOT_INITIALIZED;
    }

    if (config == NULL ||
        config->window_seconds == 0 ||
#if ULONG_MAX > LLONG_MAX
        config->window_seconds > (unsigned long)LLONG_MAX ||
#endif
        config->minimum_calls == 0 ||
        config->failure_rate_threshold_percent < 0.0 ||
        config->failure_rate_threshold_percent > 100.0) {
        return CALLLOG_ERROR_INVALID_ARGUMENT;
    }

    anomaly_config = *config;

    /*
     * The caller must reload the file to calculate anomalies
     * using the new configuration.
     */
    clear_anomalies();

    return CALLLOG_OK;
}


/* ---------------------------------------------------------
   Public anomaly retrieval API
   --------------------------------------------------------- */

CallLogStatus calllog_get_anomalies(
    CallLogAnomaly *output,
    size_t capacity,
    size_t *count
)
{
    if (count == NULL) {
        return CALLLOG_ERROR_INVALID_ARGUMENT;
    }

    if (!initialized) {
        return CALLLOG_ERROR_NOT_INITIALIZED;
    }

    *count = anomaly_count;

    if (output == NULL && capacity == 0) {
        return CALLLOG_OK;
    }

    if (output == NULL || capacity < anomaly_count) {
        return CALLLOG_ERROR_INVALID_ARGUMENT;
    }

    if (anomaly_count > 0) {
        memcpy(
            output,
            anomalies,
            anomaly_count * sizeof(*anomalies)
        );
    }

    return CALLLOG_OK;
}

static int write_json_string(FILE *file, const char *value)
{
    const unsigned char *p = (const unsigned char *)value;

    if (fputc('"', file) == EOF) {
        return 0;
    }

    while (*p != '\0') {
        switch (*p) {
            case '"':
                if (fputs("\\\"", file) == EOF) return 0;
                break;
            case '\\':
                if (fputs("\\\\", file) == EOF) return 0;
                break;
            case '\n':
                if (fputs("\\n", file) == EOF) return 0;
                break;
            case '\r':
                if (fputs("\\r", file) == EOF) return 0;
                break;
            case '\t':
                if (fputs("\\t", file) == EOF) return 0;
                break;
            default:
                if (*p < 0x20) {
                    if (fprintf(file, "\\u%04x", (unsigned int)*p) < 0)
                        return 0;
                } else {
                    if (fputc(*p, file) == EOF) return 0;
                }
        }
        ++p;
    }

    return fputc('"', file) != EOF;
}

CallLogStatus calllog_generate_investigation(const char *path)
{
    CallLogSummary summary;
    CallLogFailureCode codes[256];
    CallLogAnomaly anomalies[1024];
    size_t code_count = 0;
    size_t anomaly_count = 0;
    size_t i;
    FILE *file;
    CallLogStatus status;
    int ok = 1;

    if (!initialized) {
        return CALLLOG_ERROR_NOT_INITIALIZED;
    }

    if (path == NULL || path[0] == '\0') {
        return CALLLOG_ERROR_INVALID_ARGUMENT;
    }

    status = calllog_get_summary(&summary);
    if (status != CALLLOG_OK) return status;

    status = calllog_get_failure_codes(
        codes, sizeof(codes) / sizeof(codes[0]), &code_count
    );
    if (status != CALLLOG_OK) return status;

    status = calllog_get_anomalies(
        anomalies, sizeof(anomalies) / sizeof(anomalies[0]),
        &anomaly_count
    );
    if (status != CALLLOG_OK) return status;

    file = fopen(path, "w");
    if (file == NULL) {
        return CALLLOG_ERROR_FILE;
    }

    ok = fprintf(file,
        "{\n"
        "  \"source\": \"call_log_csv\",\n"
        "  \"summary\": {\n"
        "    \"total_calls\": %lu,\n"
        "    \"successful_calls\": %lu,\n"
        "    \"failed_calls\": %lu,\n"
        "    \"failure_rate_percent\": %.2f,\n"
        "    \"average_success_duration_ms\": %.2f\n"
        "  },\n"
        "  \"failure_codes\": [\n",
        summary.total_calls,
        summary.successful_calls,
        summary.failed_calls,
        summary.failure_rate_percent,
        summary.average_success_duration_ms
    ) >= 0;

    for (i = 0; ok && i < code_count; ++i) {
        if (i > 0 && fputs(",\n", file) == EOF) {
            ok = 0;
            break;
        }

        if (fputs("    {\"code\": ", file) == EOF ||
            !write_json_string(file, codes[i].code) ||
            fprintf(file, ", \"count\": %lu}", codes[i].count) < 0) {
            ok = 0;
        }
    }

    if (ok && fputs("\n  ],\n  \"anomalies\": [\n", file) == EOF) {
        ok = 0;
    }

    for (i = 0; ok && i < anomaly_count; ++i) {
        if (i > 0 && fputs(",\n", file) == EOF) {
            ok = 0;
            break;
        }

        if (fputs("    {\"window_start\": ", file) == EOF ||
            !write_json_string(file, anomalies[i].window_start) ||
            fprintf(file,
                ", \"total_calls\": %lu, \"failed_calls\": %lu, "
                "\"failure_rate_percent\": %.2f}",
                anomalies[i].total_calls,
                anomalies[i].failed_calls,
                anomalies[i].failure_rate_percent
            ) < 0) {
            ok = 0;
        }
    }

    if (ok && fputs("\n  ]\n}\n", file) == EOF) {
        ok = 0;
    }

    if (fclose(file) != 0) {
        ok = 0;
    }

    return ok ? CALLLOG_OK : CALLLOG_ERROR_FILE;
}
