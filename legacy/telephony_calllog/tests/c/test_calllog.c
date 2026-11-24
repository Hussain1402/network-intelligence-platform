
#include <stdio.h>
#include <string.h>

#include "calllog.h"

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "FAIL at line %d: %s\n", \
                __LINE__, #condition); \
        return 1; \
    } \
} while (0)

static int write_file(const char *path, const char *contents)
{
    FILE *file = fopen(path, "w");

    if (file == NULL) {
        return 0;
    }

    if (fputs(contents, file) == EOF) {
        fclose(file);
        return 0;
    }

    return fclose(file) == 0;
}

int main(void)
{
    const char *valid_csv =
        "timestamp,call_id,source,destination,status,failure_code,duration_ms\n"
        "2026-10-14T10:00:00,C001,A101,B201,SUCCESS,NONE,1200\n"
        "2026-10-14T10:00:05,C002,A102,B202,FAILED,NETWORK_TIMEOUT,0\n"
        "2026-10-14T10:00:10,C003,A103,B203,SUCCESS,NONE,1800\n"
        "2026-10-14T10:00:15,C004,A104,B204,FAILED,BUSY,0\n"
        "2026-10-14T10:00:20,C005,A105,B205,FAILED,BUSY,0\n";

    const char *invalid_csv =
        "timestamp,call_id,source,destination,status,failure_code,duration_ms\n"
        "2026-10-14T10:00:00,C001,A101,B201,UNKNOWN,NONE,1200\n";

    CallLogSummary summary;
    CallLogFailureCode codes[4];
    size_t count = 0;
    size_t i;
    int found_timeout = 0;
    int found_busy = 0;

    CHECK(calllog_init() == CALLLOG_OK);

    CHECK(calllog_get_summary(&summary) == CALLLOG_OK);
    CHECK(summary.total_calls == 0);

    CHECK(calllog_get_summary(NULL) == CALLLOG_ERROR_INVALID_ARGUMENT);

    CHECK(calllog_load_file(NULL) == CALLLOG_ERROR_INVALID_ARGUMENT);
    CHECK(calllog_load_file("missing_test_file.csv") == CALLLOG_ERROR_FILE);

    CHECK(write_file("test_valid.csv", valid_csv));
    CHECK(write_file("test_invalid.csv", invalid_csv));
    CHECK(write_file(
        "test_empty.csv",
        "timestamp,call_id,source,destination,status,failure_code,duration_ms\n"
    ));

    CHECK(calllog_load_file("test_valid.csv") == CALLLOG_OK);

    CHECK(calllog_get_summary(&summary) == CALLLOG_OK);
    CHECK(summary.total_calls == 5);
    CHECK(summary.successful_calls == 2);
    CHECK(summary.failed_calls == 3);
    CHECK(summary.failure_rate_percent > 59.99);
    CHECK(summary.failure_rate_percent < 60.01);
    CHECK(summary.average_success_duration_ms == 1500.0);

    CHECK(calllog_get_failure_codes(NULL, 0, &count) == CALLLOG_OK);
    CHECK(count == 2);

    CHECK(calllog_get_failure_codes(codes, 1, &count) ==
          CALLLOG_ERROR_INVALID_ARGUMENT);
    CHECK(count == 2);

    CHECK(calllog_get_failure_codes(codes, 4, &count) == CALLLOG_OK);

    for (i = 0; i < count; i++) {
        if (strcmp(codes[i].code, "NETWORK_TIMEOUT") == 0) {
            CHECK(codes[i].count == 1);
            found_timeout = 1;
        } else if (strcmp(codes[i].code, "BUSY") == 0) {
            CHECK(codes[i].count == 2);
            found_busy = 1;
        }
    }

    CHECK(found_timeout);
    CHECK(found_busy);

    CHECK(calllog_load_file("test_invalid.csv") ==
          CALLLOG_ERROR_INVALID_DATA);

    CHECK(calllog_get_summary(&summary) == CALLLOG_OK);
    CHECK(summary.total_calls == 0);

    CHECK(calllog_get_failure_codes(NULL, 0, &count) == CALLLOG_OK);
    CHECK(count == 0);

    CHECK(calllog_load_file("test_empty.csv") == CALLLOG_OK);
    CHECK(calllog_get_summary(&summary) == CALLLOG_OK);
    CHECK(summary.total_calls == 0);
    CHECK(summary.failure_rate_percent == 0.0);
    CHECK(summary.average_success_duration_ms == 0.0);

    calllog_cleanup();

    CHECK(calllog_get_summary(&summary) ==
          CALLLOG_ERROR_NOT_INITIALIZED);

    remove("test_valid.csv");
    remove("test_invalid.csv");
    remove("test_empty.csv");

    puts("All call-log tests passed.");
    return 0;
}
