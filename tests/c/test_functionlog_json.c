#include "functionlog.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

#define OUTPUT_FILE "output/functionlog_json_test.json"

static void assert_file_contains(const char *content, const char *expected)
{
    if (strstr(content, expected) == NULL) {
        fprintf(stderr, "Missing expected JSON content: %s\n", expected);
        assert(0);
    }
}

int main(void)
{
    unsigned long long id1, id2;
    char buffer[16384];

    assert(functionlog_init() == FUNCTIONLOG_OK);

    /* Test quotation mark escaping in function names. */
    assert(functionlog_enter(
        "worker\"task", "main", &id1
    ) == FUNCTIONLOG_OK);

    /* Test newline and quotation mark escaping in error messages. */
    assert(functionlog_exit(
        id1,
        FUNCTIONLOG_FAILED,
        500,
        "line1\nline2 \"failure\""
    ) == FUNCTIONLOG_OK);

    /* Leave another execution in progress. */
    assert(functionlog_enter(
        "database_query", "main", &id2
    ) == FUNCTIONLOG_OK);

    assert(functionlog_export_json(OUTPUT_FILE) == FUNCTIONLOG_OK);

    FILE *file = fopen(OUTPUT_FILE, "r");
    assert(file != NULL);

    size_t bytes_read = fread(buffer, 1, sizeof(buffer) - 1, file);
    buffer[bytes_read] = '\0';
    fclose(file);

    assert_file_contains(buffer, "\"total_executions\": 2");
    assert_file_contains(buffer, "\"failed_executions\": 1");
    assert_file_contains(buffer, "\"in_progress_executions\": 1");

    assert_file_contains(buffer, "worker\\\"task");
    assert_file_contains(buffer, "line1\\nline2 \\\"failure\\\"");

    assert_file_contains(buffer, "\"execution_time_ms\": null");
    assert_file_contains(buffer, "\"status\": \"IN_PROGRESS\"");

    assert(functionlog_export_json(NULL) ==
           FUNCTIONLOG_ERROR_INVALID_ARGUMENT);

    printf("JSON exporter tests passed.\n");
    printf("JSON escaping verified.\n");
    printf("In-progress execution handling verified.\n");

    functionlog_cleanup();
    return 0;
}
