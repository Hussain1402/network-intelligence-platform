#include "functionlog.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void test_initialization(void)
{
    assert(functionlog_init() == FUNCTIONLOG_OK);
    functionlog_cleanup();
}

static void test_successful_execution(void)
{
    unsigned long long id = 0;

    assert(functionlog_init() == FUNCTIONLOG_OK);
    assert(functionlog_enter("test_function", "test_main", &id)
           == FUNCTIONLOG_OK);
    assert(id != 0);

    assert(functionlog_exit(id, FUNCTIONLOG_SUCCESS, 0, NULL)
           == FUNCTIONLOG_OK);

    functionlog_cleanup();
}

static void test_failed_execution(void)
{
    unsigned long long id = 0;

    assert(functionlog_init() == FUNCTIONLOG_OK);
    assert(functionlog_enter("failing_function", "test_main", &id)
           == FUNCTIONLOG_OK);

    assert(functionlog_exit(
        id, FUNCTIONLOG_FAILED, 500, "Test failure"
    ) == FUNCTIONLOG_OK);

    functionlog_cleanup();
}

static void test_invalid_execution_id(void)
{
    assert(functionlog_init() == FUNCTIONLOG_OK);

    assert(functionlog_exit(
        999999, FUNCTIONLOG_SUCCESS, 0, NULL
    ) == FUNCTIONLOG_ERROR_NOT_FOUND);

    functionlog_cleanup();
}

static void test_csv_export(void)
{
    unsigned long long id = 0;

    assert(functionlog_init() == FUNCTIONLOG_OK);
    assert(functionlog_enter("export_test", "test_main", &id)
           == FUNCTIONLOG_OK);
    assert(functionlog_exit(id, FUNCTIONLOG_SUCCESS, 0, NULL)
           == FUNCTIONLOG_OK);

    assert(functionlog_export_csv("output/functionlog_test.csv")
           == FUNCTIONLOG_OK);

    FILE *file = fopen("output/functionlog_test.csv", "r");
    assert(file != NULL);

    char header[512];
    assert(fgets(header, sizeof(header), file) != NULL);
    assert(strstr(header, "parent_id") != NULL);

    fclose(file);
    remove("output/functionlog_test.csv");

    functionlog_cleanup();
}

static void test_in_progress_csv_has_empty_duration(void)
{
    unsigned long long id = 0;

    assert(functionlog_init() == FUNCTIONLOG_OK);

    assert(functionlog_enter(
        "in_progress_function", "test_main", &id
    ) == FUNCTIONLOG_OK);

    /* Export before functionlog_exit(). */
    assert(functionlog_export_csv(
        "output/functionlog_in_progress_test.csv"
    ) == FUNCTIONLOG_OK);

    FILE *file = fopen(
        "output/functionlog_in_progress_test.csv", "r"
    );
    assert(file != NULL);

    char line[2048];

    /* Skip CSV header. */
    assert(fgets(line, sizeof(line), file) != NULL);

    /* Read the in-progress execution. */
    assert(fgets(line, sizeof(line), file) != NULL);

    assert(strstr(line, "IN_PROGRESS") != NULL);

    /*
     * The end_timestamp field is followed by an empty
     * execution_time_ms field, then IN_PROGRESS.
     */
    assert(strstr(line, ",\"\",,IN_PROGRESS,0,") != NULL);

    fclose(file);
    remove("output/functionlog_in_progress_test.csv");

    functionlog_cleanup();
}


static void test_out_of_order_exit_is_rejected(void)
{
    unsigned long long parent_id = 0;
    unsigned long long child_id = 0;

    assert(functionlog_init() == FUNCTIONLOG_OK);

    assert(functionlog_enter(
        "parent_function", "main", &parent_id
    ) == FUNCTIONLOG_OK);

    assert(functionlog_enter(
        "child_function", "parent_function", &child_id
    ) == FUNCTIONLOG_OK);

    /* Parent must not exit while its child is still active. */
    assert(functionlog_exit(
        parent_id, FUNCTIONLOG_SUCCESS, 0, NULL
    ) == FUNCTIONLOG_ERROR_INVALID_ARGUMENT);

    /* The child and then parent can still complete normally. */
    assert(functionlog_exit(
        child_id, FUNCTIONLOG_SUCCESS, 0, NULL
    ) == FUNCTIONLOG_OK);

    assert(functionlog_exit(
        parent_id, FUNCTIONLOG_SUCCESS, 0, NULL
    ) == FUNCTIONLOG_OK);

    functionlog_cleanup();
}
static void test_nested_function_tracking(void)
{
    unsigned long long parent_id = 0;
    unsigned long long child_id = 0;

    assert(functionlog_init() == FUNCTIONLOG_OK);

    assert(functionlog_enter("parent_function", "main", &parent_id)
           == FUNCTIONLOG_OK);

    assert(functionlog_enter(
        "child_function", "parent_function", &child_id
    ) == FUNCTIONLOG_OK);

    assert(child_id != parent_id);

    assert(functionlog_exit(
        child_id, FUNCTIONLOG_SUCCESS, 0, NULL
    ) == FUNCTIONLOG_OK);

    assert(functionlog_exit(
        parent_id, FUNCTIONLOG_SUCCESS, 0, NULL
    ) == FUNCTIONLOG_OK);

    assert(functionlog_export_csv("output/functionlog_nested_test.csv")
           == FUNCTIONLOG_OK);

    FILE *file = fopen("output/functionlog_nested_test.csv", "r");
    assert(file != NULL);

    char line[1024];

    assert(fgets(line, sizeof(line), file) != NULL);

    assert(fgets(line, sizeof(line), file) != NULL);
    assert(strncmp(line, "1,0,", 4) == 0);

    assert(fgets(line, sizeof(line), file) != NULL);
    assert(strncmp(line, "2,1,", 4) == 0);

    fclose(file);
    remove("output/functionlog_nested_test.csv");

    functionlog_cleanup();
}

int main(void)
{
    test_initialization();
    test_successful_execution();
    test_failed_execution();
    test_invalid_execution_id();
    test_csv_export();
    test_in_progress_csv_has_empty_duration();
    test_out_of_order_exit_is_rejected();
    test_nested_function_tracking();

    printf("All functionlog tests passed.\n");
    return 0;
}
