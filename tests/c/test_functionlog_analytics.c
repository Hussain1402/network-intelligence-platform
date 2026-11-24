#include "functionlog.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
    FunctionLogAnalytics analytics;
    unsigned long long id1, id2, id3, id4, id5;

    assert(functionlog_init() == FUNCTIONLOG_OK);

    /* process_request: successful execution */
    assert(functionlog_enter("process_request", "main", &id1)
           == FUNCTIONLOG_OK);
    assert(functionlog_exit(id1, FUNCTIONLOG_SUCCESS, 0, NULL)
           == FUNCTIONLOG_OK);

    /* process_request: failed execution */
    assert(functionlog_enter("process_request", "main", &id2)
           == FUNCTIONLOG_OK);
    assert(functionlog_exit(
        id2, FUNCTIONLOG_FAILED, 1001, "Request failed"
    ) == FUNCTIONLOG_OK);

    /* process_request: successful execution */
    assert(functionlog_enter("process_request", "main", &id3)
           == FUNCTIONLOG_OK);
    assert(functionlog_exit(id3, FUNCTIONLOG_SUCCESS, 0, NULL)
           == FUNCTIONLOG_OK);

    /* validate_input: successful execution */
    assert(functionlog_enter("validate_input", "process_request", &id4)
           == FUNCTIONLOG_OK);
    assert(functionlog_exit(id4, FUNCTIONLOG_SUCCESS, 0, NULL)
           == FUNCTIONLOG_OK);

    /* An execution that is intentionally left in progress */
    assert(functionlog_enter("database_query", "main", &id5)
           == FUNCTIONLOG_OK);

    assert(functionlog_get_analytics(&analytics) == FUNCTIONLOG_OK);

    assert(analytics.total_executions == 5);
    assert(analytics.successful_executions == 3);
    assert(analytics.failed_executions == 1);
    assert(analytics.in_progress_executions == 1);
    assert(analytics.unique_functions == 3);

    /* Failure rate is calculated from 4 completed executions. */
    assert(analytics.failure_rate_percent > 24.99);
    assert(analytics.failure_rate_percent < 25.01);

    assert(analytics.average_execution_time_ms >= 0.0);
    assert(analytics.minimum_execution_time_ms >= 0.0);
    assert(analytics.maximum_execution_time_ms >=
           analytics.minimum_execution_time_ms);

    int found_process = 0;
    int found_validation = 0;
    int found_database = 0;

    for (size_t i = 0; i < analytics.unique_functions; i++) {
        FunctionLogFunctionStats *stats = &analytics.functions[i];

        if (strcmp(stats->function_name, "process_request") == 0) {
            found_process = 1;
            assert(stats->total_executions == 3);
            assert(stats->successful_executions == 2);
            assert(stats->failed_executions == 1);
        }

        if (strcmp(stats->function_name, "validate_input") == 0) {
            found_validation = 1;
            assert(stats->total_executions == 1);
            assert(stats->successful_executions == 1);
            assert(stats->failed_executions == 0);
        }

        if (strcmp(stats->function_name, "database_query") == 0) {
            found_database = 1;
            assert(stats->total_executions == 1);
            assert(stats->successful_executions == 0);
            assert(stats->failed_executions == 0);
        }
    }

    assert(found_process);
    assert(found_validation);
    assert(found_database);

    /* Invalid argument test */
    assert(functionlog_get_analytics(NULL) ==
           FUNCTIONLOG_ERROR_INVALID_ARGUMENT);

    printf("Function analytics tests passed.\n");
    printf("Total executions: %zu\n", analytics.total_executions);
    printf("Successful: %zu\n", analytics.successful_executions);
    printf("Failed: %zu\n", analytics.failed_executions);
    printf("In progress: %zu\n", analytics.in_progress_executions);
    printf("Unique functions: %zu\n", analytics.unique_functions);
    printf("Failure rate: %.2f%%\n", analytics.failure_rate_percent);

    functionlog_cleanup();
    return 0;
}
