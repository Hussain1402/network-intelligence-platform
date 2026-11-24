#include "functionlog.h"

#include <stdio.h>

static int validate_input(void)
{
    unsigned long long id = 0;

    FunctionLogResult result =
        functionlog_enter("validate_input", "process_request", &id);

    if (result != FUNCTIONLOG_OK) {
        fprintf(stderr, "Could not start validate_input monitoring.\n");
        return -1;
    }

    int valid = 1;

    result = functionlog_exit(
        id,
        valid ? FUNCTIONLOG_SUCCESS : FUNCTIONLOG_FAILED,
        valid ? 0 : 1002,
        valid ? NULL : "Input validation failed"
    );

    if (result != FUNCTIONLOG_OK) {
        fprintf(stderr, "Could not complete validate_input monitoring.\n");
        return -1;
    }

    return valid;
}

static int process_request(void)
{
    unsigned long long id = 0;

    FunctionLogResult result =
        functionlog_enter("process_request", "main", &id);

    if (result != FUNCTIONLOG_OK) {
        fprintf(stderr, "Could not start process_request monitoring.\n");
        return -1;
    }

    int operation_result = validate_input();
    int success = operation_result >= 0;

    result = functionlog_exit(
        id,
        success ? FUNCTIONLOG_SUCCESS : FUNCTIONLOG_FAILED,
        success ? 0 : 1002,
        success ? NULL : "Input validation or monitoring failed"
    );

    if (result != FUNCTIONLOG_OK) {
        fprintf(stderr, "Could not complete process_request monitoring.\n");
        return -1;
    }

    return operation_result;
}

int main(void)
{
    if (functionlog_init() != FUNCTIONLOG_OK) {
        fprintf(stderr, "Logger initialization failed.\n");
        return 1;
    }

    int result = process_request();

    if (result < 0) {
        fprintf(stderr, "Request processing failed.\n");
        functionlog_cleanup();
        return 1;
    }

    printf("Request result: %d\n", result);

    if (functionlog_export_csv("output/function_execution_logs.csv")
        != FUNCTIONLOG_OK) {
        fprintf(stderr, "CSV export failed.\n");
        functionlog_cleanup();
        return 1;
    }

    printf("Function execution logs exported.\n");

    if (functionlog_export_json("output/function_execution_evidence.json")
        != FUNCTIONLOG_OK) {
        fprintf(stderr, "JSON evidence export failed.\n");
        functionlog_cleanup();
        return 1;
    }

    printf("JSON evidence exported.\n");

    functionlog_cleanup();
    return 0;
}
