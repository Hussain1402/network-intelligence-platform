#ifndef FUNCTIONLOG_H
#define FUNCTIONLOG_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FUNCTIONLOG_NAME_MAX 128
#define FUNCTIONLOG_ERROR_MAX 256
#define FUNCTIONLOG_MAX_ACTIVE 1024
#define FUNCTIONLOG_MAX_UNIQUE_FUNCTIONS 256

typedef enum {
    FUNCTIONLOG_SUCCESS = 0,
    FUNCTIONLOG_FAILED = 1
} FunctionLogStatus;

typedef enum {
    FUNCTIONLOG_OK = 0,
    FUNCTIONLOG_ERROR_INVALID_ARGUMENT,
    FUNCTIONLOG_ERROR_NOT_INITIALIZED,
    FUNCTIONLOG_ERROR_MEMORY,
    FUNCTIONLOG_ERROR_IO,
    FUNCTIONLOG_ERROR_NOT_FOUND,
    FUNCTIONLOG_ERROR_LIMIT
} FunctionLogResult;

typedef struct {
    unsigned long long id;
    unsigned long long parent_id;
    char function_name[FUNCTIONLOG_NAME_MAX];
    char caller_name[FUNCTIONLOG_NAME_MAX];
    char start_timestamp[32];
    char end_timestamp[32];
    double execution_time_ms;
    FunctionLogStatus status;
    int error_code;
    char error_message[FUNCTIONLOG_ERROR_MAX];
} FunctionLogRecord;

typedef struct {
    char function_name[FUNCTIONLOG_NAME_MAX];

    size_t total_executions;
    size_t successful_executions;
    size_t failed_executions;

    double average_execution_time_ms;
    double minimum_execution_time_ms;
    double maximum_execution_time_ms;
} FunctionLogFunctionStats;

typedef struct {
    size_t total_executions;
    size_t successful_executions;
    size_t failed_executions;
    size_t in_progress_executions;
    size_t unique_functions;

    double failure_rate_percent;
    double average_execution_time_ms;
    double minimum_execution_time_ms;
    double maximum_execution_time_ms;

    FunctionLogFunctionStats functions[
        FUNCTIONLOG_MAX_UNIQUE_FUNCTIONS
    ];
} FunctionLogAnalytics;

/* Initialize the function execution logger. */
FunctionLogResult functionlog_init(void);

/*
 * Call only after all threads using the logger have stopped.
 * Concurrent cleanup and logging operations are not supported.
 */
void functionlog_cleanup(void);

FunctionLogResult functionlog_enter(
    const char *function_name,
    const char *caller_name,
    unsigned long long *execution_id
);

/*
 * Complete an execution started by functionlog_enter().
 * Must be called on the same thread and in reverse order of nested entries.
 */
FunctionLogResult functionlog_exit(
    unsigned long long execution_id,
    FunctionLogStatus status,
    int error_code,
    const char *error_message
);

FunctionLogResult functionlog_export_csv(const char *output_path);


FunctionLogResult functionlog_export_json(const char *output_path);
FunctionLogResult functionlog_get_analytics(
    FunctionLogAnalytics *analytics
);

#ifdef __cplusplus
}
#endif

#endif
