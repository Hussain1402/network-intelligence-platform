
#ifndef CALLLOG_H
#define CALLLOG_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CALLLOG_FAILURE_CODE_MAX 256
#define CALLLOG_TIMESTAMP_MAX 32

typedef enum {
    CALLLOG_OK = 0,
    CALLLOG_ERROR_INVALID_ARGUMENT,
    CALLLOG_ERROR_NOT_INITIALIZED,
    CALLLOG_ERROR_FILE,
    CALLLOG_ERROR_INVALID_DATA,
    CALLLOG_ERROR_MEMORY
} CallLogStatus;

typedef struct {
    unsigned long total_calls;
    unsigned long successful_calls;
    unsigned long failed_calls;
    double failure_rate_percent;
    double average_success_duration_ms;
} CallLogSummary;

typedef struct {
    char code[CALLLOG_FAILURE_CODE_MAX];
    unsigned long count;
} CallLogFailureCode;

typedef struct {
    unsigned long window_seconds;
    double failure_rate_threshold_percent;
    unsigned long minimum_calls;
} CallLogAnomalyConfig;

typedef struct {
    char window_start[CALLLOG_TIMESTAMP_MAX];
    unsigned long total_calls;
    unsigned long failed_calls;
    double failure_rate_percent;
} CallLogAnomaly;

CallLogStatus calllog_init(void);
CallLogStatus calllog_load_file(const char *path);
CallLogStatus calllog_get_summary(CallLogSummary *summary);

CallLogStatus calllog_get_failure_codes(
    CallLogFailureCode *codes,
    size_t capacity,
    size_t *count
);

/* Configure detection. Must be called after initialization. */
CallLogStatus calllog_set_anomaly_config(
    const CallLogAnomalyConfig *config
);

/* Query the number of detected anomaly windows. */
CallLogStatus calllog_get_anomalies(
    CallLogAnomaly *anomalies,
    size_t capacity,
    size_t *count
);
CallLogStatus calllog_generate_investigation(const char *path);

void calllog_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif
