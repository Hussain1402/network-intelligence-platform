
#ifndef NETWORK_METRICS_H
#define NETWORK_METRICS_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NETWORK_METRICS_TIMESTAMP_LENGTH 20

typedef struct {
    char timestamp[NETWORK_METRICS_TIMESTAMP_LENGTH];

    double latency_ms;
    double packet_loss_percent;
    double throughput_mbps;
    double error_rate_percent;
    double memory_used_mb;
    double memory_usage_percent;
} NetworkMetric;

/*
 * Load and validate network metrics from a CSV file.
 *
 * csv_path: path to the input CSV.
 * metrics: caller-provided array for validated records.
 * capacity: maximum number of records the array can hold.
 * out_count: receives the number of successfully loaded records.
 * error: optional buffer for an error message.
 * error_capacity: size of the error buffer.
 *
 * Returns 0 on success and -1 on failure.
 */
int network_metrics_load_csv(
    const char *csv_path,
    NetworkMetric *metrics,
    size_t capacity,
    size_t *out_count,
    char *error,
    size_t error_capacity
);

#ifdef __cplusplus
}
#endif

#endif
