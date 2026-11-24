#ifndef NETWORK_TRENDS_H
#define NETWORK_TRENDS_H

#include <stddef.h>
#include "network_metrics.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NETWORK_TREND_METRIC_COUNT 5

typedef enum {
    NETWORK_TREND_LATENCY = 0,
    NETWORK_TREND_PACKET_LOSS,
    NETWORK_TREND_THROUGHPUT,
    NETWORK_TREND_ERROR_RATE,
    NETWORK_TREND_MEMORY_USAGE
} NetworkTrendMetric;

typedef struct {
    size_t baseline_count;
    size_t minimum_consecutive_measurements;

    double latency_increase_percent;
    double packet_loss_increase_percent;
    double throughput_decrease_percent;
    double error_rate_increase_percent;
    double memory_usage_increase_percent;
} NetworkTrendConfig;

typedef struct {
    int detected;
    int recovered;

    char start_timestamp[NETWORK_METRICS_TIMESTAMP_LENGTH];
    char end_timestamp[NETWORK_METRICS_TIMESTAMP_LENGTH];
    char recovery_timestamp[NETWORK_METRICS_TIMESTAMP_LENGTH];

    double baseline_average;
    double observed_average;
    double deviation_percent;
    int deviation_percent_defined;

    size_t consecutive_measurements;
} NetworkTrendEvent;

typedef struct {
    size_t total_measurements;
    size_t baseline_measurements;
    size_t analyzed_measurements;

    NetworkTrendEvent events[NETWORK_TREND_METRIC_COUNT];
} NetworkTrendSummary;

/*
 * Analyze measurements against an initial historical baseline.
 *
 * The first baseline_count measurements establish the baseline.
 * Remaining measurements are examined for sustained deviations.
 *
 * Returns 0 on success, -1 on invalid arguments or data.
 */
int network_trends_analyze(
    const NetworkMetric *metrics,
    size_t count,
    const NetworkTrendConfig *config,
    NetworkTrendSummary *summary
);

/* Export trend findings as JSON. */
int network_trends_write_json(
    const char *output_path,
    const NetworkTrendSummary *summary
);

#ifdef __cplusplus
}
#endif

#endif