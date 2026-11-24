#ifndef NETWORK_ANALYTICS_H
#define NETWORK_ANALYTICS_H

#include <stddef.h>
#include "network_metrics.h"
#include "network_anomaly.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    double minimum;
    double maximum;
    double average;
} NetworkMetricStatistics;

typedef struct {
    size_t total_measurements;
    size_t anomaly_count;
    size_t normal_count;
    double anomaly_rate_percent;

    NetworkMetricStatistics latency_ms;
    NetworkMetricStatistics packet_loss_percent;
    NetworkMetricStatistics throughput_mbps;
    NetworkMetricStatistics error_rate_percent;
    NetworkMetricStatistics memory_used_mb;
    NetworkMetricStatistics memory_usage_percent;
} NetworkAnalyticsSummary;

/*
 * Calculate aggregate statistics for network measurements.
 *
 * metrics: input network measurements.
 * count: number of measurements.
 * results: corresponding anomaly results, or NULL if unavailable.
 * summary: output aggregate statistics.
 *
 * Returns 0 on success, -1 on invalid arguments or data.
 */
int network_analytics_calculate(
    const NetworkMetric *metrics,
    const NetworkAnomalyResult *results,
    size_t count,
    NetworkAnalyticsSummary *summary
);

/*
 * Write aggregate analytics to a JSON file.
 *
 * Returns 0 on success, -1 on failure.
 */
int network_analytics_write_json(
    const char *output_path,
    const NetworkAnalyticsSummary *summary
);

#ifdef __cplusplus
}
#endif

#endif