
#ifndef NETWORK_ANOMALY_H
#define NETWORK_ANOMALY_H

#include <stddef.h>

#include "network_metrics.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Configuration for network anomaly detection.
 *
 * A measurement is flagged when:
 * - Latency exceeds max_latency_ms.
 * - Packet loss exceeds max_packet_loss_percent.
 * - Throughput falls below min_throughput_mbps.
 * - Error rate exceeds max_error_rate_percent.
 */
typedef struct {
    double max_latency_ms;
    double max_packet_loss_percent;
    double min_throughput_mbps;
    double max_error_rate_percent;
    double max_memory_usage_percent;
} NetworkAnomalyConfig;

/*
 * Bit flags identifying individual anomaly conditions.
 * Multiple flags may be set for one measurement.
 */
typedef enum {
    NETWORK_ANOMALY_NONE = 0,
    NETWORK_ANOMALY_HIGH_LATENCY = 1 << 0,
    NETWORK_ANOMALY_HIGH_PACKET_LOSS = 1 << 1,
    NETWORK_ANOMALY_LOW_THROUGHPUT = 1 << 2,
    NETWORK_ANOMALY_HIGH_ERROR_RATE = 1 << 3,
    NETWORK_ANOMALY_HIGH_MEMORY_USAGE = 1 << 4
} NetworkAnomalyFlag;

/*
 * Result of analyzing one network measurement.
 */
typedef struct {
    char timestamp[NETWORK_METRICS_TIMESTAMP_LENGTH];

    double latency_ms;
    double packet_loss_percent;
    double throughput_mbps;
    double error_rate_percent;
    double memory_used_mb;
    double memory_usage_percent;

    unsigned int flags;
    int is_anomaly;
} NetworkAnomalyResult;

/*
 * Analyze one measurement against configured thresholds.
 *
 * metric: input measurement.
 * config: anomaly detection thresholds.
 * result: receives the analysis result.
 *
 * Returns 0 on success and -1 for invalid arguments or configuration.
 */
int network_anomaly_analyze_one(
    const NetworkMetric *metric,
    const NetworkAnomalyConfig *config,
    NetworkAnomalyResult *result
);

/*
 * Analyze multiple network measurements.
 *
 * metrics: input measurement array.
 * count: number of input measurements.
 * config: anomaly detection thresholds.
 * results: output array with capacity for at least count results.
 * capacity: number of elements available in results.
 * out_anomaly_count: receives the number of anomalous measurements.
 *
 * Returns 0 on success and -1 on failure.
 */
int network_anomaly_analyze(
    const NetworkMetric *metrics,
    size_t count,
    const NetworkAnomalyConfig *config,
    NetworkAnomalyResult *results,
    size_t capacity,
    size_t *out_anomaly_count
);

/*
 * Write an anomaly analysis report as JSON.
 *
 * output_path: destination file path.
 * results: array of analyzed measurements.
 * count: number of results.
 * config: thresholds used during analysis.
 *
 * Returns 0 on success and -1 on failure.
 */
int network_anomaly_write_json(
    const char *output_path,
    const NetworkAnomalyResult *results,
    size_t count,
    const NetworkAnomalyConfig *config
);

#ifdef __cplusplus
}
#endif

#endif
