#include "network_metrics.h"
#include "network_anomaly.h"
#include "network_analytics.h"
#include "network_trends.h"

#include <stdio.h>
#include <string.h>

#define MAX_METRICS 1024
#define PATH_CAPACITY 512

int main(int argc, char *argv[]) {
    const char *input_path = "data/network_metrics.csv";
    const char *output_dir = "output";

    NetworkMetric metrics[MAX_METRICS];
    NetworkAnomalyResult results[MAX_METRICS];

    NetworkAnomalyConfig anomaly_config = {
        .max_latency_ms = 100.0,
        .max_packet_loss_percent = 2.0,
        .min_throughput_mbps = 60.0,
        .max_error_rate_percent = 5.0,
        .max_memory_usage_percent = 60.0
    };

    NetworkTrendConfig trend_config = {
        .baseline_count = 3,
        .minimum_consecutive_measurements = 2,
        .latency_increase_percent = 50.0,
        .packet_loss_increase_percent = 50.0,
        .throughput_decrease_percent = 30.0,
        .error_rate_increase_percent = 50.0,
        .memory_usage_increase_percent = 50.0
    };

    size_t count = 0;
    size_t anomaly_count = 0;
    char error[256] = {0};

    char anomaly_path[PATH_CAPACITY];
    char analytics_path[PATH_CAPACITY];
    char trends_path[PATH_CAPACITY];

    if (argc > 3) {
        fprintf(
            stderr,
            "Usage: %s [input.csv] [output_directory]\n",
            argv[0]
        );
        return 2;
    }

    if (argc >= 2) {
        input_path = argv[1];
    }

    if (argc >= 3) {
        output_dir = argv[2];
    }

    if (snprintf(
            anomaly_path,
            sizeof(anomaly_path),
            "%s/network_anomaly_report.json",
            output_dir
        ) >= (int)sizeof(anomaly_path) ||
        snprintf(
            analytics_path,
            sizeof(analytics_path),
            "%s/network_analytics_report.json",
            output_dir
        ) >= (int)sizeof(analytics_path) ||
        snprintf(
            trends_path,
            sizeof(trends_path),
            "%s/network_trend_report.json",
            output_dir
        ) >= (int)sizeof(trends_path)) {
        fprintf(stderr, "Output path is too long.\n");
        return 1;
    }

    if (network_metrics_load_csv(
            input_path,
            metrics,
            MAX_METRICS,
            &count,
            error,
            sizeof(error)
        ) != 0) {
        fprintf(stderr, "CSV loading failed: %s\n", error);
        return 1;
    }

    if (count <= trend_config.baseline_count) {
        fprintf(
            stderr,
            "At least %zu measurements are required for trend analysis.\n",
            trend_config.baseline_count + 1
        );
        return 1;
    }

    if (network_anomaly_analyze(
            metrics,
            count,
            &anomaly_config,
            results,
            MAX_METRICS,
            &anomaly_count
        ) != 0) {
        fprintf(stderr, "Network anomaly detection failed.\n");
        return 1;
    }

    if (network_anomaly_write_json(
            anomaly_path,
            results,
            count,
            &anomaly_config
        ) != 0) {
        fprintf(stderr, "Could not write anomaly report: %s\n", anomaly_path);
        return 1;
    }

    NetworkAnalyticsSummary analytics;

    if (network_analytics_calculate(
            metrics,
            results,
            count,
            &analytics
        ) != 0) {
        fprintf(stderr, "Network analytics calculation failed.\n");
        return 1;
    }

    if (network_analytics_write_json(
            analytics_path,
            &analytics
        ) != 0) {
        fprintf(stderr, "Could not write analytics report: %s\n", analytics_path);
        return 1;
    }

    NetworkTrendSummary trends;

    if (network_trends_analyze(
            metrics,
            count,
            &trend_config,
            &trends
        ) != 0) {
        fprintf(stderr, "Network trend analysis failed.\n");
        return 1;
    }

    if (network_trends_write_json(
            trends_path,
            &trends
        ) != 0) {
        fprintf(stderr, "Could not write trend report: %s\n", trends_path);
        return 1;
    }

    printf("\nPS2 network analysis completed successfully.\n");
    printf("Input CSV: %s\n", input_path);
    printf("Total measurements: %zu\n", count);
    printf("Normal measurements: %zu\n", count - anomaly_count);
    printf("Anomalous measurements: %zu\n", anomaly_count);

    printf("\nGenerated reports:\n");
    printf("1. %s\n", anomaly_path);
    printf("2. %s\n", analytics_path);
    printf("3. %s\n", trends_path);

    printf("\nAggregate anomaly rate: %.2f%%\n", analytics.anomaly_rate_percent);
    printf(
        "Trend baseline measurements: %zu\n",
        trends.baseline_measurements
    );

    return 0;
}
