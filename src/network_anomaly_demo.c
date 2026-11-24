
#include "network_anomaly.h"

#include <stdio.h>

#define MAX_METRICS 1024

int main(int argc, char *argv[]) {
    const char *input_path = "data/network_metrics.csv";
    const char *output_path = "output/network_anomaly_report.json";

    NetworkMetric metrics[MAX_METRICS];
    NetworkAnomalyResult results[MAX_METRICS];

    NetworkAnomalyConfig config = {
        .max_latency_ms = 100.0,
        .max_packet_loss_percent = 2.0,
        .min_throughput_mbps = 60.0,
        .max_error_rate_percent = 5.0,
        .max_memory_usage_percent = 60.0
    };

    size_t count = 0;
    size_t anomaly_count = 0;
    char error[256];

    if (argc > 3) {
        fprintf(
            stderr,
            "Usage: %s [input.csv] [output.json]\n",
            argv[0]
        );
        return 2;
    }

    if (argc >= 2) {
        input_path = argv[1];
    }

    if (argc >= 3) {
        output_path = argv[2];
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

    if (network_anomaly_analyze(
            metrics,
            count,
            &config,
            results,
            MAX_METRICS,
            &anomaly_count
        ) != 0) {
        fprintf(stderr, "Network anomaly analysis failed.\n");
        return 1;
    }

    if (network_anomaly_write_json(
            output_path,
            results,
            count,
            &config
        ) != 0) {
        fprintf(
            stderr,
            "Could not write report to: %s\n",
            output_path
        );
        return 1;
    }

    printf("Network metrics analysis completed.\n");
    printf("Input file: %s\n", input_path);
    printf("Total measurements: %zu\n", count);
    printf("Normal measurements: %zu\n", count - anomaly_count);
    printf("Anomalous measurements: %zu\n", anomaly_count);
    printf("Report saved to: %s\n", output_path);

    return 0;
}
