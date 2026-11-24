#include "network_analytics.h"

#include <stdio.h>
#include <string.h>

#define CHECK(condition, message) \
    do { \
        if (!(condition)) { \
            fprintf(stderr, "FAIL: %s\n", message); \
            return 1; \
        } \
    } while (0)

int main(void) {
    NetworkMetric metrics[3] = {
        {
            .latency_ms = 10,
            .packet_loss_percent = 1,
            .throughput_mbps = 100,
            .error_rate_percent = 2,
            .memory_used_mb = 100,
            .memory_usage_percent = 20
        },
        {
            .latency_ms = 20,
            .packet_loss_percent = 2,
            .throughput_mbps = 80,
            .error_rate_percent = 4,
            .memory_used_mb = 200,
            .memory_usage_percent = 40
        },
        {
            .latency_ms = 30,
            .packet_loss_percent = 3,
            .throughput_mbps = 60,
            .error_rate_percent = 6,
            .memory_used_mb = 300,
            .memory_usage_percent = 60
        }
    };

    NetworkAnomalyResult results[3] = {0};
    results[1].is_anomaly = 1;

    NetworkAnalyticsSummary summary;

    CHECK(
        network_analytics_calculate(
            metrics, results, 3, &summary
        ) == 0,
        "Analytics calculation failed."
    );

    CHECK(summary.total_measurements == 3,
          "Total count is incorrect.");
    CHECK(summary.anomaly_count == 1,
          "Anomaly count is incorrect.");
    CHECK(summary.normal_count == 2,
          "Normal count is incorrect.");
    CHECK(summary.anomaly_rate_percent > 33.33 &&
          summary.anomaly_rate_percent < 33.34,
          "Anomaly rate is incorrect.");

    CHECK(summary.latency_ms.minimum == 10,
          "Minimum latency is incorrect.");
    CHECK(summary.latency_ms.maximum == 30,
          "Maximum latency is incorrect.");
    CHECK(summary.latency_ms.average == 20,
          "Average latency is incorrect.");

    CHECK(summary.memory_used_mb.average == 200,
          "Average memory in MB is incorrect.");
    CHECK(summary.memory_usage_percent.average == 40,
          "Average memory percentage is incorrect.");

    const char *path = "output/network_analytics_test.json";

    CHECK(
        network_analytics_write_json(path, &summary) == 0,
        "JSON report generation failed."
    );

    FILE *file = fopen(path, "r");
    CHECK(file != NULL, "Could not open JSON report.");

    char buffer[8192];
    size_t bytes = fread(buffer, 1, sizeof(buffer) - 1, file);
    int read_error = ferror(file);
    fclose(file);

    CHECK(!read_error, "Could not read JSON report.");

    buffer[bytes] = '\0';

    CHECK(strstr(buffer, "memory_used_mb") != NULL,
          "Memory MB statistics are missing.");
    CHECK(strstr(buffer, "memory_usage_percent") != NULL,
          "Memory percentage statistics are missing.");

    CHECK(
        network_analytics_calculate(
            metrics, results, 0, &summary
        ) == -1,
        "Empty input should be rejected."
    );

    puts("PASS: Aggregate statistics verified.");
    puts("PASS: Memory analytics verified.");
    puts("PASS: Anomaly summary verified.");
    puts("PASS: JSON export verified.");
    puts("All network analytics tests passed.");

    return 0;
}