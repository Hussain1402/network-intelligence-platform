
#include "network_anomaly.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(condition, message)       \
    do {                                \
        if (!(condition)) {             \
            fprintf(stderr,             \
                    "FAIL: %s\n",        \
                    message);            \
            return 1;                   \
        }                               \
    } while (0)

int main(void) {
    NetworkMetric metrics[16];
    NetworkAnomalyResult results[16];

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

    const char *report_path = "build/network_anomaly_report.json";

    /* Test 1: Load the CSV. */
    int load_result = network_metrics_load_csv(
        "data/network_metrics.csv",
        metrics,
        16,
        &count,
        error,
        sizeof(error)
    );

    CHECK(load_result == 0, error);
    CHECK(count == 12, "Expected 10 input measurements.");

    /* Test 2: Analyze all measurements. */
    int result = network_anomaly_analyze(
        metrics,
        count,
        &config,
        results,
        16,
        &anomaly_count
    );

    CHECK(result == 0, "Anomaly analysis failed.");
    CHECK(anomaly_count == 3,
          "Expected exactly 3 anomalous measurements.");

    /* The first six records should be normal. */
    for (size_t i = 0; i < 6; i++) {
        CHECK(results[i].is_anomaly == 0,
              "A normal measurement was flagged.");
        CHECK(results[i].flags == NETWORK_ANOMALY_NONE,
              "A normal measurement has unexpected flags.");
    }

    /* The three degraded records should trigger all four flags. */
    const unsigned int expected_flags =
        NETWORK_ANOMALY_HIGH_LATENCY |
        NETWORK_ANOMALY_HIGH_PACKET_LOSS |
        NETWORK_ANOMALY_LOW_THROUGHPUT |
        NETWORK_ANOMALY_HIGH_ERROR_RATE |
        NETWORK_ANOMALY_HIGH_MEMORY_USAGE;

    for (size_t i = 6; i < 9; i++) {
        CHECK(results[i].is_anomaly == 1,
              "Expected an anomalous measurement.");
        CHECK(results[i].flags == expected_flags,
              "Expected all four anomaly flags.");
    }

    /* The final three records should show recovery. */
    /* The final three records should show recovery. */
    for (size_t i = 9; i < 12; i++) {
        CHECK(results[i].is_anomaly == 0,
              "A recovery measurement should be normal.");
    }
    /* Test 3: Generate the JSON report. */
    result = network_anomaly_write_json(
        report_path,
        results,
        count,
        &config
    );

    CHECK(result == 0, "Could not write JSON anomaly report.");

    FILE *report = fopen(report_path, "r");
    CHECK(report != NULL, "Generated report cannot be opened.");

    char contents[16384];
    size_t bytes_read = fread(
        contents,
        1,
        sizeof(contents) - 1,
        report
    );

    int read_error = ferror(report);
    fclose(report);

    CHECK(!read_error, "Could not read generated report.");

    contents[bytes_read] = '\0';

    CHECK(
        strstr(contents, "\"report_type\": \"network_anomaly_report\"")
            != NULL,
        "Report type is missing."
    );

    CHECK(
        strstr(contents, "\"total_measurements\": 12") != NULL,
        "Total measurement count is incorrect."
    );

    CHECK(
        strstr(contents, "\"anomaly_count\": 3") != NULL,
        "Anomaly count is incorrect."
    );

    CHECK(
        strstr(contents, "\"normal_count\": 9") != NULL,
        "Normal count is incorrect."
    );

    CHECK(
        strstr(contents, "\"high_latency\"") != NULL,
        "High-latency reason is missing."
    );

    CHECK(
        strstr(contents, "\"high_packet_loss\"") != NULL,
        "High packet-loss reason is missing."
    );

    CHECK(
        strstr(contents, "\"low_throughput\"") != NULL,
        "Low-throughput reason is missing."
    );

    CHECK(
        strstr(contents, "\"high_error_rate\"") != NULL,
        "High error-rate reason is missing."
    );

    CHECK(
        strstr(contents, "\"high_memory_usage\"") != NULL,
        "High memory usage reason is missing."
    );

    CHECK(
        strstr(contents, "\"memory_used_mb\": 920") != NULL,
        "Memory MB measurement is missing."
    );

    CHECK(
        strstr(contents, "\"memory_usage_percent\": 76.7") != NULL,
        "Memory percentage measurement is missing."
    );

    printf("PASS: JSON report generated.\n");
    printf("PASS: Report summary and anomaly reasons verified.\n");
    printf("Report location: %s\n", report_path);
    printf("All network anomaly tests passed.\n");

    return 0;
}
