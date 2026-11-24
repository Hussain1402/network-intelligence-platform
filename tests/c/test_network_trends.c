#include "network_trends.h"

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
    NetworkMetric metrics[8] = {
        {
            .timestamp = "2026-10-15T10:00:00",
            .latency_ms = 10,
            .packet_loss_percent = 1,
            .throughput_mbps = 100,
            .error_rate_percent = 1,
            .memory_used_mb = 200,
            .memory_usage_percent = 20
        },
        {
            .timestamp = "2026-10-15T10:01:00",
            .latency_ms = 10,
            .packet_loss_percent = 1,
            .throughput_mbps = 100,
            .error_rate_percent = 1,
            .memory_used_mb = 200,
            .memory_usage_percent = 20
        },
        {
            .timestamp = "2026-10-15T10:02:00",
            .latency_ms = 10,
            .packet_loss_percent = 1,
            .throughput_mbps = 100,
            .error_rate_percent = 1,
            .memory_used_mb = 200,
            .memory_usage_percent = 20
        },
        {
            .timestamp = "2026-10-15T10:03:00",
            .latency_ms = 20,
            .packet_loss_percent = 2,
            .throughput_mbps = 50,
            .error_rate_percent = 2,
            .memory_used_mb = 400,
            .memory_usage_percent = 40
        },
        {
            .timestamp = "2026-10-15T10:04:00",
            .latency_ms = 20,
            .packet_loss_percent = 2,
            .throughput_mbps = 50,
            .error_rate_percent = 2,
            .memory_used_mb = 400,
            .memory_usage_percent = 40
        },
        {
            .timestamp = "2026-10-15T10:05:00",
            .latency_ms = 10,
            .packet_loss_percent = 1,
            .throughput_mbps = 100,
            .error_rate_percent = 1,
            .memory_used_mb = 200,
            .memory_usage_percent = 20
        },
        {
            .timestamp = "2026-10-15T10:06:00",
            .latency_ms = 10,
            .packet_loss_percent = 1,
            .throughput_mbps = 100,
            .error_rate_percent = 1,
            .memory_used_mb = 200,
            .memory_usage_percent = 20
        },
        {
            .timestamp = "2026-10-15T10:07:00",
            .latency_ms = 10,
            .packet_loss_percent = 1,
            .throughput_mbps = 100,
            .error_rate_percent = 1,
            .memory_used_mb = 200,
            .memory_usage_percent = 20
        }
    };

    NetworkTrendConfig config = {
        .baseline_count = 3,
        .minimum_consecutive_measurements = 2,
        .latency_increase_percent = 50,
        .packet_loss_increase_percent = 50,
        .throughput_decrease_percent = 30,
        .error_rate_increase_percent = 50,
        .memory_usage_increase_percent = 50
    };

    NetworkTrendSummary summary;

    CHECK(
        network_trends_analyze(
            metrics, 8, &config, &summary
        ) == 0,
        "Trend analysis failed."
    );

    CHECK(summary.baseline_measurements == 3,
          "Baseline count is incorrect.");

    CHECK(summary.analyzed_measurements == 5,
          "Analyzed measurement count is incorrect.");

    for (size_t i = 0; i < NETWORK_TREND_METRIC_COUNT; i++) {
        CHECK(summary.events[i].detected,
              "Expected sustained trend was not detected.");

        CHECK(summary.events[i].recovered,
              "Expected recovery was not detected.");

        CHECK(summary.events[i].consecutive_measurements == 2,
              "Incorrect sustained trend duration.");
    }

    CHECK(
        strcmp(
            summary.events[NETWORK_TREND_LATENCY].start_timestamp,
            "2026-10-15T10:03:00"
        ) == 0,
        "Trend start timestamp is incorrect."
    );

    CHECK(
        strcmp(
            summary.events[NETWORK_TREND_LATENCY].recovery_timestamp,
            "2026-10-15T10:05:00"
        ) == 0,
        "Recovery timestamp is incorrect."
    );

    const char *path = "output/network_trends_test.json";

    CHECK(
        network_trends_write_json(path, &summary) == 0,
        "Trend JSON export failed."
    );

    FILE *file = fopen(path, "r");
    CHECK(file != NULL, "Cannot open trend report.");

    char buffer[8192];
    size_t bytes = fread(buffer, 1, sizeof(buffer) - 1, file);
    int read_error = ferror(file);
    fclose(file);

    CHECK(!read_error, "Cannot read trend report.");

    buffer[bytes] = '\0';

    CHECK(strstr(buffer, "network_trend_report") != NULL,
          "Report type is missing.");

    CHECK(strstr(buffer, "memory_usage") != NULL,
          "Memory trend is missing.");

    CHECK(strstr(buffer, "\"recovered\": true") != NULL,
          "Recovery status is missing.");

    /* A sustained trend without enough healthy readings must remain unrecovered. */
    NetworkMetric unrecovered[8];

    memcpy(unrecovered, metrics, sizeof(metrics));

    for (size_t i = 5; i < 8; i++) {
        unrecovered[i] = metrics[4];
        snprintf(
            unrecovered[i].timestamp,
            sizeof(unrecovered[i].timestamp),
            "2026-10-15T10:%02d:00",
            (int)(5 + i)
        );
    }

    CHECK(
        network_trends_analyze(
            unrecovered, 8, &config, &summary
        ) == 0,
        "Unrecovered trend analysis failed."
    );

    for (size_t i = 0; i < NETWORK_TREND_METRIC_COUNT; i++) {
        CHECK(
            summary.events[i].detected,
            "Expected unrecovered trend was not detected."
        );

        CHECK(
            !summary.events[i].recovered,
            "Trend without recovery readings was incorrectly marked recovered."
        );
    }
    /* A single spike must not be considered a sustained trend. */
    NetworkMetric single_spike[5];

    for (size_t i = 0; i < 5; i++) {
        single_spike[i] = metrics[i < 3 ? i : 2];
    }

    single_spike[3].timestamp[17] = '3';
    single_spike[4].timestamp[17] = '4';
    single_spike[3].latency_ms = 30;
    single_spike[4].latency_ms = 10;

    CHECK(
        network_trends_analyze(
            single_spike, 5, &config, &summary
        ) == 0,
        "Single-spike analysis failed."
    );

    CHECK(
        !summary.events[NETWORK_TREND_LATENCY].detected,
        "A single spike was incorrectly classified as sustained."
    );

    NetworkMetric zero_baseline[5];
    memcpy(zero_baseline, metrics, sizeof(zero_baseline));
    for (size_t i = 0; i < 5; i++) {
        snprintf(
            zero_baseline[i].timestamp,
            sizeof(zero_baseline[i].timestamp),
            "2026-10-15T11:00:%02d",
            (int)i
        );
        zero_baseline[i].latency_ms = i < 3 ? 0.0 : 10.0;
    }

    CHECK(
        network_trends_analyze(
            zero_baseline, 5, &config, &summary
        ) == 0,
        "Zero-baseline trend analysis failed."
    );
    CHECK(
        summary.events[NETWORK_TREND_LATENCY].detected,
        "Positive measurements after a zero baseline were not detected."
    );
    CHECK(
        !summary.events[NETWORK_TREND_LATENCY].deviation_percent_defined,
        "A relative deviation from a zero baseline must be undefined."
    );

    const char *zero_baseline_path = "output/network_zero_baseline_test.json";
    CHECK(
        network_trends_write_json(zero_baseline_path, &summary) == 0,
        "Zero-baseline trend report export failed."
    );
    file = fopen(zero_baseline_path, "r");
    CHECK(file != NULL, "Cannot open zero-baseline trend report.");
    bytes = fread(buffer, 1, sizeof(buffer) - 1, file);
    read_error = ferror(file);
    fclose(file);
    CHECK(!read_error, "Cannot read zero-baseline trend report.");
    buffer[bytes] = '\0';
    CHECK(
        strstr(buffer, "\"deviation_percent\": null") != NULL,
        "Undefined relative change must be emitted as JSON null."
    );
    remove(zero_baseline_path);

    NetworkMetric out_of_order[8];
    memcpy(out_of_order, metrics, sizeof(out_of_order));
    NetworkMetric temporary = out_of_order[3];
    out_of_order[3] = out_of_order[4];
    out_of_order[4] = temporary;
    CHECK(
        network_trends_analyze(
            out_of_order, 8, &config, &summary
        ) == -1,
        "Out-of-order measurements must be rejected for trend analysis."
    );

    puts("PASS: Historical baseline calculation verified.");
    puts("PASS: Five metric trends detected.");
    puts("PASS: Sustained degradation verified.");
    puts("PASS: Recovery detection verified.");
    puts("PASS: Single-spike rejection verified.");
    puts("PASS: Zero-baseline relative changes remain undefined.");
    puts("PASS: Out-of-order measurements are rejected.");
    puts("PASS: Trend JSON export verified.");
    puts("All network trend tests passed.");

    return 0;
}
