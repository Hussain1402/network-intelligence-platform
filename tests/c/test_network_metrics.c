
#include "network_metrics.h"

#include <stdio.h>
#include <string.h>

static int write_invalid_csv(const char *path) {
    FILE *file = fopen(path, "w");

    if (file == NULL) {
        return 0;
    }

    fprintf(
        file,
        "timestamp,latency_ms,packet_loss_percent,"
        "throughput_mbps,error_rate_percent,memory_used_mb,memory_usage_percent\n"
        "2026-10-15T10:00:00,40,101,95,0.5,512,42.7\n"
    );

    return fclose(file) == 0;
}

int main(void) {
    NetworkMetric metrics[16];
    size_t count = 0;
    char error[256];

    /* Test 1: Load the valid dataset. */
    int result = network_metrics_load_csv(
        "data/network_metrics.csv",
        metrics,
        16,
        &count,
        error,
        sizeof(error)
    );

    if (result != 0 || count != 12) {
        fprintf(stderr, "FAIL: Valid CSV: %s\n", error);
        return 1;
    }

    if (metrics[7].latency_ms != 240.0 ||
        metrics[7].packet_loss_percent != 7.0 ||
        metrics[7].throughput_mbps != 32.0 ||
        metrics[7].error_rate_percent != 18.0) {
        fprintf(stderr, "FAIL: Anomaly values are incorrect.\n");
        return 1;
    }

    if (metrics[0].memory_used_mb != 512.0 ||
        metrics[0].memory_usage_percent != 42.7) {
        fprintf(stderr, "FAIL: Memory metrics are incorrect.\n");
        return 1;
    }

    printf("PASS: Valid CSV loads all 12 records and memory metrics.\n");

    /* Test 2: The array cannot hold all 12 records. */
    count = 99;

    result = network_metrics_load_csv(
        "data/network_metrics.csv",
        metrics,
        9,
        &count,
        error,
        sizeof(error)
    );

    if (result == 0 || count != 0) {
        fprintf(stderr, "FAIL: Capacity limit was not enforced.\n");
        return 1;
    }

    printf("PASS: Insufficient capacity is rejected.\n");

    /* Test 3: Packet loss must not exceed 100 percent. */
    const char *invalid_path = "build/invalid_metrics.csv";

    if (!write_invalid_csv(invalid_path)) {
        fprintf(stderr, "FAIL: Could not create invalid test CSV.\n");
        return 1;
    }

    count = 99;

    result = network_metrics_load_csv(
        invalid_path,
        metrics,
        16,
        &count,
        error,
        sizeof(error)
    );

    remove(invalid_path);

    if (result == 0 || count != 0) {
        fprintf(stderr, "FAIL: Invalid percentage was accepted.\n");
        return 1;
    }

    printf("PASS: Invalid packet-loss percentage is rejected.\n");
    printf("All network metrics parser tests passed.\n");

    return 0;
}
