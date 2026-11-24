
#include <stdio.h>
#include <stdlib.h>

#include "calllog.h"

int main(int argc, char *argv[])
{
    CallLogSummary summary;
    CallLogFailureCode *codes = NULL;
    CallLogAnomaly *anomalies = NULL;

    size_t code_count = 0;
    size_t anomaly_count = 0;
    size_t i;

    CallLogStatus status;
    const char *path;

    CallLogAnomalyConfig config = {
        60,     /* Window length in seconds */
        20.0,   /* Failure-rate threshold */
        5       /* Minimum calls per window */
    };

    if (argc > 2) {
        fprintf(stderr, "Usage: %s [path-to-csv]\n", argv[0]);
        return 2;
    }

    path = (argc == 2)
        ? argv[1]
        : "data/sample_calls.csv";

    status = calllog_init();

    if (status != CALLLOG_OK) {
        fprintf(stderr, "Library initialization failed.\n");
        return 1;
    }

    status = calllog_set_anomaly_config(&config);

    if (status != CALLLOG_OK) {
        fprintf(stderr, "Failed to configure anomaly detection.\n");
        calllog_cleanup();
        return 1;
    }

    status = calllog_load_file(path);

    if (status != CALLLOG_OK) {
        fprintf(stderr, "Failed to load CSV (error code %d).\n",
                (int)status);
        calllog_cleanup();
        return 1;
    }

    status = calllog_get_summary(&summary);

    if (status != CALLLOG_OK) {
        fprintf(stderr, "Failed to retrieve summary.\n");
        calllog_cleanup();
        return 1;
    }

    status = calllog_get_failure_codes(
        NULL, 0, &code_count
    );

    if (status != CALLLOG_OK) {
        fprintf(stderr, "Failed to query failure codes.\n");
        calllog_cleanup();
        return 1;
    }

    if (code_count > 0) {
        codes = malloc(code_count * sizeof(*codes));

        if (codes == NULL) {
            fprintf(stderr, "Out of memory.\n");
            calllog_cleanup();
            return 1;
        }

        status = calllog_get_failure_codes(
            codes, code_count, &code_count
        );

        if (status != CALLLOG_OK) {
            fprintf(stderr, "Failed to retrieve failure codes.\n");
            free(codes);
            calllog_cleanup();
            return 1;
        }
    }

    status = calllog_get_anomalies(
        NULL, 0, &anomaly_count
    );

    if (status != CALLLOG_OK) {
        fprintf(stderr, "Failed to query anomalies.\n");
        free(codes);
        calllog_cleanup();
        return 1;
    }

    if (anomaly_count > 0) {
        anomalies = malloc(
            anomaly_count * sizeof(*anomalies)
        );

        if (anomalies == NULL) {
            fprintf(stderr, "Out of memory.\n");
            free(codes);
            calllog_cleanup();
            return 1;
        }

        status = calllog_get_anomalies(
            anomalies, anomaly_count, &anomaly_count
        );

        if (status != CALLLOG_OK) {
            fprintf(stderr, "Failed to retrieve anomalies.\n");
            free(anomalies);
            free(codes);
            calllog_cleanup();
            return 1;
        }
    }

    printf("Call Log Analysis Results\n");
    printf("-------------------------\n");
    printf("Input file: %s\n", path);
    printf("Total calls: %lu\n", summary.total_calls);
    printf("Successful calls: %lu\n", summary.successful_calls);
    printf("Failed calls: %lu\n", summary.failed_calls);
    printf("Failure rate: %.2f%%\n",
           summary.failure_rate_percent);
    printf("Average successful call duration: %.2f ms\n",
           summary.average_success_duration_ms);

    printf("\nFailure-Code Distribution\n");
    printf("-------------------------\n");

    if (code_count == 0) {
        printf("No failure codes found.\n");
    }

    for (i = 0; i < code_count; i++) {
        printf("%s: %lu\n",
               codes[i].code,
               codes[i].count);
    }

    printf("\nTime-Window Anomalies\n");
    printf("---------------------\n");

    if (anomaly_count == 0) {
        printf("No anomalous windows detected.\n");
    }

    for (i = 0; i < anomaly_count; i++) {
        printf("Window start: %s UTC\n",
               anomalies[i].window_start);

        printf("Total calls: %lu\n",
               anomalies[i].total_calls);

        printf("Failed calls: %lu\n",
               anomalies[i].failed_calls);

        printf("Failure rate: %.2f%%\n\n",
               anomalies[i].failure_rate_percent);
    }

    free(anomalies);
    free(codes);
    calllog_cleanup();

    return 0;
}
