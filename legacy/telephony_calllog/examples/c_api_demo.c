#include <stdio.h>
#include "calllog.h"

int main(int argc, char *argv[])
{
    CallLogStatus status;
    CallLogSummary summary;
    CallLogAnomalyConfig config = {60, 20.0, 5};

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <input.csv>\n", argv[0]);
        return 2;
    }

    status = calllog_init();
    if (status != CALLLOG_OK) {
        fprintf(stderr, "Initialization failed: %d\n", (int)status);
        return 1;
    }

    status = calllog_set_anomaly_config(&config);
    if (status != CALLLOG_OK) {
        fprintf(stderr, "Configuration failed: %d\n", (int)status);
        calllog_cleanup();
        return 1;
    }

    status = calllog_load_file(argv[1]);
    if (status != CALLLOG_OK) {
        fprintf(stderr, "Loading CSV failed: %d\n", (int)status);
        calllog_cleanup();
        return 1;
    }

    status = calllog_get_summary(&summary);
    if (status != CALLLOG_OK) {
        fprintf(stderr, "Reading summary failed: %d\n", (int)status);
        calllog_cleanup();
        return 1;
    }

    printf("Total calls: %lu\n", summary.total_calls);
    printf("Successful calls: %lu\n", summary.successful_calls);
    printf("Failed calls: %lu\n", summary.failed_calls);
    printf("Failure rate: %.2f%%\n", summary.failure_rate_percent);
    printf("Average successful duration: %.2f ms\n",
           summary.average_success_duration_ms);

    calllog_cleanup();
    return 0;
}
