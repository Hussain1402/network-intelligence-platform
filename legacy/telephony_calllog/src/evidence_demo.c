#include <stdio.h>
#include "calllog.h"

int main(int argc, char *argv[])
{
    CallLogStatus status;
    CallLogAnomalyConfig config = {60, 20.0, 5};

    if (argc != 3) {
        fprintf(stderr,
                "Usage: %s <input.csv> <output.json>\n",
                argv[0]);
        return 2;
    }

    status = calllog_init();
    if (status != CALLLOG_OK) {
        fprintf(stderr, "Failed to initialize call-log engine.\n");
        return 1;
    }

    status = calllog_set_anomaly_config(&config);
    if (status != CALLLOG_OK) {
        fprintf(stderr, "Failed to configure anomaly detection.\n");
        calllog_cleanup();
        return 1;
    }

    status = calllog_load_file(argv[1]);
    if (status != CALLLOG_OK) {
        fprintf(stderr, "Failed to load input CSV (status %d).\n",
                (int)status);
        calllog_cleanup();
        return 1;
    }

    status = calllog_generate_investigation(argv[2]);
    if (status != CALLLOG_OK) {
        fprintf(stderr, "Failed to generate JSON (status %d).\n",
                (int)status);
        calllog_cleanup();
        return 1;
    }

    printf("Investigation evidence written to: %s\n", argv[2]);

    calllog_cleanup();
    return 0;
}
