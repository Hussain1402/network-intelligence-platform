
#include "network_metrics.h"

#include <ctype.h>
#include <errno.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_LINE_LENGTH 512
#define EXPECTED_COLUMNS 7

static void set_error(
    char *error,
    size_t error_capacity,
    const char *message
) {
    if (error != NULL && error_capacity > 0) {
        snprintf(error, error_capacity, "%s", message);
    }
}

static int is_leap_year(int year) {
    return (year % 400 == 0) ||
           ((year % 4 == 0) && (year % 100 != 0));
}

static int valid_timestamp(const char *s) {
    int year, month, day, hour, minute, second;
    int days_in_month[] = {
        31, 28, 31, 30, 31, 30,
        31, 31, 30, 31, 30, 31
    };

    if (s == NULL || strlen(s) != 19) {
        return 0;
    }

    /* YYYY-MM-DDTHH:MM:SS */
    if (s[4] != '-' || s[7] != '-' ||
        s[10] != 'T' || s[13] != ':' ||
        s[16] != ':') {
        return 0;
    }

    for (int i = 0; i < 19; i++) {
        if (i != 4 && i != 7 && i != 10 &&
            i != 13 && i != 16 &&
            !isdigit((unsigned char)s[i])) {
            return 0;
        }
    }

    if (sscanf(
            s,
            "%4d-%2d-%2dT%2d:%2d:%2d",
            &year, &month, &day,
            &hour, &minute, &second
        ) != 6) {
        return 0;
    }

    if (year < 1 || month < 1 || month > 12) {
        return 0;
    }

    if (is_leap_year(year)) {
        days_in_month[1] = 29;
    }

    if (day < 1 || day > days_in_month[month - 1]) {
        return 0;
    }

    if (hour > 23 || minute > 59 || second > 59) {
        return 0;
    }

    return 1;
}

static int parse_number(
    const char *text,
    double *value
) {
    char *end;
    double parsed;

    if (text == NULL || value == NULL || *text == '\0') {
        return 0;
    }

    errno = 0;
    parsed = strtod(text, &end);

    if (text == end || errno == ERANGE || !isfinite(parsed)) {
        return 0;
    }

    while (isspace((unsigned char)*end)) {
        end++;
    }

    if (*end != '\0' || parsed < 0.0) {
        return 0;
    }

    *value = parsed;
    return 1;
}

static int parse_csv_row(
    char *line,
    NetworkMetric *metric
) {
    char *columns[EXPECTED_COLUMNS];
    char *cursor;
    double latency;
    double packet_loss;
    double throughput;
    double error_rate;
    double memory_used_mb;
    double memory_usage_percent;

    /* Remove trailing newline characters. */
    line[strcspn(line, "\r\n")] = '\0';

    cursor = line;

    for (int i = 0; i < EXPECTED_COLUMNS; i++) {
        columns[i] = cursor;

        char *comma = strchr(cursor, ',');

        if (i < EXPECTED_COLUMNS - 1) {
            if (comma == NULL) {
                return 0;
            }

            *comma = '\0';
            cursor = comma + 1;
        } else if (comma != NULL) {
            /* More than the expected five columns. */
            return 0;
        }
    }

    if (!valid_timestamp(columns[0])) {
        return 0;
    }

    if (!parse_number(columns[1], &latency) ||
        !parse_number(columns[2], &packet_loss) ||
        !parse_number(columns[3], &throughput) ||
        !parse_number(columns[4], &error_rate) ||
        !parse_number(columns[5], &memory_used_mb) ||
        !parse_number(columns[6], &memory_usage_percent)) {
        return 0;
    }

    if (packet_loss > 100.0 ||
        error_rate > 100.0 ||
        memory_usage_percent > 100.0) {
        return 0;
    }

    snprintf(
        metric->timestamp,
        sizeof(metric->timestamp),
        "%s",
        columns[0]
    );

    metric->latency_ms = latency;
    metric->packet_loss_percent = packet_loss;
    metric->throughput_mbps = throughput;
    metric->error_rate_percent = error_rate;
    metric->memory_used_mb = memory_used_mb;
    metric->memory_usage_percent = memory_usage_percent;

    return 1;
}

int network_metrics_load_csv(
    const char *csv_path,
    NetworkMetric *metrics,
    size_t capacity,
    size_t *out_count,
    char *error,
    size_t error_capacity
) {
    FILE *file;
    char line[MAX_LINE_LENGTH];
    size_t count = 0;
    size_t line_number = 0;

    if (out_count != NULL) {
        *out_count = 0;
    }

    if (csv_path == NULL ||
        out_count == NULL ||
        (capacity > 0 && metrics == NULL)) {
        set_error(error, error_capacity, "Invalid function arguments.");
        return -1;
    }

    file = fopen(csv_path, "r");

    if (file == NULL) {
        set_error(error, error_capacity, "Could not open CSV file.");
        return -1;
    }

    /* Read and validate the header. */
    if (fgets(line, sizeof(line), file) == NULL) {
        set_error(error, error_capacity, "CSV file is empty.");
        fclose(file);
        return -1;
    }

    line_number++;

    line[strcspn(line, "\r\n")] = '\0';

    if (strcmp(
            line,
            "timestamp,latency_ms,packet_loss_percent,"
            "throughput_mbps,error_rate_percent,memory_used_mb,memory_usage_percent"
        ) != 0) {
        set_error(error, error_capacity, "CSV header does not match.");
        fclose(file);
        return -1;
    }

    while (fgets(line, sizeof(line), file) != NULL) {
        NetworkMetric parsed;
        line_number++;

        /* Reject a line that did not fit in the buffer. */
        if (strchr(line, '\n') == NULL && !feof(file)) {
            char message[128];
            int ch;

            while ((ch = fgetc(file)) != '\n' && ch != EOF) {
                /* Discard the remainder of the oversized line. */
            }

            snprintf(
                message,
                sizeof(message),
                "Line %lu exceeds the maximum line length.",
                (unsigned long)line_number
            );

            set_error(error, error_capacity, message);
            fclose(file);
            return -1;
        }

        /* Ignore completely blank lines. */
        if (line[strspn(line, " \t\r\n")] == '\0') {
            continue;
        }

        if (count >= capacity) {
            set_error(
                error,
                error_capacity,
                "Metrics array capacity exceeded."
            );
            fclose(file);
            return -1;
        }

        if (!parse_csv_row(line, &parsed)) {
            char message[128];

            snprintf(
                message,
                sizeof(message),
                "Invalid data on line %lu.",
                (unsigned long)line_number
            );

            set_error(error, error_capacity, message);
            fclose(file);
            return -1;
        }

        metrics[count++] = parsed;
    }

    if (ferror(file)) {
        set_error(error, error_capacity, "Error reading CSV file.");
        fclose(file);
        return -1;
    }

    fclose(file);

    if (count == 0) {
        set_error(error, error_capacity, "CSV contains no data rows.");
        return -1;
    }

    *out_count = count;
    set_error(error, error_capacity, "Success.");
    return 0;
}
