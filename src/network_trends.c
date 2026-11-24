#include "network_trends.h"

#include <math.h>
#include <stdio.h>
#include <string.h>

static const char *metric_names[NETWORK_TREND_METRIC_COUNT] = {
    "latency",
    "packet_loss",
    "throughput",
    "error_rate",
    "memory_usage"
};

static double metric_value(
    const NetworkMetric *m,
    NetworkTrendMetric type
) {
    switch (type) {
        case NETWORK_TREND_LATENCY:
            return m->latency_ms;
        case NETWORK_TREND_PACKET_LOSS:
            return m->packet_loss_percent;
        case NETWORK_TREND_THROUGHPUT:
            return m->throughput_mbps;
        case NETWORK_TREND_ERROR_RATE:
            return m->error_rate_percent;
        case NETWORK_TREND_MEMORY_USAGE:
            return m->memory_usage_percent;
        default:
            return 0.0;
    }
}

static double metric_threshold(
    const NetworkTrendConfig *config,
    NetworkTrendMetric type
) {
    switch (type) {
        case NETWORK_TREND_LATENCY:
            return config->latency_increase_percent;
        case NETWORK_TREND_PACKET_LOSS:
            return config->packet_loss_increase_percent;
        case NETWORK_TREND_THROUGHPUT:
            return config->throughput_decrease_percent;
        case NETWORK_TREND_ERROR_RATE:
            return config->error_rate_increase_percent;
        case NETWORK_TREND_MEMORY_USAGE:
            return config->memory_usage_increase_percent;
        default:
            return 0.0;
    }
}

static int valid_metric(const NetworkMetric *m) {
    return m != NULL &&
        m->timestamp[0] != '\0' &&
        isfinite(m->latency_ms) && m->latency_ms >= 0.0 &&
        isfinite(m->packet_loss_percent) &&
        m->packet_loss_percent >= 0.0 &&
        m->packet_loss_percent <= 100.0 &&
        isfinite(m->throughput_mbps) &&
        m->throughput_mbps >= 0.0 &&
        isfinite(m->error_rate_percent) &&
        m->error_rate_percent >= 0.0 &&
        m->error_rate_percent <= 100.0 &&
        isfinite(m->memory_used_mb) &&
        m->memory_used_mb >= 0.0 &&
        isfinite(m->memory_usage_percent) &&
        m->memory_usage_percent >= 0.0 &&
        m->memory_usage_percent <= 100.0;
}

static int valid_config(const NetworkTrendConfig *c, size_t count) {
    if (c == NULL ||
        c->baseline_count == 0 ||
        c->baseline_count >= count ||
        c->minimum_consecutive_measurements == 0) {
        return 0;
    }

    const double thresholds[] = {
        c->latency_increase_percent,
        c->packet_loss_increase_percent,
        c->throughput_decrease_percent,
        c->error_rate_increase_percent,
        c->memory_usage_increase_percent
    };

    for (size_t i = 0; i < NETWORK_TREND_METRIC_COUNT; i++) {
        if (!isfinite(thresholds[i]) ||
            thresholds[i] < 0.0 ||
            thresholds[i] >= 100.0) {
            return 0;
        }
    }

    return 1;
}

static int is_breach(
    double value,
    double baseline,
    double threshold,
    int decreasing
) {
    if (decreasing) {
        return value < baseline * (1.0 - threshold / 100.0);
    }

    return value > baseline * (1.0 + threshold / 100.0);
}

static void calculate_event(
    const NetworkMetric *metrics,
    size_t count,
    const NetworkTrendConfig *config,
    NetworkTrendMetric type,
    NetworkTrendEvent *event
) {
    double baseline_sum = 0.0;

    for (size_t i = 0; i < config->baseline_count; i++) {
        baseline_sum += metric_value(&metrics[i], type);
    }

    double baseline =
        baseline_sum / (double)config->baseline_count;

    event->baseline_average = baseline;
    event->deviation_percent = 0.0;
    event->deviation_percent_defined = 1;

    size_t streak_start = 0;
    size_t streak_count = 0;
    size_t streak_end = 0;
    double observed_sum = 0.0;

    int decreasing = (type == NETWORK_TREND_THROUGHPUT);

    for (size_t i = config->baseline_count; i < count; i++) {
        double value = metric_value(&metrics[i], type);

        if (is_breach(
                value,
                baseline,
                metric_threshold(config, type),
                decreasing
            )) {
            if (streak_count == 0) {
                streak_start = i;
                observed_sum = 0.0;
            }

            streak_count++;
            observed_sum += value;

            if (streak_count >=
                config->minimum_consecutive_measurements) {
                streak_end = i;
                event->detected = 1;
                break;
            }
        } else {
            streak_count = 0;
            observed_sum = 0.0;
        }
    }

    if (!event->detected) {
        return;
    }

    /*
     * Continue measuring the same sustained breach episode.
     */
    for (size_t i = streak_end + 1; i < count; i++) {
        double value = metric_value(&metrics[i], type);

        if (!is_breach(
                value,
                baseline,
                metric_threshold(config, type),
                decreasing
            )) {
            break;
        }

        streak_count++;
        observed_sum += value;
        streak_end = i;
    }

    event->consecutive_measurements = streak_count;

    event->observed_average =
        observed_sum / (double)streak_count;

    if (baseline > 0.0) {
        double change =
            (event->observed_average - baseline) / baseline * 100.0;

        event->deviation_percent = decreasing ? -change : change;
    } else if (event->observed_average > 0.0) {
        event->deviation_percent_defined = 0;
    }

    snprintf(
        event->start_timestamp,
        sizeof(event->start_timestamp),
        "%s",
        metrics[streak_start].timestamp
    );

    snprintf(
        event->end_timestamp,
        sizeof(event->end_timestamp),
        "%s",
        metrics[streak_end].timestamp
    );

    /*
     * Recovery requires the configured number of consecutive
     * measurements back inside the baseline threshold.
     */
    size_t recovery_count = 0;
    size_t recovery_start = 0;

    for (size_t i = streak_end + 1; i < count; i++) {
        double value = metric_value(&metrics[i], type);

        if (!is_breach(
                value,
                baseline,
                metric_threshold(config, type),
                decreasing
            )) {
            if (recovery_count == 0) {
                recovery_start = i;
            }

            recovery_count++;

            if (recovery_count >=
                config->minimum_consecutive_measurements) {
                event->recovered = 1;

                snprintf(
                    event->recovery_timestamp,
                    sizeof(event->recovery_timestamp),
                    "%s",
                    metrics[recovery_start].timestamp
                );

                break;
            }
        } else {
            recovery_count = 0;
        }
    }
}

int network_trends_analyze(
    const NetworkMetric *metrics,
    size_t count,
    const NetworkTrendConfig *config,
    NetworkTrendSummary *summary
) {
    if (metrics == NULL ||
        summary == NULL ||
        !valid_config(config, count)) {
        return -1;
    }

    memset(summary, 0, sizeof(*summary));

    for (size_t i = 0; i < count; i++) {
        if (!valid_metric(&metrics[i])) {
            memset(summary, 0, sizeof(*summary));
            return -1;
        }

        if (i > 0 &&
            strcmp(metrics[i - 1].timestamp, metrics[i].timestamp) >= 0) {
            memset(summary, 0, sizeof(*summary));
            return -1;
        }
    }

    summary->total_measurements = count;
    summary->baseline_measurements = config->baseline_count;
    summary->analyzed_measurements = count - config->baseline_count;

    for (size_t i = 0; i < NETWORK_TREND_METRIC_COUNT; i++) {
        calculate_event(
            metrics,
            count,
            config,
            (NetworkTrendMetric)i,
            &summary->events[i]
        );
    }

    return 0;
}

static int write_json_string(FILE *file, const char *text) {
    if (fputc('"', file) == EOF) {
        return -1;
    }

    for (const unsigned char *p = (const unsigned char *)text;
         *p != '\0'; p++) {
        switch (*p) {
            case '"':
                if (fputs("\\\"", file) == EOF) return -1;
                break;
            case '\\':
                if (fputs("\\\\", file) == EOF) return -1;
                break;
            case '\n':
                if (fputs("\\n", file) == EOF) return -1;
                break;
            case '\r':
                if (fputs("\\r", file) == EOF) return -1;
                break;
            default:
                if (*p < 0x20) {
                    if (fprintf(file, "\\u%04x", (unsigned int)*p) < 0)
                        return -1;
                } else if (fputc(*p, file) == EOF) {
                    return -1;
                }
        }
    }

    return fputc('"', file) == EOF ? -1 : 0;
}

int network_trends_write_json(
    const char *output_path,
    const NetworkTrendSummary *summary
) {
    if (output_path == NULL || summary == NULL ||
        summary->total_measurements == 0 ||
        summary->baseline_measurements == 0 ||
        summary->baseline_measurements >= summary->total_measurements ||
        summary->analyzed_measurements !=
            summary->total_measurements - summary->baseline_measurements) {
        return -1;
    }

    FILE *file = fopen(output_path, "w");

    if (file == NULL) {
        return -1;
    }

    int failed = 0;

    if (fprintf(
        file,
        "{\n"
        "  \"report_type\": \"network_trend_report\",\n"
        "  \"summary\": {\n"
        "    \"total_measurements\": %zu,\n"
        "    \"baseline_measurements\": %zu,\n"
        "    \"analyzed_measurements\": %zu\n"
        "  },\n"
        "  \"trends\": [\n",
        summary->total_measurements,
        summary->baseline_measurements,
        summary->analyzed_measurements
    ) < 0) {
        failed = 1;
    }

    for (size_t i = 0;
         !failed && i < NETWORK_TREND_METRIC_COUNT;
         i++) {
        const NetworkTrendEvent *e = &summary->events[i];

        if (i > 0 && fputs(",\n", file) == EOF) {
            failed = 1;
            break;
        }

        if (fputs("    {\n      \"metric\": ", file) == EOF ||
            write_json_string(file, metric_names[i]) != 0 ||
            fprintf(
                file,
                ",\n"
                "      \"detected\": %s,\n"
                "      \"recovered\": %s,\n"
                "      \"baseline_average\": %.6g,\n"
                "      \"observed_average\": %.6g,\n"
                "      \"deviation_percent\": ",
                e->detected ? "true" : "false",
                e->recovered ? "true" : "false",
                e->baseline_average,
                e->observed_average
            ) < 0 ||
            (e->deviation_percent_defined
                ? fprintf(file, "%.6g", e->deviation_percent) < 0
                : fputs("null", file) == EOF) ||
            fprintf(
                file,
                ",\n"
                "      \"consecutive_measurements\": %zu,\n"
                "      \"start_timestamp\": ",
                e->consecutive_measurements
            ) < 0 ||
            write_json_string(file, e->start_timestamp) != 0 ||
            fputs(",\n      \"end_timestamp\": ", file) == EOF ||
            write_json_string(file, e->end_timestamp) != 0 ||
            fputs(",\n      \"recovery_timestamp\": ", file) == EOF ||
            write_json_string(file, e->recovery_timestamp) != 0 ||
            fputs("\n    }", file) == EOF) {
            failed = 1;
        }
    }

    if (!failed && fputs("\n  ]\n}\n", file) == EOF) {
        failed = 1;
    }

    if (fclose(file) != 0) {
        failed = 1;
    }

    return failed ? -1 : 0;
}