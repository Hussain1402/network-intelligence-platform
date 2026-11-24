
#include "network_anomaly.h"

#include <math.h>
#include <stdio.h>
#include <string.h>

static int valid_config(const NetworkAnomalyConfig *config) {
    if (config == NULL) {
        return 0;
    }

    if (!isfinite(config->max_latency_ms) ||
        !isfinite(config->max_packet_loss_percent) ||
        !isfinite(config->min_throughput_mbps) ||
        !isfinite(config->max_error_rate_percent) ||
        !isfinite(config->max_memory_usage_percent)) {
        return 0;
    }

    return config->max_latency_ms >= 0.0 &&
           config->max_packet_loss_percent >= 0.0 &&
           config->max_packet_loss_percent <= 100.0 &&
           config->min_throughput_mbps >= 0.0 &&
           config->max_error_rate_percent >= 0.0 &&
           config->max_error_rate_percent <= 100.0 &&
           config->max_memory_usage_percent >= 0.0 &&
           config->max_memory_usage_percent <= 100.0;
}

int network_anomaly_analyze_one(
    const NetworkMetric *metric,
    const NetworkAnomalyConfig *config,
    NetworkAnomalyResult *result
) {
    if (metric == NULL || result == NULL || !valid_config(config)) {
        return -1;
    }

    memset(result, 0, sizeof(*result));

    snprintf(
        result->timestamp,
        sizeof(result->timestamp),
        "%s",
        metric->timestamp
    );

    result->latency_ms = metric->latency_ms;
    result->packet_loss_percent = metric->packet_loss_percent;
    result->throughput_mbps = metric->throughput_mbps;
    result->error_rate_percent = metric->error_rate_percent;
    result->memory_used_mb = metric->memory_used_mb;
    result->memory_usage_percent = metric->memory_usage_percent;

    if (metric->latency_ms > config->max_latency_ms) {
        result->flags |= NETWORK_ANOMALY_HIGH_LATENCY;
    }

    if (metric->packet_loss_percent >
        config->max_packet_loss_percent) {
        result->flags |= NETWORK_ANOMALY_HIGH_PACKET_LOSS;
    }

    if (metric->throughput_mbps <
        config->min_throughput_mbps) {
        result->flags |= NETWORK_ANOMALY_LOW_THROUGHPUT;
    }

    if (metric->error_rate_percent >
        config->max_error_rate_percent) {
        result->flags |= NETWORK_ANOMALY_HIGH_ERROR_RATE;
    }

    if (metric->memory_usage_percent >
        config->max_memory_usage_percent) {
        result->flags |= NETWORK_ANOMALY_HIGH_MEMORY_USAGE;
    }

    result->is_anomaly = (result->flags != NETWORK_ANOMALY_NONE);

    return 0;
}

int network_anomaly_analyze(
    const NetworkMetric *metrics,
    size_t count,
    const NetworkAnomalyConfig *config,
    NetworkAnomalyResult *results,
    size_t capacity,
    size_t *out_anomaly_count
) {
    size_t anomaly_count = 0;

    if (out_anomaly_count != NULL) {
        *out_anomaly_count = 0;
    }

    if (!valid_config(config) ||
        (count > 0 && (metrics == NULL || results == NULL)) ||
        capacity < count ||
        out_anomaly_count == NULL) {
        return -1;
    }

    for (size_t i = 0; i < count; i++) {
        if (network_anomaly_analyze_one(
                &metrics[i],
                config,
                &results[i]
            ) != 0) {
            *out_anomaly_count = 0;
            return -1;
        }

        if (results[i].is_anomaly) {
            anomaly_count++;
        }
    }

    *out_anomaly_count = anomaly_count;
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
            case '\t':
                if (fputs("\\t", file) == EOF) return -1;
                break;
            default:
                if (*p < 0x20) {
                    if (fprintf(file, "\\u%04x", (unsigned int)*p) < 0) {
                        return -1;
                    }
                } else if (fputc(*p, file) == EOF) {
                    return -1;
                }
        }
    }

    return fputc('"', file) == EOF ? -1 : 0;
}

static int write_anomaly_reasons(
    FILE *file,
    unsigned int flags
) {
    int first = 1;

    if (fputc('[', file) == EOF) return -1;

    #define WRITE_REASON(flag, label)                         \
        do {                                                  \
            if ((flags & (flag)) != 0) {                      \
                if (!first && fputc(',', file) == EOF)        \
                    return -1;                                \
                if (write_json_string(file, label) != 0)      \
                    return -1;                                \
                first = 0;                                    \
            }                                                 \
        } while (0)

    WRITE_REASON(NETWORK_ANOMALY_HIGH_LATENCY, "high_latency");
    WRITE_REASON(NETWORK_ANOMALY_HIGH_PACKET_LOSS, "high_packet_loss");
    WRITE_REASON(NETWORK_ANOMALY_LOW_THROUGHPUT, "low_throughput");
    WRITE_REASON(NETWORK_ANOMALY_HIGH_ERROR_RATE, "high_error_rate");
    WRITE_REASON(NETWORK_ANOMALY_HIGH_MEMORY_USAGE, "high_memory_usage");

    #undef WRITE_REASON

    return fputc(']', file) == EOF ? -1 : 0;
}

int network_anomaly_write_json(
    const char *output_path,
    const NetworkAnomalyResult *results,
    size_t count,
    const NetworkAnomalyConfig *config
) {
    FILE *file;
    size_t anomaly_count = 0;

    if (output_path == NULL ||
        config == NULL ||
        (count > 0 && results == NULL)) {
        return -1;
    }

    if (!valid_config(config)) {
        return -1;
    }

    for (size_t i = 0; i < count; i++) {
        if (!isfinite(results[i].latency_ms) ||
            !isfinite(results[i].packet_loss_percent) ||
            !isfinite(results[i].throughput_mbps) ||
            !isfinite(results[i].error_rate_percent) ||
            !isfinite(results[i].memory_used_mb) ||
            !isfinite(results[i].memory_usage_percent) ||
            results[i].memory_used_mb < 0.0 ||
            results[i].memory_usage_percent < 0.0 ||
            results[i].memory_usage_percent > 100.0) {
            return -1;
        }

        if (results[i].is_anomaly) {
            anomaly_count++;
        }
    }

    file = fopen(output_path, "w");

    if (file == NULL) {
        return -1;
    }

    int failed = 0;

    if (fprintf(file,
        "{\n"
        "  \"report_type\": \"network_anomaly_report\",\n"
        "  \"summary\": {\n"
        "    \"total_measurements\": %zu,\n"
        "    \"anomaly_count\": %zu,\n"
        "    \"normal_count\": %zu\n"
        "  },\n"
        "  \"thresholds\": {\n"
        "    \"max_latency_ms\": %.6g,\n"
        "    \"max_packet_loss_percent\": %.6g,\n"
        "    \"min_throughput_mbps\": %.6g,\n"
        "    \"max_error_rate_percent\": %.6g,\n"
        "    \"max_memory_usage_percent\": %.6g\n"
        "  },\n"
        "  \"measurements\": [\n",
        count,
        anomaly_count,
        count - anomaly_count,
        config->max_latency_ms,
        config->max_packet_loss_percent,
        config->min_throughput_mbps,
        config->max_error_rate_percent,
        config->max_memory_usage_percent) < 0) {
        failed = 1;
    }

    for (size_t i = 0; !failed && i < count; i++) {
        const NetworkAnomalyResult *r = &results[i];

        if (i > 0 && fputs(",\n", file) == EOF) {
            failed = 1;
            break;
        }

        if (fputs("    {\n      \"timestamp\": ", file) == EOF ||
            write_json_string(file, r->timestamp) != 0 ||
            fprintf(file,
                ",\n"
                "      \"latency_ms\": %.6g,\n"
                "      \"packet_loss_percent\": %.6g,\n"
                "      \"throughput_mbps\": %.6g,\n"
                "      \"error_rate_percent\": %.6g,\n"
                "      \"memory_used_mb\": %.6g,\n"
                "      \"memory_usage_percent\": %.6g,\n"
                "      \"is_anomaly\": %s,\n"
                "      \"reasons\": ",
                r->latency_ms,
                r->packet_loss_percent,
                r->throughput_mbps,
                r->error_rate_percent,
                r->memory_used_mb,
                r->memory_usage_percent,
                r->is_anomaly ? "true" : "false") < 0 ||
            write_anomaly_reasons(file, r->flags) != 0 ||
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
