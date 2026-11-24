#include "network_analytics.h"

#include <math.h>
#include <stdio.h>
#include <string.h>

static int valid_metric(const NetworkMetric *m) {
    return m != NULL &&
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

static void initialize_stat(NetworkMetricStatistics *s, double value) {
    s->minimum = value;
    s->maximum = value;
    s->average = 0.0;
}

static void update_stat(
    NetworkMetricStatistics *s,
    double value,
    double *sum
) {
    if (value < s->minimum) {
        s->minimum = value;
    }

    if (value > s->maximum) {
        s->maximum = value;
    }

    *sum += value;
}

int network_analytics_calculate(
    const NetworkMetric *metrics,
    const NetworkAnomalyResult *results,
    size_t count,
    NetworkAnalyticsSummary *summary
) {
    if (summary == NULL || count == 0 || metrics == NULL) {
        return -1;
    }

    memset(summary, 0, sizeof(*summary));

    if (!valid_metric(&metrics[0])) {
        return -1;
    }

    initialize_stat(&summary->latency_ms, metrics[0].latency_ms);
    initialize_stat(
        &summary->packet_loss_percent,
        metrics[0].packet_loss_percent
    );
    initialize_stat(
        &summary->throughput_mbps,
        metrics[0].throughput_mbps
    );
    initialize_stat(
        &summary->error_rate_percent,
        metrics[0].error_rate_percent
    );
    initialize_stat(
        &summary->memory_used_mb,
        metrics[0].memory_used_mb
    );
    initialize_stat(
        &summary->memory_usage_percent,
        metrics[0].memory_usage_percent
    );

    double latency_sum = 0.0;
    double packet_loss_sum = 0.0;
    double throughput_sum = 0.0;
    double error_rate_sum = 0.0;
    double memory_mb_sum = 0.0;
    double memory_percent_sum = 0.0;

    for (size_t i = 0; i < count; i++) {
        const NetworkMetric *m = &metrics[i];

        if (!valid_metric(m)) {
            memset(summary, 0, sizeof(*summary));
            return -1;
        }

        update_stat(
            &summary->latency_ms,
            m->latency_ms,
            &latency_sum
        );
        update_stat(
            &summary->packet_loss_percent,
            m->packet_loss_percent,
            &packet_loss_sum
        );
        update_stat(
            &summary->throughput_mbps,
            m->throughput_mbps,
            &throughput_sum
        );
        update_stat(
            &summary->error_rate_percent,
            m->error_rate_percent,
            &error_rate_sum
        );
        update_stat(
            &summary->memory_used_mb,
            m->memory_used_mb,
            &memory_mb_sum
        );
        update_stat(
            &summary->memory_usage_percent,
            m->memory_usage_percent,
            &memory_percent_sum
        );

        if (results != NULL) {
            if (results[i].is_anomaly != 0 &&
                results[i].is_anomaly != 1) {
                memset(summary, 0, sizeof(*summary));
                return -1;
            }

            if (results[i].is_anomaly) {
                summary->anomaly_count++;
            }
        }
    }

    summary->total_measurements = count;
    summary->normal_count = count - summary->anomaly_count;

    summary->latency_ms.average = latency_sum / (double)count;
    summary->packet_loss_percent.average =
        packet_loss_sum / (double)count;
    summary->throughput_mbps.average =
        throughput_sum / (double)count;
    summary->error_rate_percent.average =
        error_rate_sum / (double)count;
    summary->memory_used_mb.average =
        memory_mb_sum / (double)count;
    summary->memory_usage_percent.average =
        memory_percent_sum / (double)count;

    summary->anomaly_rate_percent =
        100.0 * (double)summary->anomaly_count / (double)count;

    return 0;
}

static int write_stat(
    FILE *file,
    const char *name,
    const NetworkMetricStatistics *s,
    int comma
) {
    return fprintf(
        file,
        "    \"%s\": {\"minimum\": %.6g, \"maximum\": %.6g, "
        "\"average\": %.6g}%s\n",
        name,
        s->minimum,
        s->maximum,
        s->average,
        comma ? "," : ""
    ) < 0 ? -1 : 0;
}

int network_analytics_write_json(
    const char *output_path,
    const NetworkAnalyticsSummary *summary
) {
    if (output_path == NULL || summary == NULL ||
        summary->total_measurements == 0 ||
        summary->anomaly_count > summary->total_measurements ||
        summary->normal_count !=
            summary->total_measurements - summary->anomaly_count ||
        !isfinite(summary->anomaly_rate_percent)) {
        return -1;
    }

    const NetworkMetricStatistics *stats[] = {
        &summary->latency_ms,
        &summary->packet_loss_percent,
        &summary->throughput_mbps,
        &summary->error_rate_percent,
        &summary->memory_used_mb,
        &summary->memory_usage_percent
    };

    for (size_t i = 0; i < sizeof(stats) / sizeof(stats[0]); i++) {
        if (!isfinite(stats[i]->minimum) ||
            !isfinite(stats[i]->maximum) ||
            !isfinite(stats[i]->average) ||
            stats[i]->minimum < 0.0 ||
            stats[i]->maximum < stats[i]->minimum) {
            return -1;
        }
    }

    FILE *file = fopen(output_path, "w");

    if (file == NULL) {
        return -1;
    }

    int failed = 0;

    if (fprintf(
        file,
        "{\n"
        "  \"report_type\": \"network_analytics_report\",\n"
        "  \"summary\": {\n"
        "    \"total_measurements\": %zu,\n"
        "    \"anomaly_count\": %zu,\n"
        "    \"normal_count\": %zu,\n"
        "    \"anomaly_rate_percent\": %.6g\n"
        "  },\n"
        "  \"statistics\": {\n",
        summary->total_measurements,
        summary->anomaly_count,
        summary->normal_count,
        summary->anomaly_rate_percent
    ) < 0) {
        failed = 1;
    }

    const char *names[] = {
        "latency_ms",
        "packet_loss_percent",
        "throughput_mbps",
        "error_rate_percent",
        "memory_used_mb",
        "memory_usage_percent"
    };

    for (size_t i = 0; !failed && i < 6; i++) {
        if (write_stat(file, names[i], stats[i], i < 5) != 0) {
            failed = 1;
        }
    }

    if (!failed && fputs("  }\n}\n", file) == EOF) {
        failed = 1;
    }

    if (fclose(file) != 0) {
        failed = 1;
    }

    return failed ? -1 : 0;
}