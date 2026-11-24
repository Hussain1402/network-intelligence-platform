# PS2 network analytics

## Input

`network_metrics_load_csv()` consumes rows in this exact format:

```csv
timestamp,latency_ms,packet_loss_percent,throughput_mbps,error_rate_percent,memory_used_mb,memory_usage_percent
```

Timestamps use `YYYY-MM-DDTHH:MM:SS`. Numeric values must be finite and
non-negative; percentage metrics must not exceed 100. The current pipeline
uses batch CSV data and does not connect to live network equipment or services.

## Analysis

- `network_anomaly_analyze()` flags measurements above/below the configured
  absolute thresholds.
- `network_analytics_calculate()` calculates count, min, max, average, and
  anomaly rate for all six metrics.
- `network_trends_analyze()` uses the first `baseline_count` measurements as
  an initial average, then detects sustained threshold deviations and
  configured consecutive-measurement recovery.

Trend input timestamps must be strictly increasing. Relative percentage
deviation from a zero baseline is mathematically undefined when observed values
are positive; the JSON report encodes that value as `null`. No cause is inferred
from metric correlation.

## Pipeline

Run `scripts/run_ps2.ps1` to configure/build the C targets, execute the C
pipeline, consolidate the C reports with `python/network_evidence.py`, run
`python/network_mock_ai.py`, and parse the final JSON documents. Generated
files are placed under `output/`.

The investigator is deterministic rule logic operating on those generated
reports. It is not a trained model. No live telemetry or dedicated external
model integration is currently included for PS2.
