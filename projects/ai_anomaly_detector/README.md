# 📡 AI Anomaly Detector: Statistical Threat Scanner

An intelligent statistical intrusion detection system (IDS) that dynamically builds traffic baselines and isolates network abnormalities using standard deviation Z-score models.

### Operational Features
*   **Dynamic Baseline Profiling**: Automatically calculates the statistical mean and variance of normal network connection sizes and frequencies.
*   **DDoS Isolation**: Identifies anomalous spikes in connection frequency (Z-score threshold violation).
*   **Exfiltration Shield**: Triggers critical alerts when standard payload size distributions indicate large-scale data queries.

### How to Run
```bash
python3 ai_anomaly_detector.py
```
This runs the statistical profiler on a generated set of connection logs, isolates standard standard deviation outliers, and prints a telemetry diagnostics report.
