#!/usr/bin/env python3
import math
import sys
import json
import random

# Generate synthetic network traffic metrics representing standard server traffic with a few threat anomalies
# normal: ~100-300 bytes size, request rates ~1-5 req/min
# anomaly: 50,000 bytes (exfiltration) or 120 req/min (DDoS)
def generate_traffic_data():
    data = []
    # Generate 100 normal traffic logs
    for i in range(100):
        data.append({
            "ip": f"192.168.1.{random.randint(10, 99)}",
            "req_size_bytes": random.randint(150, 450),
            "req_frequency_per_min": random.randint(2, 8)
        })
    # Inject anomaly 1: Data Exfiltration (large size)
    data.append({
        "ip": "10.0.0.99",
        "req_size_bytes": 85000,
        "req_frequency_per_min": 3
    })
    # Inject anomaly 2: DDoS / Brute Force (high frequency)
    data.append({
        "ip": "172.16.5.42",
        "req_size_bytes": 220,
        "req_frequency_per_min": 145
    })
    return data

def calculate_stats(values):
    n = len(values)
    if n == 0:
        return 0.0, 0.0
    mean = sum(values) / n
    variance = sum((x - mean) ** 2 for x in values) / n
    std_dev = math.sqrt(variance)
    return mean, std_dev

def scan_anomalies(traffic_logs, threshold_z=3.0):
    sizes = [log["req_size_bytes"] for log in traffic_logs]
    freqs = [log["req_frequency_per_min"] for log in traffic_logs]
    
    # Calculate baseline normal profiles dynamically (mean and standard deviation)
    size_mean, size_std = calculate_stats(sizes)
    freq_mean, freq_std = calculate_stats(freqs)
    
    anomalies = []
    
    for log in traffic_logs:
        # Avoid division by zero if std_dev is 0
        z_size = (log["req_size_bytes"] - size_mean) / size_std if size_std > 0 else 0
        z_freq = (log["req_frequency_per_min"] - freq_mean) / freq_std if freq_std > 0 else 0
        
        # Check if either metric exceeds standard Z-score threshold
        is_anomaly = False
        reason = []
        
        if abs(z_size) > threshold_z:
            is_anomaly = True
            reason.append(f"Payload Size Anomaly (Z-score: {z_size:.2f})")
            
        if abs(z_freq) > threshold_z:
            is_anomaly = True
            reason.append(f"Connection Frequency Anomaly (Z-score: {z_freq:.2f})")
            
        if is_anomaly:
            anomalies.append({
                "ip": log["ip"],
                "req_size_bytes": log["req_size_bytes"],
                "req_frequency_per_min": log["req_frequency_per_min"],
                "outlier_reasons": reason,
                "threat_prediction": "Data Exfiltration" if abs(z_size) > threshold_z else "DDoS / Scanning Activity"
            })
            
    return {
        "baselines": {
            "size_mean_bytes": round(size_mean, 2),
            "size_std_dev": round(size_std, 2),
            "frequency_mean_per_min": round(freq_mean, 2),
            "frequency_std_dev": round(freq_std, 2)
        },
        "anomalies_detected": len(anomalies),
        "anomalies": anomalies
    }

def main():
    print("=== COGNITIVE LOG SENTINEL: ANOMALY DETECTOR ===")
    
    logs = generate_traffic_data()
    print(f"[*] Generated {len(logs)} network traffic metrics for profiling.")
    
    report = scan_anomalies(logs)
    print("\n=== SYSTEM ANOMALY SCANNING REPORT ===")
    print(json.dumps(report, indent=2))
    print("======================================")

if __name__ == "__main__":
    main()
# telemetry update VK-962021
