# 📡 NetRadar: Active Network Telemetry Scanner

A lightweight multi-threaded Python CLI script for verifying host network health (status/latency) and checking public port exposure.

### Features
*   **Concurrent Pinging**: Performs fast latency diagnostics across multiple host targets in parallel threads.
*   **TCP Handshake Verification**: Determines accurate response times using localized TCP handshakes instead of raw ICMP echo headers.
*   **Port Scanning**: Discovers open/closed states on core communication ports (SSH, HTTP, HTTPS, Web proxy).

### How to Run
```bash
python3 net_radar.py <target-host-1> <target-host-2> ...
```
Example:
```bash
python3 net_radar.py google.com github.com
```
This runs latency checks on targets, and executes a full port scan on the primary target.
