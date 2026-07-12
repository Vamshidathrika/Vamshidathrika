#!/usr/bin/env python3
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor

# Default targets to check
DEFAULT_HOSTS = ["google.com", "github.com", "cloudflare.com"]
# Common ports to scan
COMMON_PORTS = [22, 80, 443, 8080]

def check_host_ping(host):
    # Simulates active ping latency by checking TCP handshake time on port 443
    print(f"[*] Pinging {host}...")
    start_time = time.time()
    try:
        # Create a socket and connect to port 443 (HTTPS) to verify host is up
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3.0)
        sock.connect((host, 443))
        sock.close()
        latency = round((time.time() - start_time) * 1000, 2)
        return {"host": host, "status": "UP", "latency_ms": latency}
    except Exception as e:
        return {"host": host, "status": "DOWN", "latency_ms": None}

def scan_port(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.5)
        result = sock.connect_ex((host, port))
        sock.close()
        status = "OPEN" if result == 0 else "CLOSED"
        return {"port": port, "status": status}
    except Exception:
        return {"port": port, "status": "ERROR"}

def run_port_scan(host):
    print(f"\n[*] Scanning ports on {host}...")
    results = []
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {executor.submit(scan_port, host, port): port for port in COMMON_PORTS}
        for future in futures:
            results.append(future.result())
    return results

def main():
    print("=== NETRADAR: ACTIVE NETWORK TELEMETRY ===")
    
    hosts = DEFAULT_HOSTS
    if len(sys.argv) > 1:
        hosts = sys.argv[1:]
        
    # Check host latency concurrently
    ping_results = []
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {executor.submit(check_host_ping, host): host for host in hosts}
        for future in futures:
            ping_results.append(future.result())
            
    print("\n--- HOST STATUS REPORT ---")
    for res in ping_results:
        status_color = "🟢 UP" if res["status"] == "UP" else "🔴 DOWN"
        latency_str = f"{res['latency_ms']} ms" if res["latency_ms"] else "N/A"
        print(f"Host: {res['host']:<18} | Status: {status_color:<8} | Latency: {latency_str}")
        
    # Run a port scan on the first host
    if ping_results and ping_results[0]["status"] == "UP":
        target = ping_results[0]["host"]
        scan_results = run_port_scan(target)
        print(f"--- PORT CONFIGURATION FOR {target.upper()} ---")
        for port_res in scan_results:
            port_status = "🟢 OPEN" if port_res["status"] == "OPEN" else "🔴 CLOSED"
            print(f"Port: {port_res['port']:<5} | Status: {port_status}")
            
    print("\n==========================================")

if __name__ == "__main__":
    main()
