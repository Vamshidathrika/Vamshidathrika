#!/usr/bin/env python3
import re
import sys
import json
from datetime import datetime

# Regex rules for detecting common attack patterns in URL parameters or request bodies
RULES = {
    "SQL_Injection": re.compile(
        r"(union\s+select|select\s+.*\s+from|'\s*or\s*'1'\s*=\s*'1|--|#)", re.IGNORECASE
    ),
    "Cross_Site_Scripting_XSS": re.compile(
        r"(<script>|javascript:|onerror\s*=|onload\s*=|<iframe)", re.IGNORECASE
    ),
    "Path_Traversal": re.compile(
        r"(\.\./|\.\.\\|/etc/passwd|/windows/win\.ini)", re.IGNORECASE
    )
}

SAMPLE_LOGS = """127.0.0.1 - - [13/Jul/2026:10:15:30 +0530] "GET /index.html HTTP/1.1" 200 1043
192.168.1.50 - - [13/Jul/2026:10:16:01 +0530] "GET /search?q=foo%20UNION%20SELECT%20username,%20password%20FROM%20users HTTP/1.1" 403 293
10.0.0.12 - - [13/Jul/2026:10:16:45 +0530] "GET /login?user=admin HTTP/1.1" 200 450
10.0.0.12 - - [13/Jul/2026:10:16:48 +0530] "POST /login HTTP/1.1" 401 120
10.0.0.12 - - [13/Jul/2026:10:16:50 +0530] "POST /login HTTP/1.1" 401 120
10.0.0.12 - - [13/Jul/2026:10:16:52 +0530] "POST /login HTTP/1.1" 401 120
10.0.0.12 - - [13/Jul/2026:10:16:55 +0530] "POST /login HTTP/1.1" 200 450
192.168.1.55 - - [13/Jul/2026:10:17:12 +0530] "GET /../../etc/passwd HTTP/1.1" 404 150
192.168.1.60 - - [13/Jul/2026:10:18:00 +0530] "GET /assets/logo.png?v=<script>alert(1)</script> HTTP/1.1" 403 220
"""

def generate_sample_file(filepath):
    with open(filepath, "w") as f:
        f.write(SAMPLE_LOGS.strip())
    print(f"[+] Sample log file created at: {filepath}")

def analyze_logs(filepath):
    print(f"[*] Scanning log file: {filepath}")
    
    anomalies = []
    brute_force_tracker = {} # Track IP login attempts
    
    with open(filepath, "r") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
                
            # Parse standard Common Log Format / Nginx format
            match = re.match(r"^(\S+) \S+ \S+ \[(.*?)\] \"(\S+) (.*?) \S+\" (\d+) (\d+|-)", line)
            if not match:
                continue
                
            ip, timestamp, method, url, status, bytes_sent = match.groups()
            
            # Check rules
            for threat_type, pattern in RULES.items():
                if pattern.search(url):
                    anomalies.append({
                        "line": line_num,
                        "ip": ip,
                        "timestamp": timestamp,
                        "threat_type": threat_type,
                        "severity": "HIGH",
                        "payload": url
                    })
            
            # Track brute force (more than 3 failed logins (401) within a short window)
            if "/login" in url and status == "401":
                brute_force_tracker[ip] = brute_force_tracker.get(ip, 0) + 1
                if brute_force_tracker[ip] >= 3:
                    anomalies.append({
                        "line": line_num,
                        "ip": ip,
                        "timestamp": timestamp,
                        "threat_type": "Brute_Force_Attempt",
                        "severity": "MEDIUM",
                        "payload": f"Multiple failed login attempts ({brute_force_tracker[ip]})"
                    })
                    # Reset tracker to avoid duplicate alerts
                    brute_force_tracker[ip] = 0

    return anomalies

def main():
    log_file = "access.log"
    if len(sys.argv) > 1:
        log_file = sys.argv[1]
    else:
        generate_sample_file(log_file)
        
    try:
        threats = analyze_logs(log_file)
        print("\n=== SECURITY TELEMETRY REPORT ===")
        print(f"Total threats detected: {len(threats)}")
        print("=================================")
        if threats:
            print(json.dumps(threats, indent=2))
        else:
            print("[+] Scan complete. No active security threats detected.")
    except FileNotFoundError:
        print(f"[-] Error: Log file '{log_file}' not found.")
        sys.exit(1)

if __name__ == "__main__":
    main()
