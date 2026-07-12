# 🛡️ LogSentry: Threat Intelligence Parser

A lightweight Python command-line utility designed to scan Nginx or Apache raw access logs for active cyber threats.

### Features
*   **SQL Injection Detection**: Scans parameters for structural database escape payloads.
*   **Cross-Site Scripting (XSS)**: Flags injected `<script>` nodes and onload/onerror HTML hooks.
*   **Path Traversal**: Intercepts `../` directory escapes and attempts to access system critical routes (e.g. `/etc/passwd`).
*   **Brute Force Detection**: Correlates multiple sequential `401 Unauthorized` responses from a single IP targeting `/login`.

### How to Run
```bash
python3 log_sentry.py
```
This will automatically generate a sample `access.log` containing simulated attacks and output a JSON threat report to the console.
