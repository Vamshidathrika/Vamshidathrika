# 🛡️ AI Phishing Detector: NLP Social Engineering Scanner

A self-contained Natural Language Processing (NLP) heuristic classifier designed to analyze raw email text and header structures for social engineering and phishing risk factors.

### Operational Features
*   **Weighted Threat Vector Engine**: Features a probabilistic model that weights multiple signals (Urgency, Call-to-action link density, Generic Salutations, and Financial hooks).
*   **Urgency Vector Diagnostics**: Flags NLP patterns trying to induce immediate fear or action pressure.
*   **Security Verdict**: Automatically classifies payloads into `LOW RISK (SAFE)` or `HIGH RISK (PHISHING)` with a granular probability percentage.

### How to Run
```bash
python3 ai_phishing_detector.py "Insert email text here..."
```
If no payload is supplied, the script runs automated test scenarios showing classification telemetry on both a standard business email and a severe phishing attack.
