#!/usr/bin/env python3
import sys
import json
import re

# Weighted threat vectors used by our heuristic social engineering classifier
THREAT_WEIGHTS = {
    "urgency_keywords": 0.35,  # e.g., "immediate action", "account suspended"
    "credential_link": 0.30,   # e.g., "verify here", "click to login"
    "generic_greeting": 0.15,  # e.g., "Dear customer", "Valued user"
    "financial_hook": 0.20     # e.g., "refund", "invoice payment", "crypto"
}

# Regex parameters for classification features
URGENCY_REGEX = re.compile(r"(immediate|action\s+required|suspended|urgent|verify\s+your|block)", re.IGNORECASE)
LINK_REGEX = re.compile(r"(click\s+here|verify\s+now|login\s+to|update\s+account|href=)", re.IGNORECASE)
GREETING_REGEX = re.compile(r"(dear\s+customer|dear\s+user|valued\s+member|attention\s+user)", re.IGNORECASE)
FINANCIAL_REGEX = re.compile(r"(bank|payment|invoice|wire|refund|crypto|bitcoin|transfer)", re.IGNORECASE)

SAMPLE_NORMAL = """Subject: Project Update Meeting Schedule
Hi Team,
Please review the attached schedule for our backend integration sync. The meeting will take place tomorrow at 10 AM. Let me know if you have any questions.
Best,
Vamshi
"""

SAMPLE_PHISHING = """Subject: URGENT: Your Security Profile is SUSPENDED!
Dear customer,
We detected suspicious activity on your bank profile. Action required: immediate action is necessary to prevent complete block. Click here to verify now and update account credentials: http://secure-bank-login-update.com/signin.
If you do not update within 24 hours your bank transfer limits will be reset.
"""

def analyze_email_heuristics(text):
    score = 0.0
    indicators = {}
    
    # 1. Evaluate Urgency & Threat Vector
    urgency_matches = URGENCY_REGEX.findall(text)
    if urgency_matches:
        score += THREAT_WEIGHTS["urgency_keywords"]
        indicators["Urgent_Language"] = f"Detected keywords: {list(set(urgency_matches))}"
        
    # 2. Evaluate Credential Link Indicators
    link_matches = LINK_REGEX.findall(text)
    if link_matches:
        score += THREAT_WEIGHTS["credential_link"]
        indicators["Credential_Call_To_Action"] = f"Detected link phrases: {list(set(link_matches))}"
        
    # 3. Evaluate Greetings Format
    greeting_matches = GREETING_REGEX.findall(text)
    if greeting_matches:
        score += THREAT_WEIGHTS["generic_greeting"]
        indicators["Generic_Greetings"] = f"Detected non-specific greetings: {list(set(greeting_matches))}"
        
    # 4. Evaluate Financial Hooks
    financial_matches = FINANCIAL_REGEX.findall(text)
    if financial_matches:
        score += THREAT_WEIGHTS["financial_hook"]
        indicators["Financial_Language"] = f"Detected fiscal targets: {list(set(financial_matches))}"
        
    return {
        "phishing_risk_index": round(score * 100, 2),
        "classification": "HIGH RISK (PHISHING)" if score >= 0.5 else "LOW RISK (SAFE)",
        "indicators_triggered": len(indicators),
        "telemetry_findings": indicators
    }

def main():
    print("=== NLP SENTINEL: SOCIAL ENGINEERING DETECTOR ===")
    
    if len(sys.argv) > 1:
        email_content = " ".join(sys.argv[1:])
        print("[*] Analyzing user-provided email payload...")
        result = analyze_email_heuristics(email_content)
        print("\n=== CLASSIFIER REPORT ===")
        print(json.dumps(result, indent=2))
        print("=========================")
    else:
        print("[*] No custom payload provided. Executing automated test cases...")
        
        print("\n--- TEST CASE A: STABLE OPERATIONAL EMAIL ---")
        res_a = analyze_email_heuristics(SAMPLE_NORMAL)
        print(json.dumps(res_a, indent=2))
        
        print("\n--- TEST CASE B: MALICIOUS PHISHING INTRUSION ---")
        res_b = analyze_email_heuristics(SAMPLE_PHISHING)
        print(json.dumps(res_b, indent=2))
        
    print("\n================================================")

if __name__ == "__main__":
    main()
# telemetry update VK-598568
