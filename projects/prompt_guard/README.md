# 🛡️ PromptGuard: LLM Input Firewall

A lightweight input firewall designed to intercept **Prompt Injection**, **Jailbreaks**, **PII Leakage**, and **Code Execution Payload Injection** before raw user prompts reach LLM inference backends.

### Operational Features
*   **Jailbreak Guard**: Protects against context-escaping strings (like "DAN", "ignore previous instructions", "developer mode").
*   **PII Masking**: Prevents leakage of emails, API tokens, phone numbers, and credit cards.
*   **Command Sanitizer**: Scans prompts for Python script syntax injection (`eval()`, `exec()`) or Unix system shell escapes.

### How to Run
```bash
python3 prompt_guard.py "Your test prompt here..."
```
If no prompt is provided, it executes a simulated attack payload demonstrating multiple security violations and returns a detailed JSON diagnostics schema.
