# 🔑 PasswordVault: Secure Key Generator & Entropy Analyzer

A cryptographically secure password generation and cryptographic entropy analysis CLI tool written in Python.

### Features
*   **Cryptographic Randomness**: Utilizes Python's standard `secrets` library (not pseudo-random `random`) to safely generate keys.
*   **Entropy Calculations**: Calculates raw mathematical entropy based on the size of the character pool ($L \times \log_2(R)$).
*   **Security Grading**: Maps passwords to operational security tiers, ranging from `VERY WEAK` to `MILITARY-GRADE`.

### How to Run
```bash
python3 password_vault.py <length>
```
Example:
```bash
python3 password_vault.py 24
```
This generates a 24-character high-entropy secure key and outputs its telemetry score.
