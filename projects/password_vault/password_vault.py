#!/usr/bin/env python3
import sys
import secrets
import string
import math

def calculate_entropy(password):
    # Determine the character pool size (Range)
    pool_size = 0
    if any(c in string.ascii_lowercase for c in password):
        pool_size += 26
    if any(c in string.ascii_uppercase for c in password):
        pool_size += 26
    if any(c in string.digits for c in password):
        pool_size += 10
    if any(c in string.punctuation for c in password):
        pool_size += len(string.punctuation)
        
    if pool_size == 0 or len(password) == 0:
        return 0.0
        
    # Shannon Entropy formula: E = L * log2(R)
    entropy = len(password) * math.log2(pool_size)
    return round(entropy, 2)

def generate_password(length=16, use_upper=True, use_digits=True, use_special=True):
    pool = string.ascii_lowercase
    if use_upper:
        pool += string.ascii_uppercase
    if use_digits:
        pool += string.digits
    if use_special:
        pool += string.punctuation
        
    # Generate secure random characters using secrets module
    password = "".join(secrets.choice(pool) for _ in range(length))
    return password

def get_strength_rating(entropy):
    if entropy < 40:
        return "🔴 VERY WEAK (Low Entropy)"
    elif entropy < 60:
        return "🟡 WEAK (Medium Entropy)"
    elif entropy < 80:
        return "🟢 STRONG (High Entropy)"
    else:
        return "🛡️ MILITARY-GRADE (Extreme Entropy)"

def main():
    print("=== SECURE PASSWORD TELEMETRY SYSTEM ===")
    
    length = 16
    if len(sys.argv) > 1:
        try:
            length = int(sys.argv[1])
        except ValueError:
            print("[-] Invalid length argument. Defaulting to 16.")
            
    # Generate secure password
    pwd = generate_password(length)
    entropy = calculate_entropy(pwd)
    rating = get_strength_rating(entropy)
    
    print(f"\nGenerated Key : {pwd}")
    print(f"Key Length    : {len(pwd)} characters")
    print(f"Entropy Score : {entropy} bits")
    print(f"Rating Status : {rating}\n")
    print("========================================")

if __name__ == "__main__":
    main()
