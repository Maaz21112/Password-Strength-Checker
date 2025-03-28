import math
import string
import hashlib
import requests
import getpass

def load_common_passwords(filename='common_passwords.txt'):
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            return set(f.read().splitlines())
    except FileNotFoundError:
        print(f"Warning: {filename} not found. Skipping common password check.")
        return set()

def check_nist_guidelines(password, common_passwords):
    if len(password) < 8:
        return False, "Password must be at least 8 characters."
    if len(password) > 64:
        return False, "Password exceeds 64 characters."
    if password in common_passwords:
        return False, "Password is too common."
    return True, "Meets NIST guidelines."

def calculate_entropy(password):
    charset_size = 0
    if any(c in string.ascii_lowercase for c in password):
        charset_size += 26
    if any(c in string.ascii_uppercase for c in password):
        charset_size += 26
    if any(c in string.digits for c in password):
        charset_size += 10
    if any(c in string.punctuation for c in password):
        charset_size += 32  # Approximate for special chars
    if charset_size == 0:
        return 0
    return len(password) * math.log2(charset_size)

def get_strength(entropy):
    if entropy < 28: return "Very Weak"
    elif entropy < 36: return "Weak"
    elif entropy < 60: return "Moderate"
    elif entropy < 128: return "Strong"
    else: return "Very Strong"

def generate_suggestions(password):
    suggestions = []
    if len(password) < 12:
        suggestions.append("Use at least 12 characters.")
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in string.punctuation for c in password)
    if not has_upper: suggestions.append("Add uppercase letters.")
    if not has_lower: suggestions.append("Add lowercase letters.")
    if not has_digit: suggestions.append("Include numbers.")
    if not has_special: suggestions.append("Include special characters (e.g., !@#$).")
    return suggestions

def check_breached(password):
    sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]
    try:
        response = requests.get(f'https://api.pwnedpasswords.com/range/{prefix}')
        if response.status_code != 200:
            return False, "API Error"
        for line in response.text.splitlines():
            if line.split(':')[0] == suffix:
                return True, f"Password found in {line.split(':')[1]} breaches."
        return False, "Password not breached."
    except Exception:
        return False, "Failed to check breaches."

def main():
    password = getpass.getpass("Enter password: ")
    common_passwords = load_common_passwords()
    
    # NIST Check
    nist_valid, nist_msg = check_nist_guidelines(password, common_passwords)
    print("\nNIST Guidelines:", nist_msg)
    
    # Entropy & Strength
    entropy = calculate_entropy(password)
    print(f"Entropy: {entropy:.2f} bits")
    print("Strength:", get_strength(entropy))
    
    # Suggestions
    suggestions = generate_suggestions(password)
    if suggestions:
        print("\nSuggestions:")
        for s in suggestions: print(f"- {s}")
    else:
        print("\nNo suggestions. Great password!")
    
    # Breach Check
    breached, breach_msg = check_breached(password)
    print("\nBreach Check:", breach_msg)

if __name__ == "__main__":
    main()