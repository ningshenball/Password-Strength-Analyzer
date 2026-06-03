import re
import secrets
import string

COMMON_WEAK = {"password", "123456", "qwerty", "admin", "letmein", "welcome", "password123"}


def has_weak_name_pattern(password):
    """Detect name-based patterns including long/uncommon names"""
    pw = password
    pw_lower = pw.lower()

    # Rule 1: Long alphabetic sequence at start + symbol/number suffix (very common)
    if re.match(r'^[A-Za-z]{8,}[@#$_-]?\d{1,6}$', pw):
        return True

    # Rule 2: Contains long letter sequence (8+) followed by simple suffix
    if re.search(r'[A-Za-z]{8,}[@#$_-]?\d{1,6}', pw):
        return True

    # Rule 3: Very low randomness (mostly letters)
    letter_count = sum(c.isalpha() for c in pw)
    if len(pw) >= 10 and letter_count / len(pw) > 0.85:
        return True

    return False


def calculate_score(password):
    score = 0.0
    issues = []
    pw_lower = password.lower()

    # Length scoring
    if len(password) >= 16:
        score += 1.5
    elif len(password) >= 12:
        score += 1.2
    elif len(password) >= 8:
        score += 0.8
    else:
        issues.append("Password is too short")

    # Character diversity
    if re.search(r'[A-Z]', password):
        score += 0.5
    else:
        issues.append("Missing uppercase letters")

    if re.search(r'[a-z]', password):
        score += 0.5
    else:
        issues.append("Missing lowercase letters")

    if re.search(r'[0-9]', password):
        score += 0.5
    else:
        issues.append("Missing numbers")

    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        score += 0.5
    else:
        issues.append("Missing special characters")

    # Common weak passwords
    if pw_lower in COMMON_WEAK:
        score -= 2.0
        issues.append("Very common and easily guessable password")

    # Improved name pattern detection
    if has_weak_name_pattern(password):
        score -= 2.0
        issues.append("Contains name-like pattern with simple numbers (easily guessable)")

    # Sequential / keyboard patterns
    if re.search(r'(1234|2345|abcd|qwerty|asdfgh|zxcvbn)', pw_lower):
        score -= 1.0
        issues.append("Contains sequential or keyboard patterns")

    # Repeated characters
    if re.search(r'(.)\1{2,}', password):
        score -= 0.8
        issues.append("Contains repeated characters")

    final_score = max(0.0, min(5.0, round(score, 1)))
    return final_score, issues


def generate_suggestions(password):
    suggestions = []

    # Leetspeak version
    leet = password
    for old, new in [('a', '@'), ('s', '$'), ('i', '1'), ('o', '0')]:
        leet = leet.replace(old, new).replace(old.upper(), new)
    if leet != password:
        suggestions.append(leet + "X7kP!")

    # Add strong random suffix
    suffix = ''.join(secrets.choice(string.ascii_letters + string.digits + "!@#$") for _ in range(6))
    suggestions.append(password[:8] + suffix)

    # Fully random strong password
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    suggestions.append(''.join(secrets.choice(alphabet) for _ in range(16)))

    return suggestions


def main():
    print("=" * 55)
    print("           PASSWORD STRENGTH ANALYSIS REPORT")
    print("=" * 55)

    password = input("\nEnter password to analyze: ")
    score, issues = calculate_score(password)

    if score < 2.0:
        strength = "WEAK"
    elif score < 3.5:
        strength = "MEDIUM"
    else:
        strength = "STRONG"

    print(f"\nOverall Score      : {score}/5.0")
    print(f"Strength Rating    : {strength}")

    if issues:
        print("\nSecurity Issues Found:")
        for issue in issues:
            print(f"  • {issue}")
    else:
        print("\nNo major security issues detected.")

    if score < 4.0:
        print("\nRecommended Stronger Alternatives:")
        for i, sug in enumerate(generate_suggestions(password), 1):
            print(f"  {i}. {sug}")

    print("\n" + "=" * 55)


if __name__ == "__main__":
    main()