import re
import getpass


#  A function that checks one rule at a time

def check_length(password: str) -> tuple[bool, str]:
    """Rule: password should be at least 8 characters."""
    if len(password) >= 8:
        return True, f"✔ Length is good ({len(password)} characters)"
    else:
        return False, f"✘ Too short — only {len(password)} characters (need at least 8)"


def check_uppercase(password: str) -> tuple[bool, str]:
    """Rule: must contain at least one uppercase letter."""
    if re.search(r"[A-Z]", password):
        return True, "✔ Contains uppercase letters"
    return False, "✘ No uppercase letters found (add A-Z)"


def check_lowercase(password: str) -> tuple[bool, str]:
    """Rule: must contain at least one lowercase letter."""
    if re.search(r"[a-z]", password):
        return True, "✔ Contains lowercase letters"
    return False, "✘ No lowercase letters found (add a-z)"


def check_digits(password: str) -> tuple[bool, str]:
    """Rule: must contain at least one number."""
    if re.search(r"\d", password):
        return True, "✔ Contains numbers"
    return False, "✘ No numbers found (add 0-9)"


def check_symbols(password: str) -> tuple[bool, str]:
    """Rule: must contain at least one special character."""
    if re.search(r"[^a-zA-Z0-9]", password):
        return True, "✔ Contains special characters"
    return False, "✘ No special characters (add !@#$%^&*)"


# Combine all rules into one score

def simple_strength_check(password: str) -> dict:
    checks = [
        check_length(password),
        check_uppercase(password),
        check_lowercase(password),
        check_digits(password),
        check_symbols(password),
    ]

    passed = sum(1 for passed, _ in checks if passed)
    score = passed * 20  # 5 rules × 20 points each = 100 max

    if score <= 40:
        label = "Weak"
    elif score <= 60:
        label = "Fair"
    elif score <= 80:
        label = "Strong"
    else:
        label = "Very Strong"

    return {
        "score": score,
        "label": label,
        "results": checks,
    }


# Show results to the user

def display_results(data: dict):
    print("\n" + "=" * 40)
    print(f"  Score  : {data['score']}/100")
    print(f"  Rating : {data['label']}")
    print("=" * 40)
    for passed, message in data["results"]:
        print(f"  {message}")
    print("=" * 40 + "\n")


# Main entry point
def main():
    print("\n🔐 Password Strength Checker (Starter Version)")
    print("────────────────────────────────────────────")
    password = input("Enter a password to check: ")

    if not password:
        print("[!] No password entered.")
        return

    results = simple_strength_check(password)
    display_results(results)

    print("Now try the full version: python src/analyzer.py")



if __name__ == "__main__":
    main()
