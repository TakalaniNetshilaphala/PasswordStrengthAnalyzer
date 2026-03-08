import hashlib
import re
import math
import argparse
import sys
from dataclasses import dataclass, field
from typing import Optional

try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    COLORS = True
except ImportError:
    COLORS = False
# CONSTANTS
HIBP_API_URL = "https://api.pwnedpasswords.com/range/{prefix}"
# Most commonly used weak passwords (NIST & OWASP recommendations)
COMMON_PASSWORDS = {
    "password", "123456", "password1", "12345678", "qwerty",
    "abc123", "monkey", "1234567", "letmein", "trustno1",
    "dragon", "baseball", "iloveyou", "master", "sunshine",
    "ashley", "bailey", "passw0rd", "shadow", "123123",
    "654321", "superman", "qazwsx", "michael", "football",
    "password2", "qwerty123", "1q2w3e4r", "pass", "hello",
}
# Keyboard walk sequences
SEQUENTIAL_PATTERNS = [
    "01234", "12345", "23456", "34567", "45678", "56789",
    "abcde", "bcdef", "cdefg", "qwert", "werty", "ertyu",
    "asdfg", "sdfgh", "zxcvb", "!@#$%",
]
# DATA STRUCTURES
@dataclass
class CheckResult:
    """Stores the result of a single password rule check."""
    passed: bool
    rule: str
    detail: str
    penalty: int = 0      # score deducted if failed
    bonus: int = 0        # score added if passed

@dataclass
class AnalysisReport:
    """Full analysis report for one password."""
    score: int
    label: str
    entropy: float
    length: int
    checks: list[CheckResult] = field(default_factory=list)
    breached_count: Optional[int] = None   # None = not checked, -1 = API error, 0 = clean

    @property
    def passed_checks(self) -> list[CheckResult]:
        return [c for c in self.checks if c.passed]

    @property
    def failed_checks(self) -> list[CheckResult]:
        return [c for c in self.checks if not c.passed]
# ENTROPY CALCULATION
def calculate_entropy(password: str) -> float:
    """
    Estimates password entropy in bits.
    Entropy = length × log2(character_pool_size)
    A strong password should have at least 60 bits of entropy.
    Reference: NIST SP 800-63B
    """
    pool_size = 0
    if re.search(r"[a-z]", password):         pool_size += 26
    if re.search(r"[A-Z]", password):         pool_size += 26
    if re.search(r"\d", password):             pool_size += 10
    if re.search(r"[^a-zA-Z0-9]", password):  pool_size += 32

    if pool_size == 0:
        return 0.0
    return round(len(password) * math.log2(pool_size), 2)

# INDIVIDUAL RULE CHECKS
def rule_length(password: str) -> CheckResult:
    """Passwords under 8 chars are immediately weak."""
    n = len(password)
    if n >= 16:
        return CheckResult(True, "Length", f"{n} characters (excellent — 16+)", bonus=15)
    elif n >= 12:
        return CheckResult(True, "Length", f"{n} characters (good — 12+)", bonus=10)
    elif n >= 8:
        return CheckResult(True, "Length", f"{n} characters (minimum met — aim for 12+)", bonus=5)
    else:
        return CheckResult(False, "Length", f"Only {n} characters — minimum is 8", penalty=30)


def rule_uppercase(password: str) -> CheckResult:
    if re.search(r"[A-Z]", password):
        return CheckResult(True, "Uppercase", "Contains uppercase letters (A–Z)", bonus=10)
    return CheckResult(False, "Uppercase", "No uppercase letters — add at least one A–Z", penalty=10)


def rule_lowercase(password: str) -> CheckResult:
    if re.search(r"[a-z]", password):
        return CheckResult(True, "Lowercase", "Contains lowercase letters (a–z)", bonus=10)
    return CheckResult(False, "Lowercase", "No lowercase letters — add at least one a–z", penalty=10)


def rule_digits(password: str) -> CheckResult:
    if re.search(r"\d", password):
        return CheckResult(True, "Digits", "Contains numbers (0–9)", bonus=10)
    return CheckResult(False, "Digits", "No numbers — add at least one digit 0–9", penalty=10)


def rule_symbols(password: str) -> CheckResult:
    if re.search(r"[^a-zA-Z0-9]", password):
        return CheckResult(True, "Symbols", "Contains special characters (!@#$...)", bonus=15)
    return CheckResult(False, "Symbols", "No special characters — add symbols like !@#$%^&*", penalty=10)


def rule_common_password(password: str) -> CheckResult:
    if password.lower() in COMMON_PASSWORDS:
        return CheckResult(False, "Common password", f"'{password}' is one of the most guessed passwords", penalty=40)
    return CheckResult(True, "Common password", "Not in the common passwords list", bonus=5)


def rule_repeating_chars(password: str) -> CheckResult:
    if re.search(r"(.)\1{2,}", password):
        return CheckResult(False, "Repeating chars", "Repeating characters found (e.g. 'aaa', '111')", penalty=10)
    return CheckResult(True, "Repeating chars", "No excessive repeating characters", bonus=5)


def rule_sequential_patterns(password: str) -> CheckResult:
    lower = password.lower()
    for seq in SEQUENTIAL_PATTERNS:
        if seq in lower:
            return CheckResult(
                False, "Sequential pattern",
                f"Keyboard/number sequence detected ('{seq}') — easy to guess",
                penalty=10
            )
    return CheckResult(True, "Sequential pattern", "No sequential patterns detected", bonus=5)


def rule_entropy_bonus(entropy: float) -> CheckResult:
    if entropy >= 80:
        return CheckResult(True, "Entropy", f"{entropy} bits (excellent complexity)", bonus=10)
    elif entropy >= 60:
        return CheckResult(True, "Entropy", f"{entropy} bits (good complexity)", bonus=5)
    else:
        return CheckResult(False, "Entropy", f"Only {entropy} bits — increase variety and length", penalty=0)

# ANALYSIS ENGINE (combines all rules)
def analyze_password(password: str) -> AnalysisReport:
    entropy = calculate_entropy(password)
    checks = [
        rule_length(password),
        rule_uppercase(password),
        rule_lowercase(password),
        rule_digits(password),
        rule_symbols(password),
        rule_common_password(password),
        rule_repeating_chars(password),
        rule_sequential_patterns(password),
        rule_entropy_bonus(entropy),
    ]
    # Score calculation
    score = 30  # base
    for check in checks:
        if check.passed:
            score += check.bonus
        else:
            score -= check.penalty

    score = max(0, min(100, score))
    # Label
    if score < 30:
        label = "Very Weak"
    elif score < 50:
        label = "Weak"
    elif score < 65:
        label = "Fair"
    elif score < 80:
        label = "Strong"
    else:
        label = "Very Strong"

    return AnalysisReport(
        score=score,
        label=label,
        entropy=entropy,
        length=len(password),
        checks=checks,
    )
#  HIBP BREACH CHECK (k-anonymity model)
def check_hibp_breach(password: str) -> int:
    if not HTTPX_AVAILABLE:
        print("[!] httpx not installed. Run: pip install httpx")
        return -1

    sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]

    try:
        response = httpx.get(
            HIBP_API_URL.format(prefix=prefix),
            timeout=6,
            headers={
                "User-Agent": "PasswordStrengthAnalyzer/1.0",
                "Add-Padding": "true",    # adds fake results for extra privacy
            }
        )
        response.raise_for_status()
        # Search the returned list for our hash suffix
        for line in response.text.splitlines():
            parts = line.split(":")
            if len(parts) == 2 and parts[0].strip() == suffix:
                return int(parts[1].strip())

        return 0   # suffix not found — password not breached

    except httpx.TimeoutException:
        print("[!] HIBP API request timed out.")
        return -1
    except httpx.HTTPStatusError as e:
        print(f"[!] HIBP API returned HTTP {e.response.status_code}")
        return -1
    except httpx.RequestError as e:
        print(f"[!] Could not connect to HIBP API: {e}")
        return -1
# DISPLAY
# Inner content width (characters between the │ borders)
INNER = 56

def _c(text: str, color_code: str) -> str:
    if not COLORS:
        return text
    return f"{color_code}{text}{Style.RESET_ALL}"


def _row(content: str = "") -> None:
    """Print one row: │  content padded to INNER  │"""
    # Strip invisible color codes for length calculation
    visible = content
    for code in [Fore.RED, Fore.GREEN, Fore.YELLOW, Fore.CYAN,
                 Fore.WHITE, Fore.RESET, Style.RESET_ALL,
                 Style.BRIGHT, Style.DIM]:
        visible = visible.replace(code, "")
    pad = INNER - len(visible)
    print(f"  │  {content}{' ' * max(0, pad)}  │")


def _top()    : print(f"  ┌{'─' * (INNER + 4)}┐")
def _mid()    : print(f"  ├{'─' * (INNER + 4)}┤")
def _bot()    : print(f"  └{'─' * (INNER + 4)}┘")
def _blank()  : _row()


def display_report(report: AnalysisReport, show_password: str = "•••"):

    # ── Label colors ──
    label_colors = {
        "Very Weak":   Fore.RED    if COLORS else "",
        "Weak":        Fore.RED    if COLORS else "",
        "Fair":        Fore.YELLOW if COLORS else "",
        "Strong":      Fore.CYAN   if COLORS else "",
        "Very Strong": Fore.GREEN  if COLORS else "",
    }
    lc = label_colors.get(report.label, "")

    # ── Score bar (fixed 20 chars) ──
    filled = int(report.score / 5)
    bar    = "█" * filled + "░" * (20 - filled)

    # ── Breach text (keep short) ──
    if report.breached_count is None:
        breach_text  = "Not checked"
        breach_color = ""
    elif report.breached_count == 0:
        breach_text  = "Clean — not found in any breach database"
        breach_color = Fore.GREEN if COLORS else ""
    elif report.breached_count == -1:
        breach_text  = "Unavailable — could not reach API"
        breach_color = Fore.YELLOW if COLORS else ""
    else:
        breach_text  = f"COMPROMISED — seen {report.breached_count:,}x in breaches"
        breach_color = Fore.RED if COLORS else ""

    print()
    _top()
    _row(_c("PASSWORD STRENGTH REPORT: ", Fore.WHITE if COLORS else ""))
    _row("By Takalani Netshilaphala - Aspiring Cyber Analyst")
    _mid()

    _blank()
    _row(f"{'Password':<12}  {show_password}")
    _row(f"{'Strength':<12}  {_c(report.label, lc)}")
    _row(f"{'Score':<12}  {bar}  {report.score}/100")
    _row(f"{'Length':<12}  {report.length} characters")
    _row(f"{'Entropy':<12}  {report.entropy} bits")
    if report.breached_count is not None:
        _row(f"{'HIBP':<12}  {_c(breach_text, breach_color)}")
    _blank()

    if report.passed_checks:
        _mid()
        _blank()
        _row(_c("CRITERIA MET", Fore.GREEN if COLORS else ""))
        _blank()
        for c in report.passed_checks:
            _row(f"  {_c('✔', Fore.GREEN if COLORS else '')}  {c.detail}")
        _blank()

    if report.failed_checks:
        _mid()
        _blank()
        _row(_c("ISSUES DETECTED", Fore.RED if COLORS else ""))
        _blank()
        for c in report.failed_checks:
            _row(f"  {_c('✘', Fore.RED if COLORS else '')}  {c.detail}")
        _blank()

    _bot()
    print()
#  CLI ARGUMENT PARSING & MAIN

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="analyzer",
        description="🔐 Password Strength Analyzer & HaveIBeenPwned Breach Checker",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
        """
    )
    parser.add_argument(
        "-p", "--password",
        help="Password to analyze (use quotes around it)"
    )
    parser.add_argument(
        "--no-breach",
        action="store_true",
        help="Skip the HaveIBeenPwned breach check (offline mode)"
    )
    parser.add_argument(
        "--show",
        action="store_true",
        help="Show the password in the output (hidden by default)"
    )
    parser.add_argument(
        "--batch",
        metavar="FILE",
        help="Path to a text file with one password per line"
    )
    return parser


def run_single(password: str, breach: bool, show: bool):
    """Analyze one password and print the report."""
    report = analyze_password(password)

    if breach:
        sys.stdout.write("  Checking HaveIBeenPwned... ")
        sys.stdout.flush()
        report.breached_count = check_hibp_breach(password)
        print("done.")

    display = password if show else "•" * min(len(password), 12)
    display_report(report, show_password=display)


def run_batch(filepath: str, breach: bool):
    """Read passwords from a file and analyze each one."""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            passwords = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        print(f"[!] File not found: {filepath}")
        return

    print(f"\n  Analyzing {len(passwords)} password(s) from '{filepath}' ...\n")
    print(f"  {'─' * 58}")
    for i, pw in enumerate(passwords, 1):
        print(f"\n  [ Password {i} of {len(passwords)} ]")
        run_single(pw, breach=breach, show=False)


def main():
    parser = build_arg_parser()
    args = parser.parse_args()

    print("\n  ┌────────────────────────────────────────────────────────┐")
    print("  │     PASSWORD STRENGTH ANALYZER                         │")
    print("  │     By Takalani Netshilaphala - Aspiring Cyber Analyst │")
    print("  └────────────────────────────────────────────────────────┘")
    # Batch mode
    if args.batch:
        run_batch(args.batch, breach=not args.no_breach)
        return
    # Single password — from arg or interactive
    if args.password:
        password = args.password
    else:
        try:
            password = input("\n  Please Enter Password To Analyze : ")
        except KeyboardInterrupt:
            print("\n  [Cancelled]")
            return

    if not password:
        print("  [!] No password entered.")
        return

    run_single(password, breach=not args.no_breach, show=args.show)


if __name__ == "__main__":
    main()
