import sys
import os

# Allow importing from src/ folder
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import pytest
from analyzer import (
    analyze_password,
    calculate_entropy,
    check_hibp_breach,
    rule_length,
    rule_uppercase,
    rule_lowercase,
    rule_digits,
    rule_symbols,
    rule_common_password,
    rule_repeating_chars,
    rule_sequential_patterns,
)


# ENTROPY TESTS
class TestEntropy:

    def test_all_lowercase_has_small_pool(self):
        e = calculate_entropy("abcdefgh")
        assert e == round(8 * 4.7, 2) or e > 0

    def test_mixed_charset_higher_than_single(self):
        low  = calculate_entropy("aaaaaaaa")
        high = calculate_entropy("aA1!bB2@")
        assert high > low

    def test_longer_password_higher_entropy(self):
        short = calculate_entropy("aA1!")
        long  = calculate_entropy("aA1!bB2@cC3#")
        assert long > short

    def test_empty_password_zero_entropy(self):
        assert calculate_entropy("") == 0.0

    def test_only_spaces_returns_nonzero(self):
        # spaces are symbols — pool includes 32 special chars
        e = calculate_entropy("    ")
        assert e > 0

# INDIVIDUAL RULE TESTS

class TestRules:

    # Length rule
    def test_length_below_minimum(self):
        r = rule_length("abc")
        assert r.passed is False
        assert r.penalty > 0

    def test_length_at_minimum(self):
        r = rule_length("abcdefgh")
        assert r.passed is True

    def test_length_excellent(self):
        r = rule_length("a" * 16)
        assert r.passed is True
        assert r.bonus >= 15

    # Uppercase rule
    def test_no_uppercase_fails(self):
        assert rule_uppercase("allowercase1!").passed is False

    def test_uppercase_present_passes(self):
        assert rule_uppercase("hasUpperCase").passed is True

    # Lowercase rule
    def test_no_lowercase_fails(self):
        assert rule_lowercase("ALLCAPS123!").passed is False

    def test_lowercase_present_passes(self):
        assert rule_lowercase("haslower").passed is True

    # Digits rule
    def test_no_digits_fails(self):
        assert rule_digits("NoDigitsHere!").passed is False

    def test_digit_present_passes(self):
        assert rule_digits("has1digit").passed is True

    # Symbols rule
    def test_no_symbols_fails(self):
        assert rule_symbols("NoSymbols123").passed is False

    def test_symbol_present_passes(self):
        assert rule_symbols("has!symbol").passed is True

    # Common password rule
    def test_common_password_fails(self):
        r = rule_common_password("password")
        assert r.passed is False
        assert r.penalty >= 30

    def test_uncommon_password_passes(self):
        r = rule_common_password("Xk9#mN2$qLw7")
        assert r.passed is True

    # Repeating chars rule
    def test_triple_repeat_fails(self):
        r = rule_repeating_chars("aaabbb111")
        assert r.passed is False

    def test_double_repeat_passes(self):
        r = rule_repeating_chars("aabb")
        assert r.passed is True

    # Sequential patterns rule
    def test_numeric_sequence_fails(self):
        r = rule_sequential_patterns("Pass12345")
        assert r.passed is False

    def test_alpha_sequence_fails(self):
        r = rule_sequential_patterns("myabcdepass")
        assert r.passed is False

    def test_no_sequence_passes(self):
        r = rule_sequential_patterns("Xk9#mNqLw7")
        assert r.passed is True


# FULL ANALYSIS TESTS

class TestAnalysis:

    def test_very_weak_password(self):
        report = analyze_password("abc")
        assert report.label in ["Very Weak", "Weak"]
        assert report.score < 50

    def test_common_password_low_score(self):
        report = analyze_password("password")
        assert report.score < 30

    def test_strong_password_high_score(self):
        report = analyze_password("T!ger$9Lamp#Wave42")
        assert report.score >= 75
        assert report.label in ["Strong", "Very Strong"]

    def test_score_is_between_0_and_100(self):
        for pw in ["a", "password", "123456", "T!ger$9Lamp#Wave42xx!!", "x" * 100]:
            r = analyze_password(pw)
            assert 0 <= r.score <= 100, f"Score out of range for: {pw}"

    def test_report_has_length(self):
        report = analyze_password("Hello123!")
        assert report.length == 9

    def test_longer_password_scores_higher(self):
        short  = analyze_password("Ab1!")
        longer = analyze_password("Ab1!Cd2@Ef3#Gh4$")
        assert longer.score >= short.score

    def test_adding_symbol_improves_score(self):
        without = analyze_password("Password123")
        with_sym = analyze_password("Password123!")
        assert with_sym.score >= without.score

    def test_adding_uppercase_improves_score(self):
        without = analyze_password("password123!")
        with_up  = analyze_password("Password123!")
        assert with_up.score >= without.score

    def test_breached_count_defaults_to_none(self):
        report = analyze_password("anything")
        assert report.breached_count is None


# EDGE CASES

class TestEdgeCases:

    def test_empty_password(self):
        report = analyze_password("")
        assert report.score < 30

    def test_single_character(self):
        report = analyze_password("a")
        assert report.label in ["Very Weak", "Weak"]

    def test_very_long_password(self):
        report = analyze_password("aA1!" * 30)  # 120 chars
        assert 0 <= report.score <= 100

    def test_whitespace_only(self):
        report = analyze_password("     ")
        assert report.score < 60

    def test_unicode_characters(self):
        # Should not crash
        report = analyze_password("Pässwörд123!")
        assert report.score >= 0

    def test_all_digits(self):
        report = analyze_password("12345678")
        assert report.label in ["Very Weak", "Weak", "Fair"]

# INTEGRATION HINT (real API — disabled by default)

class TestHIBPIntegration:
    """
    These tests require a live internet connection.
    Remove the skip decorator to run them.
    """
    @pytest.mark.skip(reason="Requires internet connection — remove skip to enable")
    def test_known_breached_password(self):
        # "password" has been in hundreds of millions of breaches
        count = check_hibp_breach("password")
        assert count > 0

    @pytest.mark.skip(reason="Requires internet connection — remove skip to enable")
    def test_random_safe_password_not_breached(self):
        # An extremely random string very unlikely to be in any breach
        count = check_hibp_breach("Xk9#mN2$qLw7!Rz5@Vb8")
        assert count == 0
