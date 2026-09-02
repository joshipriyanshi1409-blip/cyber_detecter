"""
Tests for src.features.entropy

Dependency-free (tests/test_features.py imports scapy at module level
and can't run in this sandbox at all, so these had NO working coverage
here before this file). Run standalone with
`python3 tests/test_entropy.py`.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.features.entropy import EntropyCalculator, DomainEntropyAnalyzer


def test_shannon_entropy_empty_and_uniform():
    assert EntropyCalculator.shannon_entropy("") == 0.0
    assert EntropyCalculator.shannon_entropy("aaaa") == 0.0
    # 4 distinct, evenly-used symbols -> max entropy = log2(4) = 2.0
    assert abs(EntropyCalculator.shannon_entropy("abcd") - 2.0) < 1e-9
    print("PASS: shannon_entropy handles empty/uniform/max-entropy cases correctly")


def test_normalized_entropy_bounds():
    for text in ["", "a", "aa", "ab", "abcdefgh12345!@#$"]:
        val = EntropyCalculator.normalized_entropy(text)
        assert 0.0 <= val <= 1.0 + 1e-9, f"normalized_entropy({text!r}) out of [0,1]: {val}"
    print("PASS: normalized_entropy stays within [0, 1] across varied inputs")


def test_ngram_features_consistent_dict_shape_regardless_of_length():
    """
    Regression test: calculate_ngram_features() must return the SAME
    set of keys whether or not the input is long enough to produce any
    n-grams. Before the fix, a text shorter than n (a realistic input --
    short DGA-style labels exist) omitted "ngram_entropy" entirely,
    giving two inconsistent return shapes from the same function.
    """
    analyzer = DomainEntropyAnalyzer()

    empty_result = analyzer.calculate_ngram_features("")
    short_result = analyzer.calculate_ngram_features("a", n=2)  # shorter than n=2
    long_result = analyzer.calculate_ngram_features("abcdefgh", n=2)

    expected_keys = {"ngram_score", "unique_ngrams", "ngram_entropy"}
    assert set(empty_result.keys()) == expected_keys, empty_result
    assert set(short_result.keys()) == expected_keys, short_result
    assert set(long_result.keys()) == expected_keys, long_result

    assert empty_result["ngram_entropy"] == 0.0
    assert short_result["ngram_entropy"] == 0.0
    print("PASS: calculate_ngram_features always returns a consistent dict shape")


def test_analyze_domain_short_label_does_not_crash():
    """A single-character main label (shorter than the default n=2
    n-gram size) must not crash analyze_domain -- this is exactly the
    path that hit the inconsistent-dict-shape bug."""
    analyzer = DomainEntropyAnalyzer()
    features = analyzer.analyze_domain("a.com")
    assert features["main_label_length"] == 1
    assert "ngram_entropy" in features
    assert features["ngram_entropy"] == 0.0
    print("PASS: analyze_domain with a short main label -> no crash, consistent features")


def test_analyze_domain_empty_input():
    analyzer = DomainEntropyAnalyzer()
    features = analyzer.analyze_domain("")
    assert features["domain"] == ""
    assert features["entropy"] == 0.0
    print("PASS: analyze_domain('') -> empty feature dict, no crash")


def test_digit_vowel_consonant_ratios_sum_reasonably():
    ratio_d = DomainEntropyAnalyzer.calculate_digit_ratio("abc123")
    ratio_v = DomainEntropyAnalyzer.calculate_vowel_ratio("abc123")
    ratio_c = DomainEntropyAnalyzer.calculate_consonant_ratio("abc123")
    assert abs(ratio_d - (3 / 6)) < 1e-9
    # a is a vowel, b,c are consonants, digits are neither
    assert abs(ratio_v - (1 / 6)) < 1e-9
    assert abs(ratio_c - (2 / 6)) < 1e-9
    print("PASS: digit/vowel/consonant ratios computed correctly")


if __name__ == "__main__":
    tests = [v for k, v in list(globals().items()) if k.startswith("test_")]
    passed, failed = 0, 0
    for t in tests:
        try:
            t()
            passed += 1
        except AssertionError as e:
            print(f"FAIL {t.__name__}: {e}")
            failed += 1
        except Exception as e:
            print(f"ERROR {t.__name__}: {type(e).__name__}: {e}")
            failed += 1
    print(f"\n{passed} passed, {failed} failed")
