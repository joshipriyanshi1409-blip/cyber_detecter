"""
Dependency-free tests for src/cti/rate_limiter.py and its wiring into
src/cti/enrichment.py::ThreatIntelligenceEnricher.

Run standalone: python3 tests/test_cti_rate_limiting.py
(No pytest/network required -- follows the same pattern as
tests/test_window_rates.py etc.)
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.cti.rate_limiter import CTIRateLimiter
from src.cti.enrichment import ThreatIntelligenceEnricher
from src.cti.providers import LocalThreatIntelligenceProvider
from src.alerts.alert_models import Alert


def test_limiter_allows_up_to_max_then_blocks():
    limiter = CTIRateLimiter(max_requests=3, window_seconds=60.0)
    now = 1000.0
    assert limiter.allow(now) is True
    assert limiter.allow(now) is True
    assert limiter.allow(now) is True
    # 4th request in the same instant exceeds the cap
    assert limiter.allow(now) is False
    assert limiter.rejected_count == 1
    assert limiter.allowed_count == 3
    print("PASS: limiter allows up to max_requests, then blocks")


def test_limiter_window_slides():
    limiter = CTIRateLimiter(max_requests=2, window_seconds=10.0)
    assert limiter.allow(now=0.0) is True
    assert limiter.allow(now=1.0) is True
    assert limiter.allow(now=2.0) is False  # still within window, cap hit
    # advance past the window -- the first two requests should have expired
    assert limiter.allow(now=11.5) is True
    print("PASS: sliding window expires old requests correctly")


def test_limiter_rejects_invalid_config():
    try:
        CTIRateLimiter(max_requests=0)
        assert False, "expected ValueError for max_requests=0"
    except ValueError:
        pass
    try:
        CTIRateLimiter(max_requests=5, window_seconds=0)
        assert False, "expected ValueError for window_seconds=0"
    except ValueError:
        pass
    print("PASS: invalid limiter configuration rejected")


def test_limiter_status_reports_real_counts():
    # Uses real time.time() (no synthetic `now`) so current_load(), which
    # get_status() calls without a `now` override, reflects these same
    # timestamps rather than evicting them against a much-later "now".
    limiter = CTIRateLimiter(max_requests=2, window_seconds=60.0)
    limiter.allow()
    limiter.allow()
    limiter.allow()  # rejected
    status = limiter.get_status()
    assert status["allowed_count"] == 2
    assert status["rejected_count"] == 1
    assert status["current_load"] == 2
    print("PASS: limiter status reports real allowed/rejected counts")


def test_cache_hit_does_not_consume_rate_limit_budget():
    enricher = ThreatIntelligenceEnricher(
        providers=[LocalThreatIntelligenceProvider()],
        max_lookups_per_window=1,
        rate_limit_window_seconds=60.0,
    )
    # First lookup consumes the only slot and gets cached.
    result1, status1 = enricher.lookup_indicator_with_status("10.0.0.1", "ip")
    assert status1 == "checked"
    assert result1 is not None and result1.is_malicious is True

    # Repeated lookup of the SAME indicator should be a cache hit and must
    # NOT be blocked, even though the rate-limit budget is exhausted.
    result2, status2 = enricher.lookup_indicator_with_status("10.0.0.1", "ip")
    assert status2 == "cache_hit"
    assert result2 is not None and result2.is_malicious is True
    print("PASS: cache hits do not consume rate-limit budget")


def test_distinct_indicators_get_rate_limited_and_not_falsely_cached_negative():
    enricher = ThreatIntelligenceEnricher(
        providers=[LocalThreatIntelligenceProvider()],
        max_lookups_per_window=1,
        rate_limit_window_seconds=60.0,
    )
    # Consume the single slot on one indicator.
    enricher.lookup_indicator_with_status("1.2.3.4", "ip")

    # A DIFFERENT indicator (e.g. from a flood of spoofed sources) must be
    # rate-limited, not silently treated as "checked, not malicious".
    result, status = enricher.lookup_indicator_with_status("5.6.7.8", "ip")
    assert status == "rate_limited"
    assert result is None

    # And it must NOT have been cached as a negative result -- once budget
    # frees up, it should be checked for real, not served a stale "clean".
    assert "ip:5.6.7.8" not in enricher.cache
    print("PASS: rate-limited lookups are distinguishable from real negatives and not cached")


def test_enrich_alert_records_rate_limited_indicators_explicitly():
    enricher = ThreatIntelligenceEnricher(
        providers=[LocalThreatIntelligenceProvider()],
        max_lookups_per_window=1,
        rate_limit_window_seconds=60.0,
    )
    # Burn the one slot on an unrelated indicator first.
    enricher.lookup_indicator_with_status("9.9.9.9", "ip")

    alert = Alert(
        threat_type="PORT_SCAN",
        source_ip="1.1.1.1",
        destination_ip="2.2.2.2",
        severity="LOW",
        risk_score=10.0,
        confidence=0.5,
        detector="test",
    )
    enriched = enricher.enrich_alert(alert)
    # Both source_ip and destination_ip lookups should have been
    # rate-limited (only one external slot existed, already spent).
    assert enriched.details.get('cti_rate_limited') is True
    assert any("1.1.1.1" in i for i in enriched.details.get('cti_rate_limited_indicators', []))
    print("PASS: enrich_alert exposes rate-limited indicators on the alert, never silently")


def test_provider_status_includes_rate_limiter_health():
    enricher = ThreatIntelligenceEnricher(providers=[LocalThreatIntelligenceProvider()])
    status = enricher.get_provider_status()
    assert '_rate_limiter' in status
    assert 'max_requests' in status['_rate_limiter']
    print("PASS: get_provider_status() exposes rate-limiter health (Section 35)")


if __name__ == "__main__":
    tests = [v for k, v in list(globals().items()) if k.startswith("test_") and callable(v)]
    passed = 0
    failed = 0
    for t in tests:
        try:
            t()
            passed += 1
        except AssertionError as e:
            print(f"FAIL: {t.__name__}: {e}")
            failed += 1
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
