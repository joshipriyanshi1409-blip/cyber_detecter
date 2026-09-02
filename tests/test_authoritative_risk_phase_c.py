from datetime import datetime, timezone

from src.risk.authoritative_risk import Evidence, calculate_risk


def ev(contribution):
    return Evidence(
        source="rule",
        detector="test",
        feature="x",
        raw_value=1,
        threshold=0,
        contribution=contribution,
        reason="test",
        timestamp=datetime.now(timezone.utc),
    )


def test_risk_is_bounded_and_breakdown_has_same_evidence():
    result = calculate_risk([ev(20), ev(30)])
    assert result.score == 50
    assert len(result.breakdown) == 2
    assert sum(item["contribution"] for item in result.breakdown) == 50


def test_risk_clamps_above_100():
    result = calculate_risk([ev(80), ev(50)])
    assert result.score == 100


def test_risk_clamps_below_zero():
    result = calculate_risk([ev(-80), ev(10)])
    assert result.score == 0


def test_empty_evidence_is_zero():
    result = calculate_risk([])
    assert result.score == 0
    assert result.breakdown == ()
