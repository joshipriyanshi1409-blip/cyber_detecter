from datetime import datetime, timezone
from pathlib import Path

from src.alerts.alert_engine import AlertEngine
from src.alerts.alert_models import Alert
from src.risk.authoritative_risk import Evidence, calculate_risk
from src.models.artifact_security import ModelIntegrityError, sha256_file, verify_model_artifact


def test_risk_breakdown_reconciles_when_raw_evidence_exceeds_100():
    now = datetime.now(timezone.utc)
    result = calculate_risk([
        Evidence("rule", "ddos", "rule", 1.0, None, 90, "rule", now),
        Evidence("cti", "cti", "indicator", True, None, 30, "cti", now),
    ])
    assert result.score == 100
    assert abs(sum(item["contribution"] for item in result.breakdown) - result.score) < 1e-9
    assert result.breakdown[0]["raw_contribution"] == 90
    assert result.breakdown[1]["raw_contribution"] == 30


def test_dedup_uses_processing_time_not_historical_event_time():
    engine = AlertEngine(deduplication_window=300)
    first = Alert(
        threat_type="TEST",
        source_ip="10.0.0.1",
        destination_ip="10.0.0.2",
        timestamp="2020-01-01T00:00:00+00:00",
    )
    second = Alert(
        threat_type="TEST",
        source_ip="10.0.0.1",
        destination_ip="10.0.0.2",
        timestamp="2020-01-01T00:00:01+00:00",
    )
    assert engine.process_detection(first) is not None
    # Same processing-time window means this is still a duplicate even though
    # the traffic timestamps are historical.
    assert engine.process_detection(second) is None


def test_model_integrity_hash(tmp_path: Path):
    model = tmp_path / "model.joblib"
    model.write_bytes(b"trusted-artifact")
    digest = sha256_file(model)
    assert verify_model_artifact(model, digest, require_hash=True) == digest

    model.write_bytes(b"tampered")
    try:
        verify_model_artifact(model, digest, require_hash=True)
    except ModelIntegrityError:
        pass
    else:
        raise AssertionError("tampered model artifact was accepted")
