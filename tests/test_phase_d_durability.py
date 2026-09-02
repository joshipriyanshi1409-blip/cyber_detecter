import json
from pathlib import Path

from src.alerts.alert_models import Alert
from src.blockchain.hash_chain import HashChain
from src.storage.database import DatabaseManager, serialize_alert


def make_alert(i=1):
    return Alert(
        alert_id=f"phase-d-{i}",
        threat_type="TEST",
        source_ip="10.0.0.1",
        destination_ip="10.0.0.2",
        severity="HIGH",
        risk_score=70.0,
        confidence=0.8,
        detector="test",
        details={"b": 2, "a": 1},
    )


def test_alert_serialization_is_deterministic():
    a = make_alert()
    assert serialize_alert(a) == serialize_alert(a)


def test_database_is_idempotent(tmp_path):
    db = DatabaseManager(str(tmp_path / "alerts.db"))
    a = make_alert()
    assert db.health_check()
    assert db.add_alerts([a]) == 1
    assert db.add_alerts([a]) == 0
    assert db.get_alert(a.alert_id) is not None
    db.close()


def test_hash_chain_persists_atomically(tmp_path):
    path = tmp_path / "chain.json"
    chain = HashChain(str(path))
    chain.append_alert(make_alert())
    assert chain.validate_chain()["is_valid"] is True
    assert path.exists()
    loaded = HashChain(str(path))
    assert loaded.validate_chain()["is_valid"] is True
    assert len(loaded.chain) == 1
