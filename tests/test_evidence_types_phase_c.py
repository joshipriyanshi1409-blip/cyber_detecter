import pytest

from src.risk.evidence_types import EvidenceSource, validate_source


def test_rule_and_ml_are_distinct_sources():
    assert EvidenceSource.RULE.value != EvidenceSource.MACHINE_LEARNING.value


def test_unknown_source_is_rejected():
    with pytest.raises(ValueError):
        validate_source("confidence")
