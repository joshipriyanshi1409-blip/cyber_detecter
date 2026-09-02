"""Controlled evidence-source labels used by Phase C."""
from enum import Enum


class EvidenceSource(str, Enum):
    RULE = "rule"
    MACHINE_LEARNING = "machine_learning"
    CTI = "cti"
    BEHAVIORAL = "behavioral"
    ASSET_CONTEXT = "asset_context"


def validate_source(source: str) -> str:
    value = str(source)
    allowed = {item.value for item in EvidenceSource}
    if value not in allowed:
        raise ValueError(f"unsupported evidence source: {value}")
    return value
