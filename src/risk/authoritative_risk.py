"""Authoritative evidence-based risk calculation.

Phase C establishes one deterministic calculation boundary. Existing callers can
adopt it incrementally; no existing detector is removed or rewritten here.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any, Iterable


@dataclass(frozen=True)
class Evidence:
    source: str
    detector: str
    feature: str
    raw_value: float | int | str | bool | None
    threshold: float | int | str | None
    contribution: float
    reason: str
    timestamp: datetime


@dataclass(frozen=True)
class RiskResult:
    score: float
    evidence: tuple[Evidence, ...]
    breakdown: tuple[dict[str, Any], ...]


def _clamp(value: float) -> float:
    return max(0.0, min(100.0, float(value)))


def calculate_risk(evidence: Iterable[Evidence]) -> RiskResult:
    """Calculate a bounded score whose displayed breakdown exactly reconciles."""
    items = tuple(evidence)
    raw_total = max(0.0, sum(float(e.contribution) for e in items))
    scale = 1.0 if raw_total <= 100.0 or raw_total == 0 else 100.0 / raw_total
    score = _clamp(raw_total)

    breakdown_items = []
    for evidence_item in items:
        item = asdict(evidence_item)
        item["raw_contribution"] = float(evidence_item.contribution)
        item["contribution"] = float(evidence_item.contribution) * scale
        item["timestamp"] = evidence_item.timestamp.astimezone(timezone.utc).isoformat()
        breakdown_items.append(item)

    # Rounding can introduce a tiny reconciliation error. Correct only the last
    # item so the operator-visible breakdown is mathematically auditable.
    if breakdown_items:
        displayed_total = sum(item["contribution"] for item in breakdown_items)
        breakdown_items[-1]["contribution"] += score - displayed_total

    return RiskResult(
        score=score,
        evidence=items,
        breakdown=tuple(breakdown_items),
    )
