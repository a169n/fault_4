"""Part E: AI-assisted detection — anomaly count, rate, prioritisation and threshold sensitivity."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence

from fault4.data import AnomalySignal

ANOMALY_THRESHOLD = 0.75


@dataclass(frozen=True)
class AnomalyResult:
    name: str
    normal: float
    observed: float
    delta: float
    ratio: Optional[float]
    margin: float
    is_anomaly: bool


def score_signals(signals: Sequence[AnomalySignal], threshold: float = ANOMALY_THRESHOLD) -> List[AnomalyResult]:
    return [
        AnomalyResult(
            name=s.name,
            normal=s.normal,
            observed=s.observed,
            delta=round(s.observed - s.normal, 2),
            ratio=round(s.observed / s.normal, 2) if s.normal else None,
            margin=round(s.observed - threshold, 2),
            is_anomaly=s.observed >= threshold,
        )
        for s in signals
    ]


def anomaly_summary(results: Sequence[AnomalyResult]) -> Dict[str, Any]:
    """Priority = largest deviation from baseline (ties: higher observed score); ratio shown for comparison."""
    flagged = [r for r in results if r.is_anomaly]
    by_delta = max(flagged, key=lambda r: (r.delta, r.observed), default=None)
    with_ratio = [r for r in flagged if r.ratio is not None]
    by_ratio = max(with_ratio, key=lambda r: r.ratio, default=None)
    return {
        "count": len(flagged),
        "total": len(results),
        "rate": round(len(flagged) / len(results), 2) if results else 0.0,
        "highest_priority": by_delta.name if by_delta else None,
        "highest_by_ratio": by_ratio.name if by_ratio else None,
    }


def threshold_sensitivity(
    signals: Sequence[AnomalySignal], thresholds: Sequence[float] = (0.75, 0.80, 0.85, 0.90, 0.95)
) -> List[Dict[str, float]]:
    return [{"threshold": t, "count": sum(1 for s in signals if s.observed >= t)} for t in thresholds]
