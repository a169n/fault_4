"""Part B: risk matrix, Risk = Likelihood x Impact on 1-5 scales."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Sequence, Tuple

SCALE = range(1, 6)
# Spec bands: 1-4 Low, 5-9 Medium, 10-16 High, 17-25 Critical.
BANDS = ((4, "Low"), (9, "Medium"), (16, "High"), (25, "Critical"))

LIKELIHOOD_RULE = (
    "Likelihood 5 = observed and succeeded in this incident; "
    "4 = attempted or indirectly evidenced, with the outcome not logged."
)
IMPACT_RULE = (
    "Impact 5 = loss of research data or of the ability to recover; "
    "4 = serious but bounded (access or confidentiality)."
)


def _check_scale(name: str, value: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value not in SCALE:
        raise ValueError(f"{name} must be an integer from 1 to 5, got {value!r}")


def risk_score(likelihood: int, impact: int) -> int:
    _check_scale("likelihood", likelihood)
    _check_scale("impact", impact)
    return likelihood * impact


def risk_level(score: int) -> str:
    if isinstance(score, bool) or not isinstance(score, int) or not 1 <= score <= 25:
        raise ValueError(f"risk score must be an integer from 1 to 25, got {score!r}")
    return next(level for upper, level in BANDS if score <= upper)


@dataclass(frozen=True)
class ThreatRisk:
    threat: str
    likelihood: int
    impact: int
    likelihood_reason: str
    impact_reason: str

    @property
    def score(self) -> int:
        return risk_score(self.likelihood, self.impact)

    @property
    def level(self) -> str:
        return risk_level(self.score)


THREATS: Tuple[ThreatRisk, ...] = (
    ThreatRisk(
        "Credential compromise", 5, 4,
        "L5 (observed and succeeded): the 09:04 login succeeded after 36 guesses against password-only access.",
        "I4: it grants entry to the research server but is not damage by itself.",
    ),
    ThreatRisk(
        "Ransomware", 5, 5,
        "L5 (observed and succeeded): 1,200 files were encrypted by 09:10.",
        "I5: loss of research data and of the server's availability.",
    ),
    ThreatRisk(
        "Backup destruction", 4, 5,
        "L4 (attempted, outcome not logged): a deletion attempt at 09:12 against mutable backups, "
        "by an attacker who already held the rights it needs.",
        "I5: it removes recoverability, turning a recoverable incident into permanent loss.",
    ),
    ThreatRisk(
        "Data exfiltration", 4, 4,
        "L4 (indirectly evidenced): an outbound connection to an unknown IP (09:13) and a database spike "
        "within 2 min (09:15), with no transfer volume logged.",
        "I4: confidentiality loss of research and personal data with legal exposure, but no data destroyed.",
    ),
    ThreatRisk(
        "Privilege escalation", 4, 4,
        "L4 (indirectly evidenced): disabling antivirus and deleting backups both require administrative rights.",
        "I4: an enabler of the other threats rather than damage by itself.",
    ),
)


def prioritise(threats: Sequence[ThreatRisk]) -> List[Tuple[int, ThreatRisk]]:
    """Rank by score desc, then impact desc, then input (template) order."""
    order = sorted(enumerate(threats), key=lambda it: (-it[1].score, -it[1].impact, it[0]))
    return [(rank, t) for rank, (_, t) in enumerate(order, start=1)]


def likelihood_sensitivity(t: ThreatRisk) -> Dict[str, str]:
    """Risk level with likelihood moved one step down/up, clamped to the 1-5 scale."""
    def level_at(likelihood: int) -> str:
        return risk_level(risk_score(min(5, max(1, likelihood)), t.impact))

    return {"L-1": level_at(t.likelihood - 1), "L": level_at(t.likelihood), "L+1": level_at(t.likelihood + 1)}
