"""Synthetic dataset loading: incident events and AI anomaly scores."""

from __future__ import annotations

import csv
import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = REPO_ROOT / "data"
CONFIG_DIR = REPO_ROOT / "configs"
OUTPUT_DIR = REPO_ROOT / "outputs"
REPORT_DIR = REPO_ROOT / "report"
SPEC_PDF = REPO_ROOT / "docs" / "assignment" / "Assignment_4_AITU_Security_Resilience_Report_Template.pdf"

EVENT_KINDS = (
    "failed_logins",
    "login_success",
    "files_modified",
    "cpu_usage",
    "files_encrypted",
    "backup_deletion",
    "outbound_unknown",
    "db_access_spike",
    "av_disabled",
)

# One pattern per event kind; group 1, when present, is the numeric value.
_PATTERNS = (
    ("failed_logins", re.compile(r"^([\d,]+) failed logins$", re.I)),
    ("login_success", re.compile(r"^successful login$", re.I)),
    ("files_modified", re.compile(r"^([\d,]+) files modified$", re.I)),
    ("cpu_usage", re.compile(r"^cpu usage increased to (\d+(?:\.\d+)?)%$", re.I)),
    ("files_encrypted", re.compile(r"^([\d,]+) files encrypted$", re.I)),
    ("backup_deletion", re.compile(r"^backup deletion attempt$", re.I)),
    ("outbound_unknown", re.compile(r"^outbound connection to unknown ip$", re.I)),
    ("db_access_spike", re.compile(r"^database access spike$", re.I)),
    ("av_disabled", re.compile(r"^antivirus disabled$", re.I)),
)


@dataclass(frozen=True)
class Event:
    time: str
    minute: int  # minutes since midnight, 09:01 -> 541
    description: str
    source: str
    severity: str
    kind: str
    value: Optional[float]


@dataclass(frozen=True)
class AnomalySignal:
    name: str
    normal: float
    observed: float


def parse_event_text(text: str) -> Tuple[str, Optional[float]]:
    """Map a dataset event description to (kind, numeric value or None)."""
    cleaned = text.strip()
    for kind, pattern in _PATTERNS:
        match = pattern.match(cleaned)
        if match:
            value = float(match.group(1).replace(",", "")) if match.groups() else None
            return kind, value
    raise ValueError(f"Unrecognised event text: {text!r}")


def _to_minute(hhmm: str) -> int:
    hours, minutes = hhmm.split(":")
    return int(hours) * 60 + int(minutes)


def fmt_minute(minute: int) -> str:
    return f"{minute // 60:02d}:{minute % 60:02d}"


def load_events(path: Path = DATA_DIR / "incident_events.csv") -> List[Event]:
    events = []
    with open(path, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            kind, value = parse_event_text(row["event"])
            events.append(
                Event(
                    time=row["time"].strip(),
                    minute=_to_minute(row["time"]),
                    description=row["event"].strip(),
                    source=row["source"].strip(),
                    severity=row["severity"].strip(),
                    kind=kind,
                    value=value,
                )
            )
    return sorted(events, key=lambda e: e.minute)


def load_anomaly_signals(path: Path = DATA_DIR / "anomaly_scores.csv") -> List[AnomalySignal]:
    with open(path, newline="", encoding="utf-8") as fh:
        return [
            AnomalySignal(row["event"].strip(), float(row["normal_score"]), float(row["observed_score"]))
            for row in csv.DictReader(fh)
        ]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()
