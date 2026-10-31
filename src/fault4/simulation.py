"""Before/after replay of the incident through the as-is and hardened architectures.

The replay is deterministic and non-adaptive: the attacker follows the dataset timing, and each dataset row
is treated as a per-minute aggregate.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from fault4.data import CONFIG_DIR, Event, fmt_minute
from fault4.recovery import clean_restore_points

SCENARIO_KEYS = (
    "name",
    "label",
    "failed_login_alert",
    "lockout_threshold",
    "lockout_window_min",
    "mfa_required",
    "mfa_bypassed",
    "file_change_alert_per_min",
    "auto_isolation_delay_min",
    "backup_immutable",
    "egress_allowlist",
    "av_tamper_protection",
    "snapshot_interval_min",
)
ISOLATION_STOPPED_BY = "automated isolation (FIM rate + entropy rule)"
_DEFAULT_NOTE = {
    "failed_logins": "no alerting or lockout configured",
    "cpu_usage": "encryption workload; not alerted on its own",
    "db_access_spike": "research database queried through the compromised server",
}


@dataclass(frozen=True)
class Scenario:
    name: str
    label: str
    failed_login_alert: Optional[int]
    lockout_threshold: Optional[int]
    lockout_window_min: int
    mfa_required: bool
    mfa_bypassed: bool
    file_change_alert_per_min: Optional[int]
    auto_isolation_delay_min: Optional[int]
    backup_immutable: bool
    egress_allowlist: bool
    av_tamper_protection: bool
    snapshot_interval_min: Optional[int]


@dataclass(frozen=True)
class TimelineEntry:
    time: str
    event: str
    status: str  # executed | detected | blocked | contained | not reached
    note: str


@dataclass(frozen=True)
class SimulationResult:
    scenario: str
    label: str
    attacker_access: bool
    stopped_at: Optional[str]
    stopped_by: Optional[str]
    first_detection: Optional[str]
    files_impacted: int
    backup_destroyed: bool
    exfiltration_succeeded: bool
    av_disabled: bool
    data_loss_min: Optional[int]
    data_loss_fallback_min: Optional[int]
    recovery_time_min: Optional[int]
    timeline: List[TimelineEntry]


def load_scenarios(path: Path = CONFIG_DIR / "scenarios.json") -> List[Scenario]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    scenarios = []
    for index, item in enumerate(raw):
        name = item.get("name", f"#{index}")
        missing = [k for k in SCENARIO_KEYS if k not in item]
        if missing:
            raise ValueError(f"scenario {name} is missing key(s): {', '.join(missing)}")
        unknown = sorted(set(item) - set(SCENARIO_KEYS))
        if unknown:
            raise ValueError(f"scenario {name} has unknown key(s): {', '.join(unknown)}")
        scenarios.append(Scenario(**{k: item[k] for k in SCENARIO_KEYS}))
    return scenarios


def _independent_layers(e: Event, sc: Scenario) -> List[str]:
    """Controls that would have stopped this post-compromise event even without isolation."""
    layers = []
    if e.kind == "backup_deletion" and sc.backup_immutable:
        layers.append("vault credential separation (RS-01 holds no vault credentials; copies under zfs hold / "
                      "object lock)")
    if e.kind == "outbound_unknown" and sc.egress_allowlist:
        layers.append("egress allow-list")
    if e.kind == "av_disabled" and sc.av_tamper_protection:
        layers.append("tamper protection")
    return layers


def simulate(events: Sequence[Event], scenario: Scenario, recovery_time_min: int,
             planned_isolation_min: int = 2) -> SimulationResult:
    """recovery_time_min assumes isolation within planned_isolation_min of the first malicious change
    (Part D steps 1-2); later isolation shifts the whole recovery plan by the difference."""
    sc = scenario
    ordered = sorted(events, key=lambda e: e.minute)
    login_event = next((e for e in ordered if e.kind == "login_success"), None)

    failure_history: Dict[str, List[Tuple[int, int]]] = {}
    blocked_sources = set()
    access_minute: Optional[int] = None
    isolation_minute: Optional[int] = None
    stopped_at: Optional[str] = None
    stopped_by: Optional[str] = None
    first_detection: Optional[str] = None
    first_malicious: Optional[int] = None
    files_impacted = 0
    backup_destroyed = exfiltration = av_off = False
    timeline: List[TimelineEntry] = []

    for e in ordered:
        status, notes = "executed", []
        if e.kind == "failed_logins":
            if e.source in blocked_sources:
                status = "blocked"
                notes.append(f"source {e.source} blocked since {stopped_at}; MFA would also reject a guessed password")
            else:
                history = failure_history.setdefault(e.source, [])
                history.append((e.minute, int(e.value or 0)))
                total = sum(count for minute, count in history if e.minute - minute < sc.lockout_window_min)
                if sc.failed_login_alert is not None and total >= sc.failed_login_alert:
                    status = "detected"
                    first_detection = first_detection or e.time
                    notes.append(f"brute-force alert: {total} failures within {sc.lockout_window_min} min")
                    if sc.lockout_threshold is None:
                        notes.append("alert not acted on (assume breach)")
                if sc.lockout_threshold is not None and total >= sc.lockout_threshold:
                    blocked_sources.add(e.source)
                    if stopped_at is None:
                        stopped_at = e.time
                        login_at = f" {login_event.time}" if login_event else ""
                        stopped_by = (
                            f"source block after lockout threshold ({sc.lockout_threshold} failures/"
                            f"{sc.lockout_window_min} min); MFA would independently block the{login_at} login"
                        )
                    notes.append(f"lockout threshold reached; source {e.source} blocked")
        elif e.kind == "login_success":
            if e.source in blocked_sources:
                status = "blocked"
                notes.append(f"source blocked since {stopped_at}; MFA would independently reject the login")
            elif sc.mfa_required and not sc.mfa_bypassed:
                status = "blocked"
                notes.append("MFA challenge failed: a guessed password is not enough")
                if stopped_at is None:
                    stopped_at, stopped_by = e.time, "MFA rejected the login"
            else:
                access_minute = e.minute
                notes.append("MFA bypassed (assume breach)" if sc.mfa_required else "password-only login accepted")
        elif access_minute is None:
            status = "not reached"
            notes.append("attacker never obtained a session")
        elif isolation_minute is not None and e.minute >= isolation_minute:
            status = "contained"
            notes.append(f"RS-01 isolated at {fmt_minute(isolation_minute)}")
            layers = _independent_layers(e, sc)
            if layers:
                notes.append("independently blocked by " + " and ".join(layers))
        else:
            if (e.kind == "files_modified" and sc.file_change_alert_per_min is not None
                    and (e.value or 0) >= sc.file_change_alert_per_min):
                status = "detected"
                first_detection = first_detection or e.time
                notes.append(f"FIM rate + entropy alert: {int(e.value):,} changes/min ≥ {sc.file_change_alert_per_min}")
                if sc.auto_isolation_delay_min is not None and isolation_minute is None:
                    isolation_minute = e.minute + sc.auto_isolation_delay_min
                    stopped_at = fmt_minute(isolation_minute)
                    stopped_by = (ISOLATION_STOPPED_BY if sc.auto_isolation_delay_min <= planned_isolation_min
                                  else f"isolation {sc.auto_isolation_delay_min} min after the FIM rate + entropy alert")
                    notes.append(f"isolation completes at {stopped_at}")
            # Effects of events that happened (executed or detected).
            if e.kind in ("files_modified", "files_encrypted"):
                files_impacted = max(files_impacted, int(e.value or 0))
                first_malicious = e.minute if first_malicious is None else first_malicious
                notes.append(f"{int(e.value or 0):,} files affected")
            elif e.kind == "backup_deletion":
                if sc.backup_immutable:
                    status = "blocked"
                    notes.append("deletion fails: RS-01 holds no vault credentials; vault copies are under zfs hold "
                                 "and object lock")
                else:
                    backup_destroyed = True
                    notes.append("mutable backups deleted")
            elif e.kind == "outbound_unknown":
                if sc.egress_allowlist:
                    status = "blocked"
                    notes.append("connection denied by egress allow-list")
                else:
                    exfiltration = True
                    notes.append("channel to unknown IP open: data can leave")
            elif e.kind == "av_disabled":
                if sc.av_tamper_protection:
                    status = "blocked"
                    notes.append("stop request refused by tamper protection")
                else:
                    av_off = True
                    notes.append("antivirus stopped")
        if not notes:
            notes.append(_DEFAULT_NOTE.get(e.kind, "no control triggered"))
        timeline.append(TimelineEntry(e.time, e.description, status, "; ".join(notes)))

    if files_impacted == 0:
        data_loss = data_loss_fallback = recovery_time = 0
    elif backup_destroyed or sc.snapshot_interval_min is None or first_malicious is None or access_minute is None:
        data_loss = data_loss_fallback = recovery_time = None
    else:
        points = clean_restore_points(first_malicious, access_minute, sc.snapshot_interval_min)
        data_loss = first_malicious - points["preferred"]
        data_loss_fallback = first_malicious - points["fallback"]
        late = isolation_minute - (first_malicious + planned_isolation_min) if isolation_minute is not None else 0
        recovery_time = recovery_time_min + max(0, late)

    return SimulationResult(
        scenario=sc.name,
        label=sc.label,
        attacker_access=access_minute is not None,
        stopped_at=stopped_at,
        stopped_by=stopped_by,
        first_detection=first_detection,
        files_impacted=files_impacted,
        backup_destroyed=backup_destroyed,
        exfiltration_succeeded=exfiltration,
        av_disabled=av_off,
        data_loss_min=data_loss,
        data_loss_fallback_min=data_loss_fallback,
        recovery_time_min=recovery_time,
        timeline=timeline,
    )
