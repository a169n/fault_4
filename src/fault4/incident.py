"""Part A: classify each incident event into an attack stage with evidence and risk."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence

from fault4.data import Event

ATTACK_STAGES = (
    "reconnaissance",
    "credential attack",
    "privilege compromise",
    "lateral movement",
    "data destruction",
    "persistence",
    "exfiltration",
    "recovery attack",
)

_STAGE_BY_KIND = {
    "login_success": "privilege compromise",
    "files_modified": "data destruction",
    "cpu_usage": "data destruction",
    "files_encrypted": "data destruction",
    "backup_deletion": "recovery attack",
    "outbound_unknown": "exfiltration",
    "db_access_spike": "lateral movement",
    "av_disabled": "persistence",
}

_IMPACT_REF = "T1486 Data Encrypted for Impact (tactic: Impact)"
_ATTACK_REF = {
    "reconnaissance": "T1589 Gather Victim Identity Information (tactic: Reconnaissance)",
    "credential attack": "T1110.001 Password Guessing (tactic: Credential Access)",
    "login_success": "T1078 Valid Accounts (tactic: Initial Access)",
    "files_modified": _IMPACT_REF,
    "cpu_usage": _IMPACT_REF,
    "files_encrypted": _IMPACT_REF,
    "backup_deletion": "T1490 Inhibit System Recovery (tactic: Impact)",
    "outbound_unknown": "T1041 Exfiltration Over C2 Channel (tactic: Exfiltration)",
    "db_access_spike": (
        "TA0008 Lateral Movement (assumed T1021 Remote Services, RS-01 → DB) + "
        "T1213 Data from Information Repositories (tactic: Collection)"
    ),
    "av_disabled": "T1562.001 Impair Defenses: Disable or Modify Tools (tactic: Defense Evasion)",
}

# Alternative readings for the interpretive classifications (defended in the report).
_ALTERNATIVE = {
    "reconnaissance": "Start of the credential attack (T1110).",
    "cpu_usage": (
        "95% CPU alone is not specific on a research server (see Part E); "
        "resource hijacking (T1496) is less likely given the timing."
    ),
    "outbound_unknown": "A command-and-control channel only; double extortion is a hypothesis.",
    "db_access_spike": "Exfiltration (collection).",
    "av_disabled": "Defense evasion; the spec vocabulary has no such stage, so it is classed as persistence.",
}


@dataclass(frozen=True)
class ClassifiedEvent:
    event: Event
    stage: str
    evidence: str
    risk: str
    attack_ref: str
    alternative: str


def _count(value: Optional[float]) -> str:
    return f"{int(value):,}" if value is not None else "an unknown number of"


def _first(events: Sequence[Event], kind: str) -> Optional[Event]:
    return next((e for e in events if e.kind == kind), None)


def _evidence(e: Event, stage: str, events: Sequence[Event], failures: int, first_failure: Optional[Event]) -> str:
    modified = _first(events, "files_modified")
    encrypted = _first(events, "files_encrypted")
    login = _first(events, "login_success")
    outbound = _first(events, "outbound_unknown")

    if stage == "reconnaissance":
        return (
            f"First contact from {e.source}: {_count(e.value)} failed logins in the first logged burst "
            f"({e.severity} severity). Consistent with probing which usernames exist and whether lockout is enforced."
        )
    if stage == "credential attack":
        since = first_failure.time if first_failure else e.time
        return (
            f"{_count(e.value)} more failed logins from the same source {e.source}; "
            f"{failures} cumulative failures logged between {since} and {e.time}."
        )
    if e.kind == "login_success":
        if failures:
            return (
                f"Successful login from {e.source} immediately after {failures} failed attempts "
                f"(first failure logged {first_failure.time}): a guessed password became a valid session."
            )
        return f"Successful login from {e.source}."
    if e.kind == "files_modified":
        after = f", {e.minute - login.minute} min after the successful login" if login else ""
        return f"{_count(e.value)} files modified by the attacker session (source {e.source}){after}."
    if e.kind == "cpu_usage":
        if modified and encrypted:
            return (
                f"CPU at {e.value:g}% on {e.source}, {e.minute - modified.minute} min after the "
                f"{_count(modified.value)} file modifications and {encrypted.minute - e.minute} min before "
                f"{_count(encrypted.value)} files are reported encrypted, so consistent with the encryption workload."
            )
        return f"CPU at {e.value:g}% on {e.source}."
    if e.kind == "files_encrypted":
        return f"{_count(e.value)} files encrypted on {e.source}: direct loss of research data."
    if e.kind == "backup_deletion":
        after = f", {e.minute - encrypted.minute} min after encryption" if encrypted else ""
        return f"Backup deletion attempt on {e.source}{after}: an attack on the ability to recover."
    if e.kind == "outbound_unknown":
        return (
            f"Outbound connection from {e.source} to an unknown IP. No transfer volume is logged, "
            "so exfiltration is assessed, not confirmed."
        )
    if e.kind == "db_access_spike":
        feeds = f" The queries may feed the outbound channel opened at {outbound.time}." if outbound else ""
        return (
            f"Database access spike from {e.source}: the compromised server is used as a pivot into the research "
            f"database. Stated assumption: the database runs on a separate host.{feeds}"
        )
    if e.kind == "av_disabled":
        if encrypted and modified:
            return (
                f"Antivirus disabled on {e.source} at {e.time}, {e.minute - encrypted.minute} min after "
                f"{_count(encrypted.value)} files were encrypted. The dataset shows no AV alert during "
                f"{modified.time}–{encrypted.time}, so AV did not stop the encryption. Disabling it protects "
                "the attacker's continued access and hampers forensics."
            )
        return f"Antivirus disabled on {e.source} at {e.time}."
    raise ValueError(f"No evidence rule for event kind {e.kind!r}")


def classify_events(events: Sequence[Event]) -> List[ClassifiedEvent]:
    ordered = sorted(events, key=lambda e: e.minute)
    seen_sources = set()
    failures: Dict[str, int] = {}
    first_failure: Dict[str, Event] = {}
    result = []
    for e in ordered:
        if e.kind == "failed_logins":
            stage = "credential attack" if e.source in seen_sources else "reconnaissance"
            seen_sources.add(e.source)
            failures[e.source] = failures.get(e.source, 0) + int(e.value or 0)
            first_failure.setdefault(e.source, e)
            ref_key, alt_key = stage, stage
        else:
            stage = _STAGE_BY_KIND[e.kind]
            ref_key, alt_key = e.kind, e.kind
        risk = "Critical" if stage == "privilege compromise" else e.severity
        result.append(
            ClassifiedEvent(
                event=e,
                stage=stage,
                evidence=_evidence(e, stage, ordered, failures.get(e.source, 0), first_failure.get(e.source)),
                risk=risk,
                attack_ref=_ATTACK_REF[ref_key],
                alternative=_ALTERNATIVE.get(alt_key, ""),
            )
        )
    return result


def attack_metrics(classified: Sequence[ClassifiedEvent]) -> Dict[str, Optional[int]]:
    events = [c.event for c in classified]
    if not events:
        return {}
    login = _first(events, "login_success")
    encrypted = _first(events, "files_encrypted")
    return {
        "failed_logins_total": sum(int(e.value or 0) for e in events if e.kind == "failed_logins"),
        "minutes_to_compromise": login.minute - events[0].minute if login else None,
        "minutes_compromise_to_encryption": encrypted.minute - login.minute if login and encrypted else None,
        "attack_duration_minutes": events[-1].minute - events[0].minute,
        "stage_categories_used": len({c.stage for c in classified}),
    }
