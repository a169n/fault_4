"""Part D: seven-step recovery plan checked against RTO <= 30 min and RPO <= 5 min."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Sequence, Tuple

RTO_TARGET_MIN = 30
RPO_TARGET_MIN = 5
SNAPSHOT_INTERVAL_MIN = 3
REPLICATION_LAG_MIN = 1
SNAPSHOT_ORIGIN_MINUTE = 9 * 60  # snapshots aligned to 09:00


@dataclass(frozen=True)
class RecoveryStep:
    number: int
    action: str
    component: str
    duration_min: int
    depends_on: Tuple[int, ...]
    details: str


RECOVERY_STEPS: Tuple[RecoveryStep, ...] = (
    RecoveryStep(
        1, "Detect incident",
        "Intrusion detection + SIEM (decoy files, mass file changes, AI score)",
        1, (),
        "The mass file change at 09:07 triggers the alert; the SIEM links it with the 09:01 failed-login alert "
        "and the AI score.",
    ),
    RecoveryStep(
        2, "Isolate affected system",
        "Hypervisor (pause RS-01, quarantine network) + firewall (block traffic) + login server (lock the account), "
        "started automatically by the SIEM",
        1, (1,),
        "Automatic: RS-01 is paused with its memory kept and moved into the quarantine network, the attacker's "
        "address is blocked, and the stolen account is locked.",
    ),
    RecoveryStep(
        3, "Preserve evidence",
        "Hypervisor (copy of memory and disk) + SIEM (logs), stored where they cannot be changed",
        4, (2,),
        "Save a copy of RS-01's memory and disk and all logs, record their fingerprints (SHA-256) and store them "
        "in write-once storage.",
    ),
    RecoveryStep(
        4, "Activate backup",
        "Immutable backup (choose the clean restore point and open a read-only copy in the clean room)",
        3, (2,),
        "Choose the restore point before restoring: compare the 09:06 snapshot with 09:03. Use 09:06 if nothing "
        "suspicious was added (new programs, login keys, scheduled tasks), otherwise 09:03, before the attacker "
        "logged in.",
    ),
    RecoveryStep(
        5, "Restore services",
        "Spare server RS-02 (data copied from the clean point; database rolled back to the same moment)",
        8, (4,),
        "Copy the data onto RS-02 (about 3 minutes for up to 200 GB) and roll the database back to the clean "
        "point (up to 5 minutes).",
    ),
    RecoveryStep(
        6, "Verify integrity",
        "Clean room (compare file fingerprints, malware scan, check for back doors and decoy files)",
        5, (5,),
        "Check that files match their fingerprints, scan for malware, confirm the attacker left no way back in, "
        "check the database and confirm the decoy files are untouched.",
    ),
    RecoveryStep(
        7, "Return to production",
        "Spare server + hypervisor (RS-02 joins the research network, users are switched over, passwords changed)",
        2, (3, 6),
        "Promote RS-02: move it into the research network, point users to it, change passwords and keep closer "
        "monitoring. Done only after evidence is saved and the check has passed.",
    ),
)


def sequential_recovery_time(steps: Sequence[RecoveryStep]) -> int:
    return sum(s.duration_min for s in steps)


def step_finish_times(steps: Sequence[RecoveryStep]) -> Dict[int, int]:
    """Earliest finish time of every step over the depends_on DAG (steps listed in dependency order)."""
    finish: Dict[int, int] = {}
    numbers = {s.number for s in steps}
    for s in steps:
        unknown = [d for d in s.depends_on if d not in numbers]
        if unknown:
            raise ValueError(f"step {s.number} depends on unknown step(s) {unknown}")
        missing = [d for d in s.depends_on if d not in finish]
        if missing:
            raise ValueError(f"step {s.number} is listed before its dependencies {missing}")
        start = max((finish[d] for d in s.depends_on), default=0)
        finish[s.number] = start + s.duration_min
    return finish


def critical_path_recovery_time(steps: Sequence[RecoveryStep]) -> int:
    return max(step_finish_times(steps).values(), default=0)


def target_time_cell(step: RecoveryStep, finish: int, steps: Sequence[RecoveryStep] = RECOVERY_STEPS) -> str:
    """Template 'Target time' cell; steps sharing the same predecessors run in parallel."""
    peers = [s.number for s in steps if s.number != step.number and step.depends_on and s.depends_on == step.depends_on]
    parallel = "".join(f", parallel with step {n}" for n in peers)
    return f"{step.duration_min} min (by T+{finish}{parallel})"


def worst_case_data_loss(interval_min: int = SNAPSHOT_INTERVAL_MIN, lag_min: int = REPLICATION_LAG_MIN) -> int:
    """The immutable copy can be one snapshot interval plus the replication lag behind production."""
    return interval_min + lag_min


def last_clean_snapshot(before_minute: int, interval_min: int, origin_minute: int = SNAPSHOT_ORIGIN_MINUTE) -> int:
    """Latest snapshot taken strictly before before_minute (a snapshot in the same minute is not trusted)."""
    if before_minute <= origin_minute:
        raise ValueError(f"no snapshot exists before minute {before_minute}")
    return origin_minute + ((before_minute - origin_minute - 1) // interval_min) * interval_min


def clean_restore_points(
    first_malicious_minute: int, attacker_access_minute: int, interval_min: int = SNAPSHOT_INTERVAL_MIN
) -> Dict[str, int]:
    """Preferred point: last snapshot before the first malicious change; fallback: before attacker access."""
    return {
        "preferred": last_clean_snapshot(first_malicious_minute, interval_min),
        "fallback": last_clean_snapshot(attacker_access_minute, interval_min),
    }


def recovery_check(steps: Sequence[RecoveryStep] = RECOVERY_STEPS) -> Dict[str, Any]:
    sequential = sequential_recovery_time(steps)
    data_loss = worst_case_data_loss()
    return {
        "recovery_time_sequential": sequential,
        "recovery_time_critical_path": critical_path_recovery_time(steps),
        "rto_target": RTO_TARGET_MIN,
        "rto_met": sequential <= RTO_TARGET_MIN,
        "slack_min": RTO_TARGET_MIN - sequential,
        "worst_case_data_loss": data_loss,
        "rpo_target": RPO_TARGET_MIN,
        "rpo_met": data_loss <= RPO_TARGET_MIN,
    }
