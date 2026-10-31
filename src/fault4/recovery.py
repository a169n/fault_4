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
        "ids + monitoring (canary / FIM + entropy rule, SIEM correlation, AI score)",
        1, (),
        "Canary write or FIM rate + entropy rule fires on the 09:07 mass modification; Wazuh correlates it with "
        "the 09:01 brute-force alert and the AI score.",
    ),
    RecoveryStep(
        2, "Isolate affected system",
        "hypervisor (VM pause, vNIC into the quarantine VLAN) + segmentation (OPNsense deny rule) + "
        "privacyIDEA/IdP (account lock), triggered by Wazuh active response",
        1, (1,),
        "Automated: the hypervisor pauses RS-01 (memory preserved) and re-tags its vNIC into the quarantine VLAN, "
        "OPNsense blocks 10.20.4.15 and RS-01's address, and privacyIDEA locks the compromised account.",
    ),
    RecoveryStep(
        3, "Preserve evidence",
        "hypervisor (VM memory + disk snapshot) + monitoring (SIEM log export, SHA-256, WORM bucket)",
        4, (2,),
        "Snapshot the paused VM's memory and disk, export SIEM/FIM/Suricata logs, hash everything with SHA-256 "
        "and store it in a write-once bucket.",
    ),
    RecoveryStep(
        4, "Activate backup",
        "immutable_backup (choose the clean point, clone it read-only from the vault ZFS pool into the clean room)",
        3, (2,),
        "Choose the clean point before restoring: diff the 09:06 snapshot against 09:03 (new executables, "
        "authorized_keys or cron entries, changed canaries). Use 09:06 if the diff is clean, otherwise 09:03 (before "
        "attacker access), and clone it read-only into the recovery environment.",
    ),
    RecoveryStep(
        5, "Restore services",
        "failover (RS-02 warm VM from a golden image; data copied from the clean point; PostgreSQL PITR)",
        8, (4,),
        "Copy data from the clean point onto RS-02 (assumption: ≤200 GB over 10 GbE ≈ 3 min) and run PostgreSQL "
        "point-in-time recovery to the clean point (≤5 min) unless the DB audit log shows an earlier malicious "
        "write.",
    ),
    RecoveryStep(
        6, "Verify integrity",
        "recovery_env (hash manifest, YARA/AV scan, persistence check, DB consistency, canaries intact)",
        5, (5,),
        "Compare file hashes with the clean-point manifest, scan with YARA/AV, confirm no new executables, "
        "authorized_keys or cron entries, run DB consistency checks and confirm the canary files are intact.",
    ),
    RecoveryStep(
        7, "Return to production",
        "failover + hypervisor (RS-02 vNIC into the research VLAN, VIP/DNS switch, rotated credentials)",
        2, (3, 6),
        "Promote RS-02: re-tag its vNIC from the recovery VLAN into the research VLAN, switch the service VIP/DNS, "
        "rotate credentials and keep heightened monitoring; only after the evidence is preserved and integrity is "
        "verified.",
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
