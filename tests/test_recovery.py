import dataclasses

import pytest

from fault4.recovery import (
    RECOVERY_STEPS,
    RecoveryStep,
    clean_restore_points,
    critical_path_recovery_time,
    last_clean_snapshot,
    recovery_check,
    sequential_recovery_time,
    step_finish_times,
    target_time_cell,
    worst_case_data_loss,
)


def test_steps_follow_template():
    assert [s.action for s in RECOVERY_STEPS] == ["Detect incident", "Isolate affected system", "Preserve evidence",
                                                  "Activate backup", "Restore services", "Verify integrity",
                                                  "Return to production"]


def test_recovery_times():
    assert sequential_recovery_time(RECOVERY_STEPS) == 24 and critical_path_recovery_time(RECOVERY_STEPS) == 20
    assert step_finish_times(RECOVERY_STEPS) == {1: 1, 2: 2, 3: 6, 4: 5, 5: 13, 6: 18, 7: 20}


def test_target_time_cells():
    f = step_finish_times(RECOVERY_STEPS)
    assert [target_time_cell(s, f[s.number]) for s in RECOVERY_STEPS] == [
        "1 min (by T+1)", "1 min (by T+2)", "4 min (by T+6, parallel with step 4)",
        "3 min (by T+5, parallel with step 3)", "8 min (by T+13)", "5 min (by T+18)", "2 min (by T+20)"]


def test_data_loss_counts_replication_lag():
    assert worst_case_data_loss() == 4 and worst_case_data_loss(5, 1) == 6  # why 5-min snapshots would breach RPO


def test_last_clean_snapshot_is_strictly_before():
    assert last_clean_snapshot(547, 3) == 546  # 09:07 -> 09:06
    assert last_clean_snapshot(546, 3) == 543  # a snapshot in the same minute is not trusted


def test_clean_restore_points():
    assert clean_restore_points(547, 544) == {"preferred": 546, "fallback": 543}  # 09:06 verified / 09:03 before access


def test_recovery_check_passes_and_flags_violation():
    assert recovery_check() == {"recovery_time_sequential": 24, "recovery_time_critical_path": 20, "rto_target": 30,
                                "rto_met": True, "slack_min": 6, "worst_case_data_loss": 4, "rpo_target": 5,
                                "rpo_met": True}
    slow = tuple(dataclasses.replace(s, duration_min=s.duration_min + 1) for s in RECOVERY_STEPS)
    assert recovery_check(slow)["rto_met"] is False  # sequential 31 > 30 (critical path 26 would pass)


def test_unknown_dependency_raises():
    with pytest.raises(ValueError):
        critical_path_recovery_time((RecoveryStep(1, "a", "x", 1, (9,), ""),))
