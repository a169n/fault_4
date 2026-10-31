import json

import pytest

from fault4.data import CONFIG_DIR, load_events
from fault4.simulation import load_scenarios, simulate


def run(name):
    sc = {s.name: s for s in load_scenarios()}[name]
    return simulate(load_events(), sc, recovery_time_min=24)


def test_load_scenarios_names():
    assert [s.name for s in load_scenarios()] == [
        "baseline", "hardened", "hardened_assume_breach", "hardened_manual_isolation"]


def test_missing_key_raises(tmp_path):
    data = json.loads((CONFIG_DIR / "scenarios.json").read_text())
    del data[0]["mfa_required"]
    p = tmp_path / "s.json"
    p.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="mfa_required"):
        load_scenarios(p)


def test_baseline_reproduces_incident():
    r = run("baseline")
    assert (r.attacker_access, r.files_impacted, r.backup_destroyed, r.exfiltration_succeeded, r.av_disabled,
            r.first_detection, r.data_loss_min, r.recovery_time_min) == (True, 1200, True, True, True, None, None, None)


def test_hardened_stops_attack_at_0901():
    r = run("hardened")
    assert (r.attacker_access, r.stopped_at, r.first_detection, r.files_impacted, r.data_loss_min,
            r.recovery_time_min) == (False, "09:01", "09:01", 0, 0, 0)
    assert "MFA" in r.stopped_by and {e.time: e.status for e in r.timeline}["09:04"] == "blocked"


def test_assume_breach_contains_at_0909():
    r = run("hardened_assume_breach")
    assert (r.attacker_access, r.first_detection, r.stopped_at, r.stopped_by, r.files_impacted, r.backup_destroyed,
            r.exfiltration_succeeded, r.av_disabled, r.data_loss_min, r.data_loss_fallback_min,
            r.recovery_time_min) == (
        True, "09:01", "09:09", "automated isolation (FIM rate + entropy rule)", 320, False, False, False, 1, 4, 24)
    assert {e.time: e.status for e in r.timeline}["09:08"] == "executed"


def test_manual_isolation_loses_files_but_still_recovers():
    r = run("hardened_manual_isolation")
    assert (r.stopped_at, r.files_impacted, r.backup_destroyed, r.data_loss_min, r.recovery_time_min) == (
        "09:11", 1200, False, 1, 24)


def test_assume_breach_names_independent_layers():
    notes = {e.time: e.note for e in run("hardened_assume_breach").timeline}
    assert "object lock" in notes["09:12"] and "egress allow-list" in notes["09:13"] and "tamper protection" in notes["09:18"]


def test_every_timeline_entry_has_a_note():
    for s in load_scenarios():
        assert all(e.note for e in simulate(load_events(), s, recovery_time_min=24).timeline), s.name
