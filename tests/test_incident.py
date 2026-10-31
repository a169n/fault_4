from fault4.data import Event, load_events
from fault4.incident import ATTACK_STAGES, attack_metrics, classify_events


def test_every_event_gets_expected_stage():
    assert {c.event.time: c.stage for c in classify_events(load_events())} == {
        "09:01": "reconnaissance",
        "09:03": "credential attack",
        "09:04": "privilege compromise",
        "09:07": "data destruction",
        "09:08": "data destruction",
        "09:10": "data destruction",
        "09:12": "recovery attack",
        "09:13": "exfiltration",
        "09:15": "lateral movement",
        "09:18": "persistence",
    }


def test_assessed_risk_upgrades_only_the_successful_login():
    c = classify_events(load_events())
    assert {x.event.time for x in c if x.risk != x.event.severity} == {"09:04"}
    assert next(x for x in c if x.event.time == "09:04").risk == "Critical"


def test_all_eight_stage_categories_assigned():
    assert {c.stage for c in classify_events(load_events())} == set(ATTACK_STAGES)


def test_interpretive_rows_carry_alternative():
    assert {c.event.time for c in classify_events(load_events()) if c.alternative} == {
        "09:01", "09:08", "09:13", "09:15", "09:18"}


def test_attack_metrics():
    assert attack_metrics(classify_events(load_events())) == {
        "failed_logins_total": 36,
        "minutes_to_compromise": 3,
        "minutes_compromise_to_encryption": 6,
        "attack_duration_minutes": 17,
        "stage_categories_used": 8,
    }


def test_first_failed_login_burst_per_source_is_reconnaissance():
    mk = lambda t, src: Event(t, int(t[:2]) * 60 + int(t[3:]), "5 failed logins", src, "Medium", "failed_logins", 5.0)  # noqa: E731
    st = [c.stage for c in classify_events([mk("09:00", "a"), mk("09:01", "b"), mk("09:02", "a")])]
    assert st == ["reconnaissance", "reconnaissance", "credential attack"]


def test_evidence_cites_dataset_values_and_attack_refs():
    by = {c.event.time: c for c in classify_events(load_events())}
    assert "1,200" in by["09:10"].evidence and "36" in by["09:03"].evidence
    assert by["09:03"].attack_ref == "T1110.001 Password Guessing (tactic: Credential Access)"
    assert "Defense Evasion" in by["09:18"].attack_ref and "separate host" in by["09:15"].evidence
    assert "~1 min" not in " ".join(c.evidence for c in by.values())
