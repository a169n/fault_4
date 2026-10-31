import pytest

from fault4.risk import THREATS, likelihood_sensitivity, prioritise, risk_level, risk_score


@pytest.mark.parametrize("score,level", [(1, "Low"), (4, "Low"), (5, "Medium"), (9, "Medium"), (10, "High"),
                                         (16, "High"), (17, "Critical"), (25, "Critical")])
def test_risk_level_band_boundaries(score, level):
    assert risk_level(score) == level


@pytest.mark.parametrize("score", [0, 26])
def test_risk_level_rejects_out_of_range(score):
    with pytest.raises(ValueError):
        risk_level(score)


@pytest.mark.parametrize("l,i", [(0, 3), (6, 1), (3, 0), (2, 6), (2.5, 2), (True, 3)])
def test_risk_score_rejects_out_of_scale(l, i):
    with pytest.raises(ValueError):
        risk_score(l, i)


def test_threat_table():
    assert {t.threat: (t.likelihood, t.impact, t.score, t.level) for t in THREATS} == {
        "Credential compromise": (5, 4, 20, "Critical"),
        "Ransomware": (5, 5, 25, "Critical"),
        "Backup destruction": (4, 5, 20, "Critical"),
        "Data exfiltration": (4, 4, 16, "High"),
        "Privilege escalation": (4, 4, 16, "High"),
    }


def test_priority_ranking():
    assert [t.threat for _, t in prioritise(THREATS)] == [
        "Ransomware", "Backup destruction", "Credential compromise", "Data exfiltration", "Privilege escalation"]


def test_likelihood_sensitivity_all_threats():
    assert {t.threat: likelihood_sensitivity(t) for t in THREATS} == {
        "Credential compromise": {"L-1": "High", "L": "Critical", "L+1": "Critical"},
        "Ransomware": {"L-1": "Critical", "L": "Critical", "L+1": "Critical"},
        "Backup destruction": {"L-1": "High", "L": "Critical", "L+1": "Critical"},
        "Data exfiltration": {"L-1": "High", "L": "High", "L+1": "Critical"},
        "Privilege escalation": {"L-1": "High", "L": "High", "L+1": "Critical"},
    }
