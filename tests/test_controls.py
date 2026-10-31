from fault4.controls import COMPONENTS, REQUIRED_COMPONENTS, THREAT_CONTROLS, ThreatControls, coverage_gaps


def test_all_required_components_present():
    assert set(REQUIRED_COMPONENTS) <= {c.satisfies for c in COMPONENTS}


def test_threat_names_follow_part_c_template():
    assert [t.threat for t in THREAT_CONTROLS] == [
        "Credential attack", "Ransomware", "Backup deletion", "Data exfiltration", "Privilege escalation"]


def test_every_threat_has_p_d_r():
    assert all(t.preventive and t.detective and t.recovery for t in THREAT_CONTROLS)


def test_roles_are_valid_and_defended():
    assert {c.role for c in COMPONENTS} <= {"preventive", "detective", "recovery"}
    assert all(c.why for c in COMPONENTS)


def test_recovery_cells_separate_respond_from_recover():
    assert all("Recover:" in t.recovery for t in THREAT_CONTROLS)


def test_no_coverage_gaps():
    assert coverage_gaps() == []


def test_gap_detection_unknown_and_unused():
    bad = (ThreatControls("X", "p", "d", "r", ("nope",)),)
    gaps = coverage_gaps(COMPONENTS, bad)
    assert any("nope" in g for g in gaps) and any("mfa" in g for g in gaps)  # unknown key + unused component


def test_gap_detection_missing_required_and_empty_cell():
    gaps = coverage_gaps(COMPONENTS[1:], (ThreatControls("Y", "", "d", "r", ("segmentation",)),))
    assert any("MFA" in g for g in gaps) and any("Y" in g and "preventive" in g for g in gaps)


def test_hypervisor_is_part_of_the_architecture():
    by_key = {c.key: c for c in COMPONENTS}
    assert by_key["hypervisor"].role == "recovery" and "quarantine VLAN" in by_key["hypervisor"].technology
    assert any("hypervisor" in t.components for t in THREAT_CONTROLS)


def test_standby_lives_in_the_isolated_recovery_zone():
    by_key = {c.key: c for c in COMPONENTS}
    assert by_key["failover"].zone.startswith("Recovery zone") and "promot" in by_key["failover"].technology
