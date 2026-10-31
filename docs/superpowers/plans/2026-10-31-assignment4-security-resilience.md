# Assignment 4 — Security, Resilience & Intrusion Tolerance: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A reproducible Python analysis of the synthetic Research-Server-01 ransomware incident and a completed English submission report (.docx + .pdf). The analysis covers Parts A–E, a before/after attack simulation, figures and the filled-in student record.

**Architecture:** Each assignment part is computed by its own module in `src/fault4/`, all reading the same versioned CSV/JSON inputs. `pipeline.py` turns everything into one deterministic `outputs/results.json` plus a human-readable `outputs/run_log.txt`. `figures.py` and the report builder only *render* that results dict, so every number in the report comes from code and can be traced to a file and a commit.

**Tech Stack:** Python ≥ 3.9 (stdlib `csv`, `json`, `hashlib`, `dataclasses`), matplotlib (Agg) for figures, python-docx for the report, pytest. LibreOffice (`soffice`) is optional and used only to export the PDF.

**Spec:** `docs/assignment/Assignment_4_AITU_Security_Resilience_Report_Template.pdf`. Pages 1–3 are the tasks (Parts A–E and the submission list). Pages 4–7 are the Student Technical Work Report template to fill in.

## Global Constraints

- Must run on macOS system Python **3.9.6**, so: no `match`, no PEP 604 `X | Y` unions at runtime, no `dataclass(slots=/kw_only=)`, no `tomllib`. Use `typing.Optional/List/Dict/Tuple`, with `from __future__ import annotations` allowed.
- Dependencies are exactly `matplotlib==3.9.4`, `python-docx==1.1.2` and `pytest==8.3.5` in `requirements.txt`. Everything else is stdlib.
- Resolve every path from `REPO_ROOT = Path(__file__).resolve().parents[2]`, never from the cwd.
- Call `matplotlib.use("Agg")` before importing `pyplot`, so no GUI window opens on macOS.
- `outputs/results.json` must be byte-identical across runs: no timestamps, `json.dumps(..., indent=2, sort_keys=True)`, and floats rounded to 2 dp. Timestamps go only into `run_log.txt` and the report.
- Spec values must be used verbatim:
  - Risk bands: 1–4 Low, 5–9 Medium, 10–16 High, 17–25 Critical. L and I range from 1 to 5.
  - Anomaly threshold: score **≥ 0.75**.
  - RPO ≤ 5 min, RTO ≤ 30 min.
- Use the attack-stage vocabulary exactly as the spec spells it: `reconnaissance, credential attack, privilege compromise, lateral movement, data destruction, persistence, exfiltration, recovery attack`.
- The report is in English. It must contain the spec's context note that all data are synthetic and do not describe real AITU infrastructure.
- Student data, verbatim:
  - Student full name `Talgatov Aibyn`, Student ID `255308`, Group `CSE-2505M`, Instructor `Serek Azamat`.
  - Repository `https://github.com/a169n/fault_4`.
  - The variant code was not provided, so render a blank line `______________________`.
  - Submission date: blank `____ / ____ / ______`.
  - Signatures: blank.
- Commit `outputs/` and `report/`, because they are the submission evidence. Never commit `.venv/`.
- Every commit message ends with the session attribution trailer lines from the system reminder.

## Review Focus

1. **macOS `/usr/bin/python3` 3.9.6:** a single 3.10+ construct breaks the student's demo. Task 11 runs the full suite and pipeline under Python 3.9 (`uv`).
2. **Running from another directory** (`cd outputs && ../run_all.sh`, or `python -m fault4` with a different cwd) must still find `data/` and `configs/`. Covered by `test_cli_runs_from_other_cwd` (Task 8).
3. **Number formats in the dataset:**
   - `"1,200 files encrypted"` has a thousands separator.
   - `"CPU usage increased to 95%"` carries a percent sign.
   - Unknown event text must fail loudly, never silently drop a row.
   Covered by `test_parse_thousands_separator`, `test_parse_percent` and `test_unknown_event_text_raises` (Task 1).
4. **Opening the .docx in Word for Mac / Pages:** no oversized images, no unfilled `{placeholders}`, all assignment tables present. Covered by `test_report_has_no_placeholder_leaks` and `test_report_images_fit_page` (Task 10), plus the LibreOffice render check in Task 11.
5. **Re-running the pipeline must not create diff noise** in the committed evidence. Covered by `test_results_are_deterministic` (Task 8).

---

## Pinned analytical decisions (the report argues from these)

**Part A — classification.** The Risk column is the *assessed* risk. It equals the dataset severity except at 09:04, which is upgraded to Critical: success after 36 failures in 3 minutes is the pivot that every later event depends on. The ATT&CK reference is appended to the Evidence cell as `(ATT&CK …)`.

| Time | Stage | Evidence (key facts that must appear) | Risk | ATT&CK |
|---|---|---|---|---|
| 09:01 | reconnaissance | first contact from 10.20.4.15; 15 failures in ~1 min, probing accounts | Medium | TA0043 Reconnaissance |
| 09:03 | credential attack | 21 more failures, 36 cumulative in 3 min, same source | High | T1110.001 Password Guessing |
| 09:04 | privilege compromise | successful login from the same IP right after 36 failures | **Critical** | T1078 Valid Accounts |
| 09:07 | data destruction | 320 files modified by the attacker session (source 10.20.4.15) | Critical | T1486 Data Encrypted for Impact |
| 09:08 | data destruction | CPU at 95 % on Research-Server-01 = encryption workload | High | T1486 Data Encrypted for Impact |
| 09:10 | data destruction | 1,200 files encrypted | Critical | T1486 Data Encrypted for Impact |
| 09:12 | recovery attack | backup deletion attempt 2 min after encryption | Critical | T1490 Inhibit System Recovery |
| 09:13 | exfiltration | outbound connection to unknown IP (double extortion) | High | T1041 Exfiltration Over C2 Channel |
| 09:15 | lateral movement | DB access spike: the server is used as a pivot into the research DB (also collection) | High | TA0008 Lateral Movement / T1213 Data from Information Repositories |
| 09:18 | persistence | antivirus disabled to keep the foothold. Observation: it was disabled *after* encryption, so signature AV never detected the attack | Critical | T1562.001 Impair Defenses: Disable or Modify Tools |

**Attack metrics:**
- 36 failed logins in total.
- 3 min to compromise (09:01 → 09:04).
- 6 min from compromise to encryption (09:04 → 09:10).
- 17 min attack duration (09:01 → 09:18).
- All 8 stages observed.

**Part B — risk matrix.** The threat order is the template's.

| Threat | L | I | Score | Level | Rank | L reason / I reason (gist) |
|---|---|---|---|---|---|---|
| Credential compromise | 5 | 4 | 20 | Critical | 2 | Observed: 36 guesses then success, password-only. Impact: grants entry, but is not damage by itself |
| Ransomware | 4 | 5 | 20 | Critical | 1 | Observed encryption of 1,200 files. Impact: loss of research data and availability |
| Backup destruction | 3 | 5 | 15 | High | 5 | Only an *attempt* was seen, and it needs admin rights. Impact: removes the ability to recover |
| Data exfiltration | 4 | 4 | 16 | High | 3 | Unknown outbound connection plus a DB spike within 3 min. Impact: research and personal data, legal exposure |
| Privilege escalation | 4 | 4 | 16 | High | 4 | Indirect evidence: AV disable and backup deletion both need admin. Impact: an enabler, not damage by itself |

- **Ranking rule:** score descending, then impact descending, then template order.
- **Sensitivity:** recompute the level with L±1, clamped to 1–5. Backup destruction becomes Critical at L+1 = 4, so the report treats it as *borderline Critical* and implements immutable backup first because it is the cheapest control.

**Part C — components.** All 7 required components must be present.

| key | name / technology | zone | role | satisfies |
|---|---|---|---|---|
| `mfa` | privacyIDEA TOTP/FIDO2 on SSH bastion + VPN | Access zone | preventive | MFA |
| `segmentation` | OPNsense firewall, VLANs, default-deny inter-zone, egress allow-list, quarantine VLAN | All zone boundaries | preventive | Network segmentation |
| `pam` | Just-in-time sudo, separate admin accounts, agent tamper protection | Access zone | preventive | supporting |
| `monitoring` | Wazuh SIEM + Prometheus/Grafana, alerting + active response | Security zone | detective | Monitoring |
| `ids` | Suricata NIDS + Wazuh HIDS/FIM + canary files + AI anomaly scorer | Security zone | detective | Intrusion detection |
| `immutable_backup` | ZFS snapshot every 3 min, pulled by the vault, MinIO S3 Object Lock (compliance mode, 30 days) + PostgreSQL WAL archive | Backup vault (pull-only) | recovery | Immutable backup |
| `failover` | Research-Server-02 warm standby, promoted only from a verified clean snapshot | Research zone (separate VLAN) | recovery | Secure failover |
| `recovery_env` | Isolated clean-room VLAN, no internet: restore, scan, verify | Recovery zone | recovery | Recovery environment |
| `offline_copy` | Air-gapped copy at a second Kazakhstan site (Almaty), daily, monthly restore drill | Second site | recovery | Additional (Part E Q4 / §6) |

Threat → controls (P = preventive, D = detective, R = recovery). Threat names follow the Part C template.

| Threat | Preventive | Detective | Recovery | components |
|---|---|---|---|---|
| Credential attack | MFA on bastion; lockout at 10 failures / 5 min; SSH not reachable from the user VLAN | Alert at ≥10 failures / 5 min per source; "success after failures" correlation | Lock the account, revoke sessions, rotate the password, re-enrol MFA | mfa, segmentation, monitoring |
| Ransomware | Segmentation; least privilege; `noexec` on shares | FIM rate ≥100 file changes/min; canary files; CPU >90 %; AI score | Auto-quarantine; restore data from the last clean snapshot onto the standby; verify in the clean room | segmentation, pam, ids, immutable_backup, failover, recovery_env |
| Backup deletion | Object Lock compliance mode; pull-based backup, so production holds no vault credentials | Alert on any delete or retention-change API call to the vault | Restore from the locked copy; the offline copy is the last resort | immutable_backup, monitoring, offline_copy |
| Data exfiltration | Egress allow-list proxy; least-privilege DB roles | Suricata alert on non-allow-listed destinations and volume anomalies; DB query-rate anomaly | Block the destination, revoke DB credentials, scope the leaked data, notify KZ-CERT and data subjects | segmentation, ids, monitoring |
| Privilege escalation | JIT admin, no standing root, tamper protection | Alert on AV/EDR stop, a new admin account, sudo outside the JIT window | Rebuild the host from a golden image in the clean room; rotate privileged credentials | pam, monitoring, recovery_env |

**Part D — recovery plan.** The clock starts at the first malicious change. Detection latency is included.

| # | Action (template text) | Component | min | depends_on |
|---|---|---|---|---|
| 1 | Detect incident | monitoring + ids (FIM-rate rule, SIEM correlation, AI score) | 2 | — |
| 2 | Isolate affected system | segmentation (quarantine VLAN + VM pause + account lock, automated) | 2 | 1 |
| 3 | Preserve evidence | monitoring (VM memory/disk snapshot, SIEM log export with SHA-256 to WORM) | 4 | 2 |
| 4 | Activate backup | immutable_backup (select the last clean snapshot, mount read-only in the clean room) | 3 | 2 |
| 5 | Restore services | failover (RS-02 rebuilt from a golden image; data from the snapshot; PostgreSQL PITR) | 8 | 4 |
| 6 | Verify integrity | recovery_env (hash manifest, YARA/AV scan, DB consistency, canaries intact) | 5 | 5 |
| 7 | Return to production | failover (VIP/DNS switch, rotated credentials, heightened monitoring) | 2 | 3, 6 |

**Recovery numbers:**
- Sequential RTO = **26 min** (4 min slack against 30).
- Critical path = **22 min**, because steps 3 and 4 run in parallel.
- Snapshots run every **3 min** aligned to 09:00, with a vault replication lag of **1 min**, so worst-case RPO = 3 + 1 = **4 min ≤ 5**. This is the student-specific decision: a 5-minute interval would breach the RPO once the lag is counted.
- The last clean snapshot is the one *strictly before* the first malicious change (09:07), which is **09:06**. Actual data loss is 1 min.
- Failover is snapshot-based, not live replication, because live replication would copy the encrypted files to the standby.

**Part E — AI detection.**
- **Anomalies:** 5 of 5 signals are ≥ 0.75, a rate of **100%**. Write it as "100%" everywhere.
- **Deltas:**

  | Signal | Delta |
  |---|---|
  | Login failures | 0.71 |
  | File modifications | **0.84** |
  | CPU usage | 0.68 |
  | Outbound traffic | 0.64 |
  | Database requests | 0.73 |

- **Highest priority:** File modifications, by delta and by observed score (0.96). By ratio the top signal would be Login failures (8.10× versus 8.00×), which is the "problem encountered" entry.
- **Threshold sensitivity:** 0.75→5, 0.80→4, 0.85→3, 0.90→2, 0.95→1. Outbound traffic is only 0.04 above the threshold, so at 0.80 the exfiltration signal disappears.
- **Q3 points:**
  - Detection is probabilistic: false positives and false negatives (see the 0.04 margin).
  - Research servers legitimately reach 95 % CPU on simulations, so the CPU signal has low specificity.
  - AI only detects; it cannot stop backup deletion or restore data.
  - The attacker disabled AV at 09:18, and an AI agent on the same host can be tampered with in the same way.
  - Baselines drift with semester and exam load.
  - Deterministic controls (MFA, Object Lock, egress deny) work even when detection fails, and they are auditable.
- **Q4 / §6:** the `offline_copy` mechanism, justified by four points:
  - Kazakhstan personal-data localisation: Law of the RK No. 94-V "On Personal Data and Their Protection" requires personal-data databases to be on RK territory, so a foreign cloud is not a drop-in DR site.
  - Astana–Almaty sites are roughly 1,000 km apart, which protects against site-level events.
  - The air gap survives compromise of the vault's admin plane.
  - It is a last-resort tier (RPO 24 h) verified by monthly restore drills.

**Simulation — `configs/scenarios.json`.** Expected results:

| Metric | baseline | hardened | hardened_assume_breach |
|---|---|---|---|
| attacker_access | true | false | true |
| stopped_at / stopped_by | null | "09:01" lockout + source block | "09:08" automated isolation (FIM rate rule) |
| first_detection | null | "09:01" | "09:01" |
| files_impacted | 1200 | 0 | 320 |
| backup_destroyed | true | false | false |
| exfiltration_succeeded | true | false | false |
| av_disabled | true | false | false |
| data_loss_min | null (unbounded) | 0 | 1 |
| rto_min | null (not achievable) | 0 | 26 |

- **Assumptions to state in the report:**
  - The 320 modified files are part of the 1,200 encrypted ones, so `files_impacted` takes the max, not the sum.
  - In the baseline, the deletion attempt on mutable backups succeeds.
- **Reduction:** 1,200 → 320 files impacted is **−73.3 %** under assume-breach.

---

## File Structure

```
requirements.txt  pyproject.toml  .gitignore  README.md  run_all.sh
data/incident_events.csv        data/anomaly_scores.csv
configs/scenarios.json
src/fault4/__init__.py  __main__.py  data.py  incident.py  risk.py  controls.py
           recovery.py  anomaly.py  simulation.py  pipeline.py  figures.py
           report_content.py  report_docx.py
tests/test_data.py  test_incident.py  test_risk.py  test_controls.py  test_recovery.py
      test_anomaly.py  test_simulation.py  test_pipeline.py  test_figures.py  test_report.py
outputs/results.json  outputs/run_log.txt  outputs/figures/*.png        (generated, committed)
report/Assignment4_Talgatov_Aibyn.docx  report/Assignment4_Talgatov_Aibyn.pdf  (generated, committed)
```

`pyproject.toml` contains only `[tool.pytest.ini_options] pythonpath = ["src"]  testpaths = ["tests"]`.

---

### Task 1: Scaffold, datasets, loader

**Files:**
- Create: `requirements.txt`, `pyproject.toml`, `.gitignore` (`.venv/ __pycache__/ .pytest_cache/ *.pyc .DS_Store`)
- Create: `data/incident_events.csv`, `data/anomaly_scores.csv`
- Create: `src/fault4/__init__.py` (`__version__ = "1.0.0"`), `src/fault4/data.py`
- Test: `tests/test_data.py`

The two CSVs use exactly these headers, with rows copied verbatim from spec page 1 and Part E:
- `time,event,source,severity` (the `"1,200 files encrypted"` value is quoted)
- `event,normal_score,observed_score`

**Interfaces:**
- Produces:
  - Constants `REPO_ROOT, DATA_DIR, CONFIG_DIR, OUTPUT_DIR, REPORT_DIR: Path`.
  - `EVENT_KINDS = ("failed_logins","login_success","files_modified","cpu_usage","files_encrypted","backup_deletion","outbound_unknown","db_access_spike","av_disabled")`.
  - `@dataclass(frozen=True) Event(time: str, minute: int, description: str, source: str, severity: str, kind: str, value: Optional[float])`. `minute` is minutes since midnight, so 09:01 → 541.
  - `@dataclass(frozen=True) AnomalySignal(name: str, normal: float, observed: float)`.
  - Functions:
    - `parse_event_text(text: str) -> Tuple[str, Optional[float]]`
    - `load_events(path: Path = DATA_DIR/"incident_events.csv") -> List[Event]`
    - `load_anomaly_signals(path: Path = DATA_DIR/"anomaly_scores.csv") -> List[AnomalySignal]`
    - `sha256_file(path: Path) -> str`
    - `fmt_minute(minute: int) -> str`

- [ ] **Step 1: Write failing tests**

```python
def test_load_events_reads_all_ten_rows():
    ev = load_events()
    assert [e.time for e in ev] == ["09:01","09:03","09:04","09:07","09:08","09:10","09:12","09:13","09:15","09:18"]
    assert ev[0].minute == 541 and ev[0].source == "10.20.4.15" and ev[0].severity == "Medium"
def test_parse_thousands_separator():
    assert parse_event_text("1,200 files encrypted") == ("files_encrypted", 1200.0)
def test_parse_percent():
    assert parse_event_text("CPU usage increased to 95%") == ("cpu_usage", 95.0)
def test_parse_kinds_without_value():
    assert parse_event_text("Successful login") == ("login_success", None)
    assert parse_event_text("Antivirus disabled") == ("av_disabled", None)
def test_unknown_event_text_raises():
    with pytest.raises(ValueError, match="Printer jam"): parse_event_text("Printer jam")
def test_load_anomaly_signals():
    s = load_anomaly_signals()
    assert [x.name for x in s] == ["Login failures","File modifications","CPU usage","Outbound traffic","Database requests"]
    assert (s[1].normal, s[1].observed) == (0.12, 0.96)
def test_sha256_and_fmt():
    assert len(sha256_file(DATA_DIR / "incident_events.csv")) == 64
    assert fmt_minute(541) == "09:01"
```

- [ ] **Step 2:** `python3 -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt && python -m pytest tests/test_data.py -v` should FAIL (ImportError).
- [ ] **Step 3: Implement `data.py`.** Use one case-insensitive regex per kind. Counts are written as `[\d,]+`, with commas stripped before converting to a number. The ValueError message must include the offending text.
- [ ] **Step 4:** `python -m pytest tests/test_data.py -v` should PASS.
- [ ] **Step 5:** Commit: `feat: add synthetic incident datasets and loader`. Include the spec PDF and this plan in the same first commit.

### Task 2: Part A — incident classification

**Files:** Create `src/fault4/incident.py`. Test: `tests/test_incident.py`.

**Interfaces:**
- Consumes: `Event`, `load_events`, `fmt_minute`.
- Produces:
  - `ATTACK_STAGES` (a tuple of the 8 spec strings, in spec order).
  - `@dataclass(frozen=True) ClassifiedEvent(event: Event, stage: str, evidence: str, risk: str, attack_ref: str)`.
  - `classify_events(events: Sequence[Event]) -> List[ClassifiedEvent]`.
  - `attack_metrics(classified: Sequence[ClassifiedEvent]) -> Dict[str, int]`.

- [ ] **Step 1: Failing tests.** Values come from *Pinned decisions — Part A*.

```python
def test_every_event_gets_expected_stage():
    assert {c.event.time: c.stage for c in classify_events(load_events())} == {
        "09:01":"reconnaissance","09:03":"credential attack","09:04":"privilege compromise",
        "09:07":"data destruction","09:08":"data destruction","09:10":"data destruction",
        "09:12":"recovery attack","09:13":"exfiltration","09:15":"lateral movement","09:18":"persistence"}
def test_assessed_risk_upgrades_only_the_successful_login():
    c = classify_events(load_events())
    assert {x.event.time for x in c if x.risk != x.event.severity} == {"09:04"}
    assert next(x for x in c if x.event.time == "09:04").risk == "Critical"
def test_all_eight_stages_used():
    assert {c.stage for c in classify_events(load_events())} == set(ATTACK_STAGES)
def test_attack_metrics():
    assert attack_metrics(classify_events(load_events())) == {"failed_logins_total":36,"minutes_to_compromise":3,
        "minutes_compromise_to_encryption":6,"attack_duration_minutes":17,"stages_observed":8}
def test_first_failed_login_burst_per_source_is_reconnaissance():
    mk = lambda t, src: Event(t, int(t[:2]) * 60 + int(t[3:]), "5 failed logins", src, "Medium", "failed_logins", 5.0)
    st = [c.stage for c in classify_events([mk("09:00", "a"), mk("09:01", "b"), mk("09:02", "a")])]
    assert st == ["reconnaissance", "reconnaissance", "credential attack"]
def test_evidence_cites_dataset_values():
    by = {c.event.time: c for c in classify_events(load_events())}
    assert "1,200" in by["09:10"].evidence and "36" in by["09:03"].evidence
    assert by["09:03"].attack_ref == "T1110.001 Password Guessing"
```

- [ ] **Step 2:** Run `python -m pytest tests/test_incident.py -v`. Expect FAIL.
- [ ] **Step 3: Implement.**
  - The stage comes from `kind`. For `failed_logins`, the first burst per source is `reconnaissance` and any later burst is `credential attack`.
  - Evidence strings are built from the event values and cumulative counts, and must cover every fact in the pinned table.
  - `attack_ref` uses the pinned ATT&CK strings.
- [ ] **Step 4:** Run the tests. Expect PASS.
- [ ] **Step 5:** Commit: `feat: classify incident events into attack stages (Part A)`.

### Task 3: Part B — risk matrix

**Files:** Create `src/fault4/risk.py`. Test: `tests/test_risk.py`.

**Interfaces:**
- Produces:
  - `risk_score(likelihood: int, impact: int) -> int`. Raises ValueError unless both are ints from 1 to 5.
  - `risk_level(score: int) -> str`. Raises ValueError outside 1–25.
  - `@dataclass(frozen=True) ThreatRisk(threat, likelihood, impact, likelihood_reason, impact_reason)` with `.score` and `.level` properties.
  - `THREATS: Tuple[ThreatRisk, ...]` in template order.
  - `prioritise(threats) -> List[Tuple[int, ThreatRisk]]`.
  - `likelihood_sensitivity(t: ThreatRisk) -> Dict[str, str]` with keys `"L-1","L","L+1"`.

- [ ] **Step 1: Failing tests**

```python
@pytest.mark.parametrize("score,level", [(1,"Low"),(4,"Low"),(5,"Medium"),(9,"Medium"),(10,"High"),(16,"High"),(17,"Critical"),(25,"Critical")])
def test_risk_level_band_boundaries(score, level): assert risk_level(score) == level
@pytest.mark.parametrize("l,i", [(0,3),(6,1),(3,0),(2,6),(2.5,2),(True,3)])
def test_risk_score_rejects_out_of_scale(l, i):
    with pytest.raises(ValueError): risk_score(l, i)
def test_threat_table():
    assert {t.threat:(t.likelihood,t.impact,t.score,t.level) for t in THREATS} == {
        "Credential compromise":(5,4,20,"Critical"),"Ransomware":(4,5,20,"Critical"),
        "Backup destruction":(3,5,15,"High"),"Data exfiltration":(4,4,16,"High"),"Privilege escalation":(4,4,16,"High")}
def test_priority_ranking():
    assert [t.threat for _, t in prioritise(THREATS)] == ["Ransomware","Credential compromise","Data exfiltration","Privilege escalation","Backup destruction"]
def test_backup_destruction_is_borderline_critical():
    b = next(t for t in THREATS if t.threat == "Backup destruction")
    assert likelihood_sensitivity(b) == {"L-1":"High","L":"High","L+1":"Critical"}
def test_sensitivity_clamps_at_scale_edge():
    c = next(t for t in THREATS if t.threat == "Credential compromise")
    assert likelihood_sensitivity(c) == {"L-1":"High","L":"Critical","L+1":"Critical"}
```

- [ ] **Step 2:** Run. Expect FAIL. **Step 3:** Implement. Reasons are 1–2 sentences each, following the gist column of the pinned table. `bool` must be rejected even though it is a subclass of `int`.
- [ ] **Step 4:** Run. Expect PASS. **Step 5:** Commit: `feat: risk matrix with banding, ranking and sensitivity (Part B)`.

### Task 4: Part C — resilient architecture model

**Files:** Create `src/fault4/controls.py`. Test: `tests/test_controls.py`.

**Interfaces:**
- Produces:
  - `REQUIRED_COMPONENTS = ("MFA","Network segmentation","Immutable backup","Monitoring","Intrusion detection","Secure failover","Recovery environment")`.
  - `@dataclass(frozen=True) Component(key, name, technology, zone, role, satisfies)`.
  - `COMPONENTS` (9 entries, from the pinned table).
  - `@dataclass(frozen=True) ThreatControls(threat, preventive, detective, recovery, components: Tuple[str, ...])`.
  - `THREAT_CONTROLS` (5 entries).
  - `coverage_gaps(components=COMPONENTS, threat_controls=THREAT_CONTROLS) -> List[str]`, returning human-readable problems.

- [ ] **Step 1: Failing tests**

```python
def test_all_required_components_present():
    assert set(REQUIRED_COMPONENTS) <= {c.satisfies for c in COMPONENTS}
def test_threat_names_follow_part_c_template():
    assert [t.threat for t in THREAT_CONTROLS] == ["Credential attack","Ransomware","Backup deletion","Data exfiltration","Privilege escalation"]
def test_every_threat_has_p_d_r():
    assert all(t.preventive and t.detective and t.recovery for t in THREAT_CONTROLS)
def test_roles_are_valid():
    assert {c.role for c in COMPONENTS} <= {"preventive","detective","recovery"}
def test_no_coverage_gaps(): assert coverage_gaps() == []
def test_gap_detection_unknown_and_unused():
    bad = (ThreatControls("X","p","d","r",("nope",)),)
    gaps = coverage_gaps(COMPONENTS, bad)
    assert any("nope" in g for g in gaps) and any("mfa" in g for g in gaps)   # unknown key + unused component
```

- [ ] **Step 2:** Run. Expect FAIL. **Step 3:** Implement the tables verbatim from the pinned decisions. `coverage_gaps` must report all of these:
  - a missing required component;
  - an empty P, D or R;
  - an unknown component key;
  - a component no threat uses.
- [ ] **Step 4:** Run. Expect PASS. **Step 5:** Commit: `feat: threat-to-control architecture model with coverage check (Part C)`.

### Task 5: Part D — recovery plan

**Files:** Create `src/fault4/recovery.py`. Test: `tests/test_recovery.py`.

**Interfaces:**
- Produces:
  - Constants: `RTO_TARGET_MIN = 30`, `RPO_TARGET_MIN = 5`, `SNAPSHOT_INTERVAL_MIN = 3`, `REPLICATION_LAG_MIN = 1`.
  - `@dataclass(frozen=True) RecoveryStep(number: int, action: str, component: str, duration_min: int, depends_on: Tuple[int, ...], details: str)`.
  - `RECOVERY_STEPS` (7 entries, pinned).
  - Functions:
    - `sequential_rto(steps) -> int`
    - `critical_path_rto(steps) -> int` (earliest-finish over the `depends_on` DAG; ValueError on an unknown dependency)
    - `worst_case_rpo(interval_min: int = SNAPSHOT_INTERVAL_MIN, lag_min: int = REPLICATION_LAG_MIN) -> int`
    - `last_clean_snapshot(first_malicious_minute: int, interval_min: int, origin_minute: int = 540) -> int`
    - `recovery_check(steps=RECOVERY_STEPS) -> Dict[str, Any]`, with keys `rto_sequential, rto_critical_path, rto_target, rto_met, slack_min, rpo_worst_case, rpo_target, rpo_met`

- [ ] **Step 1: Failing tests**

```python
def test_steps_follow_template():
    assert [s.action for s in RECOVERY_STEPS] == ["Detect incident","Isolate affected system","Preserve evidence",
        "Activate backup","Restore services","Verify integrity","Return to production"]
def test_rto_figures():
    assert sequential_rto(RECOVERY_STEPS) == 26 and critical_path_rto(RECOVERY_STEPS) == 22
def test_rpo_counts_replication_lag():
    assert worst_case_rpo() == 4 and worst_case_rpo(5, 1) == 6   # why 5-min snapshots would breach RPO
def test_last_clean_snapshot_is_strictly_before_first_malicious_change():
    assert last_clean_snapshot(547, 3) == 546      # 09:07 -> 09:06
    assert last_clean_snapshot(546, 3) == 543      # snapshot in the same minute is not trusted
def test_recovery_check_passes_and_flags_violation():
    assert recovery_check() == {"rto_sequential":26,"rto_critical_path":22,"rto_target":30,"rto_met":True,
        "slack_min":4,"rpo_worst_case":4,"rpo_target":5,"rpo_met":True}
    slow = tuple(dataclasses.replace(s, duration_min=s.duration_min + 1) for s in RECOVERY_STEPS)
    assert recovery_check(slow)["rto_met"] is False      # 33 > 30
def test_unknown_dependency_raises():
    bad = (RecoveryStep(1,"a","x",1,(9,),""),)
    with pytest.raises(ValueError): critical_path_rto(bad)
```

- [ ] **Step 2:** Run. Expect FAIL. **Step 3:** Implement. The `details` text follows the pinned Part D table. **Step 4:** Run. Expect PASS.
- [ ] **Step 5:** Commit: `feat: seven-step recovery plan with RTO/RPO verification (Part D)`.

### Task 6: Part E — AI-assisted detection

**Files:** Create `src/fault4/anomaly.py`. Test: `tests/test_anomaly.py`.

**Interfaces:**
- Consumes: `AnomalySignal`, `load_anomaly_signals`.
- Produces:
  - `ANOMALY_THRESHOLD = 0.75`.
  - `@dataclass(frozen=True) AnomalyResult(name, normal, observed, delta, ratio, margin, is_anomaly)`. Floats are rounded to 2 dp; the comparison uses the raw values, with `>=`.
  - `score_signals(signals, threshold=ANOMALY_THRESHOLD) -> List[AnomalyResult]`.
  - `anomaly_summary(results) -> Dict[str, Any]`, with keys `count, total, rate, highest_priority, highest_by_ratio`.
  - `threshold_sensitivity(signals, thresholds=(0.75,0.80,0.85,0.90,0.95)) -> List[Dict[str, float]]`, returning dicts of the form `{"threshold":..,"count":..}`.

- [ ] **Step 1: Failing tests**

```python
def test_all_five_are_anomalies():
    s = anomaly_summary(score_signals(load_anomaly_signals()))
    assert (s["count"], s["total"], s["rate"]) == (5, 5, 1.0)
def test_highest_priority_by_delta_differs_from_ratio():
    s = anomaly_summary(score_signals(load_anomaly_signals()))
    assert s["highest_priority"] == "File modifications" and s["highest_by_ratio"] == "Login failures"
def test_deltas_and_ratios():
    r = {x.name: (x.delta, x.ratio) for x in score_signals(load_anomaly_signals())}
    assert r == {"Login failures":(0.71,8.1),"File modifications":(0.84,8.0),"CPU usage":(0.68,4.4),
                 "Outbound traffic":(0.64,5.27),"Database requests":(0.73,5.06)}
def test_threshold_is_inclusive():
    assert score_signals([AnomalySignal("edge", 0.1, 0.75)])[0].is_anomaly is True
def test_threshold_sensitivity():
    assert [d["count"] for d in threshold_sensitivity(load_anomaly_signals())] == [5,4,3,2,1]
def test_empty_input_rate_is_zero():
    assert anomaly_summary([])["rate"] == 0.0
```

- [ ] **Step 2:** Run. Expect FAIL. **Step 3:** Implement. The priority key is the largest delta, ties broken by observed score. A zero normal score gives ratio `None`. **Step 4:** Run. Expect PASS.
- [ ] **Step 5:** Commit: `feat: anomaly scoring, prioritisation and threshold sensitivity (Part E)`.

### Task 7: Before/after attack simulation

**Files:** Create `configs/scenarios.json` and `src/fault4/simulation.py`. Test: `tests/test_simulation.py`.

**`configs/scenarios.json`:** a list of 3 objects. Every scenario has every key:

| key | baseline | hardened | hardened_assume_breach |
|---|---|---|---|
| `name` | `baseline` | `hardened` | `hardened_assume_breach` |
| `label` | `Baseline (as-is)` | `Hardened architecture` | `Hardened, assume breach (MFA bypassed)` |
| `failed_login_alert` | null | 10 | 10 |
| `lockout_threshold` | null | 10 | null |
| `lockout_window_min` | 5 | 5 | 5 |
| `mfa_required` | false | true | true |
| `mfa_bypassed` | false | false | true |
| `file_change_alert_per_min` | null | 100 | 100 |
| `auto_isolation_delay_min` | null | 1 | 1 |
| `backup_immutable` | false | true | true |
| `egress_allowlist` | false | true | true |
| `av_tamper_protection` | false | true | true |
| `snapshot_interval_min` | null | 3 | 3 |

**Interfaces:**
- Consumes: `Event`, `fmt_minute`, `last_clean_snapshot`.
- Produces:
  - `@dataclass(frozen=True) Scenario(...)`, one field per key above.
  - `load_scenarios(path: Path = CONFIG_DIR/"scenarios.json") -> List[Scenario]`. Raises ValueError naming any missing key.
  - `@dataclass(frozen=True) TimelineEntry(time: str, event: str, status: str, note: str)`, where status ∈ {`executed`,`detected`,`blocked`,`contained`,`not reached`}.
  - `@dataclass(frozen=True) SimulationResult(scenario, label, attacker_access: bool, stopped_at: Optional[str], stopped_by: Optional[str], first_detection: Optional[str], files_impacted: int, backup_destroyed: bool, exfiltration_succeeded: bool, av_disabled: bool, data_loss_min: Optional[int], rto_min: Optional[int], timeline: List[TimelineEntry])`.
  - `simulate(events: Sequence[Event], scenario: Scenario, recovery_rto_min: int) -> SimulationResult`.

**Rules:** process the events in time order.
- **`failed_logins`** — keep a running total of failures from that source inside the lockout window.
  - If the total reaches `failed_login_alert`, mark the event `detected`.
  - If it reaches `lockout_threshold`, block the source and stop the attack (`stopped_at`).
  - Once a source is blocked, its later attempts are `blocked`.
- **`login_success`** — grants access unless the source is blocked or MFA is required and not bypassed.
- **Post-login events** — `not reached` without access, `contained` at or after `isolation = detection_minute + auto_isolation_delay_min`, otherwise executed.
  - **`files_modified`** — when its value reaches `file_change_alert_per_min`, mark it `detected` and schedule the isolation.
  - **Effects** — only events that happened have effects (status `executed` or `detected`, not `blocked`, `contained` or `not reached`):
    - `files_encrypted` / `files_modified` → `files_impacted = max(...)`
    - `backup_deletion` → destroyed unless `backup_immutable`
    - `outbound_unknown` → succeeds unless `egress_allowlist`
    - `av_disabled` → succeeds unless `av_tamper_protection`
  - **Contained notes** — notes for contained events also name each *independent* layer that would have blocked them anyway: `object lock`, `egress allow-list`, `tamper protection`.
- **`data_loss_min` / `rto_min`:**
  - None if the backup was destroyed or `snapshot_interval_min` is null.
  - 0 if no files were impacted (checked first: no impact means no loss, even without snapshots).
  - Otherwise `data_loss_min = first malicious minute − last_clean_snapshot(...)` and `rto_min = recovery_rto_min`.

- [ ] **Step 1: Failing tests.** Expected values come from the pinned simulation table.

```python
def run(name):
    sc = {s.name: s for s in load_scenarios()}[name]
    return simulate(load_events(), sc, recovery_rto_min=26)
def test_load_scenarios_names(): assert [s.name for s in load_scenarios()] == ["baseline","hardened","hardened_assume_breach"]
def test_missing_key_raises(tmp_path):
    data = json.loads((CONFIG_DIR / "scenarios.json").read_text()); del data[0]["mfa_required"]
    p = tmp_path / "s.json"; p.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="mfa_required"): load_scenarios(p)
def test_baseline_reproduces_incident():
    r = run("baseline")
    assert (r.attacker_access, r.files_impacted, r.backup_destroyed, r.exfiltration_succeeded, r.av_disabled,
            r.first_detection, r.data_loss_min, r.rto_min) == (True, 1200, True, True, True, None, None, None)
def test_hardened_stops_attack_at_0901():
    r = run("hardened")
    assert (r.attacker_access, r.stopped_at, r.files_impacted, r.data_loss_min, r.rto_min) == (False, "09:01", 0, 0, 0)
    assert {e.time: e.status for e in r.timeline}["09:04"] == "blocked"
def test_assume_breach_contains_at_0908():
    r = run("hardened_assume_breach")
    assert (r.attacker_access, r.first_detection, r.stopped_at, r.files_impacted, r.backup_destroyed,
            r.exfiltration_succeeded, r.av_disabled, r.data_loss_min, r.rto_min) == (
            True, "09:01", "09:08", 320, False, False, False, 1, 26)
def test_assume_breach_names_independent_layers():
    notes = {e.time: e.note for e in run("hardened_assume_breach").timeline}
    assert "object lock" in notes["09:12"] and "egress allow-list" in notes["09:13"] and "tamper protection" in notes["09:18"]
```

- [ ] **Step 2:** Run. Expect FAIL. **Step 3:** Implement following the rules above. **Step 4:** Run. Expect PASS.
- [ ] **Step 5:** Commit: `feat: deterministic before/after attack simulation`.

### Task 8: Pipeline, CLI, run log

**Files:** Create `src/fault4/pipeline.py` and `src/fault4/__main__.py`. Test: `tests/test_pipeline.py`.

**Interfaces:**
- Consumes: everything from Tasks 1–7.
- Produces:
  - `run_analysis(data_dir: Path = DATA_DIR, config_dir: Path = CONFIG_DIR) -> Dict[str, Any]`. JSON-safe, deterministic, with exactly these top-level keys:
    - `data_sources`: {file name: sha256} for the 2 CSVs and `scenarios.json`.
    - `incident`: {`events`: [{time, event, source, severity, stage, evidence, risk, attack_ref}], `metrics`}.
    - `risk`: {`threats`: [{threat, likelihood, impact, score, level, rank, likelihood_reason, impact_reason, sensitivity}]}.
    - `controls`: {`components`: [...], `threat_controls`: [...], `coverage_gaps`: []}.
    - `recovery`: {`steps`: [...], `check`: {...}, `snapshot_interval_min`, `replication_lag_min`, `last_clean_snapshot`: "09:06"}.
    - `anomaly`: {`threshold`, `signals`: [...], `summary`, `threshold_sensitivity`}.
    - `simulation`: [ asdict(SimulationResult) ... ].
  - `git_commit(repo_root: Path = REPO_ROOT) -> Optional[str]`: short HEAD hash, or None if git or the repo is unavailable.
  - `format_run_log(results, commit: Optional[str]) -> str`. Includes a UTC timestamp, the Python version, the platform, the commit, the SHA-256 values, and the key numbers of each part plus the simulation comparison table.
  - `write_outputs(results, out_dir: Path = OUTPUT_DIR, commit=None) -> List[Path]`: writes `results.json` and `run_log.txt`.
  - `main(argv: Optional[List[str]] = None) -> int`. Subcommands are `analyze | figures | report | all`, with `all` the default. Options:
    - `--out DIR` (default `OUTPUT_DIR`)
    - `--report-dir DIR` (default `REPORT_DIR`)
    - `--submission-date STR` (optional; otherwise the date stays blank)

- [ ] **Step 1: Failing tests**

```python
def test_results_are_deterministic():
    assert json.dumps(run_analysis(), sort_keys=True) == json.dumps(run_analysis(), sort_keys=True)
def test_results_top_level_keys():
    assert set(run_analysis()) == {"data_sources","incident","risk","controls","recovery","anomaly","simulation"}
def test_write_outputs(tmp_path):
    paths = write_outputs(run_analysis(), tmp_path, commit="abc1234")
    assert json.loads((tmp_path/"results.json").read_text())["recovery"]["check"]["rto_sequential"] == 26
    assert "abc1234" in (tmp_path/"run_log.txt").read_text()
def test_cli_runs_from_other_cwd(tmp_path):
    env = {**os.environ, "PYTHONPATH": str(REPO_ROOT/"src")}
    p = subprocess.run([sys.executable,"-m","fault4","analyze","--out",str(tmp_path)], cwd=tmp_path, env=env)
    assert p.returncode == 0 and (tmp_path/"results.json").exists()
```

- [ ] **Step 2:** Run. Expect FAIL. **Step 3:** Implement. `figures` and `report` are wired up in Tasks 9 and 10; until then they print "not yet available" and return 2. **Step 4:** Run. Expect PASS.
- [ ] **Step 5:** Run `PYTHONPATH=src python -m fault4 analyze`. Check by eye that `outputs/run_log.txt` shows 26/22/4, 5/5 and the simulation table. Commit the code together with `outputs/results.json` and `run_log.txt`: `feat: analysis pipeline, CLI and run log`.

### Task 9: Figures

**Files:** Create `src/fault4/figures.py`. Test: `tests/test_figures.py`. Load the `dataviz` skill before writing chart code.

**Interfaces:**
- Consumes: the `run_analysis()` dict, read only through its keys.
- Produces: `render_all(results: Dict[str, Any], out_dir: Path = OUTPUT_DIR/"figures") -> List[Path]`. Writes exactly these files, 150 dpi, ≤ 10 in wide:
  - **`architecture.png`** — one box per zone, from the pinned component table:
    - User VLAN 10.20.4.0/24
    - Access (bastion + MFA + PAM)
    - Research (RS-01 primary, RS-02 warm standby)
    - Data (PostgreSQL + WAL)
    - Security (monitoring, IDS, AI scorer)
    - Backup vault (immutable, pull-only)
    - Recovery environment (clean room)
    - Offline copy, second KZ site

    Draw the firewall/segmentation as the zone boundary. Component colour encodes the role (preventive / detective / recovery), with a legend. There are four kinds of arrow:
    - access path: user → firewall → bastion → RS-01
    - pull backups, every 3 min: vault ← RS-01
    - logs: all → monitoring; plus monitoring → firewall "quarantine"
    - restore path: vault → clean room → RS-02 → production
  - **`attack_timeline.png`** — x axis 09:00–09:20, y axis the 8 stages in kill-chain order. Points are coloured by assessed risk. Vertical markers show "hardened: stopped 09:01" and "assume breach: isolated 09:08".
  - **`risk_matrix.png`** — a 5×5 L×I grid shaded by band. Threats sharing a cell (Data exfiltration and Privilege escalation, both at 4,4) are listed together in that cell without overlapping.
  - **`anomaly_scores.png`** — paired horizontal bars (normal vs observed) per signal. Threshold line at 0.75, delta annotated.
  - **`recovery_timeline.png`** — a Gantt chart of the 7 steps using the critical-path schedule (steps 3 and 4 in parallel). Lines at 22 (critical path), 26 (sequential) and 30 (RTO target).

- [ ] **Step 1: Failing tests**

```python
def test_render_all_writes_five_pngs(tmp_path):
    paths = render_all(run_analysis(), tmp_path)
    assert sorted(p.name for p in paths) == ["anomaly_scores.png","architecture.png","attack_timeline.png","recovery_timeline.png","risk_matrix.png"]
    for p in paths:
        assert p.read_bytes()[:8] == b"\x89PNG\r\n\x1a\n" and p.stat().st_size > 10_000
def test_backend_is_agg():
    import matplotlib; import fault4.figures  # noqa
    assert matplotlib.get_backend().lower() == "agg"
```

- [ ] **Step 2:** Run. Expect FAIL. **Step 3:** Implement and wire up `python -m fault4 figures`. **Step 4:** Run. Expect PASS.
- [ ] **Step 5:** Render into `outputs/figures/` and open each PNG with the Read tool to inspect it: no overlapping labels, legible at page width, and the arrows read as described. Fix anything found, then commit code and PNGs: `feat: architecture, timeline, risk, anomaly and recovery figures`.

### Task 10: Report (.docx)

**Files:** Create `src/fault4/report_content.py` (text only) and `src/fault4/report_docx.py` (layout only). Test: `tests/test_report.py`.

**Interfaces:**
- Consumes: the results dict and the figure paths from `render_all`.
- Produces:
  - `STUDENT: Dict[str, str]` (Global Constraints values).
  - `section_texts(results) -> Dict[str, Dict[str, str]]`. Keys are `incident, risk, architecture, recovery, ai, additional`; each value is `{summary, evidence, decision}`.
  - `individual_record(results, commit: Optional[str]) -> List[Tuple[str, str]]` (5 rows).
  - `evidence_checklist() -> List[Tuple[str, str]]` (item, file pointer).
  - `conclusion(results) -> str`.
  - `build_report(results, figures: List[Path], out_path: Path = REPORT_DIR/"Assignment4_Talgatov_Aibyn.docx", commit: Optional[str] = None, work_period: Optional[Tuple[str, str]] = None, submission_date: Optional[str] = None) -> Path`.
  - `work_period` is (first commit ISO time, build time).

**Document order:**
1. Title block + synthetic-data context note.
2. Part A table: template columns Time / Event / Attack stage / Evidence / Risk, 10 rows.
3. Part B table: Threat / Likelihood / Impact / Risk Score / Priority, 5 rows. Priority reads "Critical (#1)".
4. Part C table: Threat / Preventive / Detection / Recovery, 5 rows. Then `architecture.png` with a control-flow paragraph.
5. Part D table: Step / Action / Responsible component / Target time, 7 rows. Then the RTO/RPO calculation and `recovery_timeline.png`.
6. Part E table: Event / Normal / Observed / Δ / Anomaly (≥ 0.75). Then answers Q1–Q4, `anomaly_scores.png` and the threshold-sensitivity table.
7. Before/after simulation: the comparison table and `attack_timeline.png`.
8. *Student Technical Work Report* §1 Student info (8 rows) and §2 Work period (5 rows).
9. §3 sections 1–6, each a Required content / Student response table with Summary, Evidence, and Student-specific decision. Put `risk_matrix.png` in §3.2.
10. §4 Individual work record. §5 Evidence checklist with ☒ and file pointers. Conclusion.
11. §6 Declaration (name filled; signature and date blank) and §7 Instructor record (empty ☐ boxes, untouched).
12. Appendix: reproduce commands, data SHA-256, commit.

**Content that must appear.** Everything else is the implementer's English prose, ≤ 120 words per cell, concrete and number-led:
- **§3.1:** 8/8 stages; 17-minute attack; no automated reaction in the baseline; AV disabled after encryption. Decision: 09:15 classed as lateral movement rather than exfiltration (justify the pivot into the DB), and 09:04 upgraded to Critical.
- **§3.2:** L×I arithmetic for all 5 threats; ranking rule. Decision: backup destruction is borderline Critical (sensitivity) and is implemented first.
- **§3.3:** 7 components → keys; control flow. Decision: snapshot-based failover, not live replication.
- **§3.4:** step times 2+2+4+3+8+5+2 = 26 ≤ 30; critical path 22; RPO 3+1 = 4 ≤ 5; last clean snapshot 09:06, so the actual loss is 1 min. Decision: a 3-min interval, because 5 + 1 = 6 would breach the RPO.
- **§3.5:** 5/5 = 100%; File modifications Δ 0.84; ratio caveat; threshold sensitivity; the Q3 points from the pinned decisions.
- **§3.6:** the offline-copy justification from the pinned decisions (law No. 94-V, ~1,000 km, air gap, drills, RPO 24 h tier).
- **§4 rows:**
  - unique decision = the 3-min-snapshot / RPO-lag reasoning;
  - own evidence = simulation 1,200 → 320 (−73.3 %), RTO 26, RPO 4/1;
  - exact reference = data SHA-256 + `commit` + file paths;
  - problem = ratio vs delta disagree on the top anomaly, resolved by choosing delta plus kill-chain stage;
  - limitation = a single synthetic incident with a deterministic replay; thresholds chosen knowing this incident (overfitting risk); no false-positive rate measured.
- **Conclusion:** ≤ 150 words with the key numbers.

- [ ] **Step 1: Failing tests**

```python
@pytest.fixture(scope="module")
def doc(tmp_path_factory):
    out = tmp_path_factory.mktemp("r")
    res = run_analysis(); figs = render_all(res, out/"fig")
    return Document(build_report(res, figs, out/"r.docx", commit="abc1234", work_period=("2026-10-31T10:00","2026-10-31T18:00")))
def full_text(d): return "\n".join([p.text for p in d.paragraphs] + [c.text for t in d.tables for r in t.rows for c in r.cells])
def test_student_fields(doc):
    t = full_text(doc)
    for s in ["Talgatov Aibyn","255308","CSE-2505M","Serek Azamat","https://github.com/a169n/fault_4","abc1234","synthetic"]:
        assert s in t
def test_assignment_tables_present(doc):
    heads = {tuple(c.text for c in t.rows[0].cells): len(t.rows) for t in doc.tables}
    assert heads[("Time","Event","Attack stage","Evidence","Risk")] == 11
    assert heads[("Threat","Likelihood","Impact","Risk Score","Priority")] == 6
    assert heads[("Threat","Preventive control","Detection control","Recovery control")] == 6
    assert heads[("Step","Action","Responsible component","Target time")] == 8
def test_key_numbers_in_report(doc):
    t = full_text(doc)
    for s in ["26 min","22 min","4 min","100%","1,200","320","0.84","09:06"]: assert s in t
def test_report_has_no_placeholder_leaks(doc):
    t = full_text(doc)
    assert not any(x in t for x in ["{", "}", "TODO", "TBD"])
    cells = [c.text.strip() for tb in doc.tables for r in tb.rows for c in r.cells]
    assert not any(c in ("None", "null", "nan") for c in cells)        # raw Python values leaking into cells
def test_report_images_fit_page(doc):
    shapes = doc.inline_shapes
    assert len(shapes) == 5 and all(s.width <= Inches(6.5) for s in shapes)
```

- [ ] **Step 2:** Run. Expect FAIL. **Step 3:** Implement and wire up `python -m fault4 report` / `all`. The commit comes from `git_commit()`. `work_period` is the first commit time (`git log --reverse --format=%cI`) plus the current local time. Use Arial/Calibri 10 pt, table style `Table Grid`, and a light-blue header row like the template. **Step 4:** Run. Expect PASS.
- [ ] **Step 5:** Commit: `feat: generate completed submission report (.docx)`.

### Task 11: One-command run, README, macOS / Python 3.9 verification, publish

**Files:** Create `run_all.sh` (chmod +x) and `README.md`. Regenerate `outputs/` and `report/`.

- [ ] **Step 1: `run_all.sh`** (POSIX `sh`):
  - `set -e`, then `cd "$(dirname "$0")"`.
  - `PYTHONPATH=src python3 -m fault4 all "$@"`.
  - Then, only if `soffice` is on PATH, `soffice --headless --convert-to pdf --outdir report report/Assignment4_Talgatov_Aibyn.docx`. Otherwise print "PDF export skipped: open the .docx in Word/Pages and Export as PDF".
- [ ] **Step 2: `README.md`.** It contains:
  - purpose and the synthetic-data note;
  - macOS quick start: `python3 -m venv .venv`, `source .venv/bin/activate`, `pip install -r requirements.txt`, `./run_all.sh`, `python -m pytest`;
  - a table mapping assignment Part → module → output;
  - the key results table;
  - data provenance (SHA-256 values);
  - an oral-defence cheat sheet: one line per "why is X preventive / detective / recovery".
- [ ] **Step 3: Full verification, current Python.** Run `python -m pytest -q`. Expect all tests to pass.
- [ ] **Step 4: Python 3.9 verification (macOS parity).** In the scratchpad, run:

  ```bash
  uv venv --python 3.9 venv39
  uv pip install --python venv39 -r requirements.txt
  PYTHONPATH=src venv39/bin/python -m pytest -q
  PYTHONPATH=src venv39/bin/python -m fault4 analyze --out <scratch>/o39
  ```

  Expect all tests to pass, and `diff <scratch>/o39/results.json outputs/results.json` to print nothing.
- [ ] **Step 5: Build and inspect.** Run `./run_all.sh`, then `pdftoppm -png -r 60 report/Assignment4_Talgatov_Aibyn.pdf <scratch>/page`. Read every page image. Check:
  - tables are not cut off;
  - figures are visible;
  - no empty sections apart from the intended blanks (variant code, submission date, signatures, instructor record).
- [ ] **Step 6:** Commit `run_all.sh`, `README.md`, `outputs/` and `report/`: `docs: one-command build, README and final report`. Then run `git push -u origin claude/keen-rubin-w9hhpm`.
