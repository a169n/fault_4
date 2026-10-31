# Assignment 4 — Security, Resilience & Intrusion Tolerance: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A reproducible Python analysis of the synthetic Research-Server-01 ransomware incident and a completed English submission report (.docx + .pdf). The analysis covers Parts A–E, a before/after attack simulation, figures and the fully filled Student Technical Work Report.

**Architecture:** Each assignment part is computed by its own module in `src/fault4/`, all reading the same versioned CSV/JSON inputs. `pipeline.py` turns everything into one deterministic `outputs/results.json` plus a human-readable `outputs/run_log.txt`. `figures.py` and the report builder only *render* that results dict, so every number in the report comes from code and can be traced to a file and a commit.

**Tech Stack:** Python ≥ 3.9 (stdlib `csv`, `json`, `hashlib`, `dataclasses`, `subprocess`), matplotlib (Agg) for figures, python-docx for the report, pytest. LibreOffice (`soffice`) is optional and used only to export the PDF.

**Spec:** `docs/assignment/Assignment_4_AITU_Security_Resilience_Report_Template.pdf`. Pages 1–3 are the tasks (Parts A–E and the submission list). Pages 4–7 are the Student Technical Work Report template to fill in.

## Global Constraints

- Must run on macOS system Python **3.9.6**, so: no `match`, no PEP 604 `X | Y` unions at runtime, no `dataclass(slots=/kw_only=)`, no `tomllib`, no `zoneinfo` data dependency. Use `typing.Optional/List/Dict/Tuple`, with `from __future__ import annotations` allowed.
- Dependencies are exactly `matplotlib==3.9.4`, `python-docx==1.1.2` and `pytest==8.3.5` in `requirements.txt`. All three have macOS arm64 cp39 wheels; this was verified. Everything else is stdlib.
- Resolve every path from `REPO_ROOT = Path(__file__).resolve().parents[2]`, never from the cwd.
- Call `matplotlib.use("Agg")` in `figures.py` *before* importing `pyplot`, so no GUI window opens on macOS.
- `outputs/results.json` must be byte-identical across processes and Python versions:
  - no timestamps;
  - `json.dumps(..., indent=2, sort_keys=True, ensure_ascii=False)`;
  - floats rounded to 2 dp;
  - **never turn a set into a list without `sorted()`**.

  Timestamps go only into `run_log.txt` and the report.
- The executor runs every command with the venv interpreter explicitly: `.venv/bin/python …`. Shell activation does not persist between tool calls, and the system `python3` here has no pytest or matplotlib.
- Spec values must be used verbatim:
  - Risk bands: 1–4 Low, 5–9 Medium, 10–16 High, 17–25 Critical. L and I range from 1 to 5.
  - Anomaly threshold: score **≥ 0.75**.
  - RPO ≤ 5 min, RTO ≤ 30 min.
- Use the attack-stage vocabulary exactly as the spec spells it: `reconnaissance, credential attack, privilege compromise, lateral movement, data destruction, persistence, exfiltration, recovery attack`.
- **Terminology:** RTO and RPO are *targets*. Computed values are called **estimated recovery time** and **worst-case data loss**, both in code and in prose. A scenario with no impact reads "no recovery needed", never "RTO 0".
- The report is in English. It must contain the spec's context note that all data are synthetic and do not describe real AITU infrastructure.
- Student data, verbatim:
  - Student full name `Talgatov Aibyn`, Student ID `255308`, Group / cohort `CSE-2505M`, Instructor `Serek Azamat`.
  - Repository `https://github.com/a169n/fault_4`.
  - The variant code was not provided, so render a blank line `______________________`.
  - Submission date: blank `____ / ____ / ______`, unless `--submission-date` is given.
  - Signatures: blank.
- Times shown in the report are converted to **UTC+5 (Astana)** using a fixed `timezone(timedelta(hours=5))`.
- Commit `outputs/` and `report/`, because they are the submission evidence. Never commit `.venv/`.
- Every commit message ends with the session attribution trailer lines from the system reminder.

## Review Focus

1. **macOS `/usr/bin/python3` 3.9.6:** a single 3.10+ construct breaks the student's demo. Task 11 Step 3 runs the full suite and pipeline under Python 3.9 (`uv`) and diffs `results.json` against the 3.13 run.
2. **Running from another directory** (`../run_all.sh`, or `python -m fault4` with a different cwd) must still find `data/` and `configs/`. Covered by `test_cli_runs_from_other_cwd` (Task 8).
3. **Number formats in the dataset:**
   - `"1,200 files encrypted"` has a thousands separator.
   - `"CPU usage increased to 95%"` carries a percent sign.
   - Unknown event text must fail loudly, never silently drop a row.
   Covered by `test_parse_thousands_separator`, `test_parse_percent` and `test_unknown_event_text_raises` (Task 1).
4. **Opening the .docx in Word for Mac / Pages:** no image wider than the text area, no unfilled `{placeholders}` or raw `None`, all template labels present. Covered by `test_report_images_fit_page`, `test_report_has_no_placeholder_leaks` and `test_template_labels_verbatim` (Task 10), plus the page-image check in Task 11.
5. **Hash-seed or set ordering making `results.json` differ between runs.** Covered by `test_results_json_byte_identical_across_processes` (Task 8), which runs under two different `PYTHONHASHSEED` values. `run_log.txt`, PNGs, .docx and .pdf are *expected* to change on every rebuild, so they are committed only from the final build.

---

## Pinned analytical decisions (the report argues from these)

### Part A — classification

The Risk column is the *assessed* risk. It equals the dataset severity except at 09:04, which is upgraded to **Critical**: success right after 36 failures is the pivot that every later event depends on.

The ATT&CK reference is appended to the Evidence cell as `(ATT&CK: …)`. Five rows carry an **alternative reading**, rendered in the evidence text and in the README cheat sheet. Dataset rows are treated as **per-minute aggregates**, and no evidence text may claim a sub-minute duration.

| Time | Stage | Evidence (facts that must appear) | Risk | attack_ref | Alternative reading |
|---|---|---|---|---|---|
| 09:01 | reconnaissance | First contact from 10.20.4.15; 15 failed logins in the first logged burst (Medium). Consistent with probing which usernames exist and whether lockout is enforced | Medium | `T1589 Gather Victim Identity Information (tactic: Reconnaissance)` | Start of the credential attack (T1110) |
| 09:03 | credential attack | 21 more failures, 36 cumulative, same source | High | `T1110.001 Password Guessing (tactic: Credential Access)` | — |
| 09:04 | privilege compromise | Successful login from the same IP right after 36 failures | **Critical** | `T1078 Valid Accounts (tactic: Initial Access)` | — |
| 09:07 | data destruction | 320 files modified by the attacker session (source 10.20.4.15) | Critical | `T1486 Data Encrypted for Impact (tactic: Impact)` | — |
| 09:08 | data destruction | 95% CPU on Research-Server-01, 1 min after the 320 modifications and 2 min before 1,200 files are reported encrypted, so consistent with the encryption workload | High | `T1486 Data Encrypted for Impact (tactic: Impact)` | 95% CPU alone is not specific on a research server (Part E). Resource hijacking (T1496) is less likely given the timing |
| 09:10 | data destruction | 1,200 files encrypted | Critical | `T1486 Data Encrypted for Impact (tactic: Impact)` | — |
| 09:12 | recovery attack | Backup deletion attempt 2 min after encryption | Critical | `T1490 Inhibit System Recovery (tactic: Impact)` | — |
| 09:13 | exfiltration | Outbound connection to an unknown IP. No transfer volume is logged, so exfiltration is *assessed*, not confirmed | High | `T1041 Exfiltration Over C2 Channel (tactic: Exfiltration)` | A C2 channel only; double extortion is a hypothesis |
| 09:15 | lateral movement | DB access spike: the compromised server is used as a pivot into the research DB. *Stated assumption:* the DB runs on a separate host. The queries feed the outbound channel opened at 09:13 | High | `TA0008 Lateral Movement (pivot RS-01 → DB) + T1213 Data from Information Repositories (tactic: Collection)` | Exfiltration (collection) |
| 09:18 | persistence | AV disabled at 09:18, 8 min after 1,200 files were encrypted. The dataset shows no AV alert during 09:07–09:10, so AV did not stop the encryption. Disabling AV protects the attacker's continued access and hampers forensics | Critical | `T1562.001 Impair Defenses: Disable or Modify Tools (tactic: Defense Evasion)` | Defense evasion. The spec vocabulary has no such stage, so it is classed as persistence |

**Attack metrics:**
- 36 failed logins in total.
- 3 min to compromise (09:01 → 09:04).
- 6 min from compromise to encryption (09:04 → 09:10).
- 17 min attack duration (09:01 → 09:18).
- 8 of 8 stage categories used, of which 2 are interpretive (09:01, 09:15). The report says this; it never claims "all stages observed".

### Part B — risk matrix

The threat order is the template's. The likelihood rule is applied consistently and must be stated in the report:
- **L5** = observed *and succeeded* in this incident.
- **L4** = attempted or indirectly evidenced, with the outcome not logged.

The impact rule:
- **I5** = loss of research data or of the ability to recover.
- **I4** = serious but bounded (access or confidentiality).

| Threat | L | I | Score | Level | Rank | L reason / I reason (gist) |
|---|---|---|---|---|---|---|
| Credential compromise | 5 | 4 | 20 | Critical | 3 | Observed success at 09:04 after 36 guesses, password-only. Impact: grants entry, but is not damage by itself |
| Ransomware | 5 | 5 | 25 | Critical | 1 | Observed: 1,200 files encrypted. Impact: loss of research data and availability |
| Backup destruction | 4 | 5 | 20 | Critical | 2 | Attempt observed at 09:12. Backups were mutable and the attacker already had the rights the attempt needs; the outcome is not logged. Impact: removes recoverability |
| Data exfiltration | 4 | 4 | 16 | High | 4 | Outbound connection (09:13) and DB spike within 2 min (09:13 → 09:15), with no volume logged. Impact: research and personal data, legal exposure |
| Privilege escalation | 4 | 4 | 16 | High | 5 | Indirect: AV disable and backup deletion both need admin rights. Impact: an enabler, not damage by itself |

- **Ranking rule:** score descending, then impact descending, then template order.
- **Priority** in the template cell = level + rank, e.g. `Critical (#1)`.
- **Sensitivity** (L±1, clamped to 1–5):
  - Only Ransomware stays Critical at L−1.
  - Credential compromise and Backup destruction drop to High at L−1.
  - Data exfiltration and Privilege escalation rise to Critical at L+1.
  - Conclusion: four of five threats sit one likelihood step from the High/Critical boundary, so all five get controls.
- **Implementation order** is a separate decision from risk rank:
  1. **MFA** first, because it removes the root cause (credential compromise).
  2. **Immutable backup**, because it is the only control that still guarantees recovery when every preventive layer fails.
  The assume-breach simulation shows that data loss and recovery time become unbounded whenever backups are destroyed.

### Part C — components

All 7 required components must be present. `why` is the defence of the role and is rendered in the report's component inventory table.

| key | name / technology | zone | role | satisfies | why (role defence) |
|---|---|---|---|---|---|
| `mfa` | privacyIDEA TOTP/push via its PAM module on the SSH bastion and its FreeRADIUS plugin on the VPN; admins additionally use FIDO2 OpenSSH keys (`ed25519-sk`); per-source-IP lockout at 10 failures / 5 min | Access zone | preventive | MFA | Stops a guessed password from becoming a session; would have blocked 09:04 |
| `segmentation` | OPNsense firewall, VLANs, default-deny inter-zone, egress allow-list proxy, quarantine VLAN | All zone boundaries | preventive | Network segmentation | Preventive by design: 10.20.4.15 reaches RS-01 only through the bastion, and unknown egress (09:13) is denied. Its quarantine VLAN is *reused* for containment in Part D step 2 |
| `pam` | Just-in-time sudo, separate admin accounts, no standing root, agent tamper protection | Access zone | preventive | supporting | Backup deletion (09:12) and AV disable (09:18) need a JIT approval the attacker does not have |
| `monitoring` | Wazuh SIEM + Prometheus/Grafana, correlation rules, active response | Security zone | detective | Monitoring | Raises the 09:01 and 09:07 alerts and *triggers* responses, but blocks nothing itself |
| `ids` | Suricata NIDS, Wazuh HIDS/FIM with canary files and an extension/entropy check, AI anomaly scorer | Security zone | detective | Intrusion detection | Detects the encryption (09:07) and the unknown outbound connection (09:13) |
| `immutable_backup` | See the backup mechanism below | Backup vault (pull-only) | recovery | Immutable backup | Does not stop encryption; guarantees an untouchable clean restore point (worst-case loss 4 min) |
| `failover` | Research-Server-02: warm VM cloned from a golden image, holds no data, separate VLAN, promoted only after data is restored from a verified clean point | Research zone | recovery | Secure failover | Restores service on clean infrastructure within the RTO, and never receives live-replicated (encrypted) data |
| `recovery_env` | Isolated clean-room VLAN, no internet: restore, scan, verify | Recovery zone | recovery | Recovery environment | Restored data is verified in isolation before it returns to production |
| `offline_copy` | See the offline copy below | Second site | recovery | Additional (Part E Q4 / §6) | Last resort that survives compromise of the vault's admin plane or loss of the Astana site |

**Backup mechanism (`immutable_backup`):**
- ZFS snapshots are taken every 3 min on RS-01.
- The vault *pulls* the incrementals (`zfs send -i | zfs receive`, initiated from the vault) into its own pool and places a `zfs hold` on them.
- restic also writes a copy into a MinIO bucket with S3 Object Lock in compliance mode (30 days). This is the tamper-proof copy.
- PostgreSQL WAL is pulled continuously by `pg_receivewal` running on the vault, over a replication-only role, plus a nightly base backup. DB loss is a matter of seconds.
- Production holds no vault credentials.

**Offline copy (`offline_copy`):**
- A logically air-gapped copy at a second Kazakhstan site (Almaty, ~970 km from Astana).
- The transfer window is opened daily from the Almaty side only.
- A monthly copy is rotated to disconnected media.
- It has a separate admin domain and is checked by a monthly restore drill.
- Data-loss tier: 24 h.

**Threat → controls.** Names follow the Part C template. Containment actions are prefixed `Respond:` and restoration actions `Recover:`. The template has no Respond column (in NIST CSF terms), so containment sits in the Recovery column; the README explains this.

| Threat | Preventive control | Detection control | Recovery control | components |
|---|---|---|---|---|
| Credential attack | MFA on bastion and VPN; per-source-IP lockout at 10 failures / 5 min (per IP, not per account, so attackers cannot lock researchers out); SSH unreachable from the user VLAN | SIEM alert at ≥10 failures / 5 min per source; "success after failures" correlation | Respond: block the source, revoke sessions. Recover: rotate the password, re-enrol MFA, review account activity | mfa, segmentation, monitoring |
| Ransomware | Segmentation; least-privilege write access to research shares; `noexec` on /tmp, /dev/shm and user-writable mounts plus application allow-listing (fapolicyd) | Canary-file write (immediate); FIM rate ≥100 changes/min AND extension/entropy change; CPU >90% and AI score used only as correlating signals | Respond: automated quarantine + VM pause. Recover: restore data from the verified clean point onto RS-02 and verify in the clean room | segmentation, pam, ids, immutable_backup, failover, recovery_env |
| Backup deletion | Object Lock compliance mode; pull-based backups, so production holds no vault credentials; JIT admin | Alert on any delete or retention-change API call, or a failed vault login | Recover: restore from the locked copy; the offline Almaty copy is the last resort | immutable_backup, pam, monitoring, offline_copy |
| Data exfiltration | Egress default-deny allow-list proxy; least-privilege DB roles | Suricata alert on a non-allow-listed destination and on volume anomalies; DB query-rate anomaly | Respond: block the destination, revoke DB credentials. Recover: scope the leaked records, report to KZ-CERT, and notify the authorised personal-data body and data subjects where Law No. 94-V and university policy require it | segmentation, pam, ids, monitoring |
| Privilege escalation | JIT admin, no standing root, agent tamper protection | Alert on AV/EDR stop, a new admin account, or sudo outside the JIT window | Recover: rebuild the host from a golden image in the clean room; rotate all privileged credentials | pam, monitoring, recovery_env |

### Part D — recovery plan

The clock starts at the first logged malicious change (T = 09:07), so detection latency is inside the budget. Steps 1–2 together take 2 min, which matches the simulation's automated isolation delay. The Target time cell is rendered as `"<duration> min (by T+<finish>)"`, where finish comes from the critical-path schedule.

| # | Action (template text) | Responsible component (rendered text) | min | depends_on | Target time cell |
|---|---|---|---|---|---|
| 1 | Detect incident | ids + monitoring (canary / FIM + entropy rule, SIEM correlation, AI score) | 1 | — | `1 min (by T+1)` |
| 2 | Isolate affected system | segmentation (quarantine VLAN) + hypervisor (VM pause) + privacyIDEA/IdP (account lock), triggered by Wazuh active response | 1 | 1 | `1 min (by T+2)` |
| 3 | Preserve evidence | hypervisor (VM memory + disk snapshot) + monitoring (SIEM log export, SHA-256, WORM bucket) | 4 | 2 | `4 min (by T+6, parallel with step 4)` |
| 4 | Activate backup | immutable_backup (choose the clean point, clone it read-only from the vault ZFS pool into the clean room) | 3 | 2 | `3 min (by T+5)` |
| 5 | Restore services | failover (RS-02 warm VM from a golden image; copy data from the clean point, assuming ≤200 GB over 10 GbE ≈ 3 min; PostgreSQL PITR to the clean point, ≤5 min unless the DB audit log shows an earlier malicious write) | 8 | 4 | `8 min (by T+13)` |
| 6 | Verify integrity | recovery_env (hash manifest vs the clean point, YARA/AV scan, no new executables / authorized_keys / cron entries, DB consistency, canaries intact) | 5 | 5 | `5 min (by T+18)` |
| 7 | Return to production | failover + segmentation (VIP/DNS switch, rotated credentials, heightened monitoring) | 2 | 3, 6 | `2 min (by T+20)` |

**Recovery numbers:**
- **Estimated recovery time:** sequential **24 min** (6 min slack against the 30-min RTO). This is the committed, conservative figure, and `rto_met` and the slack are computed from it. The critical path is **20 min**, because steps 3 and 4 run in parallel.
- **Worst-case data loss:** snapshots run every **3 min** aligned to 09:00, with a vault replication lag of **1 min**, so 3 + 1 = **4 min ≤ RPO 5**. This is the student-specific decision: a 5-min interval would give 5 + 1 = 6 and breach the RPO.
- **Clean-point rule:**
  - The preferred clean point is the last snapshot strictly before the first logged malicious change (09:07), which is **09:06**. It is used only if the clean-room check in step 6 passes.
  - The attacker had access from 09:04 and the 09:07 row is a per-minute aggregate. If the check fails, fall back to the last snapshot strictly before attacker access, which is **09:03**.
  - Data loss is **1 min** at the preferred point and **4 min** at the fallback; both are ≤ 5.
- Failover is snapshot-based, not live replication, because live replication would copy the encrypted files to the standby.

### Part E — AI-assisted detection

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
- **Threshold sensitivity:** 0.75→5, 0.80→4, 0.85→3, 0.90→2, 0.95→1. Outbound traffic is only 0.04 above the threshold, so at 0.80 the exfiltration signal disappears. Decision: keep 0.75.
- **Q3 points:**
  - Detection is probabilistic: false positives and false negatives (see the 0.04 margin).
  - Research servers legitimately reach 95% CPU on simulations, so the CPU signal has low specificity.
  - AI only detects; it cannot stop backup deletion or restore data.
  - The attacker disabled AV at 09:18, and an AI agent on the same host can be tampered with in the same way.
  - Baselines drift with semester and exam load.
  - Deterministic controls (MFA, Object Lock, egress deny) work even when detection fails, and they are auditable.
- **Q4 / §6:** the `offline_copy` mechanism, justified by four points:
  - Law of the Republic of Kazakhstan No. 94-V of 21 May 2013, "On Personal Data and Their Protection", Article 12, requires personal-data databases to be stored on RK territory. A foreign cloud therefore cannot be the only DR copy of research datasets that contain personal data. Cite `https://adilet.zan.kz/eng/docs/Z1300000094` with an access date.
  - The Astana–Almaty separation (~970 km) protects against site-level events.
  - The logical air gap, separate admin domain and monthly offline media survive compromise of the vault's admin plane.
  - It is a last-resort tier (24 h) verified by monthly restore drills.

### Simulation — `configs/scenarios.json`

Expected results:

| Metric | baseline | hardened | hardened_assume_breach | hardened_manual_isolation |
|---|---|---|---|---|
| attacker_access | true | false | true | true |
| stopped_at | null | "09:01" | "09:09" | "09:11" |
| first_detection | null | "09:01" | "09:01" | "09:01" |
| files_impacted | 1200 | 0 | 320 | 1200 |
| backup_destroyed | true | false | false | false |
| exfiltration_succeeded | true | false | false | false |
| av_disabled | true | false | false | false |
| data_loss_min / data_loss_fallback_min | null / null | 0 / 0 | 1 / 4 | 1 / 4 |
| recovery_time_min | null (not achievable) | 0 ("no recovery needed") | 24 | 24 |

**Assumptions to state in the report:**
- The replay is non-adaptive: the attacker follows the dataset timing.
- Rows are per-minute aggregates, so 320 files modified at 09:07 means 320 changes/min. They are assumed to include encrypted-extension/entropy changes, so the combined FIM rule fires.
- The 100/min value is a placeholder, to be tuned on at least one week of real FIM data.
- The 320 modified files are part of the 1,200 encrypted ones, so `files_impacted` takes the max, not the sum.
- In the baseline, the deletion attempt on mutable backups succeeds.
- **Assume-breach scenarios** deliberately disable every access-zone control: lockout, MFA (e.g. a stolen session token), and response to the 09:01 alert (the alert fires but nobody acts). This tests whether detection plus immutable recovery alone bound the damage.
- In `hardened`, a low-and-slow guesser (≤9 tries per 5 min) would evade lockout. **MFA**, not lockout, is the control that robustly stops the 09:04 login, and `stopped_by` says so.

**Headline results:**
- Automated isolation within 2 min cuts impacted files from 1,200 to 320 (**−73.3%**).
- With manual isolation (4 min), all 1,200 files are hit, but the data still comes back within RPO and RTO, because the backups were immutable.
- So automation limits the blast radius, and immutability guarantees recoverability.

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
outputs/results.json  outputs/run_log.txt  outputs/test_log.txt  outputs/figures/*.png   (generated, committed)
report/Assignment4_Talgatov_Aibyn.docx  report/Assignment4_Talgatov_Aibyn.pdf          (generated, committed)
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
  - Constants `REPO_ROOT, DATA_DIR, CONFIG_DIR, OUTPUT_DIR, REPORT_DIR: Path`, and `SPEC_PDF = REPO_ROOT/"docs/assignment/Assignment_4_AITU_Security_Resilience_Report_Template.pdf"`.
  - `EVENT_KINDS = ("failed_logins","login_success","files_modified","cpu_usage","files_encrypted","backup_deletion","outbound_unknown","db_access_spike","av_disabled")`.
  - `@dataclass(frozen=True) Event(time: str, minute: int, description: str, source: str, severity: str, kind: str, value: Optional[float])`. `minute` is minutes since midnight, so 09:01 → 541.
  - `@dataclass(frozen=True) AnomalySignal(name: str, normal: float, observed: float)`.
  - Functions:
    - `parse_event_text(text: str) -> Tuple[str, Optional[float]]`
    - `load_events(path: Path = DATA_DIR/"incident_events.csv") -> List[Event]`
    - `load_anomaly_signals(path: Path = DATA_DIR/"anomaly_scores.csv") -> List[AnomalySignal]`
    - `sha256_file(path: Path) -> str`
    - `fmt_minute(minute: int) -> str`

- [ ] **Step 1: Write failing tests.** Imports: `import pytest` and `from fault4.data import DATA_DIR, SPEC_PDF, load_events, load_anomaly_signals, parse_event_text, sha256_file, fmt_minute`.

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
    assert len(sha256_file(DATA_DIR / "incident_events.csv")) == 64 and SPEC_PDF.exists()
    assert fmt_minute(541) == "09:01"
```

- [ ] **Step 2:** Run `python3 -m venv .venv && .venv/bin/pip install -r requirements.txt && .venv/bin/python -m pytest tests/test_data.py -v`. Expect FAIL with `ModuleNotFoundError: fault4.data`, *not* a missing pytest.
- [ ] **Step 3: Implement `data.py`.** Use one case-insensitive regex per kind. Counts are written as `[\d,]+`, with commas stripped before converting to a number. The ValueError message must include the offending text.
- [ ] **Step 4:** Run `.venv/bin/python -m pytest tests/test_data.py -v`. Expect PASS.
- [ ] **Step 5:** Commit: `feat: add synthetic incident datasets and loader`.

### Task 2: Part A — incident classification

**Files:** Create `src/fault4/incident.py`. Test: `tests/test_incident.py`.

**Interfaces:**
- Consumes: `Event`, `load_events`, `fmt_minute`.
- Produces:
  - `ATTACK_STAGES` (a tuple of the 8 spec strings, in spec order).
  - `@dataclass(frozen=True) ClassifiedEvent(event: Event, stage: str, evidence: str, risk: str, attack_ref: str, alternative: str)`. `alternative` is `""` when there is none.
  - `classify_events(events: Sequence[Event]) -> List[ClassifiedEvent]`.
  - `attack_metrics(classified: Sequence[ClassifiedEvent]) -> Dict[str, int]`.

- [ ] **Step 1: Failing tests.** Imports: `from fault4.data import Event, load_events` and `from fault4.incident import ATTACK_STAGES, classify_events, attack_metrics`. Values come from the pinned Part A table.

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
def test_all_eight_stage_categories_assigned():
    assert {c.stage for c in classify_events(load_events())} == set(ATTACK_STAGES)
def test_interpretive_rows_carry_alternative():
    assert {c.event.time for c in classify_events(load_events()) if c.alternative} == {"09:01","09:08","09:13","09:15","09:18"}
def test_attack_metrics():
    assert attack_metrics(classify_events(load_events())) == {"failed_logins_total":36,"minutes_to_compromise":3,
        "minutes_compromise_to_encryption":6,"attack_duration_minutes":17,"stage_categories_used":8}
def test_first_failed_login_burst_per_source_is_reconnaissance():
    mk = lambda t, src: Event(t, int(t[:2]) * 60 + int(t[3:]), "5 failed logins", src, "Medium", "failed_logins", 5.0)
    st = [c.stage for c in classify_events([mk("09:00", "a"), mk("09:01", "b"), mk("09:02", "a")])]
    assert st == ["reconnaissance", "reconnaissance", "credential attack"]
def test_evidence_cites_dataset_values_and_attack_refs():
    by = {c.event.time: c for c in classify_events(load_events())}
    assert "1,200" in by["09:10"].evidence and "36" in by["09:03"].evidence
    assert by["09:03"].attack_ref == "T1110.001 Password Guessing (tactic: Credential Access)"
    assert "Defense Evasion" in by["09:18"].attack_ref and "separate host" in by["09:15"].evidence
    assert "~1 min" not in " ".join(c.evidence for c in by.values())
```

- [ ] **Step 2:** Run `.venv/bin/python -m pytest tests/test_incident.py -v`. Expect FAIL.
- [ ] **Step 3: Implement.**
  - The stage comes from `kind`. For `failed_logins`, the first burst per source is `reconnaissance` and any later burst is `credential attack`.
  - Evidence strings are built from the event values and cumulative counts, and must cover every fact in the pinned table.
  - `attack_ref` and `alternative` are copied verbatim from the pinned table.
- [ ] **Step 4:** Run the tests. Expect PASS. **Step 5:** Commit: `feat: classify incident events into attack stages (Part A)`.

### Task 3: Part B — risk matrix

**Files:** Create `src/fault4/risk.py`. Test: `tests/test_risk.py`.

**Interfaces:**
- Produces:
  - `risk_score(likelihood: int, impact: int) -> int`. Raises ValueError unless both are ints from 1 to 5; `bool` is rejected.
  - `risk_level(score: int) -> str`. Raises ValueError outside 1–25.
  - `@dataclass(frozen=True) ThreatRisk(threat, likelihood, impact, likelihood_reason, impact_reason)` with `.score` and `.level` properties.
  - `THREATS: Tuple[ThreatRisk, ...]` in template order.
  - `LIKELIHOOD_RULE: str` and `IMPACT_RULE: str`, the pinned rule sentences.
  - `prioritise(threats) -> List[Tuple[int, ThreatRisk]]`.
  - `likelihood_sensitivity(t: ThreatRisk) -> Dict[str, str]` with keys `"L-1","L","L+1"`.

- [ ] **Step 1: Failing tests.** Imports: `import pytest` and `from fault4.risk import THREATS, risk_score, risk_level, prioritise, likelihood_sensitivity`.

```python
@pytest.mark.parametrize("score,level", [(1,"Low"),(4,"Low"),(5,"Medium"),(9,"Medium"),(10,"High"),(16,"High"),(17,"Critical"),(25,"Critical")])
def test_risk_level_band_boundaries(score, level): assert risk_level(score) == level
@pytest.mark.parametrize("l,i", [(0,3),(6,1),(3,0),(2,6),(2.5,2),(True,3)])
def test_risk_score_rejects_out_of_scale(l, i):
    with pytest.raises(ValueError): risk_score(l, i)
def test_threat_table():
    assert {t.threat:(t.likelihood,t.impact,t.score,t.level) for t in THREATS} == {
        "Credential compromise":(5,4,20,"Critical"),"Ransomware":(5,5,25,"Critical"),
        "Backup destruction":(4,5,20,"Critical"),"Data exfiltration":(4,4,16,"High"),"Privilege escalation":(4,4,16,"High")}
def test_priority_ranking():
    assert [t.threat for _, t in prioritise(THREATS)] == ["Ransomware","Backup destruction","Credential compromise","Data exfiltration","Privilege escalation"]
def test_likelihood_sensitivity_all_threats():
    assert {t.threat: likelihood_sensitivity(t) for t in THREATS} == {
        "Credential compromise":{"L-1":"High","L":"Critical","L+1":"Critical"},
        "Ransomware":{"L-1":"Critical","L":"Critical","L+1":"Critical"},
        "Backup destruction":{"L-1":"High","L":"Critical","L+1":"Critical"},
        "Data exfiltration":{"L-1":"High","L":"High","L+1":"Critical"},
        "Privilege escalation":{"L-1":"High","L":"High","L+1":"Critical"}}
```

- [ ] **Step 2:** Run. Expect FAIL. **Step 3:** Implement. Reasons are 1–2 sentences each, following the gist column of the pinned table, and each must name the rule it applies (L5 or L4).
- [ ] **Step 4:** Run. Expect PASS. **Step 5:** Commit: `feat: risk matrix with banding, ranking and sensitivity (Part B)`.

### Task 4: Part C — resilient architecture model

**Files:** Create `src/fault4/controls.py`. Test: `tests/test_controls.py`.

**Interfaces:**
- Produces:
  - `REQUIRED_COMPONENTS = ("MFA","Network segmentation","Immutable backup","Monitoring","Intrusion detection","Secure failover","Recovery environment")`.
  - `@dataclass(frozen=True) Component(key, name, technology, zone, role, satisfies, why)`.
  - `COMPONENTS` (9 entries, from the pinned table).
  - `@dataclass(frozen=True) ThreatControls(threat, preventive, detective, recovery, components: Tuple[str, ...])`.
  - `THREAT_CONTROLS` (5 entries).
  - `coverage_gaps(components=COMPONENTS, threat_controls=THREAT_CONTROLS) -> List[str]`. Returns sorted, human-readable problems.

- [ ] **Step 1: Failing tests.** Imports: `from fault4.controls import REQUIRED_COMPONENTS, COMPONENTS, THREAT_CONTROLS, ThreatControls, coverage_gaps`.

```python
def test_all_required_components_present():
    assert set(REQUIRED_COMPONENTS) <= {c.satisfies for c in COMPONENTS}
def test_threat_names_follow_part_c_template():
    assert [t.threat for t in THREAT_CONTROLS] == ["Credential attack","Ransomware","Backup deletion","Data exfiltration","Privilege escalation"]
def test_every_threat_has_p_d_r():
    assert all(t.preventive and t.detective and t.recovery for t in THREAT_CONTROLS)
def test_roles_are_valid_and_defended():
    assert {c.role for c in COMPONENTS} <= {"preventive","detective","recovery"}
    assert all(c.why for c in COMPONENTS)
def test_recovery_cells_separate_respond_from_recover():
    assert all("Recover:" in t.recovery for t in THREAT_CONTROLS)
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
    - `sequential_recovery_time(steps) -> int`
    - `step_finish_times(steps) -> Dict[int, int]` (earliest finish over the `depends_on` DAG; ValueError on an unknown dependency)
    - `critical_path_recovery_time(steps) -> int` (the max of `step_finish_times`)
    - `target_time_cell(step, finish: int) -> str` (renders `"4 min (by T+6, parallel with step 4)"`; the parallel suffix only for steps that share a predecessor)
    - `worst_case_data_loss(interval_min: int = SNAPSHOT_INTERVAL_MIN, lag_min: int = REPLICATION_LAG_MIN) -> int` (= interval + lag)
    - `last_clean_snapshot(before_minute: int, interval_min: int, origin_minute: int = 540) -> int` (the largest snapshot time *strictly* before `before_minute`)
    - `clean_restore_points(first_malicious_minute: int, attacker_access_minute: int, interval_min: int = SNAPSHOT_INTERVAL_MIN) -> Dict[str, int]`, returning keys `preferred`, `fallback`
    - `recovery_check(steps=RECOVERY_STEPS) -> Dict[str, Any]`, with keys `recovery_time_sequential, recovery_time_critical_path, rto_target, rto_met, slack_min, worst_case_data_loss, rpo_target, rpo_met`. `rto_met` and `slack_min` are computed from the **sequential** value.

- [ ] **Step 1: Failing tests.** Imports: `import dataclasses, pytest` and `from fault4.recovery import *`.

```python
def test_steps_follow_template():
    assert [s.action for s in RECOVERY_STEPS] == ["Detect incident","Isolate affected system","Preserve evidence",
        "Activate backup","Restore services","Verify integrity","Return to production"]
def test_recovery_times():
    assert sequential_recovery_time(RECOVERY_STEPS) == 24 and critical_path_recovery_time(RECOVERY_STEPS) == 20
    assert step_finish_times(RECOVERY_STEPS) == {1:1, 2:2, 3:6, 4:5, 5:13, 6:18, 7:20}
def test_target_time_cells():
    f = step_finish_times(RECOVERY_STEPS)
    assert [target_time_cell(s, f[s.number]) for s in RECOVERY_STEPS] == ["1 min (by T+1)","1 min (by T+2)",
        "4 min (by T+6, parallel with step 4)","3 min (by T+5, parallel with step 3)","8 min (by T+13)","5 min (by T+18)","2 min (by T+20)"]
def test_data_loss_counts_replication_lag():
    assert worst_case_data_loss() == 4 and worst_case_data_loss(5, 1) == 6   # why 5-min snapshots would breach RPO
def test_last_clean_snapshot_is_strictly_before():
    assert last_clean_snapshot(547, 3) == 546      # 09:07 -> 09:06
    assert last_clean_snapshot(546, 3) == 543      # a snapshot in the same minute is not trusted
def test_clean_restore_points():
    assert clean_restore_points(547, 544) == {"preferred": 546, "fallback": 543}   # 09:06 verified / 09:03 before access
def test_recovery_check_passes_and_flags_violation():
    assert recovery_check() == {"recovery_time_sequential":24,"recovery_time_critical_path":20,"rto_target":30,"rto_met":True,
        "slack_min":6,"worst_case_data_loss":4,"rpo_target":5,"rpo_met":True}
    slow = tuple(dataclasses.replace(s, duration_min=s.duration_min + 1) for s in RECOVERY_STEPS)
    assert recovery_check(slow)["rto_met"] is False      # sequential 31 > 30 (critical path 26 would pass)
def test_unknown_dependency_raises():
    with pytest.raises(ValueError): critical_path_recovery_time((RecoveryStep(1,"a","x",1,(9,),""),))
```

- [ ] **Step 2:** Run. Expect FAIL. **Step 3:** Implement. The `component` and `details` text follow the pinned Part D table. **Step 4:** Run. Expect PASS.
- [ ] **Step 5:** Commit: `feat: seven-step recovery plan with RTO/RPO verification (Part D)`.

### Task 6: Part E — AI-assisted detection

**Files:** Create `src/fault4/anomaly.py`. Test: `tests/test_anomaly.py`.

**Interfaces:**
- Consumes: `AnomalySignal`, `load_anomaly_signals`.
- Produces:
  - `ANOMALY_THRESHOLD = 0.75`.
  - `@dataclass(frozen=True) AnomalyResult(name, normal, observed, delta, ratio: Optional[float], margin, is_anomaly)`. Floats are rounded to 2 dp; the comparison uses the raw values, with `>=`.
  - `score_signals(signals, threshold=ANOMALY_THRESHOLD) -> List[AnomalyResult]`.
  - `anomaly_summary(results) -> Dict[str, Any]`, with keys `count, total, rate, highest_priority, highest_by_ratio`.
  - `threshold_sensitivity(signals, thresholds=(0.75,0.80,0.85,0.90,0.95)) -> List[Dict[str, float]]`, returning dicts of the form `{"threshold":..,"count":..}`.

- [ ] **Step 1: Failing tests.** Imports: `from fault4.data import AnomalySignal, load_anomaly_signals` and `from fault4.anomaly import score_signals, anomaly_summary, threshold_sensitivity`.

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
def test_empty_input_and_zero_baseline():
    assert anomaly_summary([])["rate"] == 0.0
    assert score_signals([AnomalySignal("z", 0.0, 0.9)])[0].ratio is None
```

- [ ] **Step 2:** Run. Expect FAIL. **Step 3:** Implement. The priority key is the largest delta, ties broken by observed score. **Step 4:** Run. Expect PASS.
- [ ] **Step 5:** Commit: `feat: anomaly scoring, prioritisation and threshold sensitivity (Part E)`.

### Task 7: Before/after attack simulation

**Files:** Create `configs/scenarios.json` and `src/fault4/simulation.py`. Test: `tests/test_simulation.py`.

**`configs/scenarios.json`:** a list of 4 objects. Every scenario has every key:

| key | baseline | hardened | hardened_assume_breach | hardened_manual_isolation |
|---|---|---|---|---|
| `label` | `Baseline (as-is)` | `Hardened` | `Assume breach, automated isolation` | `Assume breach, manual isolation` |
| `failed_login_alert` | null | 10 | 10 | 10 |
| `lockout_threshold` | null | 10 | null | null |
| `lockout_window_min` | 5 | 5 | 5 | 5 |
| `mfa_required` | false | true | true | true |
| `mfa_bypassed` | false | false | true | true |
| `file_change_alert_per_min` | null | 100 | 100 | 100 |
| `auto_isolation_delay_min` | null | 2 | 2 | 4 |
| `backup_immutable` | false | true | true | true |
| `egress_allowlist` | false | true | true | true |
| `av_tamper_protection` | false | true | true | true |
| `snapshot_interval_min` | null | 3 | 3 | 3 |

**Interfaces:**
- Consumes: `Event`, `fmt_minute`, `clean_restore_points`.
- Produces:
  - `@dataclass(frozen=True) Scenario(...)`, one field per key above plus `name`.
  - `load_scenarios(path: Path = CONFIG_DIR/"scenarios.json") -> List[Scenario]`. Raises ValueError naming any missing key.
  - `@dataclass(frozen=True) TimelineEntry(time: str, event: str, status: str, note: str)`, where status ∈ {`executed`,`detected`,`blocked`,`contained`,`not reached`}.
  - `@dataclass(frozen=True) SimulationResult(scenario, label, attacker_access: bool, stopped_at: Optional[str], stopped_by: Optional[str], first_detection: Optional[str], files_impacted: int, backup_destroyed: bool, exfiltration_succeeded: bool, av_disabled: bool, data_loss_min: Optional[int], data_loss_fallback_min: Optional[int], recovery_time_min: Optional[int], timeline: List[TimelineEntry])`.
  - `simulate(events: Sequence[Event], scenario: Scenario, recovery_time_min: int) -> SimulationResult`. The pipeline passes `recovery_time_sequential` (24).

**Rules:** process the events in time order.
1. **`failed_logins`** — keep a running total of failures from that source inside `lockout_window_min`.
   - If the total reaches `failed_login_alert`, mark the event `detected`.
   - If it reaches `lockout_threshold`, block the source:
     - `stopped_at` = event time;
     - `stopped_by = "source block after lockout threshold (10 failures/5 min); MFA would independently block the 09:04 login"`.
   - Once a source is blocked, its later events are `blocked`, and their note names MFA as the independent layer.
   - Failed-login alerts never schedule isolation.
2. **`login_success`** — grants access unless the source is blocked or `mfa_required and not mfa_bypassed`.
3. **Every later event** — `not reached` without access. Otherwise `contained` when `minute >= isolation_minute`, else `executed`.
4. **`files_modified`** — when its value reaches `file_change_alert_per_min`, mark it `detected` and set `isolation_minute = event minute + auto_isolation_delay_min`. This is the only rule that isolates.
   - It then sets `stopped_at = fmt_minute(isolation_minute)` and `stopped_by = "automated isolation (FIM rate + entropy rule)"`.
   - The same string is used for the manual scenario; only the delay differs.
5. **`first_detection`** — the time of the first event that reached *any* alert threshold, whatever its final status.
6. **Effects** — only events that happened have effects (status `executed` or `detected`):
   - `files_modified` / `files_encrypted` → `files_impacted = max(...)`
   - `backup_deletion` → destroyed unless `backup_immutable`
   - `outbound_unknown` → succeeds unless `egress_allowlist`
   - `av_disabled` → succeeds unless `av_tamper_protection`
7. **Contained notes** — notes for `contained` events also name each *independent* layer that would have blocked them anyway: `object lock` (09:12), `egress allow-list` (09:13), `tamper protection` (09:18).
8. **Data loss and recovery time:**
   - `first_malicious_minute` = the minute of the first `files_modified` or `files_encrypted` event that happened (547).
   - `attacker_access_minute` = the minute of the successful login (544).
   - All three fields are None if the backup was destroyed or `snapshot_interval_min` is null.
   - All three are 0 if no files were impacted. This check comes first, so no impact means no loss even without snapshots.
   - Otherwise:
     - `data_loss_min = first_malicious − preferred`;
     - `data_loss_fallback_min = first_malicious − fallback`, both from `clean_restore_points`;
     - `recovery_time_min = recovery_time_min` (the argument passed in).

- [ ] **Step 1: Failing tests.** Imports: `import json, pytest`, `from fault4.data import CONFIG_DIR, load_events` and `from fault4.simulation import load_scenarios, simulate`. Expected values come from the pinned simulation table.

```python
def run(name):
    sc = {s.name: s for s in load_scenarios()}[name]
    return simulate(load_events(), sc, recovery_time_min=24)
def test_load_scenarios_names():
    assert [s.name for s in load_scenarios()] == ["baseline","hardened","hardened_assume_breach","hardened_manual_isolation"]
def test_missing_key_raises(tmp_path):
    data = json.loads((CONFIG_DIR / "scenarios.json").read_text()); del data[0]["mfa_required"]
    p = tmp_path / "s.json"; p.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="mfa_required"): load_scenarios(p)
def test_baseline_reproduces_incident():
    r = run("baseline")
    assert (r.attacker_access, r.files_impacted, r.backup_destroyed, r.exfiltration_succeeded, r.av_disabled,
            r.first_detection, r.data_loss_min, r.recovery_time_min) == (True, 1200, True, True, True, None, None, None)
def test_hardened_stops_attack_at_0901():
    r = run("hardened")
    assert (r.attacker_access, r.stopped_at, r.first_detection, r.files_impacted, r.data_loss_min, r.recovery_time_min) == (
            False, "09:01", "09:01", 0, 0, 0)
    assert "MFA" in r.stopped_by and {e.time: e.status for e in r.timeline}["09:04"] == "blocked"
def test_assume_breach_contains_at_0909():
    r = run("hardened_assume_breach")
    assert (r.attacker_access, r.first_detection, r.stopped_at, r.stopped_by, r.files_impacted, r.backup_destroyed,
            r.exfiltration_succeeded, r.av_disabled, r.data_loss_min, r.data_loss_fallback_min, r.recovery_time_min) == (
            True, "09:01", "09:09", "automated isolation (FIM rate + entropy rule)", 320, False, False, False, 1, 4, 24)
    assert {e.time: e.status for e in r.timeline}["09:08"] == "executed"
def test_manual_isolation_loses_files_but_still_recovers():
    r = run("hardened_manual_isolation")
    assert (r.stopped_at, r.files_impacted, r.backup_destroyed, r.data_loss_min, r.recovery_time_min) == ("09:11", 1200, False, 1, 24)
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
    - `tool_version`: `fault4.__version__`.
    - `data_sources`: {file name: sha256} for `Assignment_4_AITU_Security_Resilience_Report_Template.pdf`, `incident_events.csv`, `anomaly_scores.csv` and `scenarios.json`.
    - `incident`: {`events`: [{time, event, source, severity, stage, evidence, risk, attack_ref, alternative}], `metrics`}.
    - `risk`: {`likelihood_rule`, `impact_rule`, `threats`: [{threat, likelihood, impact, score, level, rank, likelihood_reason, impact_reason, sensitivity}]}.
    - `controls`: {`components`: [...], `threat_controls`: [...], `coverage_gaps`: []}.
    - `recovery`: {`steps`: [{number, action, component, duration_min, depends_on, details, finish_min, target_time}], `check`: {...}, `snapshot_interval_min`, `replication_lag_min`, `clean_points`: {"preferred": "09:06", "fallback": "09:03"}}.
    - `anomaly`: {`threshold`, `signals`: [...], `summary`, `threshold_sensitivity`}.
    - `simulation`: [ asdict(SimulationResult) ... ], in config order.
  - `git_commit(repo_root: Path = REPO_ROOT) -> Optional[str]`: `git describe --always --dirty --abbrev=7`, or None if git or the repo is unavailable.
  - `format_run_log(results, commit: Optional[str]) -> str`. Includes a UTC+5 timestamp, the Python version, the platform, the commit, the SHA-256 values, and the key numbers of each part plus the simulation comparison table.
  - `write_outputs(results, out_dir: Path = OUTPUT_DIR, commit=None) -> List[Path]`: writes `results.json` and `run_log.txt`.
  - `main(argv: Optional[List[str]] = None) -> int`. Subcommands are `analyze | figures | report | all`, with `all` the default. Options:
    - `--out DIR` (default `OUTPUT_DIR`)
    - `--report-dir DIR` (default `REPORT_DIR`)
    - `--submission-date STR`

- [ ] **Step 1: Failing tests.** Imports: `import json, os, subprocess, sys` and `from fault4.data import REPO_ROOT` and `from fault4.pipeline import run_analysis, write_outputs`.

```python
def test_results_top_level_keys():
    assert set(run_analysis()) == {"tool_version","data_sources","incident","risk","controls","recovery","anomaly","simulation"}
def test_results_json_byte_identical_across_processes(tmp_path):
    outs = []
    for seed in ("1", "2"):
        env = {**os.environ, "PYTHONPATH": str(REPO_ROOT / "src"), "PYTHONHASHSEED": seed}
        subprocess.run([sys.executable, "-m", "fault4", "analyze", "--out", str(tmp_path / seed)], env=env, check=True)
        outs.append((tmp_path / seed / "results.json").read_bytes())
    assert outs[0] == outs[1]
def test_write_outputs(tmp_path):
    write_outputs(run_analysis(), tmp_path, commit="abc1234")
    res = json.loads((tmp_path / "results.json").read_text())
    assert res["recovery"]["check"]["recovery_time_sequential"] == 24 and res["recovery"]["clean_points"]["preferred"] == "09:06"
    assert "abc1234" in (tmp_path / "run_log.txt").read_text()
def test_cli_runs_from_other_cwd(tmp_path):
    env = {**os.environ, "PYTHONPATH": str(REPO_ROOT / "src")}
    p = subprocess.run([sys.executable, "-m", "fault4", "analyze", "--out", str(tmp_path)], cwd=tmp_path, env=env)
    assert p.returncode == 0 and (tmp_path / "results.json").exists()
```

- [ ] **Step 2:** Run. Expect FAIL. **Step 3:** Implement. `figures` and `report` are wired up in Tasks 9 and 10; until then they print "not yet available" and return 2. **Step 4:** Run. Expect PASS.
- [ ] **Step 5:** Run `PYTHONPATH=src .venv/bin/python -m fault4 analyze`. Check by eye that `outputs/run_log.txt` shows 24/20/4, clean points 09:06/09:03, 5/5 and the four-scenario table. Commit the code together with `outputs/results.json` and `run_log.txt`: `feat: analysis pipeline, CLI and run log`.

### Task 9: Figures

**Files:** Create `src/fault4/figures.py`. Test: `tests/test_figures.py`. Load the `dataviz` skill before writing chart code.

**Interfaces:**
- Consumes: the `run_analysis()` dict, read only through its keys.
- Produces: `render_all(results: Dict[str, Any], out_dir: Path = OUTPUT_DIR/"figures") -> List[Path]`. Writes exactly these files, 150 dpi, ≤ 10 in wide:
  - **`architecture.png`** — one box per zone, from the pinned component table:
    - Internet (outside the firewall)
    - User VLAN 10.20.4.0/24
    - Access (bastion + MFA + PAM)
    - Research (RS-01 primary, RS-02 warm standby)
    - Data (PostgreSQL)
    - Security (monitoring, IDS, AI scorer)
    - Backup vault (immutable, pull-only)
    - Recovery environment (clean room)
    - Offline copy, second KZ site (Almaty)

    The firewall/segmentation is drawn as the zone boundary. Component colour encodes the role (preventive / detective / recovery), with a legend. Number the arrows ①–⑦:
    1. user → firewall → bastion (MFA) → RS-01 (access path)
    2. vault pulls snapshots and WAL from RS-01 and the DB (every 3 min / continuous)
    3. all → monitoring/IDS/AI (logs)
    4. monitoring → firewall "quarantine"
    5. RS-01 → egress proxy → Internet (denied by default)
    6. vault → clean room → RS-02 → production (restore)
    7. vault → offline copy (daily window, dashed)
  - **`attack_timeline.png`** — x axis 09:00–09:20, y axis the 8 stages in kill-chain order. Points are coloured by assessed risk. Vertical markers show "hardened: stopped 09:01", "assume breach: isolated 09:09" and "manual: isolated 09:11".
  - **`risk_matrix.png`** — a 5×5 L×I grid shaded by band. Threats sharing a cell are listed together in that cell without overlapping: Credential compromise is alone at (5,4); Data exfiltration and Privilege escalation share (4,4).
  - **`anomaly_scores.png`** — paired horizontal bars (normal vs observed) per signal. Threshold line at 0.75, delta annotated.
  - **`recovery_timeline.png`** — a Gantt chart of the 7 steps on the critical-path schedule (steps 3 and 4 in parallel). Lines at 20 (critical path), 24 (sequential estimate) and 30 (RTO target).

- [ ] **Step 1: Failing tests.** Imports: `import os, subprocess, sys` and `from fault4.data import REPO_ROOT` and `from fault4.pipeline import run_analysis` and `from fault4.figures import render_all`.

```python
def test_render_all_writes_five_pngs(tmp_path):
    paths = render_all(run_analysis(), tmp_path)
    assert sorted(p.name for p in paths) == ["anomaly_scores.png","architecture.png","attack_timeline.png","recovery_timeline.png","risk_matrix.png"]
    for p in paths:
        assert p.read_bytes()[:8] == b"\x89PNG\r\n\x1a\n" and p.stat().st_size > 10_000
def test_figures_forces_agg():
    env = {**os.environ, "MPLBACKEND": "svg", "PYTHONPATH": str(REPO_ROOT / "src")}
    out = subprocess.run([sys.executable, "-c", "import fault4.figures, matplotlib; print(matplotlib.get_backend())"],
                         env=env, capture_output=True, text=True, check=True).stdout
    assert out.strip().lower() == "agg"
```

- [ ] **Step 2:** Run. Expect FAIL. **Step 3:** Implement and wire up `python -m fault4 figures`. **Step 4:** Run. Expect PASS.
- [ ] **Step 5:** Render into `outputs/figures/` and open each PNG with the Read tool to inspect it: no overlapping labels, legible at 6.5 in width, arrows ①–⑦ readable. Fix anything found, then commit code and PNGs: `feat: architecture, timeline, risk, anomaly and recovery figures`.

### Task 10: Report (.docx)

**Files:** Create `src/fault4/report_content.py` (text only) and `src/fault4/report_docx.py` (layout only). Test: `tests/test_report.py`.

**Interfaces:**
- Consumes: the results dict and the figure paths from `render_all`.
- Produces:
  - `STUDENT: Dict[str, str]` (Global Constraints values).
  - `TEMPLATE_LABELS: Tuple[str, ...]` (verbatim strings, listed below).
  - `section_texts(results) -> Dict[str, Dict[str, str]]`. Keys are `incident, risk, architecture, recovery, ai, additional`; each value is `{summary, evidence, decision}`.
  - `individual_record(results, commit: Optional[str]) -> List[Tuple[str, str]]` (5 rows).
  - `evidence_checklist() -> List[Tuple[str, str]]` (the 8 template items, each with a file pointer).
  - `references() -> List[str]`.
  - `conclusion(results) -> str`.
  - `build_report(results, figures: List[Path], out_path: Path = REPORT_DIR/"Assignment4_Talgatov_Aibyn.docx", commit: Optional[str] = None, work_period: Optional[Tuple[str, str]] = None, submission_date: Optional[str] = None) -> Path`.
  - `work_period` holds pre-formatted strings like `"2026-10-31 10:43 (UTC+5, Astana)"`. The CLI computes them from the first commit (`git log --reverse --format=%cI`) and the current time.

**Layout rules:**
- Set every section's margins to 1 in, so the text width is 6.5 in.
- Insert figures with `doc.add_picture(str(path), width=Inches(6.5))`. python-docx treats a `Path` as a stream and crashes.
- Use the `Table Grid` table style, Calibri 10 pt, and a light-blue header row like the template.
- Copy each template section's instruction line verbatim from spec pp. 4–6 under its heading.

**`TEMPLATE_LABELS`**, verbatim from the spec:
- **§1:** `Required field`, `Student entry`, `Student full name`, `Student ID`, `Group / cohort`, `Instructor`, `Date of submission`, `Individual variant / task code assigned by instructor`, `Git repository / project link`, `Attached code / file names`.
- **§2:** `Item`, `Work start date/time`, `Work completion date/time`, `Main task completed`, `Tools / technologies used`, `Main technical output produced`.
- **§3:**
  - Subsection titles: `1. Incident Analysis`, `2. Risk Matrix`, `3. Resilient Security Architecture`, `4. Recovery Plan`, `5. AI-Assisted Detection`, `6. Additional Resilience Recommendation`.
  - Header: `Required content`, `Student response / evidence`.
  - Row labels: `Summary`, `Evidence / calculation / artifact reference`, `Student-specific decision or observation`.
- **§4:** `4. Individual Work and Anti-Plagiarism Record` (with the intro paragraph and 5 bullets copied verbatim), `Individual evidence`, `My unique technical decision`, `My own implementation / calculation evidence`, `Exact file, code, commit, notebook, or log reference`, `One problem I personally encountered and how I solved it`, `One limitation of my own solution`.
- **§5:** the 8 checklist items verbatim, from `Completed required tables and calculations` to `Final technical conclusion`.
- **§6:**
  - The declaration paragraph verbatim: "I confirm that this report describes my own work. I have not copied another student's report, code, calculations, diagrams, logs, screenshots, or conclusions. Any external source or reused material has been identified. I understand that I may be asked to reproduce or explain any part of this submission during the oral defense."
  - The table `Role / Name / Signature / Date`, with rows `Student / Executor` (Name `Talgatov Aibyn`) and `Instructor / Accepted by` (Name `Serek Azamat`). Signature and Date are blank.
- **§7:** `Check`, `Status / comment`, `Report structure completed`, `Evidence is sufficient`, `Individual contribution is identifiable`, `Oral defense completed`, `Final status`. Cells stay unticked: `☐ Yes ☐ No Comment: ____`, and `☐ Accepted ☐ Revision required`.

**Pinned §1/§2 values:**
- Attached code / file names: `src/fault4/*.py, tests/*.py, data/*.csv, configs/scenarios.json, outputs/results.json, outputs/run_log.txt, outputs/test_log.txt, outputs/figures/*.png, run_all.sh`.
- Main task completed: `Assignment 4 Parts A–E (incident classification, risk matrix, resilient architecture, recovery plan, AI anomaly analysis) plus a before/after attack simulation`.
- Tools / technologies used: `Python 3.9+, matplotlib 3.9.4, python-docx 1.1.2, pytest 8.3.5, Git/GitHub, LibreOffice (PDF export), macOS`.
- Main technical output produced: `Reproducible analysis pipeline (python -m fault4 all), results.json, 5 figures, 4-scenario simulation, this report`.

**Document order:**
1. Title block + the synthetic-data context note.
2. Part A table: Time / Event / Attack stage / Evidence / Risk, 10 rows. Evidence includes `(ATT&CK: …)`, and `Alternative reading: …` where one exists.
3. Part B table: Threat / Likelihood / Impact / Risk Score / Priority, 5 rows, with Priority as `Critical (#1)`. Then:
   - 3b. A *Risk justification* table: Threat / Likelihood rationale / Impact rationale / Sensitivity (L-1 / L / L+1), 5 rows, from `results['risk']`.
   - The L/I rule sentences.
   - The implementation-order paragraph.
4. Part C table: Threat / Preventive control / Detection control / Recovery control, 5 rows. Then:
   - 4b. A *Component inventory* table: Required component / Implementation / Zone / Role / Why this role, 9 rows.
   - `architecture.png`.
   - A control-flow paragraph that walks through arrows ①–⑦ in order. Each arrow names the dataset event it would have stopped or detected (e.g. "① MFA would have rejected the 09:04 login").
5. Part D table: Step / Action / Responsible component / Target time, 7 rows, using the `target_time` cells. Then:
   - "Sequential estimate 24 min, critical path 20 min, both ≤ RTO 30 min".
   - The data-loss calculation and clean-point rule.
   - `recovery_timeline.png`.
6. Part E table: Event / Normal score / Observed score / Delta / Anomaly (score ≥ 0.75), 5 rows. Then answers to Q1–Q4, `anomaly_scores.png`, and the threshold-sensitivity table.
7. Before/after simulation: assumptions list, a 4-scenario comparison table (columns = scenario labels; rows = the metric names from the pinned table, with null rendered as "unbounded" / "not achievable" and 0 recovery time as "no recovery needed"), and `attack_timeline.png`.
   - 7b. **Conclusion** (≤ 150 words, key numbers).
8. *STUDENT TECHNICAL WORK REPORT / SUBMISSION RECORD* §1 (8 rows) and §2 (5 rows).
9. §3, subsections 1–6, each a three-row table. Put `risk_matrix.png` in §3 subsection 2.
10. §4 individual record. §5 checklist, all ☒, each with a pointer. The "Final technical conclusion" item points to "Conclusion section (7b)".
11. §6 declaration and §7 instructor record.
12. **References and external sources:**
    - MITRE ATT&CK Enterprise (attack.mitre.org; the technique and tactic IDs used);
    - Law RK No. 94-V, Art. 12 (adilet URL);
    - NIST SP 800-61 (incident handling);
    - vendor docs for privacyIDEA, OPNsense, Wazuh, Suricata, MinIO Object Lock, OpenZFS, PostgreSQL continuous archiving / PITR, fapolicyd;
    - the assignment PDF (file name + SHA-256);
    - an AI-assistance statement: "Analysis code and draft text were prepared with the help of an AI coding assistant (Claude, Anthropic); the student reviewed, ran and verified all results." The student may edit this line.
13. Appendix: reproduce commands, `tool_version`, every SHA-256 in `data_sources`, commit.

**§3 content map** (≤ 120 words per cell, concrete and number-led):

| § | Evidence row must cite | Decision row |
|---|---|---|
| 3.1 | `src/fault4/incident.py`; `outputs/results.json → incident`; `attack_timeline.png`; metrics 36 / 3 / 6 / 17 | 09:15 classed as lateral movement (separate-DB assumption, alternative stated); 09:04 upgraded to Critical; 2 of 8 categories interpretive |
| 3.2 | L×I arithmetic for all 5 threats; `src/fault4/risk.py`; `risk_matrix.png`; sensitivity | The consistent L5/L4 rule; implementation order MFA + immutable backup first, which is separate from risk rank |
| 3.3 | `src/fault4/controls.py`, `coverage_gaps() == []`; 7/7 components; `architecture.png` | Snapshot-based failover, not live replication; segmentation is preventive by design and reused for containment |
| 3.4 | 1+1+4+3+8+5+2 = 24 ≤ 30; critical path 20; loss 3+1 = 4 ≤ 5; clean points 09:06/09:03 → 1/4 min; `recovery.py`; `recovery_timeline.png` | 3-min interval, because 5+1 = 6 would breach the RPO; fallback clean point because the attacker was present from 09:04 |
| 3.5 | 5/5 = 100%; deltas; sweep 5/4/3/2/1; `anomaly.py`; `anomaly_scores.png` | Prioritise by delta with the kill-chain stage (not ratio); keep 0.75 because at 0.80 exfiltration (margin 0.04) disappears |
| 3.6 | Tier comparison: vault worst-case loss 4 min (lost if the vault admin plane is compromised) vs Almaty copy 24 h (survives it); ~970 km; monthly drill; `offline_copy` in `controls.py` | An in-country second site instead of a foreign cloud, because of Law No. 94-V Art. 12 |

**§4 rows:**
- Unique decision: the 3-min snapshot / replication-lag reasoning plus the two-clean-point rule.
- Own evidence:
  - simulation: 1,200 → 320 files (−73.3%) with automated isolation;
  - manual isolation still recovers;
  - estimated recovery time 24 min;
  - worst-case loss 4 min.
- Exact reference: the spec PDF and data SHA-256 values, `tool_version`, commit, file paths.
- Problem: ratio and delta disagree on the top anomaly; resolved by delta plus kill-chain stage.
- Limitation:
  - a single synthetic incident with a non-adaptive deterministic replay;
  - the FIM threshold chosen knowing this incident (overfitting risk);
  - no false-positive rate measured;
  - Part D durations are estimates, not measured drills.

- [ ] **Step 1: Failing tests.** Imports: `import pytest`, `from docx import Document`, `from fault4.pipeline import run_analysis`, `from fault4.figures import render_all`, `from fault4.report_content import TEMPLATE_LABELS` and `from fault4.report_docx import build_report`.

```python
@pytest.fixture(scope="module")
def doc(tmp_path_factory):
    out = tmp_path_factory.mktemp("r")
    res = run_analysis(); figs = render_all(res, out / "fig")
    return Document(str(build_report(res, figs, out / "r.docx", commit="abc1234",
                                     work_period=("2026-10-31 10:43 (UTC+5, Astana)", "2026-10-31 18:00 (UTC+5, Astana)"))))
def full_text(d): return "\n".join([p.text for p in d.paragraphs] + [c.text for t in d.tables for r in t.rows for c in r.cells])
def heads(d): return {tuple(c.text for c in t.rows[0].cells): len(t.rows) for t in d.tables}
def test_student_fields(doc):
    t = full_text(doc)
    for s in ["Talgatov Aibyn","255308","CSE-2505M","Serek Azamat","https://github.com/a169n/fault_4","abc1234","synthetic","UTC+5"]:
        assert s in t
def test_template_labels_verbatim(doc):
    t = full_text(doc)
    assert [s for s in TEMPLATE_LABELS if s not in t] == []
def test_assignment_tables_present(doc):
    h = heads(doc)
    assert h[("Time","Event","Attack stage","Evidence","Risk")] == 11
    assert h[("Threat","Likelihood","Impact","Risk Score","Priority")] == 6
    assert h[("Threat","Likelihood rationale","Impact rationale","Sensitivity (L-1 / L / L+1)")] == 6
    assert h[("Threat","Preventive control","Detection control","Recovery control")] == 6
    assert h[("Required component","Implementation","Zone","Role","Why this role")] == 10
    assert h[("Step","Action","Responsible component","Target time")] == 8
    assert h[("Event","Normal score","Observed score","Delta","Anomaly (score ≥ 0.75)")] == 6
def test_risk_justifications_rendered(doc):
    t = full_text(doc)
    assert all(x["likelihood_reason"] in t for x in run_analysis()["risk"]["threats"])
def test_key_numbers_in_report(doc):
    t = full_text(doc)
    for s in ["24 min","20 min","4 min","100%","1,200","320","0.84","09:06","09:03","73.3%","by T+20"]: assert s in t
def test_references_present(doc):
    t = full_text(doc)
    assert "References" in t and "MITRE ATT&CK" in t and "94-V" in t
def test_report_has_no_placeholder_leaks(doc):
    t = full_text(doc)
    assert not any(x in t for x in ["{", "}", "TODO", "TBD"])
    assert not any(c.text.strip() in ("None", "null", "nan") for tb in doc.tables for r in tb.rows for c in r.cells)
def test_report_images_fit_page(doc):
    s = doc.sections[0]; text_w = s.page_width - s.left_margin - s.right_margin
    assert len(doc.inline_shapes) == 5 and all(sh.width <= text_w for sh in doc.inline_shapes)
```

- [ ] **Step 2:** Run. Expect FAIL. **Step 3:** Implement and wire up `python -m fault4 report` / `all`. The commit comes from `git_commit()`. **Step 4:** Run. Expect PASS.
- [ ] **Step 5:** Commit: `feat: generate completed submission report (.docx)`.

### Task 11: One-command run, README, Python 3.9 verification, publish

**Files:** Create `run_all.sh` (chmod +x) and `README.md`. Regenerate `outputs/` and `report/`.

- [ ] **Step 1: `run_all.sh`** (POSIX `sh`):
  - `set -e`, then `cd "$(dirname "$0")"`, then `PY=python3; [ -x .venv/bin/python ] && PY=.venv/bin/python`.
  - Run `PYTHONPATH=src "$PY" -m pytest -q > outputs/test_log.txt 2>&1`. On failure, print the log and exit 1; otherwise print it.
  - `PYTHONPATH=src "$PY" -m fault4 all "$@"`.
  - Then, only if `soffice` is on PATH, `soffice --headless --convert-to pdf --outdir report report/Assignment4_Talgatov_Aibyn.docx`. Otherwise print "PDF export skipped: open the .docx in Word/Pages and Export as PDF".
- [ ] **Step 2: `README.md`.** It contains:
  - purpose and the synthetic-data note;
  - macOS quick start: `python3 -m venv .venv`, `.venv/bin/pip install -r requirements.txt`, `./run_all.sh`;
  - a table mapping assignment Part → module → output;
  - the key results table (four scenarios);
  - data provenance (SHA-256 values);
  - **Oral-defence cheat sheet:**
    - one line per component: the `why` column, including "Recovery column holds Respond: and Recover: actions because the template has no Respond column";
    - one line per contested classification (09:01, 09:08, 09:15, 09:18), with its alternative reading and why the chosen stage holds.
  - **Before submission (student):**
    1. On the Mac, run `./run_all.sh`, save a terminal screenshot to `outputs/screenshots/macos_run.png` and commit it.
    2. Fill the variant code (if one is assigned), the submission date and your signature in the .docx.
    3. Re-export the PDF.
    4. Review and personalise the §4 wording and the AI-assistance line in your own words.
- [ ] **Step 3: Python 3.9 verification (macOS parity).** Run:

  ```bash
  S=<scratchpad absolute path>; cd /home/user/fault_4
  uv venv --python 3.9 "$S/venv39" && uv pip install --python "$S/venv39/bin/python" -r requirements.txt
  PYTHONPATH=src "$S/venv39/bin/python" -m pytest -q
  PYTHONPATH=src "$S/venv39/bin/python" -m fault4 analyze --out "$S/o39"
  PYTHONPATH=src .venv/bin/python -m fault4 analyze --out "$S/o3x"
  diff "$S/o39/results.json" "$S/o3x/results.json"
  ```

  Expect all tests to pass and the diff to print nothing.
- [ ] **Step 4: Commit code first.** Commit `run_all.sh` and `README.md` (`docs: one-command build and README`). Check that `git status --porcelain` lists nothing outside `outputs/` and `report/`, and that `git describe --always --dirty` does not end in `-dirty`.
- [ ] **Step 5: Build and inspect.** Run `./run_all.sh`, then `pdftoppm -png -r 60 report/Assignment4_Talgatov_Aibyn.pdf "$S/page"`. Read every page image. Check:
  - tables are not cut off;
  - figures are visible;
  - the only blanks are the intended ones (variant code, submission date, signatures, §7).

  If a code fix is needed, commit it and repeat Step 5, so that the commit cited in the report always contains the code that produced it.
- [ ] **Step 6:** Commit `outputs/` and `report/`: `docs: final evidence and submission report`. Then run `git push -u origin claude/keen-rubin-w9hhpm`.
