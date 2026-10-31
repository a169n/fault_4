# Assignment 4 — Security, Resilience, and Intrusion Tolerance

Astana IT University · Fault Tolerance · 2026–2027
Student: **Talgatov Aibyn** (255308, CSE-2505M) · Instructor: Serek Azamat

> All data are **synthetic educational data**. They represent a realistic Kazakhstan/Astana university context and
> do not describe actual AITU infrastructure, incidents, or internal systems.

This repository analyses a synthetic ransomware-style incident on `Research-Server-01`, designs resilient controls, and
evaluates recovery. Everything in the report is computed by code, so it can be reproduced and checked:

- **Deliverable:** `report/Assignment4_Talgatov_Aibyn.docx` (and `.pdf`)
- **Evidence:** `outputs/results.json`, `outputs/run_log.txt`, `outputs/test_log.txt`, `outputs/figures/*.png`
- **Spec:** `docs/assignment/Assignment_4_AITU_Security_Resilience_Report_Template.pdf`

## Quick start (macOS)

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
./run_all.sh
```

`run_all.sh` does the following:
1. Runs the tests and writes `outputs/test_log.txt`.
2. Runs the analysis, figures and report steps.
3. Exports the PDF if LibreOffice is installed. Otherwise, open the .docx in Word or Pages and choose *Export as PDF*.

It works with the macOS system Python 3.9 or newer.

Single steps:

```bash
.venv/bin/python -m pytest -q
PYTHONPATH=src .venv/bin/python -m fault4 analyze            # results.json + run_log.txt
PYTHONPATH=src .venv/bin/python -m fault4 figures            # outputs/figures/*.png
PYTHONPATH=src .venv/bin/python -m fault4 report --submission-date 2026-11-07
```

## Where each part lives

| Assignment part | Code | Output |
|---|---|---|
| A — Incident analysis | `src/fault4/incident.py` | Part A table, `attack_timeline.png` |
| B — Risk matrix | `src/fault4/risk.py` | Part B tables, `risk_matrix.png` |
| C — Resilient architecture | `src/fault4/controls.py` | Part C tables, `architecture.png` |
| D — Recovery plan | `src/fault4/recovery.py` | Part D table, `recovery_timeline.png` |
| E — AI-assisted detection | `src/fault4/anomaly.py` | Part E table, `anomaly_scores.png` |
| Before/after comparison | `src/fault4/simulation.py`, `configs/scenarios.json` | simulation table |
| Pipeline / report | `src/fault4/pipeline.py`, `report_content.py`, `report_docx.py` | `results.json`, `.docx` |

## Key results

**Incident**
- 36 failed logins, then compromise at 09:04.
- 1,200 files encrypted by 09:10.
- 17 minutes from first contact to disabled antivirus, with no automated response.

**Risk ranking**
1. Ransomware 5×5 = 25
2. Backup destruction 4×5 = 20
3. Credential compromise 5×4 = 20
4. Data exfiltration 4×4 = 16
5. Privilege escalation 4×4 = 16

**Recovery**
- Estimated recovery time: 24 min sequential, 20 min on the critical path. Both meet the 30-minute RTO.
- Worst-case data loss: 3 + 1 = 4 min, within the 5-minute RPO.

**AI detection**
- 5/5 signals ≥ 0.75, a rate of 100%.
- Highest priority: file modifications (0.96, Δ 0.84).

| Scenario | Access | Stopped at | Files impacted | Backups lost | Data loss | Recovery |
|---|---|---|---|---|---|---|
| Baseline (as-is) | yes | never | 1,200 | yes | unbounded | not achievable |
| Hardened | no | 09:01 | 0 | no | none | no recovery needed |
| Assume breach, automated isolation | yes | 09:09 | 320 (−73.3%) | no | 1 min (fallback 4) | 24 min |
| Assume breach, manual isolation | yes | 09:11 | 1,200 | no | 1 min (fallback 4) | 24 min |

## Data provenance (SHA-256)

| File | SHA-256 |
|---|---|
| `Assignment_4_AITU_Security_Resilience_Report_Template.pdf` | `a1c8c43e799a9f2f31d9b5200f772ab99b37054ad648dbaa6d4770475675e35a` |
| `data/incident_events.csv` | `b4b3b59765035a9fd853bc643ded10d73fa8a3284bb49c4e34ccad0842d2ed91` |
| `data/anomaly_scores.csv` | `d50d601682cda1f6bd3ef5381520f215989eea1b3f14402f44bb85f42d272a0d` |
| `configs/scenarios.json` | `65637ad3a1ba280d3316c94c054c59a757c1a5dd610aba59947064ceeefacd30` |

## Oral-defence cheat sheet

**Why each control has its role**

| Component | Role | Why |
|---|---|---|
| MFA (privacyIDEA, FIDO2) | preventive | A guessed password does not become a session; it would have blocked the 09:04 login. |
| Segmentation (OPNsense) | preventive | By design, 10.20.4.15 reaches RS-01 only through the bastion, and unknown egress (09:13) is denied. Its quarantine VLAN is reused for containment. |
| PAM (just-in-time sudo) | preventive | Backup deletion (09:12) and AV disable (09:18) need a just-in-time approval the attacker does not have. |
| Monitoring (Wazuh, Prometheus) | detective | Raises the 09:01 and 09:07 alerts and triggers responses, but blocks nothing itself. |
| IDS (Suricata, FIM, canary, AI) | detective | Detects the encryption (09:07) and the unknown outbound connection (09:13). |
| Immutable backup (Object Lock) | recovery | Does not stop encryption; guarantees an untouchable clean restore point. |
| RS-02 warm standby | recovery | Restores service on clean infrastructure and never receives live-replicated, already-encrypted data. |
| Clean-room recovery environment | recovery | Restored data is verified in isolation before going back to production. |
| Offline copy in Almaty | recovery | Last resort if the vault's admin plane or the Astana site is lost. |

The template has no "Respond" column, so containment actions sit in the Recovery column, marked `Respond:`. Restoration
actions are marked `Recover:`.

**Contested classifications**

| Event | Chosen stage | Alternative | Why the choice holds |
|---|---|---|---|
| 09:01 | reconnaissance | credential attack | First burst from a new source, probing usernames and lockout behaviour (ATT&CK T1589). |
| 09:08 | data destruction | resource hijacking (T1496) | 95% CPU sits between 320 modified and 1,200 encrypted files, so it is the encryption workload. CPU alone is not specific. |
| 09:15 | lateral movement | exfiltration | The compromised server is used as a pivot into the research DB (assuming a separate DB host). |
| 09:18 | persistence | defense evasion | The spec has no defense-evasion stage. Disabling AV protects the attacker's foothold. |

**Numbers to remember**
- 3-min snapshots + 1-min lag = 4 min of data loss; 5 + 1 = 6 would breach the RPO.
- Clean points: 09:06 (verified) or 09:03 (before attacker access).
- Recovery steps: 1+1+4+3+8+5+2 = 24 min.

## Before submission (student)

1. On the Mac, run `./run_all.sh`, save a terminal screenshot to `outputs/screenshots/macos_run.png`, and commit it.
2. Fill in the variant code (if one is assigned), the submission date and your signature in the .docx. Then export the PDF again.
3. Re-read the §4 "Individual Work" answers and the AI-assistance line in References, and put them in your own words.
