"""All report text. Key numbers are taken from the results dict; the prose explains them."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

STUDENT = {
    "name": "Talgatov Aibyn",
    "student_id": "255308",
    "group": "CSE-2505M",
    "instructor": "Serek Azamat",
    "repository": "https://github.com/a169n/fault_4",
    "variant_blank": "______________________",
    "date_blank": "____ / ____ / ______",
}

TITLE = "Assignment 4 — Security, Resilience, and Intrusion Tolerance"
SUBTITLE = "Synthetic Kazakhstan University Research Server Incident"
CONTEXT_NOTE = (
    "Context note: All operational data in this assignment are synthetic educational data. They are designed to "
    "represent a realistic Kazakhstan/Astana university context and do not describe actual AITU infrastructure, "
    "incidents, or internal systems."
)

PART_INTROS = {
    "A": "Classify each event as reconnaissance, credential attack, privilege compromise, lateral movement, data "
         "destruction, persistence, exfiltration, or recovery attack.",
    "B": "Risk = Likelihood × Impact. Use 1–4 Low, 5–9 Medium, 10–16 High, 17–25 Critical.",
    "C": "Design a synthetic architecture containing MFA, network segmentation, immutable backup, monitoring, "
         "intrusion detection, secure failover, and a recovery environment.",
    "D": "Requirements: RPO ≤ 5 minutes; RTO ≤ 30 minutes.",
}
PART_E_QUESTIONS = (
    "Calculate the number and rate of detected anomalies.",
    "Identify the highest-priority event.",
    "Explain why AI-assisted detection should complement, not replace, deterministic security and recovery controls.",
    "Recommend one additional resilience mechanism appropriate for a Kazakhstan university research environment.",
)

FORM_TITLE = "STUDENT TECHNICAL WORK REPORT / SUBMISSION RECORD"
FORM_PURPOSE = (
    "Purpose: This form is a formal submission record. The student must complete every applicable field and attach "
    "evidence of their own work. Short generic explanations are not sufficient."
)
SECTION3_INTRO = (
    "For each section below, write the requested evidence in your own words. Include calculations, diagrams, code "
    "references, screenshots, logs, or experimental evidence where applicable."
)
SECTION3 = (
    ("incident", "1. Incident Analysis",
     "Classify every incident event into an attack stage, provide evidence from the synthetic dataset, and assess risk."),
    ("risk", "2. Risk Matrix",
     "Assign likelihood and impact, calculate Risk = Likelihood × Impact, and justify the resulting priority."),
    ("architecture", "3. Resilient Security Architecture",
     "Design the required architecture containing MFA, segmentation, immutable backup, monitoring, intrusion "
     "detection, secure failover, and recovery environment."),
    ("recovery", "4. Recovery Plan",
     "Complete the seven-step recovery plan and show how your target RPO ≤ 5 minutes and RTO ≤ 30 minutes are "
     "addressed."),
    ("ai", "5. AI-Assisted Detection",
     "Calculate the anomaly count/rate, identify the highest-priority event, and explain the role and limitations of "
     "AI-assisted detection."),
    ("additional", "6. Additional Resilience Recommendation",
     "Recommend one additional resilience mechanism appropriate for the synthetic Kazakhstan university research "
     "environment and justify it."),
)
SECTION3_ROWS = ("Summary", "Evidence / calculation / artifact reference", "Student-specific decision or observation")

SECTION4_TITLE = "4. Individual Work and Anti-Plagiarism Record"
SECTION4_INTRO = (
    "Because the assignment uses a common educational scenario and dataset, the submitted report must contain "
    "verifiable evidence of the individual student's work. Copying another student's wording, calculations, "
    "architecture, code, logs, screenshots, or conclusions is not acceptable."
)
SECTION4_BULLETS = (
    "Use your own threat/control mapping rather than copying another student's table wording.",
    "Tie each risk score to your own justification.",
    "Provide a unique architecture diagram and explain its control flow.",
    "Record the exact source file/version used for your analysis.",
    "Be prepared to defend why one control is preventive, detective, or recovery-oriented.",
)
SECTION4_ROWS = (
    "My unique technical decision",
    "My own implementation / calculation evidence",
    "Exact file, code, commit, notebook, or log reference",
    "One problem I personally encountered and how I solved it",
    "One limitation of my own solution",
)
CHECKLIST_ITEMS = (
    "Completed required tables and calculations",
    "Architecture / RBD / FTA / security diagram where applicable",
    "Source code or configuration files where applicable",
    "Execution logs / experiment results where applicable",
    "Screenshots or other reproducible evidence where applicable",
    "Links to code, datasets, notebooks, or artifacts",
    "Before/after comparison where applicable",
    "Final technical conclusion",
)
DECLARATION = (
    "I confirm that this report describes my own work. I have not copied another student's report, code, "
    "calculations, diagrams, logs, screenshots, or conclusions. Any external source or reused material has been "
    "identified. I understand that I may be asked to reproduce or explain any part of this submission during the "
    "oral defense."
)
INSTRUCTOR_CHECKS = (
    "Report structure completed",
    "Evidence is sufficient",
    "Individual contribution is identifiable",
    "Oral defense completed",
)

TEMPLATE_LABELS: Tuple[str, ...] = (
    # Section 1
    "1. Student and Submission Information", "Required field", "Student entry", "Student full name", "Student ID",
    "Group / cohort", "Instructor", "Date of submission", "Individual variant / task code assigned by instructor",
    "Git repository / project link", "Attached code / file names",
    # Section 2
    "2. Work Period and Task Record", "Item", "Work start date/time", "Work completion date/time",
    "Main task completed", "Tools / technologies used", "Main technical output produced",
    # Section 3
    "3. Report Structure to Complete", SECTION3_INTRO, "Required content", "Student response / evidence",
) + tuple(title for _, title, _ in SECTION3) + tuple(text for _, _, text in SECTION3) + SECTION3_ROWS + (
    # Section 4
    SECTION4_TITLE, SECTION4_INTRO, "Individual evidence",
) + SECTION4_BULLETS + SECTION4_ROWS + (
    # Section 5-7
    "5. Evidence Checklist",
) + CHECKLIST_ITEMS + (
    "6. Student Declaration", DECLARATION, "Role", "Name", "Signature", "Date", "Student / Executor",
    "Instructor / Accepted by", "7. Instructor Acceptance Record", "Check", "Status / comment",
) + INSTRUCTOR_CHECKS + ("Final status", "☐ Accepted ☐ Revision required", FORM_TITLE, FORM_PURPOSE)

SECTION2_VALUES = {
    "Main task completed": "Assignment 4 Parts A–E (incident classification, risk matrix, resilient architecture, "
                           "recovery plan, AI anomaly analysis) plus a before/after attack simulation",
    "Tools / technologies used": "Python 3.9+, matplotlib 3.9.4, python-docx 1.1.2, pytest 8.3.5, Git/GitHub, "
                                 "LibreOffice (PDF export), macOS",
    "Main technical output produced": "Reproducible analysis pipeline (python -m fault4 all), results.json, 5 figures, "
                                      "4-scenario simulation, this report",
}
ATTACHED_FILES = (
    "src/fault4/*.py, tests/*.py, data/*.csv, configs/scenarios.json, outputs/results.json, outputs/run_log.txt, "
    "outputs/test_log.txt, outputs/figures/*.png, run_all.sh"
)

# Numbered control flow shown in Figure 1 and walked through in Part C.
ARCHITECTURE_FLOW = (
    ("Access", "attacker host → boundary → SSH bastion. SSH reaches only the bastion, where MFA rejects the guessed "
               "password (red ✕, the 09:04 login); authorised users continue from the bastion to RS-01."),
    ("Backup", "RS-01 and the database → vault. The vault initiates the pulls (snapshots every 3 min, WAL "
               "continuously), so RS-01 holds no credential the 09:12 deletion attempt could use."),
    ("Telemetry", "bastion → SIEM and RS-01 (FIM, canary files) → IDS → SIEM. The failed logins raise the 09:01 alert "
                  "and the mass file change raises the 09:07 alert."),
    ("Response", "SIEM → enforcement points. Wazuh active response asks the hypervisor to pause RS-01 and re-tag its "
                 "vNIC into the quarantine VLAN, and OPNsense applies a deny rule (isolated by 09:09)."),
    ("Egress control", "RS-01 → Internet. The connection to the unknown IP is denied at the boundary (red ✕, the 09:13 "
                       "channel fails)."),
    ("Restore", "vault → clean room → RS-02. Data from the clean point is restored and verified in the isolated clean "
                "room, then RS-02 is promoted into the research VLAN (24 min estimate, 20 min on the critical path)."),
    ("Last-resort copy", "vault → Almaty. A daily transfer window copies the vault to the offline site (24 h tier)."),
)

FIGURE1_INTRO = (
    "Figure 1 reads from left to right: the networks outside the perimeter, the segmentation boundary (blue bar), the "
    "production zones, the protection and recovery zones, and the second site. Box colour shows the control role: blue = "
    "preventive, orange = detective, green = recovery, grey = protected asset or external system. Lines: solid = access "
    "or data path (the arrowhead shows the direction of data), dotted = telemetry, orange = automated response, dashed "
    "= scheduled offline transfer, red ✕ = path blocked by a control. Numbers (1)–(7) mark the control flow."
)
FIGURE1_ZONES = (
    ("User VLAN 10.20.4.0/24", "the campus network the attack came from (attacker host 10.20.4.15); it has no direct "
                               "route to the research servers."),
    ("Internet", "the destination of the 09:13 outbound connection, reachable only through the egress allow-list."),
    ("Segmentation boundary", "OPNsense firewall and VLAN switching: default-deny between zones, egress allow-list, "
                              "quarantine VLAN. Every arrow crossing it is an explicitly allowed or blocked path."),
    ("Access zone", "the SSH bastion and VPN with MFA, the only way into the research zone, and privileged access "
                    "management (just-in-time sudo, tamper protection)."),
    ("Research zone", "RS-01 with its canary files and FIM agent, running as a VM on the hypervisor that performs "
                      "containment."),
    ("Data zone", "the PostgreSQL research database, whose WAL the vault pulls continuously."),
    ("Security zone", "the IDS (Suricata, FIM and canary rules, AI anomaly scorer) feeding the SIEM (Wazuh, "
                      "Prometheus/Grafana), which correlates alerts and triggers the automated response."),
    ("Backup vault", "pull-only: tier 1 holds ZFS snapshots of RS-01 every 3 min (zfs hold), tier 2 restic copies every "
                     "15 min under Object Lock; production holds no vault credentials."),
    ("Recovery zone", "an isolated VLAN without internet: the clean room where restored data is scanned and verified, "
                      "and the RS-02 warm standby, promoted into the research VLAN only after verification."),
    ("Second site (Almaty)", "the offline copy, refreshed in a daily transfer window opened from the Almaty side."),
)
ROLE_NOTE = (
    "A role is relative to the threat: Object Lock is preventive against backup deletion, while the backup as a whole "
    "is a recovery control against ransomware. Monitoring detects and orchestrates; the enforcement points "
    "(hypervisor, firewall, identity provider) carry out the response, which the template's three columns list under "
    "recovery as “Respond:”."
)
SATISFIES_LABEL = {
    "supporting": "Supporting (not one of the 7 required)",
    "Additional": "Additional (Part E Q4, section 6)",
}

FIGURE_CAPTIONS = {
    "architecture.png": "Figure 1. Resilient architecture and its numbered control flow (1)–(7).",
    "recovery_timeline.png": "Figure 2. Recovery schedule against the 30-minute RTO.",
    "anomaly_scores.png": "Figure 3. Normal vs observed AI anomaly scores with the 0.75 threshold.",
    "attack_timeline.png": "Figure 4. Attack timeline with simulated containment times.",
    "risk_matrix.png": "Figure 5. Risk matrix (Risk = Likelihood × Impact).",
}


# ------------------------------------------------------------------------------------------------- helpers

def _sim(results: Dict[str, Any], name: str) -> Dict[str, Any]:
    return next(r for r in results["simulation"] if r["scenario"] == name)


def reduction_percent(results: Dict[str, Any]) -> str:
    base = _sim(results, "baseline")["files_impacted"]
    contained = _sim(results, "hardened_assume_breach")["files_impacted"]
    return f"{(base - contained) / base * 100:.1f}%"


def _threat(results: Dict[str, Any], name: str) -> Dict[str, Any]:
    return next(t for t in results["risk"]["threats"] if t["threat"] == name)


def _signal(results: Dict[str, Any], name: str) -> Dict[str, Any]:
    return next(s for s in results["anomaly"]["signals"] if s["name"] == name)


def _durations(results: Dict[str, Any]) -> str:
    return "+".join(str(s["duration_min"]) for s in results["recovery"]["steps"])


# ------------------------------------------------------------------------------------------------- Part E answers

def part_e_answers(results: Dict[str, Any]) -> List[str]:
    summary = results["anomaly"]["summary"]
    top = _signal(results, summary["highest_priority"])
    outbound = _signal(results, "Outbound traffic")
    return [
        f"{summary['count']} of {summary['total']} signals score at or above {results['anomaly']['threshold']:.2f}, "
        f"so {summary['count']} anomalies are detected and the detection rate is {summary['count']}/{summary['total']} "
        f"= {summary['rate']:.0%}.",
        f"{top['name']}: observed {top['observed']:.2f} against a normal {top['normal']:.2f} (Δ {top['delta']:.2f}), "
        "the highest score and the largest deviation. It marks the start of data destruction at 09:07, so it is the "
        "signal that should trigger isolation.",
        "AI scores are probabilistic: they produce false positives and false negatives, and outbound traffic clears the "
        f"threshold by only {outbound['margin']:.2f}, so a threshold of 0.80 would miss the exfiltration channel. "
        "Research servers legitimately run at 95% CPU during simulations, so the CPU signal alone has low specificity. "
        "The model only detects: it cannot stop the backup deletion or restore data. The attacker disabled antivirus at "
        "09:18, and an AI agent on the same host can be tampered with the same way. Baselines drift with semester and "
        "exam load. Deterministic controls (MFA, Object Lock, egress default-deny) work even when detection fails and "
        "are auditable, so AI should prioritise and correlate alerts on top of them.",
        "An offline, logically air-gapped copy of the backup vault at a second Kazakhstan site (Almaty, ~970 km from "
        "Astana), refreshed in a daily transfer window and checked by a monthly restore drill (see section 6).",
    ]


# ------------------------------------------------------------------------------------------------- section 3

def section_texts(results: Dict[str, Any]) -> Dict[str, Dict[str, str]]:
    m = results["incident"]["metrics"]
    check = results["recovery"]["check"]
    points = results["recovery"]["clean_points"]
    interval = results["recovery"]["snapshot_interval_min"]
    lag = results["recovery"]["replication_lag_min"]
    summary = results["anomaly"]["summary"]
    top = _signal(results, summary["highest_priority"])
    outbound = _signal(results, "Outbound traffic")
    sweep = "/".join(str(d["count"]) for d in results["anomaly"]["threshold_sensitivity"])
    deltas = ", ".join(f"{s['name']} {s['delta']:.2f}" for s in results["anomaly"]["signals"])
    arithmetic = "; ".join(
        f"{t['threat']} {t['likelihood']} × {t['impact']} = {t['score']} ({t['level']})"
        for t in sorted(results["risk"]["threats"], key=lambda t: t["rank"])
    )
    ransomware = _threat(results, "Ransomware")
    return {
        "incident": {
            "summary": (
                f"All 10 events are classified. The attack moves from probing at 09:01 through "
                f"{m['failed_logins_total']} failed logins to a successful login at 09:04, encryption of 1,200 files by "
                "09:10, a backup deletion attempt (09:12), an outbound channel (09:13), database access (09:15) and "
                f"disabling of antivirus (09:18). The intrusion lasted {m['attack_duration_minutes']} minutes and nothing "
                "reacted automatically: antivirus was running during the encryption and did not stop it."
            ),
            "evidence": (
                "Part A table; code src/fault4/incident.py (classify_events, attack_metrics); outputs/results.json → "
                f"incident; Figure 4. Metrics: {m['failed_logins_total']} failed logins, compromise after "
                f"{m['minutes_to_compromise']} min, encryption {m['minutes_compromise_to_encryption']} min after "
                f"compromise, {m['attack_duration_minutes']} min in total. Every row cites the dataset value and an "
                "ATT&CK reference."
            ),
            "decision": (
                "09:15 is classed as lateral movement rather than exfiltration: the spike shows the compromised server "
                "used as a pivot into the research database, which I assume runs on a separate host. 09:04 is raised "
                "from High to Critical because every later event depends on that login. Four classifications are "
                "interpretive (09:01, 09:08, 09:15, 09:18); each states its alternative reading in the Part A table."
            ),
        },
        "risk": {
            "summary": (
                f"Ransomware ranks first ({ransomware['likelihood']} × {ransomware['impact']} = {ransomware['score']}), "
                "followed by backup destruction and credential compromise (both 20, Critical); data exfiltration and "
                "privilege escalation score 16 (High). Ties are broken by impact, then template order."
            ),
            "evidence": (
                f"{arithmetic}. Code src/fault4/risk.py; Figure 5. Sensitivity (likelihood ±1): only ransomware stays "
                "Critical at L−1; data exfiltration and privilege escalation become Critical at L+1."
            ),
            "decision": (
                "One likelihood rule for every threat: 5 = observed and succeeded, 4 = attempted or indirectly evidenced. "
                "Implementation order is separate from risk rank: MFA first because it removes the root cause, then "
                "immutable backup because it is the only control that still guarantees recovery when prevention fails."
            ),
        },
        "architecture": {
            "summary": (
                "The research server sits behind an OPNsense firewall with separate access, research, data, security, "
                "backup and recovery zones. All seven required components are present (MFA, segmentation, immutable "
                "backup, monitoring, intrusion detection, secure failover to RS-02, isolated recovery environment), plus "
                "an offline copy in Almaty."
            ),
            "evidence": (
                "Part C table and component inventory; Figure 1 with control flow (1)–(7); src/fault4/controls.py, "
                "where coverage_gaps() returns an empty list: every required component exists, every threat has "
                "preventive, detective and recovery controls, and every component is used."
            ),
            "decision": (
                "Failover is snapshot-based, not live replication: live replication would have copied the 1,200 "
                "encrypted files to the standby. RS-02 waits in the isolated recovery VLAN, out of the attacker's reach, "
                "and is moved into the research VLAN only after verification. Containment is done by the hypervisor "
                "(quarantine VLAN), not the firewall, and is marked “Respond:” in the recovery column."
            ),
        },
        "recovery": {
            "summary": (
                f"Seven steps timed from the first malicious change (T = 09:07): {_durations(results)} = "
                f"{check['recovery_time_sequential']} min sequentially, {check['recovery_time_critical_path']} min on the "
                "critical path 1→2→4→5→6→7 (evidence preservation runs alongside steps 4–5, because restoring onto RS-02 "
                f"does not touch RS-01); both meet the {check['rto_target']}-minute RTO. Worst-case data loss is "
                f"{interval} + {lag} = {check['worst_case_data_loss']} min, within the {check['rpo_target']}-minute RPO."
            ),
            "evidence": (
                f"Part D table; src/fault4/recovery.py (recovery_check); Figure 2. Snapshots every {interval} min aligned "
                f"to 09:00 with {lag} min replication lag. Clean points: {points['preferred']} (last snapshot before "
                f"09:07) loses 1 min; fallback {points['fallback']} (before attacker access at 09:04) loses 4 min."
            ),
            "decision": (
                f"I chose a {interval}-minute interval because 5 + {lag} = 6 minutes of loss would breach the RPO once "
                "the replication lag is counted. The clean point is chosen in step 4, before the restore: the attacker "
                f"was present from 09:04, so {points['preferred']} is used only if its diff against {points['fallback']} "
                "is clean. Deciding first keeps both choices inside the RTO."
            ),
        },
        "ai": {
            "summary": (
                f"All signals are at or above {results['anomaly']['threshold']:.2f}: {summary['count']}/{summary['total']} "
                f"= {summary['rate']:.0%}. {top['name']} is the highest-priority event ({top['observed']:.2f}, "
                f"Δ {top['delta']:.2f}) and coincides with the data-destruction stage. AI scoring complements, but cannot "
                "replace, deterministic controls."
            ),
            "evidence": (
                f"Deltas: {deltas}. Threshold sweep 0.75/0.80/0.85/0.90/0.95 → {sweep} anomalies. Code "
                "src/fault4/anomaly.py; Figure 3."
            ),
            "decision": (
                f"Rank by absolute deviation plus kill-chain stage, not ratio: the ratio would pick "
                f"{summary['highest_by_ratio'].lower()} (8.10× vs 8.00×) only because its baseline is small. Keep the "
                f"threshold at 0.75: at 0.80 outbound traffic ({outbound['observed']:.2f}, margin "
                f"{outbound['margin']:.2f}), the exfiltration indicator, would be missed."
            ),
        },
        "additional": {
            "summary": (
                "Recommended mechanism: an offline, logically air-gapped copy of the backup vault at a second Kazakhstan "
                "site (Almaty), refreshed in a daily transfer window opened from the Almaty side, with monthly rotation to "
                "disconnected media and a monthly restore drill."
            ),
            "evidence": (
                f"Tier comparison: vault tier 1 (ZFS, {check['worst_case_data_loss']} min worst-case loss) and tier 2 "
                "(Object Lock, 15 min) share the Astana site and the vault's admin domain; the Almaty copy (~970 km "
                "away) is a 24 h tier that survives compromise of the vault's admin plane or loss of the site. Modelled "
                "as offline_copy in src/fault4/controls.py and flow (7) in Figure 1."
            ),
            "decision": (
                "An in-country second site instead of a foreign cloud: Law of the Republic of Kazakhstan No. 94-V "
                "“On Personal Data and Their Protection”, Article 12, requires databases with personal data to be kept on "
                "the territory of Kazakhstan, and research datasets may contain participants' personal data."
            ),
        },
    }


# ------------------------------------------------------------------------------------------------- section 4-5

def individual_record(results: Dict[str, Any], commit: Optional[str]) -> List[Tuple[str, str]]:
    check = results["recovery"]["check"]
    sources = results["data_sources"]
    pdf_name = next(name for name in sources if name.endswith(".pdf"))
    return [
        (SECTION4_ROWS[0],
         f"{results['recovery']['snapshot_interval_min']}-minute immutable snapshots chosen by counting the "
         f"{results['recovery']['replication_lag_min']}-minute replication lag (3 + 1 = 4 ≤ 5, while 5 + 1 = 6 would "
         "breach the RPO), a two-clean-point rule decided before the restore (09:06 if its diff against 09:03 is "
         "clean, otherwise 09:03, before attacker access), and a standby kept in the isolated recovery VLAN instead of "
         "a live replica."),
        (SECTION4_ROWS[1],
         "Python package fault4 with an automated pytest suite (outputs/test_log.txt). Four-scenario replay: the "
         "baseline loses 1,200 files and the backups; the hardened design stops the attack at 09:01; with the access "
         f"layer bypassed, automated isolation limits damage to 320 files ({reduction_percent(results)} fewer); manual "
         "isolation loses 1,200 files but still recovers, 2 min later. Estimated recovery time "
         f"{check['recovery_time_sequential']} "
         f"min (critical path {check['recovery_time_critical_path']} min), worst-case data loss "
         f"{check['worst_case_data_loss']} min."),
        (SECTION4_ROWS[2],
         f"{STUDENT['repository']}: code at commit {commit or 'see git log'} (outputs and this report are committed "
         f"in the next commit on main); fault4 v{results['tool_version']}. Dataset "
         f"transcribed from {pdf_name} (SHA-256 {sources[pdf_name][:16]}…): incident table p.1, Part E table p.2, into "
         f"data/incident_events.csv (SHA-256 {sources['incident_events.csv'][:16]}…) and data/anomaly_scores.csv "
         f"(SHA-256 {sources['anomaly_scores.csv'][:16]}…). Outputs: outputs/results.json, outputs/run_log.txt."),
        (SECTION4_ROWS[3],
         "The ratio and the absolute deviation disagreed on the top anomaly (login failures 8.10× vs file modifications "
         "Δ 0.84). I ranked on the deviation plus the kill-chain stage, because ratios inflate signals with a small "
         "baseline, and reported both in Part E."),
        (SECTION4_ROWS[4],
         "One synthetic incident replayed deterministically by a non-adaptive attacker; the FIM threshold "
         "(100 changes/min) was chosen knowing this incident, so it may overfit; no false-positive rate was measured; "
         "recovery-step durations are estimates, not measured drills; the 4-min data-loss bound holds for the "
         "preferred clean point, while the fallback's loss grows with the attacker's dwell time before the first "
         "malicious change (here 3 min)."),
    ]


def evidence_checklist() -> List[Tuple[str, str]]:
    pointers = (
        "Parts A–E tables; outputs/results.json",
        "outputs/figures/architecture.png (Figure 1)",
        "src/fault4/*.py, configs/scenarios.json",
        "outputs/run_log.txt, outputs/test_log.txt",
        "./run_all.sh reproduces outputs/results.json byte-identically (SHA-256 values in the Appendix); "
        "outputs/figures/*.png",
        f"{STUDENT['repository']}; data/*.csv",
        "Before/after simulation section (4 scenarios)",
        "Conclusion section",
    )
    return list(zip(CHECKLIST_ITEMS, pointers))


def conclusion(results: Dict[str, Any]) -> str:
    m = results["incident"]["metrics"]
    check = results["recovery"]["check"]
    summary = results["anomaly"]["summary"]
    outbound = _signal(results, "Outbound traffic")
    breach = _sim(results, "hardened_assume_breach")
    return (
        f"The synthetic incident went from first contact to disabled antivirus in {m['attack_duration_minutes']} minutes "
        "with no automated response, encrypting 1,200 files and attacking the backups. The proposed architecture answers "
        "each stage with a preventive, a detective and a recovery control. In the replay, the lockout's source block "
        "stops the attack at 09:01 (MFA would also reject the 09:04 login); if the access layer is bypassed, automated "
        f"isolation at {breach['stopped_at']} limits the damage to "
        f"{breach['files_impacted']} files ({reduction_percent(results)} fewer), immutable backups survive the 09:12 "
        "deletion attempt and egress filtering blocks the 09:13 channel. Recovery is estimated at "
        f"{check['recovery_time_sequential']} min ({check['recovery_time_critical_path']} min on the critical path) "
        f"against a {check['rto_target']}-minute RTO, with at most {check['worst_case_data_loss']} min of data loss "
        f"against a {check['rpo_target']}-minute RPO. AI scoring flags all signals ({summary['rate']:.0%}) and ranks "
        f"file modifications first, but the {outbound['margin']:.2f} margin on outbound traffic shows why it must "
        "complement, not replace, deterministic controls."
    )


def simulation_assumptions() -> List[str]:
    return [
        "The replay is deterministic and non-adaptive: the attacker follows the dataset timing.",
        "Rows are per-minute aggregates, so 320 files modified at 09:07 means 320 changes/min; they are assumed to "
        "include encrypted-extension/entropy changes, so the combined FIM rule fires. The 100/min value is a "
        "placeholder to be tuned on at least one week of real FIM data.",
        "The 320 modified files are part of the 1,200 encrypted ones (files impacted = maximum, not sum).",
        "In the baseline, the deletion attempt on mutable backups succeeds.",
        "Assume-breach scenarios disable every access-zone control (lockout, MFA via a stolen session token, response "
        "to the 09:01 alert) to test whether detection plus immutable recovery alone bound the damage. Part D assumes "
        "isolation by T+2; manual isolation at T+4 delays the whole recovery by 2 minutes.",
        "In the hardened scenario a low-and-slow guesser (≤9 tries per 5 min) would evade lockout; MFA, not lockout, is "
        "the control that robustly stops the 09:04 login.",
    ]


def references(results: Dict[str, Any]) -> List[str]:
    sources = results["data_sources"]
    pdf_name = next(name for name in sources if name.endswith(".pdf"))
    return [
        "MITRE ATT&CK Enterprise matrix, https://attack.mitre.org — techniques and tactics T1589, T1110.001, T1078, "
        "T1486, T1490, T1041, T1213, T1562.001, TA0008 (accessed 31 October 2026).",
        "Law of the Republic of Kazakhstan No. 94-V of 21 May 2013 “On Personal Data and Their Protection”, Article 12, "
        "https://adilet.zan.kz/eng/docs/Z1300000094 (accessed 31 October 2026).",
        "NIST SP 800-61 Rev. 3 (April 2025), Incident Response Recommendations and Considerations for Cybersecurity "
        "Risk Management, https://doi.org/10.6028/NIST.SP.800-61r3 (basis for separating Respond from Recover).",
        "Vendor documentation: privacyIDEA, OPNsense, Wazuh, Suricata, MinIO Object Lock, OpenZFS send/receive, "
        "PostgreSQL continuous archiving and point-in-time recovery, fapolicyd.",
        f"Assignment specification: {pdf_name} (SHA-256 {sources[pdf_name]}).",
        "AI assistance: analysis code and draft text were prepared with the help of an AI coding assistant (Claude, "
        "Anthropic); the student reviewed, ran and verified all results.",
    ]


def reproduce_commands() -> List[str]:
    return [
        "python3 -m venv .venv",
        ".venv/bin/pip install -r requirements.txt",
        "./run_all.sh            # tests, analysis, figures, report, PDF",
        "PYTHONPATH=src .venv/bin/python -m fault4 analyze   # results.json and run_log.txt only",
    ]
