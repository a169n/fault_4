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
    "Main technical output produced": "Reproducible analysis pipeline (python -m fault4 all), results.json, 4 figures, "
                                      "4-scenario simulation, this report",
}
ATTACHED_FILES = (
    "src/fault4/*.py, tests/*.py, data/*.csv, configs/scenarios.json, outputs/results.json, outputs/run_log.txt, "
    "outputs/test_log.txt, outputs/figures/*.png, run_all.sh"
)

# Numbered control flow shown in Figure 1 and walked through in Part C.
ARCHITECTURE_FLOW = (
    ("Access", "attacker → firewall → bastion. Remote login (SSH) is possible only to the bastion, where MFA rejects "
               "the guessed password (red ✕, the 09:04 login). Authorised users continue from the bastion to RS-01."),
    ("Backup", "RS-01 and the database → vault. The vault fetches the copies itself (snapshots every 3 min, the "
               "database change log continuously), so RS-01 holds no password the 09:12 deletion attempt could use."),
    ("Telemetry", "bastion → SIEM, and RS-01 (file monitoring, canary files) → IDS → SIEM. The failed logins raise the "
                  "09:01 alert and the mass file change raises the 09:07 alert."),
    ("Response", "SIEM → enforcement points. The SIEM asks the hypervisor to pause RS-01 and move it into the "
                 "quarantine network, and the firewall blocks its traffic (isolated by 09:09)."),
    ("Egress control", "RS-01 → Internet. The connection to the unknown address is blocked at the firewall (red ✕, the "
                       "09:13 channel fails)."),
    ("Restore", "vault → clean room → RS-02. Data from the clean restore point is restored and checked in the isolated "
                "clean room, then RS-02 joins the research network (estimated recovery time 24 min, 20 min on the "
                "critical path)."),
    ("Last-resort copy", "vault → Almaty. Once a day, a transfer window copies the vault to the offline site."),
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
    ("Internet", "the destination of the 09:13 outbound connection, reachable only through the egress allow-list (the "
                 "list of the only outside addresses the servers may contact)."),
    ("Segmentation boundary", "OPNsense firewall and VLAN switching: default-deny between zones, egress allow-list, "
                              "quarantine VLAN. Every arrow crossing it is an explicitly allowed or blocked path."),
    ("Access zone", "the SSH bastion (the single, well-guarded entry server) and VPN with MFA, the only way into the "
                    "research zone, and privileged access management (administrator rights only for a short, approved "
                    "time; security agents cannot be switched off)."),
    ("Research zone", "RS-01 with its canary files (decoy files nobody should touch) and FIM agent (file integrity "
                      "monitoring: it records every file change). RS-01 is a virtual machine on the hypervisor (the "
                      "software that runs virtual machines), which can pause it and move it into the quarantine "
                      "VLAN (a separate, closed-off virtual network)."),
    ("Data zone", "the PostgreSQL research database, whose WAL the vault pulls continuously."),
    ("Security zone", "the intrusion detection system (network monitoring, file monitoring, canary files, AI anomaly "
                      "scoring) feeding the SIEM, which links related alerts and starts the automatic response."),
    ("Backup vault", "pull-only (the vault fetches the copies itself; the servers cannot reach it). Tier 1 keeps "
                     "snapshots of RS-01 every 3 min under zfs hold (a lock that stops a snapshot from being "
                     "deleted); tier 2 keeps copies every 15 min under Object Lock (a storage setting that blocks "
                     "deletion until a set date, even for administrators)."),
    ("Recovery zone", "a separate network without internet: the clean room where restored data is scanned and checked, "
                      "and the RS-02 spare server, which joins the research network only after the check."),
    ("Second site (Almaty)", "the offline copy, refreshed in a daily transfer window opened from the Almaty side."),
)
ROLE_NOTE = (
    "Whether a control counts as preventive, detective or recovery depends on the threat. Object Lock prevents backup "
    "deletion, while the backup as a whole is a recovery control against ransomware. The SIEM detects and gives "
    "orders; the hypervisor, the firewall and the login server carry them out. The template has no separate “respond” "
    "column, so these actions appear in the recovery column marked “Respond:”."
)
SATISFIES_LABEL = {
    "supporting": "Supporting (not one of the 7 required)",
    "Additional": "Additional (Part E Q4, section 6)",
}

FIGURE_CAPTIONS = {
    "architecture.png": "Figure 1. Resilient architecture and its numbered control flow (1)–(7).",
    "recovery_timeline.png": "Figure 2. Recovery schedule against the 30-minute RTO.",
    "anomaly_scores.png": "Figure 3. Normal vs observed AI anomaly scores with the 0.75 threshold.",
    "risk_matrix.png": "Figure 4. Risk matrix (Risk = Likelihood × Impact).",
}

def plain_summaries(results: Dict[str, Any]) -> Dict[str, str]:
    """One short, non-technical paragraph per part; the details follow in the tables."""
    m = results["incident"]["metrics"]
    ransomware = _threat(results, "Ransomware")
    check = results["recovery"]["check"]
    interval = results["recovery"]["snapshot_interval_min"]
    lag = results["recovery"]["replication_lag_min"]
    summary = results["anomaly"]["summary"]
    breach = _sim(results, "hardened_assume_breach")
    return {
        "A": (
            f"The log shows one attacker who guessed a password, logged in, encrypted the research files, tried to "
            f"delete the backups, opened a connection to the outside and switched off the antivirus, all within "
            f"{m['attack_duration_minutes']} minutes. The table names the attack stage of each event, the evidence for "
            "that choice and how serious the event is. Each event is also matched to MITRE ATT&CK (a public catalogue "
            "of known attacker techniques). The 09:15 database spike counts as lateral movement (moving from one "
            "captured computer to others in the same network)."
        ),
        "B": (
            "Each threat gets two scores from 1 to 5: how likely it is and how much damage it would do. Multiplying "
            f"them gives the risk score. Ransomware scores highest ({ransomware['score']}) because it happened and "
            "destroyed data. Backup destruction and credential compromise (a guessed or stolen password) follow with "
            "20 each."
        ),
        "C": (
            "The design surrounds the research server with several independent layers. Some layers stop the attack "
            "(preventive), some notice it (detective) and some bring the system back (recovery). Every threat is "
            "covered by all three kinds, so the attacker has to defeat more than one layer to win. The main parts are "
            "MFA (multi-factor authentication: a second login step, such as a code from a phone app), network "
            "segmentation (splitting the network into separate zones), an immutable backup (a copy that cannot be "
            "changed or deleted), a SIEM (a system that collects logs and raises alerts), an IDS (intrusion detection "
            "system: it watches traffic and files for signs of attack), failover (switching to a spare server) and a "
            "clean room (an isolated network where restored data is checked)."
        ),
        "D": (
            "If an attack still gets through, the plan brings the service back in seven steps. The estimated recovery "
            f"time is {check['recovery_time_critical_path']} minutes on the critical path (the longest chain of steps "
            "that cannot overlap) "
            f"({check['recovery_time_sequential']} minutes one after another), within the {check['rto_target']}-minute "
            "RTO (recovery time objective: how long the service may be down). Snapshots (instant copies of the disk) "
            f"are taken every {interval} minutes and arrive {lag} minute later, so the worst-case data loss is "
            f"{check['worst_case_data_loss']} minutes of work, within the {check['rpo_target']}-minute RPO (recovery "
            "point objective: how much recent work may be lost)."
        ),
        "E": (
            f"An AI model scored each signal from 0 to 1. All {summary['total']} scored at or above the "
            f"{results['anomaly']['threshold']:.2f} cut-off, so all are anomalies ({summary['rate']:.0%}). File "
            "modifications scored highest and are the most urgent, because they show the encryption itself. AI helps "
            "to spot and rank problems, but it cannot block an attacker or restore data, so it supports the fixed "
            "security rules rather than replacing them."
        ),
        "simulation": (
            "The same ten events were replayed against the current setup and against the new design. Without "
            "protection, 1,200 files are lost together with the backups. With the new design, the attack is stopped at "
            "the first warning. In the assume-breach runs (pretending the attacker has already got in), automatic "
            "isolation (cutting the server off the network) limits the "
            f"damage to {breach['files_impacted']} files and the backups survive."
        ),
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
        f"{top['name']}: observed {top['observed']:.2f} against a normal {top['normal']:.2f} (Δ {top['delta']:.2f}, the "
        "rise above normal). It has the highest score and the biggest rise, and it marks the start of the encryption "
        "at 09:07, so it is the signal that should trigger isolation.",
        "AI scores are estimates and can be wrong both ways: they raise false alarms and they miss real attacks. "
        f"Outbound traffic is only {outbound['margin']:.2f} above the cut-off, so a cut-off of 0.80 would miss the "
        "data-theft channel. Research servers often run at 95% CPU during normal calculations, so CPU alone says "
        "little. The model only raises an alert: it cannot stop the backup deletion or bring data back. The attacker "
        "switched off the antivirus at 09:18, and an AI agent on the same server could be switched off the same way. "
        "Normal behaviour also shifts over the semester and exam periods. Fixed rules (MFA, locked backups, blocked "
        "outgoing connections) keep working when detection fails and are easy to audit, so AI should sit on top of "
        "them to sort and link alerts.",
        "An offline copy (kept disconnected from the network most of the time) of the backup vault at a second site "
        "in Kazakhstan (Almaty, about 970 km from Astana), "
        "updated in a daily transfer window and checked by a monthly test restore (see section 6).",
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
                "All 10 events are classified. The attacker first tested the login (09:01), then guessed passwords "
                f"({m['failed_logins_total']} failed attempts in total) and got in at 09:04. Three minutes later files "
                "began to change, and by 09:10 1,200 files were encrypted. The attacker then tried to delete the backups "
                "(09:12), opened a connection to an unknown outside address (09:13), read heavily from the database "
                f"(09:15) and switched off the antivirus (09:18). The whole attack took {m['attack_duration_minutes']} "
                "minutes and nothing stopped it automatically: the antivirus was running during the encryption and "
                "did not react."
            ),
            "evidence": (
                "Part A table; code src/fault4/incident.py; outputs/results.json → incident. Measured from the log: "
                f"{m['failed_logins_total']} failed logins, access gained after {m['minutes_to_compromise']} min, "
                f"encryption started {m['minutes_compromise_to_encryption']} min after access, "
                f"{m['attack_duration_minutes']} min in total. Each row quotes the log and names the matching MITRE "
                "ATT&CK technique."
            ),
            "decision": (
                "Four events can be read in more than one way (09:01, 09:08, 09:15, 09:18); the Part A table gives the "
                "other reading for each. I treat the database spike at 09:15 as lateral movement: the attacker used the "
                "captured server as a stepping stone to the research database, which I assume runs on a separate "
                "machine. I raised the 09:04 login from High to Critical because everything that followed depended on it."
            ),
        },
        "risk": {
            "summary": (
                f"Ransomware ranks first ({ransomware['likelihood']} × {ransomware['impact']} = {ransomware['score']}). "
                "Backup destruction and credential compromise follow with 20 each (Critical). Data exfiltration and "
                "privilege escalation score 16 (High). When two threats have the same score, the one with the larger "
                "impact ranks higher."
            ),
            "evidence": (
                f"{arithmetic}. Code src/fault4/risk.py; Figure 4. I also checked how stable each priority is by moving "
                "the likelihood one step down or up: only ransomware stays Critical one step down, and data exfiltration "
                "and privilege escalation become Critical one step up."
            ),
            "decision": (
                "One simple rule for every likelihood: 5 if the log shows the threat happened and worked, 4 if it shows "
                "only an attempt or an indirect sign. The order of fixing things is a separate choice from the risk "
                "rank: MFA comes first because it removes the cause (a guessed password was enough to get in), and "
                "immutable backup second because it still saves the data when every other layer fails."
            ),
        },
        "architecture": {
            "summary": (
                "The research server sits behind a firewall that splits the network into separate zones: access, "
                "research, data, security, backup and recovery. All seven required parts are included: MFA, network "
                "segmentation, immutable backup, monitoring, intrusion detection, secure failover to a spare server "
                "(RS-02) and an isolated recovery environment. An offline copy in Almaty is added as an extra."
            ),
            "evidence": (
                "Part C table and component list; Figure 1 with the numbered control flow (1)–(7); "
                "src/fault4/controls.py. An automatic check in the code confirms that every required part exists, every "
                "threat has a preventive, a detective and a recovery control, and no part is left unused."
            ),
            "decision": (
                "The spare server is filled from a backup, not kept as a live copy: a live copy would have received the "
                "1,200 encrypted files as well. RS-02 waits in a separate network the attacker cannot reach and joins "
                "the research network only after its data has been checked. The infected server is cut off by the "
                "hypervisor, which moves it into a quarantine network; the table marks this “Respond:” in the "
                "recovery column."
            ),
        },
        "recovery": {
            "summary": (
                f"Seven steps, timed from the first harmful change at 09:07 (T): {_durations(results)} = "
                f"{check['recovery_time_sequential']} min if done one after another, and "
                f"{check['recovery_time_critical_path']} min when evidence collection runs at the same time as steps "
                f"4–5. Both estimated recovery times are within the {check['rto_target']}-minute RTO target. The "
                f"worst-case data loss is {interval} + {lag} = {check['worst_case_data_loss']} min, within the "
                f"{check['rpo_target']}-minute RPO target."
            ),
            "evidence": (
                f"Part D table; src/fault4/recovery.py; Figure 2. Backups are taken every {interval} min starting at "
                f"09:00 and reach the vault {lag} min later. Two clean restore points: {points['preferred']} (the last "
                f"backup before 09:07) loses 1 min of work; {points['fallback']} (before the attacker logged in at "
                "09:04) loses 4 min."
            ),
            "decision": (
                f"I chose a {interval}-minute backup interval because a 5-minute interval plus the {lag}-minute delay "
                "would lose 6 minutes and miss the target. The restore point is chosen before restoring: the attacker "
                f"was inside from 09:04 and may have left a back door, so {points['preferred']} is used only if it shows "
                f"no unexpected changes compared with {points['fallback']}. Choosing first keeps either option inside "
                "the RTO."
            ),
        },
        "ai": {
            "summary": (
                f"All signals are at or above {results['anomaly']['threshold']:.2f}: {summary['count']}/{summary['total']} "
                f"= {summary['rate']:.0%}. {top['name']} is the highest-priority event ({top['observed']:.2f}, "
                f"Δ {top['delta']:.2f}) and matches the moment data started being destroyed. AI scoring helps to find "
                "and rank problems, but it cannot replace fixed security rules."
            ),
            "evidence": (
                f"Rise above normal (Δ): {deltas}. With cut-offs of 0.75/0.80/0.85/0.90/0.95 the number of anomalies is "
                f"{sweep}. Code src/fault4/anomaly.py; Figure 3."
            ),
            "decision": (
                "I rank by how far each signal rose above normal and by where it sits in the attack, not by the ratio "
                f"to normal. The ratio would put {summary['highest_by_ratio'].lower()} first (8.10× vs 8.00×) only "
                "because its normal value is very small. I keep the cut-off at 0.75: at 0.80, outbound traffic "
                f"({outbound['observed']:.2f}, only {outbound['margin']:.2f} above the cut-off), the sign of data theft, "
                "would be missed."
            ),
        },
        "additional": {
            "summary": (
                "Recommended: an offline copy of the backups at a second site in Kazakhstan (Almaty). It is updated once "
                "a day in a short transfer window opened from the Almaty side, moved to disconnected media every month "
                "and test-restored every month."
            ),
            "evidence": (
                f"Both backup tiers in Astana (tier 1: snapshots, {check['worst_case_data_loss']} min worst-case data "
                "loss; tier 2: locked copies every 15 min) share one site and one set of administrators. The Almaty copy "
                "(about 970 km away) is a daily tier that survives a takeover of the backup administrators or the loss "
                "of the whole Astana site. Modelled as offline_copy in src/fault4/controls.py and flow (7) in Figure 1."
            ),
            "decision": (
                "A second site inside Kazakhstan rather than a foreign cloud: Law of the Republic of Kazakhstan No. 94-V "
                "“On Personal Data and Their Protection”, Article 12, requires databases with personal data to be kept on "
                "the territory of Kazakhstan, and research data may include personal data of study participants."
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
         f"Backups every {results['recovery']['snapshot_interval_min']} min, chosen after counting the "
         f"{results['recovery']['replication_lag_min']}-minute delay (3 + 1 = 4 ≤ 5, while 5 + 1 = 6 would miss the "
         "RPO target); a rule with two clean restore points, decided before restoring (09:06 if it shows no "
         "unexpected changes compared with 09:03, otherwise 09:03, before the attacker logged in); and a spare server "
         "kept in a separate network instead of a live copy."),
        (SECTION4_ROWS[1],
         "A Python package (fault4) with automated tests (outputs/test_log.txt) and a replay of the attack in four "
         "setups. Without protection, 1,200 files and the backups are lost. With the new design the attack stops at "
         "09:01. With the login protection bypassed, automatic isolation limits the damage to 320 files "
         f"({reduction_percent(results)} fewer). With manual isolation all 1,200 files are hit but still recovered, "
         f"2 min later. Estimated recovery time {check['recovery_time_sequential']} min (critical path "
         f"{check['recovery_time_critical_path']} min), worst-case data loss {check['worst_case_data_loss']} min."),
        (SECTION4_ROWS[2],
         f"{STUDENT['repository']}: code at commit {commit or 'see git log'} (outputs and this report are committed "
         f"in the next commit on main); fault4 v{results['tool_version']}. Dataset "
         f"transcribed from {pdf_name} (SHA-256 {sources[pdf_name][:16]}…): incident table p.1, Part E table p.2, into "
         f"data/incident_events.csv (SHA-256 {sources['incident_events.csv'][:16]}…) and data/anomaly_scores.csv "
         f"(SHA-256 {sources['anomaly_scores.csv'][:16]}…). Outputs: outputs/results.json, outputs/run_log.txt."),
        (SECTION4_ROWS[3],
         "Two ways of ranking the anomalies gave different winners: login failures by ratio (8.10×) and file "
         "modifications by rise above normal (Δ 0.84). I chose the rise plus the attack stage, because a ratio makes "
         "signals with a tiny normal value look bigger than they are, and I show both in Part E."),
        (SECTION4_ROWS[4],
         "Only one synthetic attack, replayed with an attacker who does not adapt. The file-change alarm level "
         "(100 changes per minute) was set knowing this attack, so it may fit it too closely. False alarms were not "
         "measured. Recovery step times are estimates, not timed drills. The 4-minute worst-case data loss holds for "
         "the preferred restore point; with the fallback point, the loss grows with how long the attacker was inside "
         "before doing damage (here 3 min)."),
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
        f"The attacker went from the first login attempt to switching off the antivirus in "
        f"{m['attack_duration_minutes']} minutes, with nothing reacting automatically: 1,200 files were encrypted and "
        "the backups were attacked. The proposed design answers each stage of the attack with a control that prevents "
        "it, one that detects it and one that recovers from it. In the replay, the login lockout stops the attack at "
        "09:01, and MFA would also reject the 09:04 login. If the login protection is bypassed, automatic isolation at "
        f"{breach['stopped_at']} limits the damage to {breach['files_impacted']} files ({reduction_percent(results)} "
        "fewer), the locked backups survive the 09:12 deletion attempt and blocked outgoing connections stop the 09:13 "
        f"channel. The estimated recovery time is {check['recovery_time_sequential']} min "
        f"({check['recovery_time_critical_path']} min on the critical path) against a {check['rto_target']}-minute RTO "
        f"target, with a worst-case data loss of {check['worst_case_data_loss']} min against a {check['rpo_target']}-"
        f"minute RPO target. AI scoring flags all signals ({summary['rate']:.0%}) and ranks file modifications first, "
        f"but outbound traffic is only {outbound['margin']:.2f} above the cut-off, which shows why AI must support, not "
        "replace, fixed security rules."
    )


def simulation_assumptions() -> List[str]:
    return [
        "The replay follows the log exactly; the attacker does not change tactics.",
        "Each log row covers one minute, so 320 files modified at 09:07 means 320 changes per minute. These changes are "
        "assumed to look like encryption (new file endings, random-looking content), so the file-change alarm fires. "
        "Its level of 100 changes per minute is a starting value to be tuned on at least one week of real data.",
        "The 320 modified files are among the 1,200 encrypted ones (the damage is the larger number, not the sum).",
        "Without protection, the attempt to delete the ordinary (unlocked) backups succeeds.",
        "The two assume-breach setups switch off all login protection (lockout, MFA bypassed with a stolen session, "
        "nobody acting on the 09:01 alert) to test whether detection and locked backups alone still limit the damage. "
        "Part D assumes isolation by T+2; manual isolation at T+4 delays the whole recovery by 2 minutes.",
        "In the protected setup, an attacker guessing slowly (9 or fewer tries per 5 minutes) would avoid the lockout; "
        "MFA, not lockout, is what reliably stops the 09:04 login.",
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
