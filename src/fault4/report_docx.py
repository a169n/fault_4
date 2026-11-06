"""Lay out the submission report as .docx (text comes from report_content, numbers from results)."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from docx import Document
from docx.enum.text import WD_BREAK
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Inches, Pt, RGBColor

from fault4 import report_content as rc
from fault4.data import REPORT_DIR

HEADER_FILL = "D9E8F5"  # light blue header row, as in the template
FIGURE_WIDTH = Inches(6.5)


def _shade(cell, fill: str) -> None:
    props = cell._tc.get_or_add_tcPr()
    shading = OxmlElement("w:shd")
    shading.set(qn("w:val"), "clear")
    shading.set(qn("w:color"), "auto")
    shading.set(qn("w:fill"), fill)
    props.append(shading)


def _cell_text(cell, text: str, bold: bool = False, size: float = 9) -> None:
    cell.text = ""
    paragraph = cell.paragraphs[0]
    run = paragraph.add_run(text)
    run.bold = bold
    run.font.size = Pt(size)


def _row_flag(row, tag: str) -> None:
    flag = OxmlElement(tag)
    flag.set(qn("w:val"), "true")
    row._tr.get_or_add_trPr().append(flag)


def _table(doc, header: Sequence[str], rows: Sequence[Sequence[str]], widths: Optional[Sequence[float]] = None):
    table = doc.add_table(rows=1, cols=len(header))
    table.style = "Table Grid"
    _row_flag(table.rows[0], "w:tblHeader")  # repeat the header row after a page break
    for cell, text in zip(table.rows[0].cells, header):
        _cell_text(cell, text, bold=True)
        _shade(cell, HEADER_FILL)
    for row in rows:
        cells = table.add_row().cells
        for cell, text in zip(cells, row):
            _cell_text(cell, str(text))
    for row in table.rows:
        _row_flag(row, "w:cantSplit")  # keep each row on one page
    if widths:
        # Word reads cell widths, LibreOffice reads the table grid: set both.
        table.autofit = False
        for column, width in zip(table.columns, widths):
            column.width = Inches(width)
        for row in table.rows:
            for cell, width in zip(row.cells, widths):
                cell.width = Inches(width)
    doc.add_paragraph()
    return table


def _para(doc, text: str, bold: bool = False, italic: bool = False, size: Optional[float] = None, style=None):
    paragraph = doc.add_paragraph(style=style)
    run = paragraph.add_run(text)
    run.bold = bold
    run.italic = italic
    if size:
        run.font.size = Pt(size)
    return paragraph


def _labelled(doc, label: str, text: str, style=None):
    paragraph = doc.add_paragraph(style=style)
    paragraph.add_run(label).bold = True
    paragraph.add_run(text)
    return paragraph


def _figure(doc, figures: Dict[str, Path], name: str) -> None:
    if name not in figures:
        return
    doc.add_picture(str(figures[name]), width=FIGURE_WIDTH)  # python-docx needs str, not Path
    _para(doc, rc.FIGURE_CAPTIONS[name], italic=True, size=9)


def _page_break(doc) -> None:
    doc.add_paragraph().add_run().add_break(WD_BREAK.PAGE)


def _setup(doc) -> None:
    for section in doc.sections:
        section.left_margin = section.right_margin = Inches(1)
        section.top_margin = section.bottom_margin = Inches(0.9)
    normal = doc.styles["Normal"]
    normal.font.name = "Calibri"
    normal.font.size = Pt(10)
    for level in (1, 2, 3):
        style = doc.styles[f"Heading {level}"]
        style.font.name = "Calibri"
        style.font.color.rgb = RGBColor(0x2F, 0x5D, 0x8C)


def _yes_no(value: bool) -> str:
    return "yes" if value else "no"


def _simulation_rows(results: Dict[str, Any]) -> Tuple[List[str], List[List[str]]]:
    sims = results["simulation"]

    def loss(r):
        if r["data_loss_min"] is None:
            return "unbounded (backups lost)"
        if r["files_impacted"] == 0:
            return "none"
        return f"{r['data_loss_min']} (fallback {r['data_loss_fallback_min']})"

    def recovery(r):
        if r["recovery_time_min"] is None:
            return "not achievable"
        return "no recovery needed" if r["recovery_time_min"] == 0 else str(r["recovery_time_min"])

    metrics = [
        ("Attacker gains a session", lambda r: _yes_no(r["attacker_access"])),
        ("Attack stopped / contained at", lambda r: r["stopped_at"] or "never"),
        ("First automated detection", lambda r: r["first_detection"] or "none"),
        ("Files impacted", lambda r: f"{r['files_impacted']:,}"),
        ("Backups destroyed", lambda r: _yes_no(r["backup_destroyed"])),
        ("Exfiltration channel open", lambda r: _yes_no(r["exfiltration_succeeded"])),
        ("Antivirus disabled", lambda r: _yes_no(r["av_disabled"])),
        ("Data loss, min", loss),
        ("Recovery time, min", recovery),
    ]
    header = ["Metric"] + [r["label"] for r in sims]
    return header, [[name] + [fn(r) for r in sims] for name, fn in metrics]


def build_report(
    results: Dict[str, Any],
    figures: List[Path],
    out_path: Path = REPORT_DIR / "Assignment4_Talgatov_Aibyn.docx",
    commit: Optional[str] = None,
    work_period: Optional[Tuple[str, str]] = None,
    submission_date: Optional[str] = None,
) -> Path:
    figs = {Path(p).name: Path(p) for p in figures}
    doc = Document()
    _setup(doc)
    student = rc.STUDENT
    texts = rc.section_texts(results)
    plain = rc.plain_summaries(results)

    # ------------------------------------------------------------------ title
    doc.add_heading(rc.TITLE, level=0)
    _para(doc, rc.SUBTITLE, bold=True, size=12)
    _para(doc, f"{student['name']} · Student ID {student['student_id']} · {student['group']} · "
               f"Instructor: {student['instructor']}")
    _para(doc, "Astana IT University | Fault Tolerance | Academic Year 2026–2027", italic=True)
    _para(doc, rc.CONTEXT_NOTE, italic=True, size=9)

    doc.add_heading("Incident dataset (synthetic)", level=2)
    events = results["incident"]["events"]
    _table(doc, ("Time", "Event", "Source", "Severity"),
           [(e["time"], e["event"], e["source"], e["severity"]) for e in events], (0.7, 2.6, 1.8, 1.0))

    # ------------------------------------------------------------------ Part A
    doc.add_heading("Part A — Incident Analysis", level=1)
    _labelled(doc, "In plain words: ", plain["A"])
    _para(doc, rc.PART_INTROS["A"])
    _table(doc, ("Time", "Event", "Attack stage", "Evidence", "Risk"), [
        (e["time"], e["event"], e["stage"],
         e["evidence"] + f" (ATT&CK: {e['attack_ref']})" + (f" Alternative reading: {e['alternative']}"
                                                          if e["alternative"] else ""),
         e["risk"])
        for e in events
    ], (0.5, 1.1, 1.0, 3.2, 0.7))
    m = results["incident"]["metrics"]
    _para(doc, f"Attack metrics: {m['failed_logins_total']} failed logins in total; compromise after "
               f"{m['minutes_to_compromise']} min; encryption {m['minutes_compromise_to_encryption']} min after "
               f"compromise; {m['attack_duration_minutes']} min from first contact to disabled antivirus. "
               "Risk is the assessed risk: it equals the dataset severity except 09:04, raised to Critical.")

    # ------------------------------------------------------------------ Part B
    doc.add_heading("Part B — Risk Matrix", level=1)
    _labelled(doc, "In plain words: ", plain["B"])
    _para(doc, rc.PART_INTROS["B"])
    threats = results["risk"]["threats"]
    _table(doc, ("Threat", "Likelihood", "Impact", "Risk Score", "Priority"),
           [(t["threat"], t["likelihood"], t["impact"], t["score"], f"{t['level']} (#{t['rank']})") for t in threats])
    _labelled(doc, "Scoring rules. ", f"{results['risk']['likelihood_rule']} {results['risk']['impact_rule']} "
                                     "Ranking: score, then impact, then template order.")
    _table(doc, ("Threat", "Likelihood rationale", "Impact rationale", "Sensitivity (L-1 / L / L+1)"), [
        (t["threat"], t["likelihood_reason"], t["impact_reason"],
         " / ".join(t["sensitivity"][k] for k in ("L-1", "L", "L+1")))
        for t in threats
    ], (1.2, 2.5, 1.9, 0.9))
    _labelled(doc, "Implementation order. ", "What to fix first is a separate choice from the risk rank. MFA comes "
                                             "first because it removes the cause (a guessed password was enough to get "
                                             "in); immutable backup comes second because it still saves the data when "
                                             "every other layer fails.")

    # ------------------------------------------------------------------ Part C
    doc.add_heading("Part C — Resilient Security Architecture", level=1)
    _labelled(doc, "In plain words: ", plain["C"])
    _para(doc, rc.PART_INTROS["C"])
    _table(doc, ("Threat", "Preventive control", "Detection control", "Recovery control"),
           [(t["threat"], t["preventive"], t["detective"], t["recovery"]) for t in results["controls"]["threat_controls"]],
           (1.0, 1.9, 1.8, 1.8))
    _para(doc, "Component inventory and the defence of each role:", bold=True)
    _table(doc, ("Required component", "Implementation", "Zone", "Role", "Why this role"), [
        (rc.SATISFIES_LABEL.get(c["satisfies"], c["satisfies"]), f"{c['name']}: {c['technology']}", c["zone"],
         c["role"], c["why"])
        for c in results["controls"]["components"]
    ], (1.0, 2.2, 0.9, 0.8, 1.6))
    _para(doc, rc.ROLE_NOTE)
    _figure(doc, figs, "architecture.png")
    doc.add_heading("How to read Figure 1", level=2)
    _para(doc, rc.FIGURE1_INTRO)
    _para(doc, "Zones, from left to right:", bold=True)
    for zone, text in rc.FIGURE1_ZONES:
        _labelled(doc, f"{zone}: ", text, style="List Bullet")
    _para(doc, "Control flow:", bold=True)
    for i, (title, text) in enumerate(rc.ARCHITECTURE_FLOW, start=1):
        _labelled(doc, f"({i}) {title}: ", text, style="List Bullet")

    # ------------------------------------------------------------------ Part D
    doc.add_heading("Part D — Recovery Plan", level=1)
    _labelled(doc, "In plain words: ", plain["D"])
    _para(doc, rc.PART_INTROS["D"])
    _table(doc, ("Step", "Action", "Responsible component", "Target time"),
           [(s["number"], s["action"], s["component"], s["target_time"]) for s in results["recovery"]["steps"]],
           (0.5, 1.4, 3.0, 1.6))
    check = results["recovery"]["check"]
    points = results["recovery"]["clean_points"]
    _labelled(doc, "RTO. ", f"Estimated recovery time {check['recovery_time_sequential']} min if every step waits for "
                             f"the previous one, {check['recovery_time_critical_path']} min on the critical path (steps "
                             "1→2→4→5→6→7; evidence is collected at the same time as steps 4–5, because restoring onto "
                             f"RS-02 does not touch RS-01). Both are within the {check['rto_target']}-minute target, with "
                             f"{check['slack_min']} min to spare.")
    _labelled(doc, "RPO. ", f"Snapshots every {results['recovery']['snapshot_interval_min']} min (starting at 09:00) + "
                             f"{results['recovery']['replication_lag_min']} min delay before they reach the vault = "
                             f"{check['worst_case_data_loss']} min worst-case data loss, within the "
                             f"{check['rpo_target']}-minute target. The restore point is chosen in step 4, before "
                             f"restoring: {points['preferred']} (the last snapshot before the first harmful change at "
                             f"09:07) if it shows no unexpected changes compared with {points['fallback']}, otherwise "
                             f"{points['fallback']} (before the attacker logged in at 09:04). That means 1 or 4 min of "
                             "lost work. With the fallback point, the loss grows with how long the attacker was inside.")
    for s in results["recovery"]["steps"]:
        _labelled(doc, f"Step {s['number']}. ", s["details"], style="List Bullet")
    _figure(doc, figs, "recovery_timeline.png")

    # ------------------------------------------------------------------ Part E
    doc.add_heading("Part E — AI-Assisted Detection", level=1)
    _labelled(doc, "In plain words: ", plain["E"])
    threshold = results["anomaly"]["threshold"]
    _table(doc, ("Event", "Normal score", "Observed score", "Delta", f"Anomaly (score ≥ {threshold:.2f})"), [
        (s["name"], f"{s['normal']:.2f}", f"{s['observed']:.2f}", f"{s['delta']:.2f}", _yes_no(s["is_anomaly"]))
        for s in results["anomaly"]["signals"]
    ])
    for i, (question, answer) in enumerate(zip(rc.PART_E_QUESTIONS, rc.part_e_answers(results)), start=1):
        _labelled(doc, f"{i}. {question} ", answer)
    _figure(doc, figs, "anomaly_scores.png")
    _para(doc, "Threshold sensitivity: number of signals flagged at each threshold.", bold=True)
    _table(doc, ("Threshold", "Signals flagged"),
           [(f"{d['threshold']:.2f}", d["count"]) for d in results["anomaly"]["threshold_sensitivity"]], (1.2, 1.4))

    # ------------------------------------------------------------------ simulation + conclusion
    doc.add_heading("Before/After Simulation", level=1)
    _labelled(doc, "In plain words: ", plain["simulation"])
    _para(doc, "The same ten events are replayed against the as-is system and against the proposed architecture "
               "(src/fault4/simulation.py, configs/scenarios.json). Assumptions:")
    for item in rc.simulation_assumptions():
        _para(doc, item, style="List Bullet")
    header, rows = _simulation_rows(results)
    _table(doc, header, rows, (1.7, 1.2, 1.2, 1.2, 1.2))
    _para(doc, f"With automatic isolation the damage drops from 1,200 to 320 files ({rc.reduction_percent(results)} "
               "fewer). With manual isolation all 1,200 files are hit, but the data still comes back within the RPO and "
               "RTO targets because the backups could not be deleted. Automation limits how much is damaged; locked "
               "backups make sure it can always be restored.")
    doc.add_heading("Conclusion", level=1)
    _para(doc, rc.conclusion(results))

    # ------------------------------------------------------------------ submission record
    _page_break(doc)
    doc.add_heading(rc.FORM_TITLE, level=1)
    _para(doc, rc.TITLE, bold=True)
    _para(doc, rc.FORM_PURPOSE, italic=True)

    doc.add_heading("1. Student and Submission Information", level=2)
    _table(doc, ("Required field", "Student entry"), [
        ("Student full name", student["name"]),
        ("Student ID", student["student_id"]),
        ("Group / cohort", student["group"]),
        ("Instructor", student["instructor"]),
        ("Date of submission", submission_date or student["date_blank"]),
        ("Individual variant / task code assigned by instructor", student["variant_blank"]),
        ("Git repository / project link", student["repository"]),
        ("Attached code / file names", rc.ATTACHED_FILES),
    ], (2.6, 3.9))

    doc.add_heading("2. Work Period and Task Record", level=2)
    start, finish = work_period or (student["date_blank"], student["date_blank"])
    _table(doc, ("Item", "Student entry"), [
        ("Work start date/time", start),
        ("Work completion date/time", finish),
        ("Main task completed", rc.SECTION2_VALUES["Main task completed"]),
        ("Tools / technologies used", rc.SECTION2_VALUES["Tools / technologies used"]),
        ("Main technical output produced", rc.SECTION2_VALUES["Main technical output produced"]),
    ], (2.6, 3.9))

    doc.add_heading("3. Report Structure to Complete", level=2)
    _para(doc, rc.SECTION3_INTRO)
    for key, title, instruction in rc.SECTION3:
        doc.add_heading(title, level=3)
        _para(doc, instruction, italic=True)
        _table(doc, ("Required content", "Student response / evidence"),
               list(zip(rc.SECTION3_ROWS, (texts[key]["summary"], texts[key]["evidence"], texts[key]["decision"]))),
               (1.7, 4.8))
        if key == "risk":
            _figure(doc, figs, "risk_matrix.png")

    doc.add_heading(rc.SECTION4_TITLE, level=2)
    _para(doc, rc.SECTION4_INTRO)
    for bullet in rc.SECTION4_BULLETS:
        _para(doc, bullet, style="List Bullet")
    _table(doc, ("Individual evidence", "Student entry"), rc.individual_record(results, commit), (1.9, 4.6))

    doc.add_heading("5. Evidence Checklist", level=2)
    for item, pointer in rc.evidence_checklist():
        _labelled(doc, f"☒ {item}", f" — {pointer}")

    doc.add_heading("6. Student Declaration", level=2)
    _para(doc, rc.DECLARATION)
    _table(doc, ("Role", "Name", "Signature", "Date"), [
        ("Student / Executor", student["name"], "________________", "____________"),
        ("Instructor / Accepted by", student["instructor"], "________________", "____________"),
    ], (1.8, 1.6, 1.7, 1.4))

    doc.add_heading("7. Instructor Acceptance Record", level=2)
    _table(doc, ("Check", "Status / comment"),
           [(c, "☐ Yes ☐ No Comment: ____________________") for c in rc.INSTRUCTOR_CHECKS]
           + [("Final status", "☐ Accepted ☐ Revision required")], (2.6, 3.9))

    # ------------------------------------------------------------------ references + appendix
    doc.add_heading("References and external sources", level=1)
    for ref in rc.references(results):
        _para(doc, ref, style="List Number")
    doc.add_heading("Appendix — Reproducibility", level=1)
    _para(doc, f"fault4 v{results['tool_version']}, commit {commit or 'see git log'}. Commands:")
    for command in rc.reproduce_commands():
        _para(doc, command, size=9, style="List Bullet")
    _table(doc, ("File", "SHA-256"), sorted(results["data_sources"].items()), (2.6, 3.9))

    props = doc.core_properties
    props.author = props.last_modified_by = student["name"]
    props.title = rc.TITLE
    props.subject = rc.SUBTITLE
    props.comments = ""
    props.created = props.modified = datetime.now(timezone.utc).replace(tzinfo=None)

    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    doc.save(str(out_path))
    return out_path
