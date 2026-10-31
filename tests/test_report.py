import pytest
from docx import Document

from fault4.figures import render_all
from fault4.pipeline import run_analysis
from fault4.report_content import TEMPLATE_LABELS
from fault4.report_docx import build_report


@pytest.fixture(scope="module")
def doc(tmp_path_factory):
    out = tmp_path_factory.mktemp("r")
    res = run_analysis()
    figs = render_all(res, out / "fig")
    return Document(str(build_report(res, figs, out / "r.docx", commit="abc1234",
                                     work_period=("2026-10-31 10:43 (UTC+5, Astana)",
                                                  "2026-10-31 18:00 (UTC+5, Astana)"))))


def full_text(d):
    return "\n".join([p.text for p in d.paragraphs] + [c.text for t in d.tables for r in t.rows for c in r.cells])


def heads(d):
    return {tuple(c.text for c in t.rows[0].cells): len(t.rows) for t in d.tables}


def test_student_fields(doc):
    t = full_text(doc)
    for s in ["Talgatov Aibyn", "255308", "CSE-2505M", "Serek Azamat", "https://github.com/a169n/fault_4", "abc1234",
              "synthetic", "UTC+5"]:
        assert s in t


def test_template_labels_verbatim(doc):
    t = full_text(doc)
    assert [s for s in TEMPLATE_LABELS if s not in t] == []


def test_assignment_tables_present(doc):
    h = heads(doc)
    assert h[("Time", "Event", "Attack stage", "Evidence", "Risk")] == 11
    assert h[("Threat", "Likelihood", "Impact", "Risk Score", "Priority")] == 6
    assert h[("Threat", "Likelihood rationale", "Impact rationale", "Sensitivity (L-1 / L / L+1)")] == 6
    assert h[("Threat", "Preventive control", "Detection control", "Recovery control")] == 6
    assert h[("Required component", "Implementation", "Zone", "Role", "Why this role")] == 10
    assert h[("Step", "Action", "Responsible component", "Target time")] == 8
    assert h[("Event", "Normal score", "Observed score", "Delta", "Anomaly (score ≥ 0.75)")] == 6


def test_risk_justifications_rendered(doc):
    t = full_text(doc)
    assert all(x["likelihood_reason"] in t for x in run_analysis()["risk"]["threats"])


def test_key_numbers_in_report(doc):
    t = full_text(doc)
    for s in ["24 min", "20 min", "4 min", "100%", "1,200", "320", "0.84", "09:06", "09:03", "73.3%", "by T+20"]:
        assert s in t, s


def test_references_present(doc):
    t = full_text(doc)
    assert "References" in t and "MITRE ATT&CK" in t and "94-V" in t


def test_report_has_no_placeholder_leaks(doc):
    t = full_text(doc)
    assert not any(x in t for x in ["{", "}", "TODO", "TBD"])
    assert not any(c.text.strip() in ("None", "null", "nan") for tb in doc.tables for r in tb.rows for c in r.cells)


def test_report_images_fit_page(doc):
    s = doc.sections[0]
    text_w = s.page_width - s.left_margin - s.right_margin
    assert len(doc.inline_shapes) == 5 and all(sh.width <= text_w for sh in doc.inline_shapes)
