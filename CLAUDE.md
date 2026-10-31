# CLAUDE.md — Assignment 4 (Fault Tolerance, AITU)

Context for Claude Code (or any developer) continuing this project on a local machine.

## What this repository is

Assignment 4 "Security, Resilience, and Intrusion Tolerance" (Astana IT University, Fault Tolerance). The spec is in
`docs/assignment/Assignment_4_AITU_Security_Resilience_Report_Template.pdf`. Pages 1–3 are the tasks (Parts A–E), and
pages 4–7 are the Student Technical Work Report template.

- Student: Talgatov Aibyn, ID 255308, group CSE-2505M, instructor Serek Azamat. The report is in **English**.
- All data are synthetic. The report must keep the spec's "synthetic data / not real AITU infrastructure" note.
- Deliverable: `report/Assignment4_Talgatov_Aibyn.docx` (+ `.pdf`), generated from code. Every number in the report
  comes from `outputs/results.json`.

## Source of truth

- **Implementation plan:** `docs/superpowers/plans/2026-10-31-assignment4-security-resilience.md`. Its "Pinned
  analytical decisions" section fixes every classification, score, timing and expected test value. Do not change a
  number without changing the plan, its test, and the report text together.
- **Layout:** each part has one module, which is only computed in the pipeline and only rendered in figures/report:

  | Part | Module |
  |---|---|
  | A | `src/fault4/incident.py` |
  | B | `src/fault4/risk.py` |
  | C | `src/fault4/controls.py` |
  | D | `src/fault4/recovery.py` |
  | E | `src/fault4/anomaly.py` |
  | before/after simulation | `src/fault4/simulation.py` + `configs/scenarios.json` |
  | orchestration | `src/fault4/pipeline.py` |
  | figures | `src/fault4/figures.py` |
  | report | `src/fault4/report_content.py` (text) + `src/fault4/report_docx.py` (layout) |

## Commands (macOS)

```bash
/usr/bin/python3 -m venv .venv                       # Python 3.9-3.13 (no matplotlib 3.9.4 wheels for 3.14+)
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m pytest -q                        # all tests
PYTHONPATH=src .venv/bin/python -m fault4 analyze    # outputs/results.json + run_log.txt
PYTHONPATH=src .venv/bin/python -m fault4 all        # + figures + report
./run_all.sh                                         # tests + full build + PDF export if LibreOffice is on PATH
```

## Rules that must hold

- Must run on macOS system Python **3.9**:
  - No `match`, no `X | Y` type unions at runtime, no `dataclass(slots=/kw_only=)`.
  - Use `typing.Optional/List/Dict`.
- Dependencies are pinned to exactly `matplotlib==3.9.4`, `python-docx==1.1.2` and `pytest==8.3.5`; everything else is stdlib.
- Paths come from `REPO_ROOT` in `src/fault4/data.py`, never from the cwd.
- `outputs/results.json` must be byte-identical across runs:
  - no timestamps;
  - `sort_keys=True`;
  - always `sorted()` a set before turning it into a list.
- `figures.py` calls `matplotlib.use("Agg")` before importing pyplot.
- Wording: RTO/RPO are *targets*. Computed values are "estimated recovery time" (24 min sequential, 20 min critical path) and "worst-case data loss" (4 min).
- TDD: write the failing test first, watch it fail, then implement. Commit after each task.

## Git

- `main` is the branch to keep as the GitHub default. Development happened on `claude/keen-rubin-w9hhpm`; after each
  finished batch, `main` is fast-forwarded to it (`git push origin HEAD:main`).
- If GitHub still shows `claude/keen-rubin-w9hhpm` as the default: Settings → Branches → Default branch → switch to `main`.

## Status

| Plan task | State |
|---|---|
| 1 Scaffold + data loader | done |
| 2 Part A classification | done |
| 3 Part B risk matrix | done |
| 4 Part C architecture model | done |
| 5 Part D recovery plan | done |
| 6 Part E anomaly detection | done |
| 7 Before/after simulation | done |
| 8 Pipeline, CLI, run log | done |
| 9 Figures | done |
| 10 Report (.docx) | done |
| 11 run_all.sh, README, Python 3.9 check, PDF render check | done |
| Final whole-branch review + fix pass | done (Figure 1 redrawn and described, hypervisor and backup tiers added) |

All plan tasks are finished. Further work is optional polish; see "Deferred" below.

`git log --oneline` shows the finished tasks (one `feat:` commit per task).

## Deferred (minor, not required for submission)

- Report wording branches on rto_met/rpo_met only implicitly (what-if runs with other intervals need wording review).
- run_all.sh converts report/Assignment4_Talgatov_Aibyn.docx to PDF even if --report-dir points elsewhere.
- CSV loaders do not accept an Excel UTF-8 BOM; no .gitattributes for line endings; shallow clones give a short
  work period; the page size is US Letter (python-docx default) rather than A4.

## Resume prompt (paste into Claude Code locally if the cloud session ran out)

```
Read CLAUDE.md and docs/superpowers/plans/2026-10-31-assignment4-security-resilience.md.
Check `git log --oneline` and the Status table in CLAUDE.md to see which plan tasks are done.
Continue executing the plan from the first unfinished task, task by task, with TDD
(write the failing test, run it, implement, run all tests with `.venv/bin/python -m pytest -q`, commit).
Keep every pinned number from the plan unchanged. Keep the code Python 3.9 compatible.
After the last task: run ./run_all.sh, open report/Assignment4_Talgatov_Aibyn.docx and check every page,
update the Status table in CLAUDE.md, commit, then push the branch and fast-forward main (git push origin HEAD:main).
```

## Things only the student can do before submission

- Fill in the variant code (if assigned), the submission date and the signature in the .docx; re-export the PDF.
- Run `./run_all.sh` on the Mac and save a terminal screenshot to `outputs/screenshots/macos_run.png`.
- Re-read §4 "Individual Work" and the AI-assistance line in References; rephrase them in your own words for the oral defence.
