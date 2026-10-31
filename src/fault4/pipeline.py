"""Run every part of the analysis and write deterministic results plus a human-readable run log."""

from __future__ import annotations

import argparse
import json
import platform
import subprocess
import sys
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fault4 import __version__
from fault4.anomaly import ANOMALY_THRESHOLD, anomaly_summary, score_signals, threshold_sensitivity
from fault4.controls import COMPONENTS, THREAT_CONTROLS, coverage_gaps
from fault4.data import (
    CONFIG_DIR,
    DATA_DIR,
    OUTPUT_DIR,
    REPO_ROOT,
    REPORT_DIR,
    SPEC_PDF,
    fmt_minute,
    load_anomaly_signals,
    load_events,
    sha256_file,
)
from fault4.incident import attack_metrics, classify_events
from fault4.recovery import (
    RECOVERY_STEPS,
    REPLICATION_LAG_MIN,
    SNAPSHOT_INTERVAL_MIN,
    clean_restore_points,
    recovery_check,
    step_finish_times,
    target_time_cell,
)
from fault4.risk import IMPACT_RULE, LIKELIHOOD_RULE, THREATS, likelihood_sensitivity, prioritise
from fault4.simulation import load_scenarios, simulate

ASTANA = timezone(timedelta(hours=5))


def run_analysis(data_dir: Path = DATA_DIR, config_dir: Path = CONFIG_DIR) -> Dict[str, Any]:
    events_path = Path(data_dir) / "incident_events.csv"
    scores_path = Path(data_dir) / "anomaly_scores.csv"
    scenarios_path = Path(config_dir) / "scenarios.json"
    events = load_events(events_path)
    signals = load_anomaly_signals(scores_path)

    classified = classify_events(events)
    incident = {
        "events": [
            {
                "time": c.event.time,
                "event": c.event.description,
                "source": c.event.source,
                "severity": c.event.severity,
                "stage": c.stage,
                "evidence": c.evidence,
                "risk": c.risk,
                "attack_ref": c.attack_ref,
                "alternative": c.alternative,
            }
            for c in classified
        ],
        "metrics": attack_metrics(classified),
    }

    ranks = {t.threat: rank for rank, t in prioritise(THREATS)}
    risk = {
        "likelihood_rule": LIKELIHOOD_RULE,
        "impact_rule": IMPACT_RULE,
        "threats": [
            {
                "threat": t.threat,
                "likelihood": t.likelihood,
                "impact": t.impact,
                "score": t.score,
                "level": t.level,
                "rank": ranks[t.threat],
                "likelihood_reason": t.likelihood_reason,
                "impact_reason": t.impact_reason,
                "sensitivity": likelihood_sensitivity(t),
            }
            for t in THREATS
        ],
    }

    controls = {
        "components": [asdict(c) for c in COMPONENTS],
        "threat_controls": [asdict(t) for t in THREAT_CONTROLS],
        "coverage_gaps": coverage_gaps(),
    }

    check = recovery_check(RECOVERY_STEPS)
    finish = step_finish_times(RECOVERY_STEPS)
    first_malicious = next(e.minute for e in events if e.kind in ("files_modified", "files_encrypted"))
    access = next(e.minute for e in events if e.kind == "login_success")
    points = clean_restore_points(first_malicious, access, SNAPSHOT_INTERVAL_MIN)
    recovery = {
        "steps": [
            {**asdict(s), "finish_min": finish[s.number], "target_time": target_time_cell(s, finish[s.number])}
            for s in RECOVERY_STEPS
        ],
        "check": check,
        "snapshot_interval_min": SNAPSHOT_INTERVAL_MIN,
        "replication_lag_min": REPLICATION_LAG_MIN,
        "clean_points": {key: fmt_minute(minute) for key, minute in points.items()},
    }

    results = score_signals(signals, ANOMALY_THRESHOLD)
    anomaly = {
        "threshold": ANOMALY_THRESHOLD,
        "signals": [asdict(r) for r in results],
        "summary": anomaly_summary(results),
        "threshold_sensitivity": threshold_sensitivity(signals),
    }

    simulation = [
        asdict(simulate(events, scenario, check["recovery_time_sequential"]))
        for scenario in load_scenarios(scenarios_path)
    ]

    return {
        "tool_version": __version__,
        "data_sources": {
            SPEC_PDF.name: sha256_file(SPEC_PDF),
            events_path.name: sha256_file(events_path),
            scores_path.name: sha256_file(scores_path),
            scenarios_path.name: sha256_file(scenarios_path),
        },
        "incident": incident,
        "risk": risk,
        "controls": controls,
        "recovery": recovery,
        "anomaly": anomaly,
        "simulation": simulation,
    }


def git_commit(repo_root: Path = REPO_ROOT) -> Optional[str]:
    try:
        out = subprocess.run(
            ["git", "describe", "--always", "--dirty", "--abbrev=7"],
            cwd=str(repo_root), capture_output=True, text=True, check=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    return out.stdout.strip() or None


def _fmt_optional(value: Any, none_text: str) -> str:
    return none_text if value is None else str(value)


def format_run_log(results: Dict[str, Any], commit: Optional[str]) -> str:
    now = datetime.now(ASTANA).strftime("%Y-%m-%d %H:%M:%S")
    metrics = results["incident"]["metrics"]
    check = results["recovery"]["check"]
    summary = results["anomaly"]["summary"]
    lines = [
        "fault4 run log — Assignment 4 (synthetic data)",
        f"run at:        {now} (UTC+5, Astana)",
        f"python:        {sys.version.split()[0]} on {platform.platform()}",
        f"fault4:        v{results['tool_version']}",
        f"git commit:    {commit or 'unknown'}",
        "data sources (SHA-256):",
    ]
    lines += [f"  {name}: {digest}" for name, digest in sorted(results["data_sources"].items())]
    lines += ["", "Part A — incident classification"]
    lines += [f"  {e['time']}  {e['stage']:<21} {e['risk']:<9} {e['event']}" for e in results["incident"]["events"]]
    lines.append(
        f"  failed logins {metrics['failed_logins_total']}, compromise after {metrics['minutes_to_compromise']} min, "
        f"encryption {metrics['minutes_compromise_to_encryption']} min after compromise, "
        f"attack duration {metrics['attack_duration_minutes']} min, "
        f"{metrics['stage_categories_used']}/8 stage categories used"
    )
    lines += ["", "Part B — risk matrix (L x I)"]
    for t in sorted(results["risk"]["threats"], key=lambda t: t["rank"]):
        lines.append(f"  #{t['rank']} {t['threat']:<22} {t['likelihood']} x {t['impact']} = {t['score']:>2}  {t['level']}")
    gaps = results["controls"]["coverage_gaps"]
    lines += ["", "Part C — architecture coverage", f"  coverage gaps: {gaps if gaps else 'none'}"]
    lines += ["", "Part D — recovery plan"]
    lines += [f"  {s['number']}. {s['action']:<24} {s['target_time']}" for s in results["recovery"]["steps"]]
    lines.append(
        f"  estimated recovery time {check['recovery_time_sequential']} min sequential / "
        f"{check['recovery_time_critical_path']} min critical path (RTO {check['rto_target']}, met: {check['rto_met']})"
    )
    points = results["recovery"]["clean_points"]
    lines.append(
        f"  worst-case data loss {check['worst_case_data_loss']} min (RPO {check['rpo_target']}, met: {check['rpo_met']}); "
        f"clean points {points['preferred']} (preferred) / {points['fallback']} (fallback)"
    )
    lines += ["", "Part E — AI-assisted detection"]
    lines += [
        f"  {s['name']:<20} normal {s['normal']:.2f} observed {s['observed']:.2f} delta {s['delta']:.2f} "
        f"anomaly {s['is_anomaly']}"
        for s in results["anomaly"]["signals"]
    ]
    lines.append(
        f"  anomalies {summary['count']}/{summary['total']} = {summary['rate']:.0%}; highest priority "
        f"{summary['highest_priority']} (by ratio: {summary['highest_by_ratio']})"
    )
    sweep = ", ".join(f"{d['threshold']:.2f}->{d['count']}" for d in results["anomaly"]["threshold_sensitivity"])
    lines.append(f"  threshold sensitivity: {sweep}")
    lines += ["", "Before/after simulation"]
    header = f"  {'scenario':<27} {'access':<7} {'stopped':<8} {'files':>5} {'backup lost':<12} {'exfil':<6} {'loss':<6} recovery"
    lines.append(header)
    for r in results["simulation"]:
        lines.append(
            f"  {r['scenario']:<27} {str(r['attacker_access']):<7} {_fmt_optional(r['stopped_at'], '-'):<8} "
            f"{r['files_impacted']:>5} {str(r['backup_destroyed']):<12} {str(r['exfiltration_succeeded']):<6} "
            f"{_fmt_optional(r['data_loss_min'], 'unbnd'):<6} {_fmt_optional(r['recovery_time_min'], 'n/a')}"
        )
    return "\n".join(lines) + "\n"


def write_outputs(results: Dict[str, Any], out_dir: Path = OUTPUT_DIR, commit: Optional[str] = None) -> List[Path]:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    results_path = out_dir / "results.json"
    results_path.write_text(json.dumps(results, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
    log_path = out_dir / "run_log.txt"
    log_path.write_text(format_run_log(results, commit), encoding="utf-8")
    return [results_path, log_path]


def _figures(results: Dict[str, Any], out_dir: Path) -> List[Path]:
    from fault4.figures import render_all  # imported lazily: matplotlib is only needed for figures

    paths = render_all(results, out_dir)
    for path in paths:
        print(f"wrote {path}")
    return paths


def _report(results: Dict[str, Any], figures: List[Path], args: argparse.Namespace, commit: Optional[str]) -> Path:
    print("report: not yet available", file=sys.stderr)
    raise SystemExit(2)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m fault4", description="Assignment 4 analysis pipeline")
    parser.add_argument("command", nargs="?", default="all", choices=("analyze", "figures", "report", "all"))
    parser.add_argument("--out", type=Path, default=OUTPUT_DIR, help="directory for results, logs and figures")
    parser.add_argument("--report-dir", type=Path, default=REPORT_DIR, help="directory for the .docx report")
    parser.add_argument("--submission-date", default=None, help="date of submission to print in the report")
    args = parser.parse_args(argv)

    results = run_analysis()
    commit = git_commit()
    if args.command in ("analyze", "all"):
        for path in write_outputs(results, args.out, commit):
            print(f"wrote {path}")
    figures: List[Path] = []
    if args.command in ("figures", "report", "all"):
        figures = _figures(results, args.out / "figures")
    if args.command in ("report", "all"):
        print(f"wrote {_report(results, figures, args, commit)}")
    return 0
