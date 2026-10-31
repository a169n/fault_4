import json
import os
import subprocess
import sys

from fault4.data import REPO_ROOT
from fault4.pipeline import run_analysis, write_outputs


def test_results_top_level_keys():
    assert set(run_analysis()) == {"tool_version", "data_sources", "incident", "risk", "controls", "recovery",
                                   "anomaly", "simulation"}


def test_data_sources_include_spec_pdf():
    assert set(run_analysis()["data_sources"]) == {
        "Assignment_4_AITU_Security_Resilience_Report_Template.pdf", "incident_events.csv", "anomaly_scores.csv",
        "scenarios.json"}


def test_results_json_byte_identical_across_processes(tmp_path):
    outs = []
    for seed in ("1", "2"):
        env = {**os.environ, "PYTHONPATH": str(REPO_ROOT / "src"), "PYTHONHASHSEED": seed}
        subprocess.run([sys.executable, "-m", "fault4", "analyze", "--out", str(tmp_path / seed)], env=env, check=True)
        outs.append((tmp_path / seed / "results.json").read_bytes())
    assert outs[0] == outs[1]


def test_write_outputs(tmp_path):
    write_outputs(run_analysis(), tmp_path, commit="abc1234")
    res = json.loads((tmp_path / "results.json").read_text(encoding="utf-8"))
    assert res["recovery"]["check"]["recovery_time_sequential"] == 24
    assert res["recovery"]["clean_points"] == {"preferred": "09:06", "fallback": "09:03"}
    assert "abc1234" in (tmp_path / "run_log.txt").read_text(encoding="utf-8")


def test_cli_runs_from_other_cwd(tmp_path):
    env = {**os.environ, "PYTHONPATH": str(REPO_ROOT / "src")}
    p = subprocess.run([sys.executable, "-m", "fault4", "analyze", "--out", str(tmp_path)], cwd=tmp_path, env=env)
    assert p.returncode == 0 and (tmp_path / "results.json").exists()
