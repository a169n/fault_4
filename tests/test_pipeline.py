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


def _git(repo, *args):
    subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t", *args], cwd=repo, check=True,
                   capture_output=True)


def test_git_commit_ignores_regenerated_outputs(tmp_path):
    from fault4.pipeline import git_commit

    (tmp_path / "src").mkdir()
    (tmp_path / "outputs").mkdir()
    (tmp_path / "src" / "m.py").write_text("x = 1\n")
    (tmp_path / "outputs" / "test_log.txt").write_text("1 passed\n")
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-q", "-m", "init")
    (tmp_path / "outputs" / "test_log.txt").write_text("1 passed in 0.2s\n")  # run_all.sh rewrites this
    assert not git_commit(tmp_path).endswith("-dirty")
    (tmp_path / "src" / "m.py").write_text("x = 2\n")  # a real input change
    assert git_commit(tmp_path).endswith("-dirty")


def test_work_period_accepts_git_utc_z_suffix(monkeypatch):
    # Apple git prints UTC commit times as "...Z"; Python 3.9's fromisoformat rejects that suffix.
    from fault4 import pipeline

    def fake_run(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 0, stdout="2026-10-31T05:43:26Z\n2026-10-31T06:00:00Z\n", stderr="")

    monkeypatch.setattr(pipeline.subprocess, "run", fake_run)
    start, _ = pipeline.work_period()
    assert start == "2026-10-31 10:43 (UTC+5, Astana)"
