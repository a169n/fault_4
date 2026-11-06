import os
import subprocess
import sys

from fault4.data import REPO_ROOT
from fault4.figures import render_all
from fault4.pipeline import run_analysis


def test_render_all_writes_four_pngs(tmp_path):
    paths = render_all(run_analysis(), tmp_path)
    assert sorted(p.name for p in paths) == ["anomaly_scores.png", "architecture.png", "recovery_timeline.png",
                                             "risk_matrix.png"]
    for p in paths:
        assert p.read_bytes()[:8] == b"\x89PNG\r\n\x1a\n" and p.stat().st_size > 10_000


def test_figures_forces_agg():
    env = {**os.environ, "MPLBACKEND": "svg", "PYTHONPATH": str(REPO_ROOT / "src")}
    out = subprocess.run([sys.executable, "-c", "import fault4.figures, matplotlib; print(matplotlib.get_backend())"],
                         env=env, capture_output=True, text=True, check=True).stdout
    assert out.strip().lower() == "agg"
