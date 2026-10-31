"""Render the report figures from the results dict (static PNGs for the .docx)."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Tuple

import matplotlib

matplotlib.use("Agg")  # never open a GUI window (macOS default backend would)

import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch, Rectangle  # noqa: E402

from fault4.data import OUTPUT_DIR  # noqa: E402
from fault4.report_content import ARCHITECTURE_FLOW  # noqa: E402

DPI = 150
SURFACE = "#ffffff"
TEXT = "#0b0b0b"
TEXT_2 = "#52514e"
MUTED = "#a3a29c"
GRID = "#e4e3df"
ZONE_FILL = "#f3f2ef"
# Validated categorical slots 1-3 (all-pairs, light mode) encode control roles.
ROLE_COLOR = {"preventive": "#2a78d6", "detective": "#eb6834", "recovery": "#1baf7a"}
NEUTRAL_COMPONENT = "#7a7974"
# Status palette encodes risk level; always shipped with a text label.
LEVEL_COLOR = {"Low": "#0ca30c", "Medium": "#fab219", "High": "#ec835a", "Critical": "#d03b3b"}
BLUE = "#2a78d6"
BLUE_LIGHT = "#86b6ef"

plt.rcParams.update({
    "font.family": "DejaVu Sans",
    "font.size": 9,
    "axes.edgecolor": MUTED,
    "axes.labelcolor": TEXT_2,
    "xtick.color": TEXT_2,
    "ytick.color": TEXT_2,
    "axes.titleweight": "bold",
    "axes.titlesize": 11,
    "axes.titlecolor": TEXT,
    "figure.facecolor": SURFACE,
    "axes.facecolor": SURFACE,
    "savefig.facecolor": SURFACE,
})


def _tint(hex_color: str, amount: float) -> Tuple[float, float, float]:
    """Mix a color with white; amount=0 -> white, 1 -> the color."""
    r, g, b = (int(hex_color[i:i + 2], 16) / 255 for i in (1, 3, 5))
    return (1 - amount + amount * r, 1 - amount + amount * g, 1 - amount + amount * b)


def _save(fig: "plt.Figure", path: Path) -> Path:
    fig.savefig(path, dpi=DPI, bbox_inches="tight", pad_inches=0.15)
    plt.close(fig)
    return path


def _minute(hhmm: str) -> int:
    hours, minutes = hhmm.split(":")
    return int(hours) * 60 + int(minutes)


# ----------------------------------------------------------------------------------------------- architecture

def _zone(ax, x: float, y: float, w: float, h: float, title: str) -> None:
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0,rounding_size=1.2",
                                facecolor=ZONE_FILL, edgecolor=MUTED, linewidth=0.8))
    ax.text(x + 1, y + h - 1.2, title, ha="left", va="top", fontsize=8.5, fontweight="bold", color=TEXT_2)


def _component(ax, x: float, y: float, w: float, h: float, label: str, role: str = "") -> None:
    edge = ROLE_COLOR.get(role, NEUTRAL_COMPONENT)
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0,rounding_size=0.8",
                                facecolor=_tint(edge, 0.14), edgecolor=edge, linewidth=1.6))
    ax.text(x + w / 2, y + h / 2, label, ha="center", va="center", fontsize=7.6, color=TEXT, linespacing=1.25)


def _path(ax, points, num=None, label_xy=None, color: str = TEXT_2, style: str = "-") -> None:
    """Orthogonal connector: straight segments through points, arrowhead on the last one."""
    xs, ys = zip(*points)
    ax.plot(xs[:-1] + (xs[-1],), ys[:-1] + (ys[-1],), color=color, linewidth=1.4, linestyle=style,
            solid_capstyle="butt", zorder=4)
    ax.add_patch(FancyArrowPatch(points[-2], points[-1], arrowstyle="-|>", mutation_scale=12, linewidth=0,
                                 color=color, shrinkA=0, shrinkB=0, zorder=5))
    if num is not None:
        _badge(ax, label_xy, num)


def _badge(ax, xy, num: str, size: float = 8.5) -> None:
    ax.text(*xy, num, ha="center", va="center", fontsize=size, fontweight="bold", color=TEXT, zorder=6,
            bbox=dict(boxstyle="circle,pad=0.2", facecolor=SURFACE, edgecolor=TEXT, linewidth=0.9))


def render_architecture(results: Dict[str, Any], path: Path) -> Path:
    fig, ax = plt.subplots(figsize=(10, 8.4))
    ax.set_xlim(0, 100)
    ax.set_ylim(-17.5, 70)
    ax.axis("off")
    ax.set_title("Resilient research-server architecture (synthetic) and its control flow", loc="left")

    # Column A — outside the perimeter.
    _zone(ax, 1, 46, 17, 18, "User VLAN\n10.20.4.0/24")
    _component(ax, 3, 49, 13, 8, "attacker host\n10.20.4.15")
    _zone(ax, 1, 25, 17, 18, "Internet")
    _component(ax, 3, 31.5, 13, 8, "unknown IP\n(09:13 target)")
    ax.text(1.5, 20.5, "Colour = control role", fontsize=7.8, fontweight="bold", color=TEXT_2, va="center")
    for i, (label, color) in enumerate((("preventive", ROLE_COLOR["preventive"]),
                                        ("detective", ROLE_COLOR["detective"]),
                                        ("recovery", ROLE_COLOR["recovery"]),
                                        ("asset / external", NEUTRAL_COMPONENT))):
        y = 16.5 - i * 3.6
        ax.add_patch(Rectangle((1.5, y - 1.0), 2.8, 2.0, facecolor=_tint(color, 0.14), edgecolor=color, linewidth=1.4))
        ax.text(5.2, y, label, fontsize=7.6, color=TEXT, va="center")

    # Column B — segmentation boundary.
    ax.add_patch(Rectangle((20.5, 1), 4.5, 63, facecolor=_tint(ROLE_COLOR["preventive"], 0.18),
                           edgecolor=ROLE_COLOR["preventive"], linewidth=1.6))
    ax.text(22.75, 16.5, "OPNsense firewall\nsegmentation · egress allow-list", rotation=90, ha="center",
            va="center", fontsize=7.2, color=TEXT, linespacing=1.3)

    # Column C — production.
    _zone(ax, 28, 46, 24, 18, "Access zone")
    _component(ax, 29.5, 48.5, 13, 11.5, "SSH bastion\n+ VPN with MFA\n(privacyIDEA,\nFIDO2 keys)", "preventive")
    _component(ax, 43.5, 48.5, 7, 11.5, "PAM:\nJIT sudo,\ntamper\nprotect.", "preventive")
    _zone(ax, 28, 25, 24, 18, "Research zone")
    _component(ax, 29.5, 32.5, 21, 6.5, "RS-01 primary server")
    _component(ax, 29.5, 26.5, 21, 4.5, "canary files · FIM agent", "detective")
    _zone(ax, 28, 1, 24, 21, "Data zone")
    _component(ax, 29.5, 6, 21, 9, "PostgreSQL\nresearch database")

    # Column D — protection and recovery.
    _zone(ax, 56, 46, 24, 18, "Security zone")
    _component(ax, 57.5, 54.5, 21, 5.8, "Monitoring: Wazuh SIEM,\nPrometheus / Grafana", "detective")
    _component(ax, 57.5, 47.5, 21, 5.8, "IDS: Suricata, HIDS/FIM,\nAI anomaly scorer", "detective")
    _zone(ax, 56, 25, 24, 18, "Backup vault (pull-only)")
    _component(ax, 57.5, 26.5, 21, 12.5, "Immutable backup\nZFS snapshots every 3 min\nObject Lock, 30 days\n"
               "DB WAL via pg_receivewal", "recovery")
    _zone(ax, 56, 1, 24, 21, "Recovery environment")
    _component(ax, 57.5, 4, 9, 12, "RS-02\nwarm\nstandby", "recovery")
    _component(ax, 69, 4, 9.5, 12, "clean room\nrestore,\nscan,\nverify", "recovery")

    # Column E — second site.
    _zone(ax, 82.5, 25, 17, 18, "Second site\nAlmaty, ~970 km")
    _component(ax, 84.5, 26.5, 13, 9.5, "offline copy\nlogical air gap\nmonthly drill", "recovery")

    # 1 access path: attacker -> firewall -> bastion (MFA) -> RS-01
    _path(ax, [(16, 53), (29.5, 53)], "1", (19.0, 55.6))
    _path(ax, [(42, 48.5), (42, 39)], "1", (39.3, 44.5))
    # 2 backups pulled by the vault: RS-01 snapshots and database WAL
    _path(ax, [(50.5, 36), (57.5, 36)], "2", (54.0, 38.4))
    _path(ax, [(50.5, 10.5), (54, 10.5), (54, 29), (57.5, 29)], "2", (54.0, 18.5))
    # 3 logs / FIM / canary events to the security zone
    _path(ax, [(47, 39), (47, 44.5), (54.5, 44.5), (54.5, 50.4), (57.5, 50.4)], "3", (50.8, 44.5), style=":")
    # 4 SIEM triggers quarantine on the firewall
    _path(ax, [(75, 60.3), (75, 67), (22.75, 67), (22.75, 64)], "4", (45.0, 67), color=ROLE_COLOR["detective"])
    # 5 egress from RS-01 to the unknown IP, denied at the firewall
    _path(ax, [(29.5, 35.5), (16, 35.5)], "5", (26.6, 38.0), color=LEVEL_COLOR["Critical"])
    ax.text(22.75, 35.5, "✕", ha="center", va="center", fontsize=14, fontweight="bold",
            color=LEVEL_COLOR["Critical"], zorder=6)
    # 6 restore: vault -> clean room -> RS-02 (promoted to production)
    _path(ax, [(77.5, 26.5), (77.5, 16)], "6", (75.2, 23.6))
    _path(ax, [(69, 10), (66.5, 10)])
    # 7 daily transfer to the offline copy
    _path(ax, [(78.5, 31.25), (84.5, 31.25)], "7", (81.5, 33.8), style="--")

    for i, (title, text) in enumerate(ARCHITECTURE_FLOW):
        y = -1.6 - i * 2.25
        _badge(ax, (1.8, y), str(i + 1), size=7.2)
        ax.text(3.8, y, f"{title}: ", fontsize=7.6, fontweight="bold", color=TEXT, va="center")
        ax.text(18.8, y, text, fontsize=7.6, color=TEXT_2, va="center")
    return _save(fig, path)


# ----------------------------------------------------------------------------------------------- attack timeline

def render_attack_timeline(results: Dict[str, Any], path: Path) -> Path:
    events = results["incident"]["events"]
    n = len(events)
    fig, ax = plt.subplots(figsize=(10, 4.9))
    for i, e in enumerate(events):
        y = n - 1 - i
        x = _minute(e["time"])
        ax.plot([539.5, x], [y, y], color=GRID, linewidth=0.8, zorder=1)
        ax.scatter([x], [y], s=75, color=LEVEL_COLOR[e["risk"]], edgecolor=SURFACE, linewidth=1.5, zorder=3)
        ax.annotate(f"{e['stage']}  ·  {e['risk']}", (x, y), xytext=(8, 0), textcoords="offset points",
                    va="center", fontsize=7.6, color=TEXT)
    markers = {r["scenario"]: r["stopped_at"] for r in results["simulation"]}
    for key, label, style, side in (("hardened", "hardened:\nstopped", "-", "left"),
                                    ("hardened_assume_breach", "assume breach:\nisolated", "--", "right"),
                                    ("hardened_manual_isolation", "manual:\nisolated", ":", "left")):
        if markers.get(key):
            x = _minute(markers[key])
            ax.axvline(x, color=TEXT_2, linestyle=style, linewidth=1.1, zorder=2)
            dx = 0.15 if side == "left" else -0.15
            ax.text(x + dx, n - 0.35, f"{label} {markers[key]}", ha=side, va="bottom", fontsize=7, color=TEXT_2)
    ax.set_yticks(range(n))
    ax.set_yticklabels([f"{e['time']}  {e['event']}" for e in reversed(events)])
    ticks = list(range(540, 561, 2))
    ax.set_xticks(ticks)
    ax.set_xticklabels([f"{t // 60:02d}:{t % 60:02d}" for t in ticks])
    ax.set_xlim(539.5, 566)
    ax.set_ylim(-0.7, n + 0.6)
    ax.grid(axis="x", color=GRID, linewidth=0.6)
    ax.set_axisbelow(True)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    ax.tick_params(axis="y", length=0)
    ax.set_title("Attack timeline: stage and assessed risk per event, with simulated containment times", loc="left",
                 pad=28)
    handles = [plt.Line2D([], [], marker="o", linestyle="", markersize=7, color=LEVEL_COLOR[k], label=k)
               for k in ("Medium", "High", "Critical")]
    ax.legend(handles=handles, title="assessed risk", loc="lower right", fontsize=7.5, title_fontsize=7.5,
              frameon=False)
    return _save(fig, path)


# ----------------------------------------------------------------------------------------------- risk matrix

def render_risk_matrix(results: Dict[str, Any], path: Path) -> Path:
    from fault4.risk import risk_level

    fig, ax = plt.subplots(figsize=(7.2, 6.2))
    cells: Dict[Tuple[int, int], List[str]] = {}
    for t in results["risk"]["threats"]:
        first, _, rest = t["threat"].partition(" ")
        cells.setdefault((t["impact"], t["likelihood"]), []).append(f"#{t['rank']} {first}\n{rest}" if rest else
                                                                  f"#{t['rank']} {first}")
    for impact in range(1, 6):
        for likelihood in range(1, 6):
            score = impact * likelihood
            level = risk_level(score)
            ax.add_patch(Rectangle((impact - 0.5, likelihood - 0.5), 1, 1, facecolor=_tint(LEVEL_COLOR[level], 0.38),
                                   edgecolor=SURFACE, linewidth=2))
            ax.text(impact - 0.44, likelihood + 0.42, str(score), fontsize=7, color=TEXT_2, va="top", ha="left")
            names = cells.get((impact, likelihood))
            if names:
                ax.text(impact, likelihood - 0.06, "\n".join(names), ha="center", va="center", fontsize=7.4,
                        color=TEXT, fontweight="bold", linespacing=1.15)
    ax.set_xlim(0.5, 5.5)
    ax.set_ylim(0.5, 5.5)
    ax.set_xticks(range(1, 6))
    ax.set_yticks(range(1, 6))
    ax.set_xlabel("Impact (1–5)")
    ax.set_ylabel("Likelihood (1–5)")
    ax.set_aspect("equal")
    for spine in ax.spines.values():
        spine.set_visible(False)
    ax.tick_params(length=0)
    ax.set_title("Risk matrix: Risk = Likelihood × Impact (cell number = score)", loc="left")
    handles = [Rectangle((0, 0), 1, 1, facecolor=_tint(LEVEL_COLOR[k], 0.38), edgecolor=LEVEL_COLOR[k], label=lab)
               for k, lab in (("Low", "Low 1–4"), ("Medium", "Medium 5–9"), ("High", "High 10–16"),
                              ("Critical", "Critical 17–25"))]
    ax.legend(handles=handles, loc="upper center", bbox_to_anchor=(0.5, -0.11), ncol=4, fontsize=7.5, frameon=False)
    return _save(fig, path)


# ----------------------------------------------------------------------------------------------- anomaly scores

def render_anomaly_scores(results: Dict[str, Any], path: Path) -> Path:
    signals = results["anomaly"]["signals"]
    threshold = results["anomaly"]["threshold"]
    top = results["anomaly"]["summary"]["highest_priority"]
    fig, ax = plt.subplots(figsize=(9, 4.2))
    height = 0.36
    for i, s in enumerate(reversed(signals)):
        ax.barh(i + height / 2 + 0.01, s["normal"], height=height, color=MUTED, label="normal score" if i == 0 else None)
        ax.barh(i - height / 2 - 0.01, s["observed"], height=height, color=BLUE,
                label="observed score" if i == 0 else None)
        ax.text(s["observed"] + 0.012, i - height / 2 - 0.01, f"{s['observed']:.2f}  (Δ {s['delta']:.2f})",
                va="center", fontsize=7.8, color=TEXT, fontweight="bold" if s["name"] == top else "normal")
        ax.text(s["normal"] + 0.012, i + height / 2 + 0.01, f"{s['normal']:.2f}", va="center", fontsize=7.5,
                color=TEXT_2)
    ax.axvline(threshold, color=LEVEL_COLOR["Critical"], linestyle="--", linewidth=1.2)
    ax.text(threshold + 0.005, len(signals) - 0.45, f"anomaly threshold {threshold:.2f}", fontsize=7.5,
            color=TEXT, va="bottom")
    ax.set_yticks(range(len(signals)))
    ax.set_yticklabels([f"{s['name']}{'  (highest priority)' if s['name'] == top else ''}" for s in reversed(signals)])
    ax.set_xlim(0, 1.12)
    ax.set_ylim(-0.7, len(signals) - 0.1)
    ax.set_xlabel("score")
    ax.grid(axis="x", color=GRID, linewidth=0.6)
    ax.set_axisbelow(True)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    summary = results["anomaly"]["summary"]
    ax.set_title(f"AI anomaly scores: {summary['count']}/{summary['total']} signals ≥ {threshold:.2f} "
                 f"({summary['rate']:.0%})", loc="left")
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.16), ncol=2, fontsize=7.5, frameon=False)
    return _save(fig, path)


# ----------------------------------------------------------------------------------------------- recovery gantt

def render_recovery_timeline(results: Dict[str, Any], path: Path) -> Path:
    steps = results["recovery"]["steps"]
    check = results["recovery"]["check"]
    total = check["recovery_time_critical_path"]
    latest_finish = {s["number"]: total for s in steps}
    for s in reversed(steps):  # backward pass for slack
        successors = [t for t in steps if s["number"] in t["depends_on"]]
        if successors:
            latest_finish[s["number"]] = min(latest_finish[t["number"]] - t["duration_min"] for t in successors)
    fig, ax = plt.subplots(figsize=(9, 4.2))
    for i, s in enumerate(steps):
        y = len(steps) - 1 - i
        start = s["finish_min"] - s["duration_min"]
        critical = latest_finish[s["number"]] == s["finish_min"]
        ax.barh(y, s["duration_min"], left=start, height=0.62, color=BLUE if critical else BLUE_LIGHT,
                edgecolor=SURFACE, linewidth=1.5)
        ax.text(s["finish_min"] + 0.25, y, f"{s['duration_min']} min → T+{s['finish_min']}", va="center",
                fontsize=7.5, color=TEXT)
    for x, label, color, style in (
        (check["recovery_time_critical_path"], f"critical path {check['recovery_time_critical_path']} min", TEXT_2, "-"),
        (check["recovery_time_sequential"], f"sequential estimate {check['recovery_time_sequential']} min", TEXT_2,
         "--"),
        (check["rto_target"], f"RTO target {check['rto_target']} min", LEVEL_COLOR["Critical"], "-"),
    ):
        ax.axvline(x, color=color, linestyle=style, linewidth=1.2)
        ax.text(x + 0.15, len(steps) - 0.45, label, rotation=90, va="top", ha="left", fontsize=7.2, color=TEXT_2)
    ax.set_yticks(range(len(steps)))
    ax.set_yticklabels([f"{s['number']}. {s['action']}" for s in reversed(steps)])
    ax.set_xlim(0, check["rto_target"] + 2)
    ax.set_xlabel("minutes after first malicious change (T = 09:07)")
    ax.grid(axis="x", color=GRID, linewidth=0.6)
    ax.set_axisbelow(True)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    ax.set_title("Recovery plan schedule (steps 3 and 4 in parallel)", loc="left")
    handles = [Rectangle((0, 0), 1, 1, color=BLUE, label="on critical path"),
               Rectangle((0, 0), 1, 1, color=BLUE_LIGHT, label="has slack")]
    ax.legend(handles=handles, loc="lower right", fontsize=7.5, frameon=False)
    return _save(fig, path)


def render_all(results: Dict[str, Any], out_dir: Path = OUTPUT_DIR / "figures") -> List[Path]:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    return [
        render_architecture(results, out_dir / "architecture.png"),
        render_attack_timeline(results, out_dir / "attack_timeline.png"),
        render_risk_matrix(results, out_dir / "risk_matrix.png"),
        render_anomaly_scores(results, out_dir / "anomaly_scores.png"),
        render_recovery_timeline(results, out_dir / "recovery_timeline.png"),
    ]
