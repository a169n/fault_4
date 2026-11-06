"""Render the report figures from the results dict (static PNGs for the .docx)."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Tuple

import matplotlib

matplotlib.use("Agg")  # never open a GUI window (macOS default backend would)

import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch, Rectangle  # noqa: E402

from fault4.data import OUTPUT_DIR  # noqa: E402

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


# ----------------------------------------------------------------------------------------------- architecture

def _zone(ax, x: float, y: float, w: float, h: float, title: str) -> None:
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0,rounding_size=1.2",
                                facecolor=ZONE_FILL, edgecolor=MUTED, linewidth=0.8))
    ax.text(x + 1, y + h - 1.2, title, ha="left", va="top", fontsize=8.5, fontweight="bold", color=TEXT_2)


def _component(ax, x: float, y: float, w: float, h: float, label: str, role: str = "", size: float = 7.6) -> None:
    edge = ROLE_COLOR.get(role, NEUTRAL_COMPONENT)
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0,rounding_size=0.8",
                                facecolor=_tint(edge, 0.14), edgecolor=edge, linewidth=1.6))
    ax.text(x + w / 2, y + h / 2, label, ha="center", va="center", fontsize=size, color=TEXT, linespacing=1.25)


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
    """Figure 1. The legend for (1)-(7) lives in the report text ("How to read Figure 1"), not in the image."""
    fig, ax = plt.subplots(figsize=(10, 7.4))
    ax.set_xlim(0, 100)
    ax.set_ylim(-10.5, 70)
    ax.axis("off")
    ax.set_title("Resilient research-server architecture (synthetic) and its control flow", loc="left")

    # Outside the perimeter.
    _zone(ax, 1, 46, 17, 18, "User VLAN\n10.20.4.0/24")
    _component(ax, 3, 49, 13, 8, "attacker host\n10.20.4.15")
    _zone(ax, 1, 25, 17, 18, "Internet")
    _component(ax, 3, 31.5, 13, 8, "unknown IP\n(09:13 target)")

    # Segmentation boundary.
    ax.add_patch(Rectangle((20.5, 1), 4.5, 63, facecolor=_tint(ROLE_COLOR["preventive"], 0.18),
                           edgecolor=ROLE_COLOR["preventive"], linewidth=1.6))
    ax.text(22.75, 15.5, "segmentation: OPNsense firewall,\nVLANs, egress allow-list", rotation=90, ha="center",
            va="center", fontsize=7.2, color=TEXT, linespacing=1.3)

    # Production zones.
    _zone(ax, 28, 46, 24, 18, "Access zone")
    _component(ax, 29.5, 48.5, 13, 11.5, "SSH bastion\n+ VPN with MFA\n(privacyIDEA,\nFIDO2 keys)", "preventive")
    _component(ax, 43.5, 48.5, 7, 11.5, "privileged\naccess:\nJIT sudo,\ntamper\nprotect.", "preventive")
    _zone(ax, 28, 25, 24, 18, "Research zone")
    _component(ax, 29.5, 34, 21, 5.5, "RS-01 primary server")
    _component(ax, 29.5, 30.4, 21, 2.9, "canary files · FIM agent", "detective", size=7.2)
    _component(ax, 29.5, 25.9, 21, 3.9, "hypervisor (④): VM pause,\nvNIC → quarantine VLAN", "recovery", size=6.8)
    _zone(ax, 28, 1, 24, 21, "Data zone")
    _component(ax, 29.5, 6, 21, 9, "PostgreSQL\nresearch database")

    # Protection and recovery zones.
    _zone(ax, 56, 46, 24, 18, "Security zone")
    _component(ax, 57.5, 55.4, 21, 5.4, "SIEM: Wazuh, Grafana\n(correlation, response)", "detective")
    _component(ax, 57.5, 47.3, 21, 5.5, "IDS: Suricata, FIM rules,\nAI anomaly scorer", "detective")
    _zone(ax, 56, 25, 24, 18, "Backup vault (pull-only)")
    _component(ax, 57.5, 26.5, 21, 12.5, "Tier 1: ZFS pull every 3 min\n(zfs hold) + DB WAL\n"
               "Tier 2: restic → MinIO\nObject Lock every 15 min", "recovery")
    _zone(ax, 56, 1, 24, 21, "Recovery zone (isolated VLAN)")
    _component(ax, 57.5, 4, 9.5, 12, "RS-02\nwarm\nstandby\n→ research\nVLAN", "recovery", size=7.2)
    _component(ax, 69, 4, 9.5, 12, "clean room\nrestore,\nscan,\nverify", "recovery")

    # Second site.
    _zone(ax, 82.5, 25, 17, 18, "Second site\nAlmaty, ~970 km")
    _component(ax, 84.5, 26.5, 13, 9.5, "offline copy\nlogical air gap\nmonthly drill", "recovery")

    blocked = LEVEL_COLOR["Critical"]
    response = ROLE_COLOR["detective"]
    # 1 access: attacker stopped by MFA at the bastion; authorised users continue to RS-01
    _path(ax, [(16, 53), (29.5, 53)], "1", (19.0, 55.6))
    ax.text(27.3, 53, "✕", ha="center", va="center", fontsize=13, fontweight="bold", color=blocked, zorder=6)
    _path(ax, [(42, 48.5), (42, 39.5)], "1", (39.3, 44.5))
    # 2 vault-initiated pulls: RS-01 snapshots and database WAL (arrow = direction of data)
    _path(ax, [(50.5, 36.75), (57.5, 36.75)], "2", (54.0, 39.1))
    _path(ax, [(50.5, 10.5), (54, 10.5), (54, 29), (57.5, 29)], "2", (54.0, 18.5))
    # 3 telemetry: bastion -> SIEM, RS-01 (FIM, canary) -> IDS -> SIEM
    _path(ax, [(50.5, 58.1), (57.5, 58.1)], "3", (54.0, 60.5), style=":")
    _path(ax, [(47, 39.5), (47, 44.5), (54.5, 44.5), (54.5, 50.0), (57.5, 50.0)], "3", (50.8, 44.5), style=":")
    _path(ax, [(68, 52.8), (68, 55.4)], style=":")
    # 4 response: SIEM -> segmentation (deny rule); the hypervisor strip carries the VM pause / quarantine VLAN
    _path(ax, [(75, 60.8), (75, 67), (22.75, 67), (22.75, 64)], "4", (45.0, 67), color=response)
    # 5 egress from RS-01 to the unknown IP, blocked at the boundary
    _path(ax, [(29.5, 35.5), (16, 35.5)], "5", (26.6, 38.0), color=blocked)
    ax.text(22.75, 35.5, "✕", ha="center", va="center", fontsize=14, fontweight="bold", color=blocked, zorder=6)
    # 6 restore: vault -> clean room -> RS-02 (then promoted into the research VLAN)
    _path(ax, [(77.5, 26.5), (77.5, 16)], "6", (75.2, 23.6))
    _path(ax, [(69, 10), (67, 10)])
    # 7 daily transfer to the offline copy
    _path(ax, [(78.5, 31.25), (84.5, 31.25)], "7", (81.5, 33.8), style="--")

    # Key: box colours and line styles.
    ax.text(1, -2.4, "Box colour:", fontsize=7.6, fontweight="bold", color=TEXT_2, va="center")
    for i, (label, color) in enumerate((("preventive", ROLE_COLOR["preventive"]),
                                        ("detective", ROLE_COLOR["detective"]),
                                        ("recovery", ROLE_COLOR["recovery"]),
                                        ("asset / external", NEUTRAL_COMPONENT))):
        x = 12 + i * 15
        ax.add_patch(Rectangle((x, -3.3), 2.6, 1.8, facecolor=_tint(color, 0.14), edgecolor=color, linewidth=1.4))
        ax.text(x + 3.4, -2.4, label, fontsize=7.6, color=TEXT, va="center")
    ax.text(1, -7.0, "Lines:", fontsize=7.6, fontweight="bold", color=TEXT_2, va="center")
    for x, (label, color, style) in zip((12, 27, 42, 63), (("data / access", TEXT_2, "-"), ("telemetry", TEXT_2, ":"),
                                                        ("automated response", response, "-"),
                                                        ("offline transfer", TEXT_2, "--"))):
        ax.plot([x, x + 3], [-7.0, -7.0], color=color, linestyle=style, linewidth=1.4)
        ax.text(x + 3.8, -7.0, label, fontsize=7.6, color=TEXT, va="center")
    ax.text(80, -7.0, "✕", fontsize=11, fontweight="bold", color=blocked, va="center")
    ax.text(82.5, -7.0, "blocked by a control", fontsize=7.6, color=TEXT, va="center")
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
    ax.set_title("Recovery plan schedule (critical path 1→2→4→5→6→7; step 3 runs alongside 4–5)", loc="left")
    handles = [Rectangle((0, 0), 1, 1, color=BLUE, label="on critical path"),
               Rectangle((0, 0), 1, 1, color=BLUE_LIGHT, label="has slack")]
    ax.legend(handles=handles, loc="lower right", fontsize=7.5, frameon=False)
    return _save(fig, path)


def render_all(results: Dict[str, Any], out_dir: Path = OUTPUT_DIR / "figures") -> List[Path]:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    return [
        render_architecture(results, out_dir / "architecture.png"),
        render_risk_matrix(results, out_dir / "risk_matrix.png"),
        render_anomaly_scores(results, out_dir / "anomaly_scores.png"),
        render_recovery_timeline(results, out_dir / "recovery_timeline.png"),
    ]
