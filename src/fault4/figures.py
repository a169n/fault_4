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

def _zone(ax, x: float, y: float, w: float, h: float, title: str, note: str = "", right: bool = False) -> None:
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0,rounding_size=1.2",
                                facecolor=ZONE_FILL, edgecolor=MUTED, linewidth=0.8))
    tx, ha = (x + w - 1, "right") if right else (x + 1, "left")
    ax.text(tx, y + h - 1.0, title, ha=ha, va="top", fontsize=8.5, fontweight="bold", color=TEXT_2)
    if note:
        ax.text(x + 1, y + 0.9, note, ha="left", va="bottom", fontsize=6.8, style="italic", color=TEXT_2)


def _component(ax, x: float, y: float, w: float, h: float, label: str, role: str = "", size: float = 7.4) -> None:
    edge = ROLE_COLOR.get(role, NEUTRAL_COMPONENT)
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0,rounding_size=0.8",
                                facecolor=_tint(edge, 0.14), edgecolor=edge, linewidth=1.6))
    ax.text(x + w / 2, y + h / 2, label, ha="center", va="center", fontsize=size, color=TEXT, linespacing=1.25)


def _path(ax, points, num=None, label_xy=None, color: str = TEXT_2, style: str = "-") -> None:
    """Orthogonal connector: straight segments through points, arrowhead on the last one."""
    xs, ys = zip(*points)
    ax.plot(xs, ys, color=color, linewidth=1.4, linestyle=style, solid_capstyle="butt", zorder=4)
    ax.add_patch(FancyArrowPatch(points[-2], points[-1], arrowstyle="-|>", mutation_scale=12, linewidth=0,
                                 color=color, shrinkA=0, shrinkB=0, zorder=5))
    if num is not None:
        _badge(ax, label_xy, num)


def _badge(ax, xy, num: str, size: float = 8.0) -> None:
    ax.text(*xy, num, ha="center", va="center", fontsize=size, fontweight="bold", color=TEXT, zorder=6,
            bbox=dict(boxstyle="circle,pad=0.2", facecolor=SURFACE, edgecolor=TEXT, linewidth=0.9))


def _blocked(ax, x: float, y: float) -> None:
    ax.text(x, y, "✕", ha="center", va="center", fontsize=13, fontweight="bold", color=LEVEL_COLOR["Critical"],
            zorder=6)


def render_architecture(results: Dict[str, Any], path: Path) -> Path:
    """Figure 1. Three rows (access, research, data/recovery) by four columns (outside, firewall, production,
    protection). Connectors run in the gaps between zones, in separate lanes, so no two lines cross.
    The legend for (1)-(7) lives in the report text ("How to read Figure 1")."""
    fig, ax = plt.subplots(figsize=(10, 7.6))
    ax.set_xlim(0, 100)
    ax.set_ylim(-10.5, 71)
    ax.axis("off")
    ax.set_title("Resilient research-server architecture (synthetic) and its control flow", loc="left")
    blocked = LEVEL_COLOR["Critical"]
    response = ROLE_COLOR["detective"]

    # Column 1: outside the perimeter.
    _zone(ax, 1, 47, 17, 18, "User VLAN\n10.20.4.0/24")
    _component(ax, 3, 50, 13, 7.5, "attacker host\n10.20.4.15")
    _zone(ax, 1, 24, 17, 20, "Internet")
    _component(ax, 3, 25.5, 13, 6.5, "unknown IP\n(09:13 target)")

    # Column 2: segmentation boundary.
    ax.add_patch(Rectangle((20.5, 1), 4.5, 64, facecolor=_tint(ROLE_COLOR["preventive"], 0.18),
                           edgecolor=ROLE_COLOR["preventive"], linewidth=1.6))
    ax.text(22.75, 16, "segmentation: OPNsense firewall,\nVLANs, egress allow-list", rotation=90, ha="center",
            va="center", fontsize=7.0, color=TEXT, linespacing=1.3)

    # Column 3: production zones.
    _zone(ax, 28, 47, 24, 18, "Access zone")
    _component(ax, 29.5, 54, 21, 7, "SSH bastion + VPN with MFA\n(privacyIDEA, FIDO2 keys)", "preventive")
    _component(ax, 33, 48.3, 17.5, 4.6, "privileged access: JIT sudo,\ntamper protection", "preventive",
               size=6.8)
    _zone(ax, 28, 24, 24, 20, "Research zone", right=True)
    _component(ax, 33, 37.3, 17.5, 3.3, "hypervisor: pause VM,\nmove to quarantine VLAN", "recovery", size=6.6)
    _component(ax, 33, 33.4, 17.5, 3.0, "canary files · FIM agent", "detective", size=6.8)
    _component(ax, 29.5, 25.5, 21, 7, "RS-01 primary server (VM)")
    _zone(ax, 28, 1, 24, 20, "Data zone")
    _component(ax, 29.5, 6, 21, 8, "PostgreSQL\nresearch database")

    # Column 4: protection and recovery zones.
    _zone(ax, 56, 47, 24, 18, "Security zone")
    _component(ax, 57.5, 55.5, 21, 6, "SIEM: Wazuh + Grafana\n(links alerts, starts response)", "detective")
    _component(ax, 57.5, 48.3, 21, 5, "IDS: Suricata, file rules,\nAI anomaly scorer", "detective")
    _zone(ax, 56, 24, 24, 20, "Backup vault (pull-only)")
    _component(ax, 57.5, 26, 21, 13.5, "Tier 1: snapshot every 3 min\n+ database log, zfs hold\n\n"
               "Tier 2: restic every 15 min\nMinIO + Object Lock", "recovery", size=7.0)
    _zone(ax, 56, 1, 24, 20, "Recovery zone", note="isolated VLAN, no internet")
    _component(ax, 57.5, 4.5, 10, 12, "RS-02 spare\nserver (warm)\njoins research\nnetwork after\nthe check",
               "recovery", size=6.8)
    _component(ax, 69.5, 4.5, 9, 12, "clean room:\nrestore,\nscan, verify", "recovery", size=7.0)

    # Column 5: second site.
    _zone(ax, 82.5, 24, 17, 20, "Second site\nAlmaty, ~970 km")
    _component(ax, 84.5, 26, 13, 10, "offline copy\nair-gapped,\ndaily window,\nmonthly drill", "recovery", size=7.0)

    # (1) access: the attacker is stopped by MFA at the bastion; authorised users continue down to RS-01.
    _path(ax, [(16, 57.5), (29.5, 57.5)], "1", (18.9, 60.3))
    _blocked(ax, 27.2, 57.5)
    _path(ax, [(31, 54), (31, 32.5)], "1", (31, 45.5))
    # (2) the vault pulls RS-01 snapshots and the database log (arrow = direction of data).
    _path(ax, [(50.5, 29.5), (57.5, 29.5)], "2", (54.2, 31.9))
    _path(ax, [(50.5, 10), (54.2, 10), (54.2, 27.5), (57.5, 27.5)], "2", (54.2, 16))
    # (3) telemetry: bastion -> SIEM; FIM agent -> IDS -> SIEM.
    _path(ax, [(50.5, 59.8), (57.5, 59.8)], "3", (54.2, 62.6), style=":")
    _path(ax, [(50.5, 34.9), (54.8, 34.9), (54.8, 50.8), (57.5, 50.8)], "3", (54.8, 41.5), style=":")
    _path(ax, [(68, 53.3), (68, 55.5)], style=":")
    # (4) automated response: SIEM -> hypervisor (pause, quarantine VLAN) and SIEM -> firewall (deny rule).
    _path(ax, [(57.5, 57), (53, 57), (53, 39), (50.5, 39)], "4", (53, 45.5), color=response)
    _path(ax, [(75, 61.5), (75, 68), (22.75, 68), (22.75, 65)], "4", (45, 68), color=response)
    # (5) egress from RS-01 to the unknown IP, blocked at the boundary.
    _path(ax, [(29.5, 28.75), (16, 28.75)], "5", (26.6, 31.4), color=blocked)
    _blocked(ax, 22.75, 28.75)
    # (6) restore: vault -> clean room -> RS-02.
    _path(ax, [(74, 26), (74, 16.5)], "6", (74, 21.6))
    _path(ax, [(69.5, 10.5), (67.5, 10.5)])
    # (7) daily transfer to the offline copy.
    _path(ax, [(78.5, 33), (84.5, 33)], "7", (81.5, 35.6), style="--")

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
