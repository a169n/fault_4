"""Part C: resilient security architecture — components and threat-to-control mapping."""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Sequence, Tuple

REQUIRED_COMPONENTS = (
    "MFA",
    "Network segmentation",
    "Immutable backup",
    "Monitoring",
    "Intrusion detection",
    "Secure failover",
    "Recovery environment",
)
ROLES = ("preventive", "detective", "recovery")


@dataclass(frozen=True)
class Component:
    key: str
    name: str
    technology: str
    zone: str
    role: str
    satisfies: str
    why: str


@dataclass(frozen=True)
class ThreatControls:
    threat: str
    preventive: str
    detective: str
    recovery: str
    components: Tuple[str, ...]


COMPONENTS: Tuple[Component, ...] = (
    Component(
        "mfa", "Multi-factor authentication",
        "A second login step (a code from a phone app, or a hardware key for administrators) on the entry server "
        "and the VPN; the source address is blocked after 10 failed logins in 5 minutes",
        "Access zone", "preventive", "MFA",
        "Preventive: a guessed password alone no longer opens a session, so the 09:04 login would have failed.",
    ),
    Component(
        "segmentation", "Network segmentation",
        "A firewall splits the network into separate zones; traffic between zones and to the internet is blocked "
        "unless explicitly allowed; an infected machine can be moved into a closed quarantine zone",
        "All zone boundaries", "preventive", "Network segmentation",
        "Preventive: the attacker's computer can reach RS-01 only through the entry server, and the 09:13 "
        "connection to an unknown address is blocked.",
    ),
    Component(
        "pam", "Privileged access management",
        "Administrator rights only for a short, approved time window; no permanent administrator account; security "
        "software cannot be switched off without approval",
        "Access zone", "preventive", "supporting",
        "Preventive: deleting backups (09:12) and switching off antivirus (09:18) need an approval the attacker does "
        "not have.",
    ),
    Component(
        "monitoring", "Monitoring / SIEM",
        "Wazuh SIEM collects logs from all systems, links related events and raises alerts",
        "Security zone", "detective", "Monitoring",
        "Detective: raises the 09:01 and 09:07 alerts. It only gives orders; the hypervisor, firewall and login "
        "server carry out the response.",
    ),
    Component(
        "ids", "Intrusion detection",
        "Watches network traffic and file changes, including decoy (canary) files and files that suddenly look "
        "encrypted; the AI anomaly score is one more signal",
        "Security zone", "detective", "Intrusion detection",
        "Detective: notices the encryption (09:07) and the unknown outbound connection (09:13).",
    ),
    Component(
        "immutable_backup", "Immutable backup",
        "Tier 1: a snapshot every 3 minutes plus a continuous database log, locked so it cannot be deleted. "
        "Tier 2: a copy every 15 minutes, write-protected for 30 days. The backup store fetches the copies itself, "
        "so the server has no password to it",
        "Backup vault (pull-only)", "recovery", "Immutable backup",
        "Recovery against ransomware: it does not stop encryption, but keeps clean copies out of the attacker's "
        "reach. At most 4 minutes of work can be lost.",
    ),
    Component(
        "failover", "Secure failover",
        "Research-Server-02: a spare server built from a clean, checked system image. It holds no data and waits "
        "in a separate network; after the check it is promoted to replace RS-01",
        "Recovery zone (isolated VLAN; moved into the research VLAN on promotion)", "recovery", "Secure failover",
        "Recovery: service comes back on a clean server within the RTO, and the spare never receives the "
        "encrypted files.",
    ),
    Component(
        "recovery_env", "Recovery environment",
        "A clean room: a separate network without internet where restored data is scanned and checked",
        "Recovery zone (isolated VLAN)", "recovery", "Recovery environment",
        "Recovery: restored data is checked in isolation before it goes back into use.",
    ),
    Component(
        "hypervisor", "Virtualisation host (hypervisor)",
        "The software that runs RS-01 and RS-02 as virtual machines; on an alert it pauses RS-01, moves it into the "
        "quarantine VLAN and saves a copy of its memory and disk as evidence",
        "Research zone (platform)", "recovery", "supporting",
        "Response point. The template has no “respond” column, so it is listed under recovery.",
    ),
    Component(
        "offline_copy", "Offline copy at a second Kazakhstan site",
        "A copy of the backups in Almaty (~970 km from Astana), connected only during a short daily transfer and "
        "managed by different administrators; tested by a monthly restore drill",
        "Second site (Almaty)", "recovery", "Additional",
        "Recovery: last resort if the backup administrators are compromised or the whole Astana site is lost.",
    ),
)

THREAT_CONTROLS: Tuple[ThreatControls, ...] = (
    ThreatControls(
        "Credential attack",
        "MFA (a second login step); block the source address after 10 failed logins in 5 minutes; remote login "
        "only through the entry server",
        "Alert on many failed logins from one address, and on a successful login right after them",
        "Respond: block the source and end its sessions. Recover: change the password, re-issue MFA, review what "
        "the account did",
        ("mfa", "segmentation", "monitoring"),
    ),
    ThreatControls(
        "Ransomware",
        "Separate network zones; each account can change only the files it needs; only approved programs may run",
        "Alert when a decoy file changes, or when more than 100 files per minute change and start to look "
        "encrypted; CPU load and the AI score support the alert",
        "Respond: the hypervisor pauses RS-01 and cuts it off the network. Recover: restore the last clean backup "
        "onto the spare server RS-02, check it, then switch users to RS-02",
        ("segmentation", "pam", "ids", "hypervisor", "immutable_backup", "failover", "recovery_env"),
    ),
    ThreatControls(
        "Backup deletion",
        "The backup store fetches copies itself, so the server has no password to it; copies are locked against "
        "deletion; administrator rights only on approval",
        "Alert on any attempt to delete backups or shorten how long they are kept, and on failed logins to the "
        "backup store",
        "Recover: restore from tier 1, then from the locked tier 2 copy; the offline Almaty copy is the last resort",
        ("immutable_backup", "pam", "monitoring", "offline_copy"),
    ),
    ThreatControls(
        "Data exfiltration",
        "Servers may connect only to an approved list of outside addresses; database accounts see only the tables "
        "they need",
        "Alert on connections to unknown addresses, unusually large uploads, and unusually many database queries",
        "Respond: block the address and change the database passwords. Recover: find out which data left, report "
        "to KZ-CERT and notify the people affected as Law No. 94-V requires",
        ("segmentation", "pam", "ids", "monitoring"),
    ),
    ThreatControls(
        "Privilege escalation",
        "Administrator rights only for a short approved time; no permanent administrator account; antivirus cannot "
        "be switched off",
        "Alert when antivirus stops, a new administrator account appears, or admin commands run without approval",
        "Recover: rebuild the server from a clean system image; change all administrator passwords",
        ("pam", "monitoring", "recovery_env"),
    ),
)


def coverage_gaps(
    components: Sequence[Component] = COMPONENTS,
    threat_controls: Sequence[ThreatControls] = THREAT_CONTROLS,
) -> List[str]:
    """Problems with the architecture model; an empty list means full coverage."""
    gaps = []
    present = {c.satisfies for c in components}
    gaps += [f"required component missing: {name}" for name in REQUIRED_COMPONENTS if name not in present]
    gaps += [f"component {c.key} has invalid role {c.role!r}" for c in components if c.role not in ROLES]
    keys = {c.key for c in components}
    used = set()
    for t in threat_controls:
        for column in ("preventive", "detective", "recovery"):
            if not getattr(t, column).strip():
                gaps.append(f"threat {t.threat} has an empty {column} control")
        for key in t.components:
            if key not in keys:
                gaps.append(f"threat {t.threat} references unknown component {key}")
            used.add(key)
    gaps += [f"component {key} is not used by any threat" for key in sorted(keys - used)]
    return sorted(gaps)
