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
        "privacyIDEA TOTP/push via its PAM module on the SSH bastion and its FreeRADIUS plugin on the VPN; "
        "administrators additionally use FIDO2 OpenSSH keys (ed25519-sk); per-source-IP lockout at 10 failures / 5 min",
        "Access zone", "preventive", "MFA",
        "Preventive: stops a guessed password from becoming a session; it would have blocked the 09:04 login.",
    ),
    Component(
        "segmentation", "Network segmentation",
        "OPNsense firewall, VLANs, default-deny inter-zone rules, egress allow-list proxy, quarantine VLAN",
        "All zone boundaries", "preventive", "Network segmentation",
        "Preventive by design: 10.20.4.15 reaches RS-01 only through the bastion and unknown egress (09:13) "
        "is denied. Its quarantine VLAN is reused for containment in recovery step 2.",
    ),
    Component(
        "pam", "Privileged access management",
        "Just-in-time sudo, separate admin accounts, no standing root, agent tamper protection",
        "Access zone", "preventive", "supporting",
        "Preventive: backup deletion (09:12) and disabling antivirus (09:18) need a just-in-time approval "
        "the attacker does not have.",
    ),
    Component(
        "monitoring", "Monitoring / SIEM",
        "Wazuh SIEM + Prometheus/Grafana, correlation rules, active response",
        "Security zone", "detective", "Monitoring",
        "Detective: raises the 09:01 and 09:07 alerts and triggers responses, but blocks nothing itself.",
    ),
    Component(
        "ids", "Intrusion detection",
        "Suricata NIDS, Wazuh HIDS/FIM with canary files and an extension/entropy check, AI anomaly scorer",
        "Security zone", "detective", "Intrusion detection",
        "Detective: detects the encryption (09:07) and the unknown outbound connection (09:13).",
    ),
    Component(
        "immutable_backup", "Immutable backup",
        "ZFS snapshots every 3 min on RS-01; the vault pulls incrementals (zfs send -i | zfs receive, initiated "
        "from the vault) into its own pool with zfs hold; restic copy into a MinIO bucket with S3 Object Lock "
        "(compliance mode, 30 days); PostgreSQL WAL pulled continuously by pg_receivewal on the vault plus a "
        "nightly base backup; production holds no vault credentials",
        "Backup vault (pull-only)", "recovery", "Immutable backup",
        "Recovery: does not stop encryption, but guarantees an untouchable clean restore point "
        "(worst-case data loss 4 min).",
    ),
    Component(
        "failover", "Secure failover",
        "Research-Server-02: warm VM cloned from a golden image, holds no data, separate VLAN, promoted only "
        "after data is restored from a verified clean point",
        "Research zone", "recovery", "Secure failover",
        "Recovery: restores service on clean infrastructure within the RTO and never receives live-replicated "
        "(encrypted) data.",
    ),
    Component(
        "recovery_env", "Recovery environment",
        "Isolated clean-room VLAN without internet access: restore, scan, verify",
        "Recovery zone", "recovery", "Recovery environment",
        "Recovery: restored data is verified in isolation before it returns to production.",
    ),
    Component(
        "offline_copy", "Offline copy at a second Kazakhstan site",
        "Logically air-gapped copy in Almaty (~970 km from Astana): transfer window opened daily from the "
        "Almaty side only, monthly rotation to disconnected media, separate admin domain, monthly restore drill; "
        "data-loss tier 24 h",
        "Second site (Almaty)", "recovery", "Additional",
        "Recovery: last resort that survives compromise of the vault's admin plane or loss of the Astana site.",
    ),
)

THREAT_CONTROLS: Tuple[ThreatControls, ...] = (
    ThreatControls(
        "Credential attack",
        "MFA on the bastion and VPN; per-source-IP lockout at 10 failures / 5 min (per IP, not per account, so "
        "attackers cannot lock researchers out); SSH unreachable from the user VLAN",
        "SIEM alert at ≥10 failures / 5 min per source; \"success after failures\" correlation",
        "Respond: block the source, revoke sessions. Recover: rotate the password, re-enrol MFA, review account "
        "activity",
        ("mfa", "segmentation", "monitoring"),
    ),
    ThreatControls(
        "Ransomware",
        "Segmentation; least-privilege write access to research shares; noexec on /tmp, /dev/shm and "
        "user-writable mounts plus application allow-listing (fapolicyd)",
        "Canary-file write (immediate); FIM rate ≥100 changes/min AND extension/entropy change; CPU >90% and AI "
        "score used only as correlating signals",
        "Respond: automated quarantine + VM pause. Recover: restore data from the verified clean point onto RS-02 "
        "and verify it in the clean room",
        ("segmentation", "pam", "ids", "immutable_backup", "failover", "recovery_env"),
    ),
    ThreatControls(
        "Backup deletion",
        "Object Lock compliance mode; pull-based backups, so production holds no vault credentials; "
        "just-in-time admin",
        "Alert on any delete or retention-change API call, or a failed vault login",
        "Recover: restore from the locked copy; the offline Almaty copy is the last resort",
        ("immutable_backup", "pam", "monitoring", "offline_copy"),
    ),
    ThreatControls(
        "Data exfiltration",
        "Egress default-deny allow-list proxy; least-privilege database roles",
        "Suricata alert on a non-allow-listed destination and on volume anomalies; database query-rate anomaly",
        "Respond: block the destination, revoke database credentials. Recover: scope the leaked records, report "
        "to KZ-CERT, and notify the authorised personal-data body and data subjects where Law No. 94-V and "
        "university policy require it",
        ("segmentation", "pam", "ids", "monitoring"),
    ),
    ThreatControls(
        "Privilege escalation",
        "Just-in-time admin, no standing root, agent tamper protection",
        "Alert on AV/EDR stop, a new admin account, or sudo outside the just-in-time window",
        "Recover: rebuild the host from a golden image in the clean room; rotate all privileged credentials",
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
