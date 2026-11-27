# Roadmap

## Workstation qualification

- Accept a clean Omarchy installation and verify the native desktop launch.
- Qualify live AD enrollment, SSSD/PAM and SDDM login, including upgrades.
- Validate GVFS/Kerberos SMB access, CUPS queue changes and recovery, and
  optional Windows lifecycle and isolation on disposable systems.

## Inbound remote desktop

Inbound RDP is unavailable in this preview. Future qualification targets:

- Independent Hyprland remote sessions.
- Windows Remote Desktop Connection (`mstsc`) compatibility.
- Local-account remote desktop.
- Active Directory authentication.
- GPO-based authorization.
- Network Level Authentication (NLA) and Kerberos.
- Client drive redirection.

## Distribution and optional integrations

- Qualify signed package distribution and release key verification.
- Explore optional OCS Inventory integration.
- Explore optional Zabbix integration.
