# Roadmap

## Release acceptance

Features already exercised on the reference workstation are listed in the
[availability matrix](docs/availability.md). Remaining acceptance:

- Full integration on a clean Omarchy installation with the released package,
  including the native desktop launch and login after a system upgrade.
- Live Kerberos SMB access through GVFS and login-time bookmark sync.
- CUPS queue mutations and their recovery.
- Windows guest loopback connection and network isolation.

## Inbound remote desktop

Inbound RDP is unavailable in 0.5.0. Future qualification targets:

- Independent Hyprland remote sessions.
- Windows Remote Desktop Connection (`mstsc`) compatibility.
- Local-account remote desktop.
- Active Directory authentication.
- GPO-based authorization.
- Network Level Authentication (NLA) and Kerberos.
- Client drive redirection.

## Distribution and optional integrations

- Signed pacman repository: done in 0.5.0 (clean Arch install test passed).
- Explore optional OCS Inventory integration.
- Explore optional Zabbix integration.
