# Feature availability

Omarchy Enterprise was developed on a real, physical Omarchy workstation (the
*reference workstation*) joined to a real Active Directory domain, not only
with offline tests or simulated environments. This matrix separates what was
exercised there during development from what still needs acceptance for the
released `0.5.0-1` package.

| Status | Meaning |
| --- | --- |
| `IMPLEMENTED` | The feature is present in 0.5.0. |
| `OFFLINE_TESTED` | The 163 retained regression tests cover the stated scope with fixtures and adapters. |
| `REFERENCE_HOST_TESTED` | Functionally exercised on the reference workstation during development, within the stated scope. |
| `PENDING_RELEASE_ACCEPTANCE` | Still to be accepted for the released package, for example on a clean Omarchy installation, or only partially exercised so far. |
| `ROADMAP` | Future work; not available in 0.5.0. |

| Workflow | Status | Scope already tested | Remaining acceptance (`PENDING_RELEASE_ACCEPTANCE`) |
| --- | --- | --- | --- |
| Standalone deployment, rollback and packaging | `IMPLEMENTED`, `OFFLINE_TESTED`, `REFERENCE_HOST_TESTED` | Reference workstation: Standalone deployment and rollback, package upgrades. Clean Arch environment: the signed `0.5.0-1` package installed from the signed pacman repository with database and package signatures verified, 0 altered files, clean removal. Offline: staging, dry run and package verification. | Full installation on a clean Omarchy 4.5 workstation. |
| GTK4 Control Center | `IMPLEMENTED`, `OFFLINE_TESTED`, `REFERENCE_HOST_TESTED` | Reference workstation: native GTK4/Libadwaita launch and navigation. Offline: UI models and translations. | Launch from the released package on a clean Omarchy installation. |
| Active Directory, Samba, SSSD and Kerberos | `IMPLEMENTED`, `OFFLINE_TESTED`, `REFERENCE_HOST_TESTED` | Reference workstation: domain enrollment with Samba ADS, machine trust and Winbind verification, SSSD configuration with NSS and PAM integration, Kerberos authentication and ticket acquisition. Offline: configuration review and diagnostics. | Repeat enrollment with the released package on a clean Omarchy installation. |
| Graphical login and multi-user | `IMPLEMENTED`, `OFFLINE_TESTED`, `REFERENCE_HOST_TESTED` | Reference workstation: SDDM graphical login with domain and local accounts, domain home directory provisioning, administrative permissions and multi-user integration. Offline: review and opt-in staging. | Clean-install integration, including login after a system upgrade. |
| File servers (SMB, Nautilus/GVFS) | `IMPLEMENTED`, `OFFLINE_TESTED`, `REFERENCE_HOST_TESTED` (partial) | Reference workstation: SMB file server access and Nautilus/GVFS integration exercised during development. Offline: policy, managed bookmarks and recovery. | Live Kerberos SMB authentication through GVFS and login-time bookmark sync. |
| Printers (CUPS) | `IMPLEMENTED`, `OFFLINE_TESTED`, `REFERENCE_HOST_TESTED` (partial) | Reference workstation: CUPS printer discovery and queue inspection. Offline: discovery adapters and IPP/IPPS queue plans. | Queue mutations (creation, endpoint updates, undo) and their recovery. |
| Enterprise Guard, backup and recovery | `IMPLEMENTED`, `OFFLINE_TESTED`, `REFERENCE_HOST_TESTED` | Reference workstation: Guard baseline checks and its Pacman hook, configuration backup and recovery. Offline: policy and scoped recovery. | Clean-install acceptance and site-specific hook review. |
| Optional Windows workspace | `IMPLEMENTED`, `OFFLINE_TESTED`, `REFERENCE_HOST_TESTED` | Reference workstation: Windows virtual machines with Dockur, Docker and QEMU, VM storage configuration and the manual startup policy. Offline: planning and adapter behavior. | Loopback FreeRDP connection path and network isolation of the guest on a clean installation; licensed media remain the user's responsibility. |
| Inbound RDP to Omarchy, independent remote desktop sessions, OCS Inventory, Zabbix | `ROADMAP` | None. | See the [roadmap](../ROADMAP.md). |

Results marked `REFERENCE_HOST_TESTED` come from development builds on the
reference workstation. The remaining clean Omarchy installation acceptance
repeats them with the released package; it does not invalidate them. Rows
marked *partial* were exercised but are not fully qualified. No organization,
domain, account or network details of the reference environment are published.
Evaluate on a disposable workstation, with a local administrator account and a
tested backup, before production use.
