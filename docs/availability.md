# Feature availability

| Status | Meaning |
| --- | --- |
| `IMPLEMENTED` | An implementation is present. |
| `REFERENCE_HOST_TESTED` | Prior reference-host evidence covers the indicated scope. |
| `OFFLINE_TESTED` | Retained offline regression tests cover the indicated scope with fixtures or adapters. |
| `PENDING_QUALIFICATION` | A live or release acceptance check is outstanding. |
| `ROADMAP` | Future work. |

| Workflow | Evidence | Remaining qualification |
| --- | --- | --- |
| Standalone staging, package verification | `IMPLEMENTED`, `OFFLINE_TESTED` for staging and simulated signature checks | `PENDING_QUALIFICATION` signed package and clean Omarchy acceptance |
| GTK4 Control Center | `IMPLEMENTED`, `OFFLINE_TESTED` for UI models | `PENDING_QUALIFICATION` native launch on clean Omarchy |
| Active Directory, SSSD and Kerberos | `IMPLEMENTED`, `OFFLINE_TESTED` for review and diagnostics | `PENDING_QUALIFICATION` live enrollment, trust, tickets and identity resolution |
| Graphical domain login | `IMPLEMENTED`, `OFFLINE_TESTED` for review and opt-in staging | `PENDING_QUALIFICATION` PAM, SDDM and post-upgrade login |
| File servers | `IMPLEMENTED`, `OFFLINE_TESTED` for policy, managed bookmarks and recovery | `PENDING_QUALIFICATION` live GVFS/Kerberos and login-time sync |
| Printers | `IMPLEMENTED`, `OFFLINE_TESTED` for CUPS discovery adapters and queue plans | `PENDING_QUALIFICATION` live changes and recovery |
| Enterprise Guard and rollback | `IMPLEMENTED`, `REFERENCE_HOST_TESTED` for earlier Guard and hook checks, `OFFLINE_TESTED` for policy and recovery | `PENDING_QUALIFICATION` clean install and site-specific hook review |
| Optional Windows workspace | `IMPLEMENTED`, `OFFLINE_TESTED` for planning and adapter behavior | `PENDING_QUALIFICATION` licensed media, lifecycle and isolation |
| Inbound RDP to Omarchy, OCS Inventory, Zabbix | `ROADMAP` | See the [roadmap](../ROADMAP.md). |

Use disposable workstations and synthetic settings for qualification. This
release assembly includes no live qualification.
