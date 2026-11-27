# Omarchy Enterprise 0.5.0

![Omarchy Enterprise, bringing enterprise workstation capabilities to Omarchy Linux](assets/banner.png)

[![License: MIT](assets/license-mit.svg)](LICENSE)

Omarchy Enterprise is an unofficial, independent workstation extension designed
specifically for Omarchy Linux.
The GTK4 and Libadwaita Control Center helps desktop users review configuration,
workstation resources and recovery options. A separate administrative CLI
reviews plans and applies scoped changes with approval.

Version 0.5.0 is tagged `v0.5.0`. It is an early release and is not
production-ready. The 162 retained offline regression tests pass for this
source. Clean Omarchy installation, native desktop launch and live
integrations still require qualification. The package `0.5.0-1` is
distributed only after maintainer signing and clean Omarchy acceptance.

## Feature availability

| Capability | 0.5.0 scope |
| --- | --- |
| Standalone | Offline profile staging, review and recovery |
| Control Center | Native GTK4 interface with English and Italian translations and offline UI model checks |
| Active Directory | Samba ADS, SSSD and Kerberos configuration review and diagnostics |
| Graphical domain login | SDDM review and opt-in integration. Live PAM and SDDM acceptance pending |
| File servers | Managed Nautilus bookmarks and offline recovery. Live SMB authentication pending |
| Printers | CUPS discovery and IPP/IPPS queue plans. Live queue changes pending |
| Enterprise Guard | Baseline checks and scoped recovery with prior reference-host Guard and hook evidence |
| Windows workspace | Optional guest planning with manual startup by default. Live isolation pending |
| Inbound RDP to Omarchy | Roadmap |

See the [availability matrix](docs/availability.md) for evidence and
qualification by workflow.

## Architecture

![GTK4 desktop review and the administrative CLI connect to managed policy, recovery and Guard. Site integrations cover directory identity, file servers, printers and an optional Windows workspace. Inbound RDP is planned.](assets/architecture.png)

## Quick start

Extract the source archive and run from the extracted repository root as a
regular user:

```sh
sha256sum -c SOURCE-SHA256SUMS
stage=$(mktemp -d)
./install.sh --root "$stage" --profile standalone --dry-run
```

Source evaluation requires Bash and Python. The full offline suite also
requires Gettext's `msgfmt`. Clean-install qualification targets x86_64 Omarchy
4.5 (4.5 or 4.5.0). The native UI requires PyGObject, GTK 4.8 or later, and
Libadwaita 1.4 or later.

Use the [installation guide](docs/installation.md) to verify an approved
signed package. Confirm the maintainer's full fingerprint independently,
verify detached signatures and check the artifact hash against the signed
checksum list. Keep Pacman signature verification enabled.

## Documentation

| Start here | Integration and operations |
| --- | --- |
| [Quick start](docs/quick-start.md) | [Active Directory](docs/active-directory.md) |
| [Installation and verification](docs/installation.md) | [File servers](docs/file-servers.md) |
| [Control Center](docs/control-center.md) | [Printers](docs/printers.md) |
| [Administration](docs/administration.md) | [Windows workspace](docs/windows-workspace.md) |
| [Troubleshooting](docs/troubleshooting.md) | [Security](docs/security.md) and [recovery](docs/recovery.md) |
| [Avvio rapido](docs/it/quick-start.md) | [Installazione](docs/it/installation.md) |

See the [changelog](CHANGELOG.md) and [roadmap](ROADMAP.md) for release scope
and future work, including inbound RDP, OCS Inventory and Zabbix.

## Security and contributions

Evaluate on disposable systems with synthetic settings and retain independently
recoverable local access. Review approval plans and rollback scope before
changing policy. Keep graphical domain login disabled during source evaluation.
Use the [security policy](SECURITY.md) for private vulnerability reports and
the [contribution guide](CONTRIBUTING.md) for documentation fixes and synthetic
test cases.

## License and acknowledgments

Omarchy Enterprise is licensed under the [MIT License](LICENSE).
Copyright (c) 2026 Marco Porro ([www.marcoporro.it](https://www.marcoporro.it)).
See the [third-party notices](THIRD_PARTY_NOTICES.md) for separately supplied
components, which keep their own licenses.

Development and release preparation used AI assistance from ChatGPT and Codex.

Omarchy Enterprise is an unofficial, independent project. It is not affiliated
with or endorsed by Omarchy.
