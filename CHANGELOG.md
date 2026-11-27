# Changelog

## Omarchy Enterprise 0.5.0

First public release, tagged `v0.5.0`. This early release is not
production-ready; see the [availability matrix](docs/availability.md).

- Native GTK4 and Libadwaita Control Center and standalone staging workflows.
- AD configuration review, Guard, managed SMB bookmarks and printer drafts
  with scoped planning and recovery tools.
- Optional Windows workspace planning with manual startup.
- Signed pacman repository and signed package, installed and removed cleanly
  in a clean Arch environment.
- Features exercised on a real reference Omarchy workstation during
  development; clean Omarchy installation acceptance is pending (see the
  [availability matrix](docs/availability.md)).
- Uniform MIT licensing with SPDX identifiers for original sources.
- Control Center: the Windows page reports the FreeRDP client as UNAVAILABLE
  when FreeRDP is not installed instead of failing.
- Inbound RDP remains unavailable. See the [roadmap](ROADMAP.md).

The Arch package version is `0.5.0-1`. It upgrades earlier laboratory builds
such as `0.5.0lab15-2`.
