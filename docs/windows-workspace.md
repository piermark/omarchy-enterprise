# Optional Windows workspace

Use the Windows workspace form to review a digest-pinned guest image,
edition, disk capacity and dedicated storage. A live evaluation requires
properly licensed media and separately approved runtime and network settings.
Check KVM, TUN and filesystem support before approving a plan.

Manual startup is the default and networking is disabled by default. Keep
guest disk backups separate from workstation snapshots. Consider Btrfs for
dedicated guest storage and review the I/O settings during qualification.
Windows guests with Dockur, Docker and QEMU, dedicated storage and manual startup
were exercised on the reference workstation. The loopback connection path and
guest network isolation still need acceptance.
Inbound RDP to the Omarchy workstation remains a [roadmap item](../ROADMAP.md).
See [Windows workspace administration](administration.md#windows-workspace).
