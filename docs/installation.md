# Installation and evaluation

Clean installation acceptance is pending. The target for qualification is a
clean, disposable x86_64 workstation running Omarchy 4.5 (4.5 or 4.5.0),
which is based on Arch Linux. Keep independent local administrator and recovery access.
Start with the Standalone profile before evaluating directory integration.

## Offline evaluation from source

Download and extract the tagged source archive. Review the files and verify
their byte integrity from the extracted repository root. A checksum manifest
does not establish publisher identity.

```sh
sha256sum -c SOURCE-SHA256SUMS
stage=$(mktemp -d)
./install.sh --root "$stage" --profile standalone --dry-run
```

Run as a regular user with Bash and Python available. Use a private,
user-owned directory with mode 0700. After reviewing the dry run, staging in
that same directory with `--yes` writes the profile and its journal there.
The offline workflow does not install packages, start services or enroll AD.
Use `./uninstall.sh --root "$stage"` to review removal of the staged profile.

## Install from the signed pacman repository

The simplest method on Omarchy is the signed `[omarchy-enterprise]` pacman
repository. Add the release key `CDBB05E013F4F1E8BBE8F0006E3D9649B45ADEC7` to Pacman's keyring with
`pacman-key --add` and `pacman-key --lsign-key`, append

```ini
[omarchy-enterprise]
SigLevel = Required DatabaseRequired
Server = https://piermark.github.io/omarchy-enterprise/$arch
```

to `/etc/pacman.conf`, then run `sudo pacman -Syu omarchy-enterprise`. Updates
arrive with `sudo pacman -Syu`. The same qualification limits apply; evaluate
on a disposable system first.

## Signed-package qualification

The Arch package `omarchy-enterprise-0.5.0-1-any.pkg.tar.zst` (Pacman version
`0.5.0-1`) requires maintainer signing and clean Omarchy acceptance before
distribution. Follow these steps
when an approved signed package and verification key are available.

1. Use a regular desktop session for the graphical workflow. The native
   interface needs PyGObject, GTK 4.8 or later and Libadwaita 1.4 or later.
   The bootstrap checks writable Btrfs, ext4, XFS or ZFS mounts with at
   least 128 MiB free for both `/usr` and `/var`. Pacman determines actual
   dependency transaction space requirements.
2. Obtain the package, detached signature and OpenPGP release keyring.
   Confirm the full primary fingerprint `CDBB05E013F4F1E8BBE8F0006E3D9649B45ADEC7` through an independent
   trusted channel. Verify the checksum list signature with
   `gpgv --keyring ./release-keyring.gpg SHA256SUMS.asc SHA256SUMS`,
   then run `sha256sum -c SHA256SUMS` with the complete matching asset set.
   Verify the package signature with
   `gpgv --keyring ./release-keyring.gpg ARCHIVE.sig ARCHIVE`.
   Review the package digest and prerequisites using
   `./install.sh --bootstrap --package ARCHIVE --keyring KEYRING --fingerprint FINGERPRINT`.
3. Resolve dependencies through trusted package repositories. For any
   authorized installation, use an administrator-controlled package and
   signature location, recheck the digest and signing identity, and
   require a trusted signature through Pacman's `LocalFileSigLevel`.
4. Qualify the desktop launch as the regular desktop user. Use
   `./install.sh --bootstrap --launch` with the matching installed
   Omarchy Enterprise package or open **Omarchy Enterprise Installer**. Stage the
   Standalone profile and review it before separately approving a policy
   deployment. See the [administrator guide](administration.md).

Before attempting upgrades, inspect package ownership and pending recovery
state. Keep an independently recoverable backup and the trusted previous
package. If Pacman is interrupted, review its transaction and package database
before retrying. Consult the [availability matrix](availability.md) for the
live checks still required.

## Filesystems and recovery

Consider Btrfs for local snapshots and rollback. Before changing a workstation,
confirm which subvolumes the snapshot covers, test restoration and keep an
independent backup. Include home data and any separately mounted volumes in
the backup plan. Back up Windows guest disks separately and review threaded I/O
with writeback for a dedicated Btrfs guest storage path during guest
qualification.
