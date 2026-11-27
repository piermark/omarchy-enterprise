# SPDX-License-Identifier: MIT
"""Unprivileged review and handoff for signed Arch package installation."""

import argparse
import hashlib
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import sys

from . import operational

PACMAN = "/usr/bin/pacman"
PACKAGE = "omarchy-enterprise"
VERSION = "0.5.0-1"
REQUIRED = ("bash", "python", "python-gobject", "gtk4>=4.8", "libadwaita>=1.4")
INSTALLER = ("/usr/bin/omarchy-enterprise", "provision-wizard", "--native")


def preflight(root=Path("/"), *, run=operational.command, machine=platform.machine,
              disk=shutil.disk_usage):
    if machine() != "x86_64":
        raise ValueError("Omarchy Enterprise supports x86_64 Omarchy workstations")
    with (root / "etc/os-release").open() as stream:
        arch = any(line.strip() in {"ID=arch", 'ID="arch"'} for line in stream)
    with (root / "etc/omarchy/version").open() as stream:
        version = stream.read(32).strip()
    if not arch or version not in {"4.5", "4.5.0"}:
        raise ValueError("Omarchy Enterprise requires Omarchy 4.5 (Arch-based)")
    for target in ("usr", "var"):
        path = str(root / target)
        code, result = run(("/usr/bin/findmnt", "--noheadings", "--output",
                            "FSTYPE,OPTIONS", "--target", path))
        fields = result.split()
        if (code or len(fields) != 2 or fields[0] not in {"btrfs", "ext4", "xfs", "zfs"}
                or "rw" not in fields[1].split(",") or disk(path).free < 128 * 1024**2):
            raise ValueError(f"Check the supported writable filesystem and free space for /{target}")
    _code, missing = run((PACMAN, "-T", *REQUIRED))
    if _code and (_code != 127 or not missing.splitlines()
                  or any(item not in REQUIRED for item in missing.splitlines())):
        raise ValueError("Pacman dependency discovery failed")
    code, installed = run((PACMAN, "-Q", PACKAGE), capture_error=True)
    if code == 0 and re.fullmatch(r"omarchy-enterprise [^\s]+", installed.strip()):
        return installed.split()[1], missing.splitlines()
    if code == 1 and installed.strip() == "error: package 'omarchy-enterprise' was not found":
        return None, missing.splitlines()
    raise ValueError("Pacman could not determine the installed Enterprise package version")


def verify(archive, keyring, fingerprint, *, run=operational.command):
    if not re.fullmatch(r"[A-F0-9]{40}|[A-F0-9]{64}", fingerprint):
        raise ValueError("Provide the independently verified release signing fingerprint")
    signature = Path(str(archive) + ".sig")
    if not all(path.is_file() for path in (archive, signature, keyring)):
        raise ValueError("Provide the package, its detached signature and the trusted release keyring")
    with archive.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    code, output = run(("/usr/bin/gpgv", "--status-fd", "1", "--keyring",
                        str(keyring), "--", str(signature), str(archive)), timeout=60)
    valid = [line.split()[-1] for line in output.splitlines()
             if line.startswith("[GNUPG:] VALIDSIG ") and len(line.split()) == 12]
    rejected = ("BADSIG", "ERRSIG", "EXPSIG", "EXPKEYSIG", "REVKEYSIG")
    if code or valid != [fingerprint] or any(
            line.startswith(tuple(f"[GNUPG:] {status} " for status in rejected))
            for line in output.splitlines()):
        raise ValueError("Package authenticity verification failed")
    code, output = run((PACMAN, "-Qp", "--", str(archive)))
    if code or output.strip() != f"{PACKAGE} {VERSION}":
        raise ValueError(f"Expected the reviewed {PACKAGE} {VERSION} archive")
    with archive.open("rb") as stream:
        if digest != hashlib.file_digest(stream, "sha256").hexdigest():
            raise ValueError("Package changed during review")
    return digest


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", type=Path)
    parser.add_argument("--keyring", type=Path)
    parser.add_argument("--fingerprint")
    parser.add_argument("--launch", action="store_true", help="open the installed native GTK wizard")
    args = parser.parse_args(argv)
    try:
        if os.geteuid() == 0:
            raise ValueError("Run the bootstrap as an ordinary user")
        installed, missing = preflight()
        print(f"Enterprise package: {installed or 'absent'}")
        if missing:
            print("Administrator prerequisite review: " + ", ".join(missing))
        if args.launch:
            if any((args.package, args.keyring, args.fingerprint)):
                raise ValueError("Launch is a separate step after package installation")
            if installed != VERSION or missing:
                raise ValueError("Install the reviewed Omarchy Enterprise package and graphical prerequisites first")
            if not (os.getenv("WAYLAND_DISPLAY") or os.getenv("DISPLAY")):
                raise ValueError("Launch the native installer from your graphical session")
            os.execv(INSTALLER[0], INSTALLER)
        if not all((args.package, args.keyring, args.fingerprint)):
            raise ValueError("Provide --package, --keyring and --fingerprint for installation review")
        archive = args.package.resolve(strict=True)
        digest = verify(archive, args.keyring.resolve(strict=True), args.fingerprint.upper())
        print(f"Verified SHA-256 {digest}")
        if installed == VERSION:
            print("The Omarchy Enterprise package is already installed. Rerun with --launch.")
            return 0
        if installed:
            code, ordering = operational.command(("/usr/bin/vercmp", installed, VERSION))
            if code or ordering.strip() != "-1":
                raise ValueError("Automatic downgrade is unavailable; use administrator recovery")
            print("Review the existing configuration and a recovery checkpoint before upgrading.")
        if not sys.stdin.isatty() or input("Type INSTALL to approve the package handoff: ").strip() != "INSTALL":
            raise ValueError("Package handoff declined")
        print("In an authorized administrator terminal, require trusted local package signatures.")
        print("Review the same archive and SHA-256 before handing it to Pacman.")
        if missing:
            print("Resolve the missing prerequisites from trusted repositories first.")
        print(shlex.join((PACMAN, "-U", "--", str(archive))))
        print("After installation rerun ./install.sh --bootstrap --launch as your desktop user.")
        return 0
    except KeyboardInterrupt:
        print("\nPackage review interrupted. Check Pacman status if its transaction was started separately.",
              file=sys.stderr)
        return 130
    except (ValueError, OSError, EOFError) as error:
        message = str(error) if isinstance(error, ValueError) else "Required input or local resource unavailable"
        print(f"Bootstrap incomplete: {message}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
