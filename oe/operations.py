# SPDX-License-Identifier: MIT
"""Explicit workstation operations with no implicit elevation or export."""

from contextlib import ExitStack
import errno
import hashlib
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess

FINGERPRINT = re.compile(r"[0-9a-f]{64}")
QUEUE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,126}")


def command(name, *arguments, capture=False):
    executable = shutil.which(name)
    if not executable:
        raise ValueError(f"Required command is unavailable: {name}")
    return subprocess.run([executable, *arguments], check=True, text=True,
                          capture_output=capture, timeout=120)


def guard(root, manifest):
    if not isinstance(manifest, dict) or not manifest:
        raise ValueError("Expected a nonempty mapping of relative paths to SHA-256 digests")
    checks = {}
    root = root.resolve(strict=True)
    for label, expected in manifest.items():
        candidate = Path(label)
        if (candidate.is_absolute() or candidate == Path(".") or ".." in candidate.parts
                or not isinstance(expected, str) or not FINGERPRINT.fullmatch(expected)):
            raise ValueError("Invalid Guard manifest entry")
        checks[label] = file_matches(root, candidate, expected)
    return checks


def file_matches(root, candidate, expected):
    flags = os.O_RDONLY | os.O_NOFOLLOW
    try:
        with ExitStack() as cleanup:
            parent = os.open(root, flags | os.O_DIRECTORY)
            cleanup.callback(os.close, parent)
            for part in candidate.parts[:-1]:
                parent = os.open(part, flags | os.O_DIRECTORY, dir_fd=parent)
                cleanup.callback(os.close, parent)
            fd = os.open(candidate.name, flags | os.O_NONBLOCK, dir_fd=parent)
            with os.fdopen(fd, "rb") as stream:
                if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                    return False
                digest = hashlib.sha256()
                for block in iter(lambda: stream.read(65536), b""):
                    digest.update(block)
                return digest.hexdigest() == expected
    except (FileNotFoundError, NotADirectoryError, PermissionError):
        return False
    except OSError as error:
        if error.errno == errno.ELOOP:
            return False
        raise


def compliance(root, manifest):
    if not isinstance(manifest, dict) or set(manifest) != {"files"}:
        raise ValueError("Expected a compliance baseline with a files mapping")
    return guard(root, manifest["files"])


def inventory():
    return {"architecture": platform.machine(), "kernel": platform.release(),
            "logical_cpus": os.cpu_count(),
            "installed_package_count": len(command("pacman", "-Qq", capture=True).stdout.splitlines())}


def updates():
    executable = shutil.which("checkupdates")
    if not executable:
        raise ValueError("Install pacman-contrib to use checkupdates")
    result = subprocess.run([executable], check=False, text=True, timeout=120)
    return 0 if result.returncode == 2 else result.returncode


def print_file(queue, path):
    if not QUEUE.fullmatch(queue):
        raise ValueError("Invalid CUPS queue name")
    path = path.resolve(strict=True)
    if not path.is_file():
        raise ValueError("Select a regular file to print")
    command("lp", "-d", queue, "--", str(path))


def certificate(path):
    path = path.resolve(strict=True)
    if path.suffix.lower() not in (".pem", ".crt") or not path.is_file():
        raise ValueError("Select a PEM public X.509 certificate")
    with path.open("rb") as stream:
        if stream.readline(128).strip() != b"-----BEGIN CERTIFICATE-----":
            raise ValueError("Expected a public PEM certificate")
    details = command("openssl", "x509", "-in", str(path), "-noout", "-sha256",
                      "-fingerprint", "-dates", capture=True)
    print(details.stdout, end="")
