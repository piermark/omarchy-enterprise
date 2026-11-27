"""Read-only probes and redacted diagnostics for a proposed Windows storage path."""

from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import stat
import subprocess

DISK_IO = ("native", "threads", "io_uring")
DISK_CACHE = ("none", "writeback", "writethrough", "directsync")
RESTART = ("no", "always", "unless-stopped", "on-failure")
COUNTERS = ("write_io_errs", "read_io_errs", "flush_io_errs", "corruption_errs", "generation_errs")
FILESYSTEMS = {"btrfs", "ext2", "ext3", "ext4", "xfs", "zfs", "f2fs", "tmpfs", "overlay",
               "nfs", "nfs4", "cifs", "smb3", "ntfs", "ntfs3", "exfat", "vfat", "fuseblk"}
FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW


def storage_path(value):
    text = os.fspath(value)
    path = Path(text)
    if (not text or not text.isprintable() or "$" in text or ".." in path.parts
            or path in {Path("."), Path("/")} or path.anchor == "//"):
        raise ValueError("Specify a dedicated storage path without traversal or interpolation")
    return path


@contextmanager
def nearest_directory(path, *, allow_missing=True):
    path = storage_path(path).absolute()
    fd = os.open("/", FLAGS)
    missing = False
    try:
        for component in path.parts[1:]:
            try:
                child = os.open(component, FLAGS, dir_fd=fd)
            except FileNotFoundError:
                if not allow_missing:
                    raise ValueError("The configuration directory does not exist") from None
                missing = True
                break
            except OSError:
                raise ValueError("Storage path must use accessible, non-symlink directories") from None
            os.close(fd)
            fd = child
        yield fd, missing
    finally:
        os.close(fd)


def run_probe(binary, args, fd):
    try:
        return subprocess.run([binary, *args, f"/proc/self/fd/{fd}"], pass_fds=(fd,),
                              stdin=subprocess.DEVNULL, capture_output=True, text=True,
                              env={"LC_ALL": "C", "PATH": "/usr/bin:/bin"}, timeout=8, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None


def inspect(path, *, counters=False):
    with nearest_directory(path) as (fd, missing):
        result = run_probe("/usr/bin/findmnt", ["--first-only", "--noheadings", "--output", "FSTYPE",
                                               "--target"], fd)
        fs = result.stdout.strip() if result and result.returncode == 0 else ""
        if fs not in FILESYSTEMS:
            fs = "unknown"
        try:
            usage = os.fstatvfs(fd)
            available = usage.f_bavail * usage.f_frsize
        except OSError:
            available = None
        report = {"filesystem": fs, "available_bytes": available, "nearest_parent_used": missing}
        if counters:
            report["btrfs_counters"] = device_counters(fd) if fs == "btrfs" else {"status": "not applicable"}
        return report


def device_counters(fd):
    result = run_probe("/usr/bin/btrfs", ["device", "stats", "--"], fd)
    if not result or result.returncode:
        denied = result and re.search(r"permission denied|operation not permitted", result.stderr, re.I)
        return {"status": "permission denied" if denied else "unavailable"}
    counts = {}
    for key in COUNTERS:
        values = re.findall(r"\." + key + r"[ \t]+(\d{1,20})[ \t]*$", result.stdout, re.M)
        if values:
            counts[key] = sum(map(int, values))
    if not counts:
        return {"status": "unavailable"}
    return {"status": "historical cumulative counters; compare readings to detect increases", "totals": counts}


def plan_service(content):
    try:
        service = json.loads(content)["services"]["windows"]
        if not isinstance(service, dict) or not isinstance(service.get("environment", {}), dict):
            raise ValueError
        return service
    except (ValueError, KeyError, TypeError, RecursionError):
        raise ValueError("Expected a Windows Compose JSON plan") from None


def read_plan(path):
    path = storage_path(path).absolute()
    with nearest_directory(path.parent, allow_missing=False) as (parent, _):
        try:
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            with os.fdopen(fd, "rb") as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise ValueError
                data = stream.read(262145)
                if len(data) > 262144:
                    raise ValueError
                return plan_service(data)
        except (OSError, ValueError):
            raise ValueError("Cannot read the selected regular Windows Compose JSON plan") from None


def diagnostics(path, *, compose_path=None, counters=False):
    report = inspect(path, counters=counters)
    service = read_plan(compose_path) if compose_path else {}
    environment = service.get("environment", {})
    io = environment.get("DISK_IO")
    cache = environment.get("DISK_CACHE")
    restart = service.get("restart")
    report.update({
        "disk_io": io if io in DISK_IO else "unset" if io is None else "unrecognized",
        "disk_cache": cache if cache in DISK_CACHE else "unset" if cache is None else "unrecognized",
        "restart": restart if restart in RESTART else "unset" if restart is None else "unrecognized",
    })
    warnings = []
    if report["filesystem"] == "unknown":
        warnings.append("Filesystem could not be detected; verify the target before deployment.")
    if report["nearest_parent_used"]:
        warnings.append("Capacity and filesystem describe the nearest existing directory; recheck after mounting.")
    if report["filesystem"] == "btrfs" and (io, cache) != ("threads", "writeback"):
        warnings.append("Review the Btrfs threaded I/O and writeback compatibility setting.")
    if io == "native" and cache not in (None, "none", "directsync"):
        warnings.append("Native AIO requires direct I/O; verify the effective QEMU arguments.")
    if cache == "writeback":
        warnings.append("Use graceful shutdown; unflushed writes may be lost during abrupt power loss.")
    report["warnings"] = warnings
    return report
