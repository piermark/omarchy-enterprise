# SPDX-License-Identifier: MIT
"""Review and quarantine shadow commands without interpreting their contents."""
import ctypes
from contextlib import ExitStack, contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess

PREFIX = "omarchy-enterprise-"
NAMES = tuple(PREFIX + name for name in (
    "ad-testjoin", "audit", "certificates", "compliance", "doctor", "guard",
    "inventory", "policy", "printer-monitor", "printers", "provision-user",
    "updates", "view",
))
PRIVATE = ".omarchy-enterprise-migration"
DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
PACKAGE = "omarchy-enterprise"
LIVE_APPLY_BLOCK = "Review hard-coded command consumers and Guard protected-path differences"


def owner(path):
    try:
        result = subprocess.run(
            ["/usr/bin/pacman", "-Qqo", "--", str(path)],
            env={"PATH": "/usr/bin", "LC_ALL": "C"}, stdin=subprocess.DEVNULL,
            capture_output=True, text=True, timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    if result.returncode == 0:
        return PACKAGE if result.stdout.strip() == PACKAGE else "other package"
    if result.returncode == 1 and result.stderr.strip() == f"error: No package owns {path}":
        return "unowned"
    return "unknown"


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


@contextmanager
def directory(path, uid=None):
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("Expected an absolute directory")
    fd = os.open("/", DIR)
    try:
        for part in path.parts[1:]:
            child = os.open(part, DIR, dir_fd=fd)
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            if uid is not None and (info.st_uid != uid or info.st_mode & 0o022):
                raise ValueError("Migration requires administrator-controlled directories")
        yield fd
    finally:
        os.close(fd)


def read_identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def fingerprint(fd, name):
    if fd is None:
        return None
    try:
        info = os.stat(name, dir_fd=fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 1048576:
        raise ValueError("Unsupported command file")
    identity = read_identity(info)
    with os.fdopen(os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd), "rb") as file:
        if read_identity(os.fstat(file.fileno())) != identity:
            raise ValueError("Command changed during inspection")
        data = file.read(1048577)
        if read_identity(os.fstat(file.fileno())) != identity or len(data) != info.st_size:
            raise ValueError("Command changed during inspection")
    # Rename changes ctime. The journal uses the identity fields stable across moves.
    return [info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_mtime_ns, hashlib.sha256(data).hexdigest()]


class Migration:
    def __init__(self, root=Path("/"), ownership=owner):
        self.root = root
        self.local = root / "usr/local/bin"
        self.packaged = root / "usr/bin"
        self.ownership = ownership

    def inspect(self, local, packaged, administrator=0):
        rows, snapshots = {}, {}
        for name in NAMES:
            try:
                legacy = fingerprint(local, name)
                if legacy is None:
                    rows[name] = {"state": "ABSENT"}
                    continue
                replacement = fingerprint(packaged, name)
                legacy_owner = self.ownership(self.local / name)
                package_owner = self.ownership(self.packaged / name) if replacement else "absent"
                trusted = replacement and replacement[3] == administrator and (
                    replacement[2] & 0o111 and not replacement[2] & 0o7022)
                if (legacy_owner != "unowned" or package_owner != PACKAGE or not trusted
                        or legacy[3] != administrator or legacy[2] & 0o7022):
                    state = "CONFLICT"
                elif legacy[-1] == replacement[-1] and legacy[2] & 0o111:
                    state = "IDENTICAL"
                else:
                    state = "REVIEW REQUIRED"
                rows[name] = {"state": state, "legacy_owner": legacy_owner, "replacement_owner": package_owner}
                snapshots[name] = [legacy, replacement]
            except (OSError, ValueError):
                rows[name] = {"state": "BLOCKED"}
        return rows, snapshots

    def preview(self, names=(), *, administrator=0):
        with ExitStack() as stack:
            try:
                local = stack.enter_context(directory(self.local))
            except FileNotFoundError:
                local = None
            try:
                packaged = stack.enter_context(directory(self.packaged))
            except FileNotFoundError:
                packaged = None
            rows, snapshots = self.inspect(local, packaged, administrator)
        from .legacy_review import consumers

        report = self.report(rows, snapshots, names)
        report["dependency_review"] = consumers(self.root, self.ownership)
        return report

    @staticmethod
    def report(rows, snapshots, names):
        selected = tuple(sorted(set(names)))
        if any(name not in rows or rows[name]["state"] not in {"IDENTICAL", "REVIEW REQUIRED"}
               for name in selected):
            raise ValueError("Selection contains an unavailable or conflicting command")
        reviewed = {name: (rows[name], snapshots[name]) for name in selected}
        token = hashlib.sha256(encode(reviewed)).hexdigest() if selected else None
        return {"commands": rows, "quarantine": selected, "confirmation": token,
                "live_apply": "BLOCKED", "integration": LIVE_APPLY_BLOCK,
                "package_integrity": "NOT TESTED"}

    def transact(self, action, names=(), confirmation=None):
        if os.geteuid() != 0 or self.local != Path("/usr/local/bin"):
            raise ValueError("Use the administrator helper on the installed system")
        if action == "apply":
            raise ValueError(LIVE_APPLY_BLOCK)
        return self._transact(action, names, confirmation, administrator=0)

    def _transact(self, action, names=(), confirmation=None, *, administrator, trusted_paths=True):
        with directory(self.local, administrator if trusted_paths else None) as local:
            with directory(self.packaged, administrator if trusted_paths else None) as packaged:
                return self._operate(local, packaged, action, names, confirmation, administrator)

    def _operate(self, local, packaged, action, names, confirmation, administrator):
        if action not in {"apply", "rollback", "recover"}:
            raise ValueError("Unknown migration operation")
        # Lock the directory inode across journal creation and all moves.
        fcntl.flock(local, fcntl.LOCK_EX)
        try:
            backup = os.open(PRIVATE, DIR, dir_fd=local)
        except FileNotFoundError:
            if action != "apply":
                return "NO TRANSACTION"
            self.approve(local, packaged, names, confirmation, administrator)
            os.mkdir(PRIVATE, mode=0o700, dir_fd=local)
            os.fsync(local)
            backup = os.open(PRIVATE, DIR, dir_fd=local)
        try:
            info = os.fstat(backup)
            if info.st_uid != administrator or stat.S_IMODE(info.st_mode) != 0o700:
                raise ValueError("Unsafe migration backup directory")
            journal = load(backup)
            if action == "apply":
                if journal:
                    if journal["phase"] == "applied" and journal["confirmation"] == confirmation:
                        verify_positions(local, backup, journal["files"], expected="backup")
                        return "ALREADY APPLIED"
                    if journal["phase"] != "rolled back":
                        raise ValueError("Resolve the existing migration transaction first")
                files = self.approve(local, packaged, names, confirmation, administrator)
                verify_positions(local, backup, files, expected="local")
                journal = {"phase": "applying", "files": files, "confirmation": confirmation}
                save(backup, journal)
                relocate(local, backup, files, destination="backup")
                journal["phase"] = "applied"
            else:
                if not journal or journal["phase"] == "rolled back":
                    return "NO PENDING MIGRATION"
                if action == "recover" and journal["phase"] == "applied":
                    return "NO INTERRUPTED MIGRATION"
                verify_positions(local, backup, journal["files"])
                journal["phase"] = "restoring"
                save(backup, journal)
                relocate(local, backup, journal["files"], destination="local")
                journal["phase"] = "rolled back"
            save(backup, journal)
            return journal["phase"].upper()
        finally:
            os.close(backup)

    def approve(self, local, packaged, names, confirmation, administrator):
        rows, snapshots = self.inspect(local, packaged, administrator)
        report = self.report(rows, snapshots, names)
        if not confirmation or report["confirmation"] != confirmation:
            raise ValueError("Obtain a current preview and supply its confirmation token")
        return {name: snapshots[name][0] for name in report["quarantine"]}


def load(fd):
    try:
        journal = os.open("journal.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    except FileNotFoundError:
        return None
    with os.fdopen(journal, "rb") as file:
        info = os.fstat(file.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                info.st_uid != os.fstat(fd).st_uid or stat.S_IMODE(info.st_mode) != 0o600):
            raise ValueError("Unsafe migration journal")
        value = json.loads(file.read(16384))
    if (not isinstance(value, dict) or value.get("phase") not in
            {"applying", "applied", "restoring", "rolled back"} or
            not isinstance(value.get("files"), dict) or not value["files"] or
            not set(value["files"]).issubset(NAMES)):
        raise ValueError("Invalid migration journal")
    return value


def save(fd, journal):
    import secrets

    staging = ".journal-" + secrets.token_hex(12)
    handle = os.open(staging, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=fd)
    try:
        with os.fdopen(handle, "wb") as file:
            file.write(encode(journal))
            file.flush()
            os.fsync(file.fileno())
        os.replace(staging, "journal.json", src_dir_fd=fd, dst_dir_fd=fd)
        os.fsync(fd)
    finally:
        try:
            os.unlink(staging, dir_fd=fd)
        except FileNotFoundError:
            pass


def verify_positions(local, backup, files, expected=None):
    positions = {}
    for name, signature in files.items():
        position = (fingerprint(local, name), fingerprint(backup, name))
        if position == (signature, None):
            positions[name] = "local"
        elif position == (None, signature):
            positions[name] = "backup"
        else:
            raise ValueError("Migration file changed externally")
        if expected and positions[name] != expected:
            raise ValueError("Migration file is in an unexpected location")
    return positions


def relocate(local, backup, files, destination):
    positions = verify_positions(local, backup, files)
    source_fd, target_fd = (local, backup) if destination == "backup" else (backup, local)
    rename = ctypes.CDLL("libc.so.6", use_errno=True).renameat2
    for name, position in positions.items():
        if position != destination:
            if fingerprint(source_fd, name) != files[name]:
                raise ValueError("Migration file changed externally")
            filename = os.fsencode(name)
            if rename(source_fd, filename, target_fd, filename, 1) != 0:  # RENAME_NOREPLACE
                raise OSError(ctypes.get_errno(), "Safe migration rename failed")
            os.fsync(target_fd)
            os.fsync(source_fd)
    verify_positions(local, backup, files, expected=destination)


def admin_main():
    import argparse

    parser = argparse.ArgumentParser(description="Administrator-only legacy command quarantine")
    parser.add_argument("action", choices=("apply", "rollback", "recover"))
    parser.add_argument("--confirm")
    parser.add_argument("commands", nargs="*")
    args = parser.parse_intermixed_args()
    if args.action == "apply" and (not args.commands or not args.confirm):
        parser.error("Apply requires selected commands and a confirmation token")
    if args.action != "apply" and (args.commands or args.confirm):
        parser.error("Rollback and recovery use the existing transaction journal")
    if args.action == "apply":
        parser.exit(1, f"Live migration blocked. {LIVE_APPLY_BLOCK}.\n")
    try:
        print(Migration().transact(args.action, args.commands, args.confirm))
    except (OSError, ValueError, KeyError):
        parser.exit(1, "Migration stopped. Review the preview or recover the private transaction.\n")
    return 0
