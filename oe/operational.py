# SPDX-License-Identifier: MIT
"""Independent Phase 12 plans and transactions for Enterprise-owned files."""

import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import stat
import subprocess
import time

from . import deployment, policy, state

POLICY = Path("/etc/omarchy-enterprise/operational/file-servers.json")
LEDGER = "var/lib/omarchy-enterprise/operational"
PROFILES = ("standalone", "active-directory", "full-enterprise")


def encode(value):
    return json.dumps(value, sort_keys=True, indent=2) + "\n"


def command(arguments, *, timeout=15, capture_error=False):
    """Capture a bounded result without forwarding local configuration or stderr."""
    with subprocess.Popen(
        arguments, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT if capture_error else subprocess.DEVNULL,
        env={"PATH": "/usr/bin:/usr/sbin", "LC_ALL": "C", "HOME": "/nonexistent"},
        umask=0o077,
    ) as process, selectors.DefaultSelector() as selector:
        deadline = time.monotonic() + timeout
        output = bytearray()
        selector.register(process.stdout, selectors.EVENT_READ)
        try:
            while time.monotonic() < deadline:
                if not selector.select(max(0, deadline - time.monotonic())):
                    break
                chunk = os.read(process.stdout.fileno(), 8192)
                if not chunk:
                    code = process.wait(timeout=max(0, deadline - time.monotonic()))
                    return code, output.decode("utf-8", errors="replace")
                output.extend(chunk)
                if len(output) > 131072:
                    raise ValueError("Command output exceeded its limit")
            raise ValueError("Command exceeded its time limit")
        except subprocess.TimeoutExpired:
            raise ValueError("Command exceeded its time limit") from None
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()


def approved(plan, token=None, *, now=None):
    """Short-lived review fingerprint tied to the complete recomputed plan."""
    now = int(time.time()) if now is None else now
    if token is None:
        expiry = now + 300
    else:
        if not isinstance(token, str) or not re.fullmatch(r"[0-9]{1,12}:[0-9a-f]{64}", token):
            raise ValueError("Invalid approval")
        expiry = int(token.split(":")[0])
        if not now <= expiry <= now + 300:
            raise ValueError("Approval expired")
    digest = hashlib.sha256(encode([expiry, plan]).encode()).hexdigest()
    candidate = f"{expiry}:{digest}"
    if token is not None and token != candidate:
        raise ValueError("The plan or its prerequisites changed; review again")
    return candidate


def require_approval(plan, token):
    if not isinstance(token, str) or not token:
        raise ValueError("Explicit approval is required")
    approved(plan, token)


def administrator():
    if os.getuid() != 0 or os.geteuid() != 0:
        raise ValueError("Use an explicit administrator session")


def dependencies(profile, printing, runner=command):
    if profile not in PROFILES or type(printing) is not bool:
        raise ValueError("Invalid deployment profile")
    packages = deployment.dependency_plan(profile, printing)
    if profile == "full-enterprise":
        packages += ("docker", "freerdp")
    packages += ("nautilus", "gvfs-smb")
    results = {}
    for name in packages:
        status, _ = runner(("/usr/bin/pacman", "-Q", "--", name))
        if status not in (0, 1):
            raise ValueError("Package discovery failed")
        results[name] = status == 0
    return results


def document(profile, printing, shares):
    if profile not in PROFILES or type(printing) is not bool:
        raise ValueError("Invalid deployment profile")
    if (not isinstance(shares, dict) or shares.get("version") != 2
            or not isinstance(shares.get("shares"), list) or len(shares["shares"]) > 64):
        raise ValueError("Expected SMB policy version 2 with at most 64 entries")
    policy.shares(shares, set())
    if len(encode(shares).encode()) > 32768:
        raise ValueError("SMB policy is too large")
    return {"profile.json": encode({"profile": profile, "printing": printing}),
            "file-servers.json": encode(shares)}


def snapshot_hashes(files):
    return {name: hashlib.sha256(value.encode()).hexdigest() if value is not None else None
            for name, value in files.items()}


class Deployment(deployment.DeploymentStore):
    names = {"profile.json", "file-servers.json"}
    empty = dict.fromkeys(names)

    def __init__(self, root=Path("/")):
        self.root = root
        state.Store.__init__(self, deployment.safe_path(root, LEDGER, directory=True))

    def file_path(self, name):
        if name not in self.names:
            raise ValueError("Unknown operational resource")
        path = deployment.safe_path(self.root, str(POLICY.parent / name).lstrip("/"))
        if path.exists():
            info = path.lstat()
            if info.st_size > 32768 or stat.S_IMODE(info.st_mode) != 0o644:
                raise ValueError("Unexpected managed file size or permissions")
        return path

    def set_file(self, name, content):
        path = self.file_path(name)
        if content is not None:
            deployment.safe_path(self.root, str(path.parent.relative_to(self.root)),
                                 directory=True, create=True)
        state.write(path, content, mode=0o644)

    def read_record(self, path):
        self.validate_directory()
        deployment.safe_path(self.root, path.relative_to(self.root))
        try:
            if path.lstat().st_size > 1048576:
                raise ValueError("Operational transaction record exceeds its limit")
        except FileNotFoundError:
            return None
        return super().read_record(path)

    def check_history(self, history):
        if history is None:
            return
        if not isinstance(history, dict) or history.get("previous") is not None:
            raise ValueError("Invalid operational checkpoint")
        if "checkpoint_version" in history and type(history["checkpoint_version"]) is not int:
            raise ValueError("Invalid operational checkpoint version")
        if history.get("checkpoint_version", 1) != 1:
            raise ValueError("Invalid operational checkpoint version")
        super().check_history({key: value for key, value in history.items()
                               if key != "checkpoint_version"})

    def checkpoint(self, before, after):
        return {"before": before, "after": after, "previous": None, "checkpoint_version": 1}

    def rollback_checkpoint(self, history):
        if history is None or history["before"] == history["after"]:
            return None
        if "checkpoint_version" not in history and history["before"] == self.empty:
            raise ValueError("Legacy operational checkpoint has an ambiguous predecessor; review locally")
        return history

    def review(self, files, packages):
        if self.validate_directory() and os.path.lexists(self.journal):
            raise ValueError("Resolve the pending operational transaction first")
        before = self.snapshot()
        history = self.history()
        if before != (history["after"] if history else self.empty):
            raise ValueError("Unmanaged or externally changed operational configuration")
        return {"operation": "deploy operational files", "before_sha256": snapshot_hashes(before),
            "history_sha256": hashlib.sha256(encode(history).encode()).hexdigest(),
            "files": {name: json.loads(value) for name, value in files.items()},
            "packages": packages,
            "clean_host": "unqualified", "domain_enrollment": "blocked"}

    def transaction(self, files, packages, token, *, refresh_packages=None):
        require_approval(self.review(files, packages), token)
        if not all(packages.values()):
            raise ValueError("Install reviewed dependencies separately")
        deployment.safe_path(self.root, str(Path(LEDGER).parent), directory=True, create=True)
        self.directory.mkdir(mode=0o700, exist_ok=True)
        with self.locked():
            if refresh_packages is not None:
                packages = refresh_packages()
            plan = self.review(files, packages)
            require_approval(plan, token)
            if not all(packages.values()):
                raise ValueError("Install reviewed dependencies separately")
            before = self.snapshot()
            if snapshot_hashes(before) != plan["before_sha256"]:
                raise ValueError("Managed files changed after approval; review again")
            if before != files:
                # One protected rollback checkpoint keeps the ledger bounded.
                self.commit(before, files, self.checkpoint(before, files))

    def commit(self, before, after, history):
        previous = self.history()
        state.write(self.journal, encode({"before": before, "after": after,
                                         "history": history, "before_history": previous}))
        self.recover()

    def recovery_state(self, record):
        actual = super().recovery_state(record)
        if "before_history" in record and self.history() not in (record["before_history"], record["history"]):
            raise ValueError("Operational checkpoint changed during recovery; review locally")
        return actual

    def rollback(self):
        if os.path.lexists(self.journal):
            raise ValueError("Recover the pending operational transaction first")
        history = self.rollback_checkpoint(self.history())
        if history is None:
            return False
        actual = self.snapshot()
        if actual != history["after"]:
            raise ValueError("External change requires manual recovery")
        before = history["before"]
        self.commit(actual, before, self.checkpoint(before, before) if before != self.empty else None)
        return True


def qualification_required():
    raise ValueError("External mutation requires separate maintainer qualification")


class ExternalJournal:
    """Private last-operation receipt for an external adapter."""

    def __init__(self, directory, adapter):
        if adapter not in {"windows", "cups"}:
            raise ValueError("Unknown external adapter")
        self.store = state.Store(directory)
        self.path = directory / f"{adapter}.json"

    def read(self):
        if not self.store.validate_directory():
            return None
        try:
            if self.path.lstat().st_size > 65536:
                raise ValueError("External operation receipt exceeds its limit")
        except FileNotFoundError:
            return None
        return self.store.read_record(self.path)

    def run(self, operation, *, identity=None, allow_complete=False):
        with self.store.locked():
            previous = self.read()
            if previous and previous.get("status") != "complete":
                raise ValueError("An external operation is unresolved; reconcile it manually")
            if identity is not None and (previous or {}).get("identity") != identity:
                raise ValueError("No matching managed container receipt")
            if previous and identity is None and not allow_complete:
                raise ValueError("An existing receipt requires manual review")
            return operation(lambda record: state.write(self.path, encode(record)))
