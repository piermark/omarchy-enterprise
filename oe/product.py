"""Structured planning shared by the installer and Control Center."""

from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import shlex
import stat
import shutil
import tempfile

from . import installation, operational, operational_cups, policy, state


@dataclass
class PrinterDraft:
    rows: dict = field(default_factory=dict)
    default: str | None = None

    def document(self):
        return {"printers": list(self.rows.values()), "default": self.default}

    def edit(self, name, uri, *, previous=None, default=False):
        rows = self.rows.copy()
        if previous is not None:
            del rows[previous]
        if name in rows:
            raise ValueError("Select a unique managed printer name")
        rows[name] = {"name": name, "uri": uri}
        selected = name if default else None if self.default == previous else self.default
        candidate = PrinterDraft(rows, selected)
        operational_cups.validate(candidate.document())
        return candidate

    def remove(self, name):
        rows = self.rows.copy()
        del rows[name]
        return PrinterDraft(rows, None if self.default == name else self.default)


def printer_draft(*, config=None, save=None):
    config = config or Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
    path = config / "omarchy-enterprise-printers" / "definitions.json"
    store = state.Store(path.parent)
    if save is not None:
        document = save.document()
    else:
        if not store.validate_directory():
            return PrinterDraft()
        raw = state.read(path, private=True)
        if raw is None:
            return PrinterDraft()
        if len(raw.encode()) > 32768:
            raise ValueError("Printer definitions exceed the input limit")
        document = json.loads(raw)
    if document != {"printers": [], "default": None}:
        operational_cups.validate(document)
    if save is not None:
        with store.locked():
            state.write(path, operational.encode(document))
        return path
    return PrinterDraft({row["name"]: row for row in document["printers"]}, document["default"])


def deployment_payload(profile, printing, shares):
    payload = {"profile": profile, "printing": printing, "shares": shares}
    operational.document(**payload)
    data = operational.encode(payload)
    if len(data.encode()) > 32768:
        raise ValueError("The complete administrator handoff exceeds the helper input limit")
    return data


def save_handoff(data):
    config = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
    directory = config / "omarchy-enterprise-drafts"
    policy.safe_directory(directory, create=True)
    state.Store(directory).validate_directory()
    fd, name = tempfile.mkstemp(dir=directory, prefix="deployment-", suffix=".json")
    path = Path(name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as file:
            file.write(data)
            file.flush()
            os.fsync(file.fileno())
        state.sync_directory(directory)
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    return path


def administrator_commands(path):
    command = "/usr/bin/omarchy-enterprise-admin operational deploy"
    source = shlex.quote(str(path))
    return f"{command} < {source}\n{command} --approve REVIEW_TOKEN < {source}"


def workstation_review(root, *, packages, space=shutil.disk_usage):
    root = Path(root)
    review = installation.review(root)
    version_state, _ = installation.metadata(root, "etc/omarchy/version")
    version = None
    if version_state == "CONFIGURED":
        fd = os.open(root / "etc/omarchy/version", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            candidate = stream.read(32).strip() if stat.S_ISREG(os.fstat(stream.fileno()).st_mode) else b""
        if candidate in (b"4.5", b"4.5.0"):
            version = candidate.decode()
    return {"workflow": review["workflow"], "version": version, "packages": packages,
            "available_bytes": space(root).free,
            "configuration": [(name, installation.metadata(root, name)[0])
                              for name in installation.AD + installation.MARKERS[1:]],
            "live_installation": "BLOCKED"}


def image_recovery(root, action):
    """Bind a recovery action to reviewed history, journal and directory identity."""
    from . import provision

    def inspect():
        target = provision.ImageStore(root)
        if not target.validate_directory():
            raise ValueError("No staging transaction exists")
        history = target.history()
        pending = target.read_record(target.journal)
        if action == "rollback":
            if pending or not history or target.snapshot() != history["after"]:
                raise ValueError("Resolve pending changes or external conflicts before rollback")
        elif action not in {"recover", "abort"} or not pending:
            raise ValueError("No matching interrupted staging transaction")
        actual = target.recovery_state(pending) if pending else target.snapshot()
        info = target.root.stat()
        return target, (info.st_dev, info.st_ino, history, pending, actual)

    target, expected = inspect()

    def apply():
        with target.locked():
            current, observed = inspect()
            if observed != expected:
                raise ValueError("Staging state changed since review")
            if action == "rollback":
                current.rollback()
            else:
                current.recover(abort=action == "abort")
            history = current.history()
            if current.snapshot() != (history["after"] if history else current.empty):
                raise ValueError("Post-recovery verification failed")

    return apply
