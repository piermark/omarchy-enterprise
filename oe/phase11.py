# SPDX-License-Identifier: MIT
"""Independent deployment and administration against a private synthetic target."""

from dataclasses import dataclass
from enum import Enum
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import tempfile
from uuid import uuid4

from . import bookmarks, phase11_resources as resources, pilot_session, policy, state


def encode(value):
    return json.dumps(value, sort_keys=True, allow_nan=False) + "\n"


class Action(str, Enum):
    DEPLOY = "deploy"
    ROLLBACK = "rollback"
    RESUME = "recover"
    ABORT = "abort"
    SHARE_EDIT = "share-edit"
    LOGIN_SYNC = "login-sync"
    BOOKMARK_ROLLBACK = "bookmark-rollback"
    BOOKMARK_RECOVER = "bookmark-recover"
    PRINTERS = "printers"
    WINDOWS = "windows"
    START = "windows-start"
    STOP = "windows-stop"


class Role(str, Enum):
    VIEWER = "viewer"
    OPERATOR = "operator"
    ADMIN = "administrator"


OPERATIONS = {Action.LOGIN_SYNC, Action.BOOKMARK_ROLLBACK, Action.BOOKMARK_RECOVER,
              Action.START, Action.STOP}
BOOKMARKS = {Action.LOGIN_SYNC, Action.BOOKMARK_ROLLBACK, Action.BOOKMARK_RECOVER}


@dataclass(frozen=True)
class Request:
    action: Action
    role: Role
    payload: dict

    def __post_init__(self):
        if not isinstance(self.action, Action) or not isinstance(self.role, Role):
            raise ValueError("Use a defined action and synthetic role")
        if not isinstance(self.payload, dict) or len(encode(self.payload)) > 65536:
            raise ValueError("Expected a bounded JSON object")

    def authorize(self):
        if self.role is Role.ADMIN or (self.role is Role.OPERATOR and self.action in OPERATIONS):
            return
        raise PermissionError("Synthetic role is denied for this action")


class Workspace(state.Store):
    names = {"deployment.json", "shares.json", "cups.json", "windows.json"}
    empty = dict.fromkeys(names)

    @classmethod
    def create(cls):
        if os.geteuid() == 0:
            raise PermissionError("Run as an unprivileged user")
        root = Path(tempfile.mkdtemp(prefix="oe-phase11-", dir="/tmp"))
        state.write(root / "identity", uuid4().hex)
        return cls(root)

    def __init__(self, directory):
        directory = Path(directory)
        if (os.geteuid() == 0 or directory.parent != Path("/tmp")
                or not re.fullmatch(r"oe-phase11-[a-z0-9_]{8}", directory.name)):
            raise ValueError("Choose an initialized disposable Phase 11 target")
        super().__init__(directory)
        if not self.validate_directory():
            raise ValueError("Disposable target is missing")
        self.identity = state.read(directory / "identity", private=True)
        if not self.identity or not re.fullmatch(r"[0-9a-f]{32}", self.identity):
            raise ValueError("Disposable target has no valid identity")

    def snapshot(self):
        return {name: state.read(self.file_path(name), private=True) for name in self.names}

    def context(self):
        actual = self.snapshot()
        previous = self.history()
        pending = self.read_record(self.journal)
        book, ledger = bookmarks.locations(self.directory)
        bookmark_state = bookmarks.snapshot(book, ledger)
        bookmark_pending = state.Store(ledger).read_record(ledger / "pending.json")
        checkpoint = state.Store(ledger).read_record(ledger / pilot_session.BACKUP)
        runtime = state.read(self.directory / "runtime.json", private=True)
        return actual, previous, pending, bookmark_state, bookmark_pending, checkpoint, runtime

    @staticmethod
    def unapplied_checkpoint(book_state, checkpoint):
        return (checkpoint is not None and "rollback_target" not in checkpoint
                and book_state[1] == checkpoint.get("owned_before")
                and book_state[1] != checkpoint.get("expected"))

    def status(self):
        actual, history, pending, book_state, bookmark_pending, checkpoint, runtime = self.context()
        _, owned = book_state
        config = {name: self.value(actual, name) for name in actual}
        if config["windows.json"]:
            config["windows.json"]["status"] = self.vm_status(config["windows.json"], runtime)
        return {"target": str(self.directory), "backend": "synthetic", "live": "BLOCKED",
                "inbound_rdp": "OFF", "managed_bookmarks": len(owned),
                "recovery_pending": pending is not None,
                "bookmark_recovery_pending": bookmark_pending is not None or
                self.unapplied_checkpoint(book_state, checkpoint),
                "rollback_available": history is not None,
                "bookmark_rollback_available": checkpoint is not None,
                "configuration": config}

    @staticmethod
    def vm_status(current, runtime):
        return "running" if current and runtime == encode(current["identity"]) else "stopped"

    def vm_update(self, current, specification, runtime):
        if self.vm_status(current, runtime) == "running":
            if specification != current["definition"]:
                raise ValueError("Stop the synthetic VM before editing its definition")
            return current
        if specification is None:
            if current:
                raise ValueError("Existing managed storage must be retained")
            return None
        if current and any(current["definition"][key] != specification[key]
                           for key in ("name", "storage", "disk_gib")):
            raise ValueError("Existing managed name and disk configuration must be retained")
        identity = current["identity"] if current else self.identity
        return {"identity": identity, "definition": specification}

    def plan(self, request):
        context = self.context()
        actual, history, pending, book_state, bookmark_pending, checkpoint, runtime = context
        action, payload = request.action, request.payload
        recovery = action in {Action.RESUME, Action.ABORT}
        if pending is not None and not recovery:
            raise ValueError("Recover the pending transaction before continuing")
        if not recovery and actual != (history["after"] if history else self.empty):
            raise ValueError("Managed files differ from their recorded state")
        bookmark_recovery = bookmark_pending is not None or self.unapplied_checkpoint(book_state, checkpoint)
        if bookmark_recovery and action in BOOKMARKS and action is not Action.BOOKMARK_RECOVER:
            raise ValueError("Recover the pending bookmark transaction before continuing")

        updates = {}
        details = {}
        desired = None
        allowed = True
        if action is Action.DEPLOY:
            profile, prerequisites, shares, printers, vm = resources.deployment(payload)
            allowed = all(prerequisites.values())
            details = {"profile": profile, "prerequisites": prerequisites}
            updates = {"deployment.json": {"profile": profile, "inbound_rdp": False,
                                            "live_deployment": False,
                                            "capabilities": sorted(payload["capabilities"])},
                       "shares.json": shares, "cups.json": printers,
                       "windows.json": self.vm_update(self.value(actual, "windows.json"), vm, runtime)}
        elif action is Action.SHARE_EDIT:
            resources.fields(payload, "target replacement")
            if payload["target"] is not None:
                resources.example_host(policy.bookmark_uri(payload["target"]).split("/")[2])
            if payload["replacement"] is not None:
                resources.shares({"version": 2, "shares": [payload["replacement"]]})
            document = self.value(actual, "shares.json") or resources.EMPTY_SHARES
            updates["shares.json"] = resources.shares(
                pilot_session.edit(document, payload["target"], payload["replacement"]))
        elif action is Action.PRINTERS:
            updates["cups.json"] = resources.printers(payload)
        elif action is Action.WINDOWS:
            deployment = self.require_full_profile(actual)
            details["prerequisites"] = {name: name in deployment["capabilities"]
                                        for name in ("virtualization", "windows-license")}
            allowed = all(details["prerequisites"].values())
            updates["windows.json"] = self.vm_update(
                self.value(actual, "windows.json"), resources.vm(payload), runtime)
        elif action in {Action.START, Action.STOP}:
            resources.fields(payload, "identity")
            self.require_full_profile(actual)
            machine = self.value(actual, "windows.json")
            if not machine or machine["identity"] != payload["identity"]:
                raise ValueError("Expected the managed VM identity")
            before = self.vm_status(machine, runtime)
            after = "running" if action is Action.START else "stopped"
            details = {"identity": machine["identity"], "status_before": before,
                       "status_after": after, "changes": before != after}
        elif action in {Action.LOGIN_SYNC, Action.BOOKMARK_ROLLBACK}:
            if action is Action.LOGIN_SYNC:
                resources.fields(payload, "groups")
                document = self.value(actual, "shares.json") or resources.EMPTY_SHARES
                desired = policy.shares(resources.shares(document), resources.groups(payload["groups"]))
            else:
                resources.fields(payload, "")
                if checkpoint is None:
                    raise ValueError("No managed bookmark checkpoint to restore")
                if book_state[1] not in (checkpoint["expected"], checkpoint.get("rollback_target")):
                    raise ValueError("Managed bookmarks changed after synchronization")
                bookmarks.validate_managed(checkpoint["restore"])
                desired = {}
                for line in checkpoint["restore"]:
                    uri, label = line.rstrip("\n").split(" ", 1)
                    desired[label] = uri
            merged, owned = bookmarks.merge(*book_state, desired)
            if action is Action.LOGIN_SYNC and checkpoint:
                if (merged, owned) != book_state:
                    raise ValueError("Roll back the existing bookmark checkpoint before a new synchronization")
            details = {"authorized_shares": desired, "managed_before": len(book_state[1]),
                       "managed_after": len(owned), "changes": (merged, owned) != book_state}
        else:
            resources.fields(payload, "")
            if action is Action.ROLLBACK:
                target = history["before"] if history else actual
                current = self.value(actual, "windows.json")
                previous_vm = self.value(target, "windows.json")
                if self.vm_status(current, runtime) == "running" and current != previous_vm:
                    raise ValueError("Stop the synthetic VM before rolling back its transaction")
                details = {"changes": sorted(name for name in target if actual[name] != target[name])}
            else:
                details = {"pending": bookmark_recovery if action is Action.BOOKMARK_RECOVER
                           else pending is not None}
                if pending and recovery:
                    target = pending["before"] if action is Action.ABORT and not pending.get("aborted") else pending["after"]
                    details["changes"] = sorted(name for name in actual if actual[name] != target[name])

        encoded = {name: encode(value) if value is not None else None
                   for name, value in updates.items()}
        if updates:
            details["changes"] = {name: updates[name] for name in sorted(updates)
                                  if encoded[name] != actual[name]}
        permitted = self.can_apply(request) and allowed
        approval = hashlib.sha256(encode([self.identity, action.value, request.role.value,
                                          payload, context]).encode()).hexdigest()
        preview = {"action": action.value, "backend": "synthetic", "live": "BLOCKED",
                   "authorized": self.can_apply(request), "ready": allowed,
                   "approval": approval if permitted else None, **details}
        return preview, encoded, desired, book_state

    @staticmethod
    def can_apply(request):
        try:
            request.authorize()
        except PermissionError:
            return False
        return True

    @staticmethod
    def value(actual, name):
        return json.loads(actual[name]) if actual[name] is not None else None

    def require_full_profile(self, actual):
        deployment = self.value(actual, "deployment.json") or {}
        if deployment.get("profile") != "full-enterprise":
            raise ValueError("Deploy the synthetic Full Enterprise profile first")
        return deployment

    def apply(self, request, approval):
        request.authorize()
        with self.locked():
            preview, updates, desired, previous = self.plan(request)
            if (not preview["ready"] or not isinstance(approval, str)
                    or not re.fullmatch(r"[0-9a-f]{64}", approval)
                    or not secrets.compare_digest(preview["approval"], approval)):
                raise ValueError("Apply requires explicit approval of the current ready preview")
            if request.action is Action.ROLLBACK:
                return self.rollback()
            if request.action in {Action.RESUME, Action.ABORT}:
                return self.recover(abort=request.action is Action.ABORT)
            if request.action is Action.BOOKMARK_RECOVER:
                book, ledger = bookmarks.locations(self.directory)
                if not ledger.exists():
                    return False
                with bookmarks.locked(book):
                    if os.path.lexists(ledger / "pending.json"):
                        bookmarks.recover(book, ledger)
                    else:
                        checkpoint_path = ledger / pilot_session.BACKUP
                        checkpoint = state.Store(ledger).read_record(checkpoint_path)
                        if self.unapplied_checkpoint(bookmarks.snapshot(book, ledger), checkpoint):
                            state.write(checkpoint_path, None)
            elif request.action in {Action.START, Action.STOP}:
                if preview["changes"]:
                    content = encode(preview["identity"]) if request.action is Action.START else None
                    state.write(self.directory / "runtime.json", content)
            elif request.action is Action.BOOKMARK_ROLLBACK:
                pilot_session.rollback(config=self.directory, confirm=lambda _: True, quiet=True)
            elif desired is not None:
                if preview["changes"]:
                    pilot_session.stage_bookmarks(desired, self.directory, previous)
            else:
                self.change(**updates)
            return True
