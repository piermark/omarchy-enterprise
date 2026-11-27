# SPDX-License-Identifier: MIT
"""Explicit Phase 12 user and administrator interfaces."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

from . import bookmarks, deployment, directory, operational, operational_cups, operational_windows, pilot_session


def read_document():
    data = sys.stdin.buffer.read(32769)
    if len(data) > 32768:
        raise ValueError("Input document is too large")
    try:
        return json.loads(data)
    except (ValueError, RecursionError):
        raise ValueError("Expected bounded JSON input") from None


def arguments(parser):
    actions = parser.add_subparsers(dest="operation", required=True)
    packages = actions.add_parser("dependencies")
    packages.add_argument("profile", choices=operational.PROFILES)
    packages.add_argument("--printing", action="store_true")
    ad = actions.add_parser("domain-preview")
    for field in ("domain", "workgroup", "users", "admins"):
        ad.add_argument(field)
    actions.add_parser("cups-status")
    actions.add_parser("cups-review", help="read a printer document from standard input")
    windows = actions.add_parser("windows-review")
    windows.add_argument("image")
    for field in ("cpu", "memory", "disk"):
        windows.add_argument(field, type=int)
    status = actions.add_parser("windows-status", help="inspect a full Phase 12 container ID")
    status.add_argument("identity")
    lifecycle = actions.add_parser("windows-lifecycle-review")
    lifecycle.add_argument("identity")
    lifecycle.add_argument("action", choices=("start", "stop"))
    connection = actions.add_parser("windows-connect-review")
    connection.add_argument("host")
    connection.add_argument("account")
    connection.add_argument("port", type=int)
    for action in ("bookmarks-review", "bookmarks-sync", "bookmarks-rollback",
                   "bookmarks-recover", "bookmarks-accept", "login-plan", "login-worker"):
        actions.add_parser(action)


def user_action(args):
    if os.geteuid() == 0:
        raise ValueError("Use this interface as an ordinary user")
    source = operational.POLICY
    action = args.operation
    if action == "dependencies":
        return {"mode": "real read-only", "packages": operational.dependencies(args.profile, args.printing)}
    if action == "domain-preview":
        files = directory.render(args.domain, args.workgroup, args.users, args.admins)
        return {"mode": "blocked", "preview_files": sorted(files), "domain_enrollment": "blocked"}
    if action == "cups-status":
        return {"mode": "real read-only", "queues": list(operational_cups.Cups().queues().values())}
    if action == "cups-review":
        return {"mode": "implemented but unqualified", **operational_cups.Cups().review(read_document())}
    if action == "windows-review":
        settings = operational_windows.Settings(args.image, args.cpu, args.memory, args.disk)
        return {"mode": "implemented but unqualified", **operational_windows.Dockur().create_plan(settings)}
    if action == "windows-status":
        return {"mode": "real read-only", "runtime": operational_windows.Dockur().status(args.identity)}
    if action == "windows-lifecycle-review":
        return {"mode": "implemented but unqualified",
                **operational_windows.Dockur().lifecycle_plan(args.identity, args.action)}
    if action == "windows-connect-review":
        return {"mode": "real read-only", "command":
                operational_windows.connection_plan(args.host, args.account, args.port)}
    if action == "login-plan":
        return {"mode": "implemented but unqualified", "autostart_installed": False,
                "command": ["/usr/bin/omarchy-enterprise", "operational", "login-worker"],
                "policy": str(source), "principal": "desktop user"}
    if action == "login-worker":
        return pilot_session.login_worker(source, operational=True)
    if action == "bookmarks-accept":
        accept = pilot_session.bookmark_acceptance()
        if not pilot_session.approved("Keep the current managed bookmarks and finalize their rollback checkpoint?"):
            return 1
        accept()
        return {"accepted": True}
    if action == "bookmarks-rollback":
        return pilot_session.rollback(operational=True)
    if action == "bookmarks-recover":
        book, ledger = bookmarks.locations(operational=True)
        if not ledger.is_dir():
            return {"recovered": False}
        with bookmarks.locked(book):
            return {"recovered": bool(bookmarks.recover(book, ledger))}
    if action in {"bookmarks-review", "bookmarks-sync"}:
        before, resources, (_, owned) = pilot_session.bookmark_plan(source, read_only=True, operational=True)
        if action == "bookmarks-sync":
            return pilot_session.integrate(source, expected=(before, resources), operational=True)
        return {"mode": "real read-only", "eligible_count": len(resources), "managed_count": len(owned)}
    raise ValueError("Unknown operational action")


def execute(args):
    try:
        result = user_action(args)
        if isinstance(result, int):
            return result
        print(operational.encode(result), end="")
        return 0
    except (ValueError, OSError) as error:
        print(f"Operational action incomplete: {reason(error)}", file=sys.stderr)
        return 1


def reason(error):
    return str(error) if isinstance(error, ValueError) else "A required local resource is unavailable"


def recovery_plan(store, action):
    store.validate_directory()
    history = store.history()
    if action == "rollback":
        if os.path.lexists(store.journal):
            raise ValueError("Review the pending transaction before rollback")
        actual = store.snapshot()
        if actual != (history["after"] if history else store.empty):
            raise ValueError("External change requires manual recovery")
        record = store.rollback_checkpoint(history)
    else:
        record = store.read_record(store.journal)
        actual = store.recovery_state(record) if record else store.snapshot()
    return {"operation": action, "record_sha256": hashlib.sha256(operational.encode(record).encode()).hexdigest(),
            "history_sha256": hashlib.sha256(operational.encode(history).encode()).hexdigest(),
            "current_sha256": operational.snapshot_hashes(actual), "exists": record is not None}


def deployment_status(store):
    ledger = store.validate_directory()
    history = store.history()
    pending = store.read_record(store.journal)
    current = store.snapshot()
    expected = history["after"] if history else store.empty
    conflict = current != expected
    if pending:
        try:
            store.recovery_state(pending)
        except ValueError:
            conflict = True
        else:
            conflict = False
    return {"ledger_present": ledger, "pending_transaction": pending is not None,
            "external_conflict": conflict,
            "rollback_checkpoint": bool(history and history["before"] != history["after"]),
            "files": {name: value is not None for name, value in current.items()},
            "mode": "administrator read-only"}


def admin_action(args):
    operational.administrator()
    if args.operation.startswith("cups-"):
        directory = deployment.safe_path(Path("/"), f"{operational.LEDGER}/external", directory=True)
        journal = operational.ExternalJournal(directory, "cups")
        adapter = operational_cups.Cups()
        receipt = journal.read()
        if args.operation == "cups-recover-update":
            if args.approve is not None:
                adapter.recover_update(args.approve, journal)
                return {"completed": True}
            plan = adapter.update_recovery_plan(receipt)
            return plan | {"approval": operational.approved(plan), "mode": "CUPS recovery qualification required"}
        if receipt and receipt.get("status") != "complete":
            raise ValueError("Reconcile the interrupted CUPS receipt before another operation")
        if args.operation == "cups-create":
            payload = read_document()
            if args.approve is not None:
                adapter.execute_managed(payload, args.approve, journal)
                return {"completed": True}
            plan = adapter.review(payload)
        elif args.operation == "cups-rollback":
            if args.approve is not None:
                adapter.rollback(args.approve, journal)
                return {"completed": True}
            plan = adapter.rollback_plan(receipt or {})
        else:
            payload = read_document()
            if not isinstance(payload, dict) or payload.keys() != {"name", "before", "after"}:
                raise ValueError("Expected queue name, before and after fields")
            undo = args.operation == "cups-undo-update"
            if args.approve is not None:
                adapter.update(**payload, token=args.approve, journal=journal, undo=undo)
                return {"completed": True}
            plan = adapter.update_plan(receipt, **payload, undo=undo)
        return plan | {"approval": operational.approved(plan), "mode": "CUPS mutation qualification required"}
    store = operational.Deployment()
    if args.operation == "status":
        if args.approve is not None:
            raise ValueError("Status does not accept an approval token")
        return deployment_status(store)
    if args.operation == "deploy":
        payload = read_document()
        if not isinstance(payload, dict) or payload.keys() != {"profile", "printing", "shares"}:
            raise ValueError("Expected profile, printing and shares fields")
        files = operational.document(**payload)
        def discover():
            return operational.dependencies(payload["profile"], payload["printing"])

        packages = discover()
        if args.approve is not None:
            store.transaction(files, packages, args.approve, refresh_packages=discover)
            return {"completed": True}
        plan = store.review(files, packages)
    else:
        plan = recovery_plan(store, args.operation)
        if args.approve is not None:
            operational.require_approval(plan, args.approve)
            if not plan["exists"]:
                raise ValueError("No matching operational recovery record exists")
            with store.locked():
                operational.require_approval(recovery_plan(store, args.operation), args.approve)
                completed = (store.rollback() if args.operation == "rollback"
                             else store.recover(abort=args.operation == "abort"))
            return {"completed": completed}
    return plan | {"approval": operational.approved(plan), "mode": "administrator approval required"}


def admin_main():
    parser = argparse.ArgumentParser(prog="omarchy-enterprise-admin operational")
    parser.add_argument("operation", choices=("deploy", "status", "rollback", "recover", "abort",
                                              "cups-create", "cups-rollback", "cups-update",
                                              "cups-undo-update", "cups-recover-update"))
    parser.add_argument("--approve")
    try:
        print(operational.encode(admin_action(parser.parse_args())), end="")
        return 0
    except (ValueError, OSError) as error:
        print(f"Operational administration incomplete: {reason(error)}", file=sys.stderr)
        return 1
