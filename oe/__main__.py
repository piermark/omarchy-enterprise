# SPDX-License-Identifier: MIT
"""Command-line and terminal console entry points."""

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
from pathlib import Path

from . import ad_diagnostics, directory, graphical, lab, operations, policy, profiles, provision, session, windows, windows_storage, wizard
from . import __version__
from . import bookmarks, deployment, pilot_desktop, pilot_publication, pilot_session, remote_desktop
from . import diagnostics as host_diagnostics, installation, legacy_review, migration
from . import phase11_cli
from . import operational_cli
from . import status as enterprise_status
from .state import Store

SYSTEM_POLICY = Path("/etc/omarchy-enterprise/smb-policy.json")


def serialize(document):
    return json.dumps(document, indent=2, sort_keys=True) + "\n"


def configuration(args):
    profile = args.profile
    if profile is None:
        if not sys.stdin.isatty():
            raise ValueError("Specify --profile for unattended use")
        for index, name in enumerate(profiles.PROFILES, 1):
            print(f"{index}. {name}")
        selection = input("Installation profile [1]: ").strip() or "1"
        if selection not in ("1", "2", "3"):
            raise ValueError("Invalid profile selection")
        profile = tuple(profiles.PROFILES)[int(selection) - 1]
    domain = args.domain
    if profile != "standalone":
        if domain is None and sys.stdin.isatty():
            domain = input("Active Directory DNS domain: ").strip()
        if domain is None or not policy.HOST.fullmatch(domain):
            raise ValueError("Specify a fully qualified Active Directory DNS domain")
    elif domain:
        raise ValueError("The standalone profile does not use a domain")
    enabled = args.windows
    if enabled is None:
        enabled = (input("Include Windows in the plan? [y/N]: ").strip().lower() == "y"
                   if sys.stdin.isatty() else False)
    return {
        "profile": profile,
        "domain": domain.lower() if domain else None,
        "windows": enabled,
        "planned_modules": profiles.modules(profile, enabled),
    }


def refresh(store, source):
    # The installed default policy belongs in an administrator-controlled directory.
    if source == SYSTEM_POLICY and not source.exists():
        resources = {}
    else:
        resources = policy.shares(policy.load_file(source.absolute(), system=source == SYSTEM_POLICY), policy.effective_groups())
    with store.locked():
        store.change(**{"resources.json": serialize(resources)})
    return resources


def doctor(store, *, network=False):
    # Diagnose an immutable snapshot without creating a lock or state directory.
    print(serialize(host_diagnostics.report()), end="")
    if not store.validate_directory():
        return report_checks({"Transaction state": True})
    pending = os.path.lexists(store.journal)
    history = store.history()
    actual = store.snapshot()
    consistent = actual == (history["after"] if history else store.empty)
    if (pending or os.path.lexists(store.journal) or not consistent
            or history != store.history()):
        return report_checks({"Transaction state": False})
    profile = json.loads(actual["profile.json"]) if actual["profile.json"] else {}
    if (not isinstance(profile, dict) or
            (profile.get("domain") is not None and
             (not isinstance(profile["domain"], str) or not policy.HOST.fullmatch(profile["domain"])))):
        return report_checks({"Saved profile": False})
    if profile.get("domain") and not network:
        print("SKIPPED AD discovery and connectivity (use --network to authorize probes)")
    return report_checks({"Transaction state": True} | profile_checks(profile, network=network))


def profile_checks(profile, *, network=True):
    checks = {}
    if network and profile.get("domain"):
        executable = shutil.which("dig")
        try:
            result = subprocess.run(
                [executable, "+short", "+time=2", "+tries=1",
                 f"_ldap._tcp.dc._msdcs.{profile['domain']}", "SRV"],
                capture_output=True, text=True, timeout=5, check=True) if executable else None
            records = [line.split() for line in result.stdout.splitlines()] if result else []
            targets = [row[3].rstrip(".") for row in records if len(row) == 4
                       and row[2] == "389" and policy.HOST.fullmatch(row[3].rstrip("."))]
            checks["AD DC discovery"] = bool(targets)
            reachable = False
            for target in list(dict.fromkeys(targets))[:4]:
                try:
                    with socket.create_connection((target, 389), timeout=2):
                        reachable = True
                        break
                except OSError:
                    continue
            checks["AD LDAP TCP connectivity"] = reachable
        except (OSError, subprocess.SubprocessError):
            checks["AD DC discovery"] = False
            checks["AD LDAP TCP connectivity"] = False
    if profile.get("windows"):
        checks["KVM device access"] = os.access("/dev/kvm", os.R_OK | os.W_OK)
        checks["Container client"] = bool(shutil.which("docker") or shutil.which("podman"))
        checks["FreeRDP"] = bool(shutil.which("xfreerdp3") or shutil.which("xfreerdp"))
    return checks


def report_checks(checks):
    for label, passed in checks.items():
        print(f"{'PASS' if passed else 'FAIL'} {label}")
    return 0 if all(checks.values()) else 1


def console(store):
    resources = refresh(store, SYSTEM_POLICY)
    with store.locked():
        saved = store.snapshot()["profile.json"]
    profile = json.loads(saved) if saved else {}
    windows_enabled = profile.get("windows", False)
    print("Omarchy Enterprise\n1. Diagnostics")
    if windows_enabled:
        print("2. Windows Remote Desktop")
    entries = list(resources.items())
    first_share = 3 if windows_enabled else 2
    for index, (label, _) in enumerate(entries, first_share):
        print(f"{index}. Network share / {label}")
    choice = input("Choose an action or press Enter to exit: ").strip()
    if not choice:
        return 0
    if choice == "1":
        return doctor(store)
    if windows_enabled and choice == "2":
        host = input("Windows certificate DNS name: ").strip()
        account = input("Windows account: ").strip()
        return subprocess.call(windows.rdp_command(host, account, 3389))
    if choice.isascii() and choice.isdecimal() and len(choice) <= 8:
        index = int(choice) - first_share
        if 0 <= index < len(entries):
            label, uri = entries[index]
            if refresh(store, SYSTEM_POLICY).get(label) != uri:
                raise ValueError("The network share policy changed. Reopen the console.")
            return subprocess.call(["gio", "open", uri])
    raise ValueError("Invalid action")


def desktop_console(store):
    dialog = graphical.Dialog()
    while True:
        resources = refresh(store, SYSTEM_POLICY)
        shares = list(resources)
        actions = graphical.REFERENCE_ACTIONS if graphical.reference_available() else {}
        entries = [(1, "Enterprise status and diagnostics"), (2, "Inventory summary")]
        entries.extend((("file-servers-manager", "File Server Manager"),
                        ("file-servers-refresh", "Refresh Nautilus SMB bookmarks"),
                        ("guided-installer", "Guided installer (offline staging)"),
                        ("printer-admin", "Printers and queue administration"),
                        ("update-readiness", "Update and rollback readiness"),
                        ("installation-review", "Existing installation review"),
                        ("legacy-preview", "Legacy compatibility and migration preview"),
                        ("windows-status", "Windows VM status (manual start only)")))
        entries.append(("remote-desktop", "Inbound Remote Desktop is OFF"))
        entries.extend((f"reference-{action}", label) for action, label in actions.items())
        entries.extend((index, label) for index, label in enumerate(shares, 3))
        choice = dialog.choose(entries)
        if choice is None:
            return 0
        if choice == "1":
            dialog.report(graphical.DIAGNOSTIC_STATES + serialize(host_diagnostics.report(runtime=True)))
        elif choice == "2":
            dialog.report(serialize(operations.inventory()))
        elif choice == "legacy-preview":
            graphical.migration_preview(dialog)
        elif choice == "installation-review":
            dialog.report(serialize(installation.review()))
        elif choice == "guided-installer":
            wizard.run(store=store)
        elif choice == "printer-admin":
            if graphical.printer_available():
                graphical.launch_printer()
            else:
                dialog.report("Printer settings require the packaged printer command and system-config-printer. "
                              "Ask your administrator to install them. Queue changes may require approval.")
        elif choice == "update-readiness":
            dialog.report(graphical.UPDATE_GUIDANCE)
        elif choice == "windows-status":
            dialog.report(graphical.WINDOWS_GUIDANCE + serialize(
                host_diagnostics.report(runtime=True)["windows_runtime"]))
        elif choice == "file-servers-manager":
            pilot_session.manager(SYSTEM_POLICY)
        elif choice == "file-servers-refresh":
            bookmarks.update(refresh(store, SYSTEM_POLICY))
            dialog.report("Managed Nautilus bookmarks refreshed.")
        elif choice == "remote-desktop":
            dialog.report("Inbound Remote Desktop is disabled. Full acceptance is blocked.\n\n"
                          + serialize(remote_desktop.diagnostics()))
        elif choice.startswith("reference-") and choice.removeprefix("reference-") in actions:
            graphical.launch_reference(choice.removeprefix("reference-"))
        else:
            index = int(choice) - 3
            if not 0 <= index < len(shares):
                raise ValueError("Invalid desktop action")
            label = shares[index]
            uri = refresh(store, SYSTEM_POLICY).get(label)
            if uri != resources[label]:
                raise ValueError("The network share policy changed. Reopen the console.")
            operations.command("gio", "open", uri)


def windows_options(parser):
    parser.add_argument("--storage-path", type=Path)
    parser.add_argument("--disk-io", choices=windows_storage.DISK_IO)
    parser.add_argument("--disk-cache", choices=windows_storage.DISK_CACHE)
    parser.add_argument("--restart", choices=windows_storage.RESTART)


def parser():
    state = Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local/state")
    result = argparse.ArgumentParser(prog="omarchy-enterprise")
    result.add_argument("--version", action="version", version=f"%(prog)s v{__version__}")
    result.add_argument("--state-dir", type=Path, default=state / "omarchy-enterprise")
    commands = result.add_subparsers(dest="command", required=True)
    deployment.add_parser(commands)
    install = commands.add_parser("install")
    install.add_argument("--profile", choices=profiles.PROFILES)
    install.add_argument("--domain")
    install.add_argument("--windows", action=argparse.BooleanOptionalAction)
    install.add_argument("--dry-run", action="store_true")
    uninstall = commands.add_parser("uninstall")
    uninstall.add_argument("--component", choices=("profile", "resources", "all"), default="all")
    commands.add_parser("rollback")
    commands.add_parser("recover").add_argument("--abort", action="store_true")
    migration_cli = commands.add_parser("migration", help="discover shadow commands and preview quarantine")
    migration_cli.add_argument("action", choices=("discover", "preview"))
    migration_cli.add_argument("commands", nargs="*")
    hooks = commands.add_parser("hook-review", help="review Guard parity or stage an inert hook example")
    hook_actions = hooks.add_subparsers(dest="action", required=True)
    for action in ("stage", "rollback"):
        hook_actions.add_parser(action).add_argument("directory", type=Path)
    parity = hook_actions.add_parser("guard-parity")
    parity.add_argument("legacy", type=Path)
    parity.add_argument("packaged", type=Path)
    review = commands.add_parser("installation", help="review existing configuration or record adoption metadata")
    review.add_argument("action", choices=("review", "adopt"))
    review.add_argument("--confirm")
    diagnostics = commands.add_parser("doctor")
    diagnostics.add_argument("--summary", action="store_true")
    diagnostics.add_argument("--services", action="store_true", help="query service states with --summary")
    diagnostics.add_argument("--image-root", type=Path, help="inspect a disposable image with --summary")
    diagnostics.add_argument("--network", action="store_true",
                             help="allow DNS discovery and LDAP TCP checks for the saved AD profile")
    diagnostics.add_argument("--windows-storage")
    diagnostics.add_argument("--windows-compose", type=Path)
    diagnostics.add_argument("--btrfs-counters", action="store_true")
    diagnostics.add_argument("--file-servers", action="store_true")
    diagnostics.add_argument("--remote-desktop", action="store_true")
    diagnostics.add_argument("--rdp-policy", type=Path)
    phase11_cli.add_arguments(commands.add_parser("phase11", help="synthetic deployment and administration"))
    operational_cli.arguments(commands.add_parser("operational", help="real operating-system integration"))
    commands.add_parser("console")
    commands.add_parser("desktop").add_argument("--zenity", action="store_true")
    commands.add_parser("inventory")
    commands.add_parser("updates")
    for action in ("guard", "compliance"):
        baseline = commands.add_parser(action)
        baseline.add_argument("root", type=Path)
        baseline.add_argument("manifest", type=Path)
    certificate = commands.add_parser("certificate")
    certificate.add_argument("path", type=Path)
    printing = commands.add_parser("print-file")
    printing.add_argument("queue")
    printing.add_argument("path", type=Path)
    domain = commands.add_parser("ad-config")
    domain.add_argument("--output-dir", type=Path)
    for field in ("domain", "workgroup", "users", "admins"):
        domain.add_argument(f"--{field}", required=True)
    domain.add_argument("--preferred-dc", action="append", default=[])
    domain.add_argument("--dc-discovery-fallback", action="store_true")
    diagnostics = commands.add_parser("ad-diagnostics")
    diagnostics.add_argument("--machine", action="store_true")
    diagnostics.add_argument("--dc", action="append", default=[])
    provisioning = commands.add_parser("lab-provision")
    provisioning.add_argument("--root", type=Path, required=True)
    actions = provisioning.add_subparsers(dest="lab_action", required=True)
    apply = actions.add_parser("apply")
    for field in ("domain", "workgroup", "users", "admins"):
        apply.add_argument(f"--{field}", required=True)
    for action in ("remove", "rollback"):
        actions.add_parser(action)
    actions.add_parser("recover").add_argument("--abort", action="store_true")
    image_install = commands.add_parser("provision-image")
    image_install.add_argument("--root", type=Path, required=True)
    image_actions = image_install.add_subparsers(dest="image_action", required=True)
    image_apply = image_actions.add_parser("apply")
    image_apply.add_argument("--profile", choices=profiles.PROFILES, required=True)
    for field in ("domain", "workgroup", "users", "admins", "printer", "image"):
        image_apply.add_argument(f"--{field}")
    image_apply.add_argument("--preferred-dc", action="append", default=[])
    image_apply.add_argument("--file-servers", type=Path)
    image_apply.add_argument("--rdp-policy", type=Path)
    image_apply.add_argument("--dc-discovery-fallback", action="store_true")
    image_apply.add_argument("--cpu", type=int, default=4)
    image_apply.add_argument("--memory", type=int, default=8)
    image_apply.add_argument("--disk", type=int, default=128)
    windows_options(image_apply)
    image_apply.add_argument("--dry-run", action="store_true")
    image_apply.add_argument("--yes", action="store_true")
    for action in ("remove", "rollback", "recover"):
        step = image_actions.add_parser(action)
        step.add_argument("--yes", action="store_true")
        if action == "remove":
            step.add_argument("--component", choices=("all", *provision.REMOVABLE), default="all")
        if action == "recover":
            step.add_argument("--abort", action="store_true")
    gui = commands.add_parser("provision-wizard")
    gui.add_argument("--native", action="store_true", help="require the native GTK installer")
    gui.add_argument("--zenity", action="store_true")
    gui.add_argument("--root", type=Path)
    gui.add_argument("--dry-run", action="store_true")
    update = commands.add_parser("policy-refresh")
    update.add_argument("--policy", type=Path, default=SYSTEM_POLICY)
    update.add_argument("--login", action="store_true")
    compose = commands.add_parser("windows-plan")
    compose.add_argument("--image", required=True)
    compose.add_argument("--cpu", type=int, default=4)
    compose.add_argument("--memory", type=int, default=8)
    compose.add_argument("--disk", type=int, default=128)
    windows_options(compose)
    commands.add_parser("rdp-capabilities")
    commands.add_parser("windows-connect")
    remote = commands.add_parser("remote-desktop", help="inspect Remote Desktop prerequisites and review policy offline")
    remote.add_argument("--policy", type=Path, help="review an explicit policy without activating it")
    remote.add_argument("--acknowledge-delegation", action="store_true", help=remote_desktop.DELEGATION_WARNING)
    windows_actions = commands.add_parser("windows-lifecycle")
    windows_actions.add_argument("action", choices=("start", "stop", "restart", "status", "settings"))
    resource_actions = commands.add_parser("file-servers")
    shared_actions = ("integrate", "rollback", "manager", "kerberos", "login-refresh", "login-worker")
    resource_actions.add_argument("action", choices=("list", "refresh", "clear", "set", "remove", *shared_actions))
    pilot_publication.add_arguments(commands.add_parser("publish-file-servers"))
    resource_actions.add_argument("--draft", type=Path)
    resource_actions.add_argument("--uri")
    resource_actions.add_argument("--label")
    resource_actions.add_argument("--group", action="append", default=[])
    pilot = commands.add_parser("pilot-session", help="opt-in Enterprise desktop integration")
    pilot.add_argument("action", choices=("integrate", "rollback", "manager", "kerberos", "login-refresh",
                                          "login-worker", "menu"))
    desktop = commands.add_parser("desktop-integration", aliases=["pilot-desktop"], help="review or selectively update native Omarchy integration")
    desktop.add_argument("target", choices=("menu", "login"))
    desktop.add_argument("action", choices=("preview", "enable", "disable"))
    desktop.add_argument("--confirm", action="store_true")
    smb = commands.add_parser("kerberos-smb-check")
    smb.add_argument("uri")
    rdp = commands.add_parser("rdp")
    rdp.add_argument("host")
    rdp.add_argument("account")
    rdp.add_argument("--port", type=int, default=3389)
    auth = rdp.add_mutually_exclusive_group()
    auth.add_argument("--kerberos-probe", action="store_true")
    auth.add_argument("--kerberos-session", action="store_true")
    return result


def install_profile(store, profile):
    checks = profile_checks(profile)
    if not all(checks.values()):
        return report_checks(checks)
    with store.locked():
        store.change(**{"profile.json": serialize(profile)})
        history = store.history()
        consistent = store.snapshot() == history["after"] and not store.journal.exists()
    return report_checks({"Transaction state": consistent} | checks)


def provision_image(args):
    target = provision.ImageStore(args.root)
    files = None
    reviewed_history = None
    if args.image_action == "apply":
        detection = installation.review(target.root, target=target)
        print(serialize(detection), end="")
        if detection["review_only"]:
            raise ValueError("Existing unmanaged integration requires review. Choose a clean staging directory.")
        reviewed_history = (target.history(),)
        files = provision.render(args.profile, domain=args.domain, workgroup=args.workgroup,
                                 users=args.users, admins=args.admins, printer=args.printer,
                                 image=args.image, cpu=args.cpu, memory=args.memory, disk=args.disk,
                                 preferred_dcs=args.preferred_dc,
                                 discovery_fallback=args.dc_discovery_fallback,
                                 storage=args.storage_path, disk_io=args.disk_io,
                                 disk_cache=args.disk_cache, restart=args.restart,
                                 windows_base=target.root / provision.CONFIG / "windows",
                                 existing_windows=target.windows_settings() if args.image else None,
                                 file_servers=policy.load_file(args.file_servers.absolute()) if args.file_servers else None,
                                 rdp_policy=policy.load_file(args.rdp_policy.absolute()) if args.rdp_policy else None)
        changes = target.plan(files)
        rdp_review = json.loads(files["profile.json"]).get("remote_desktop")
        print(wizard.preview(changes, provision.health(args.profile, bool(args.image)), rdp_review), end="")
        if args.dry_run:
            return int("CONFLICT" in changes.values())
        if "CONFLICT" in changes.values():
            raise ValueError("Resolve provisioning conflicts before applying")
    if args.image_action == "remove":
        print(f"Remove managed image files ({args.component}). Unrelated files and VM disks are preserved.")
    if not args.yes:
        if not sys.stdin.isatty() or input("Apply the requested transaction? [y/N]: ").strip().lower() != "y":
            raise ValueError("Explicit confirmation is required; pass --yes only after review")
    if args.image_action == "apply" and installation.review(target.root, target=target) != detection:
        raise ValueError("Installation detection changed. Review the selected target again.")
    installed = provision.mutate(args.root, args.image_action, files,
                                 abort=getattr(args, "abort", False), expected_history=reviewed_history,
                                 component=getattr(args, "component", "all"))
    print("Transaction verified")
    for destination in installed:
        print(destination)
    return 0


def connect_windows(host, account, port, *, kerberos_session=False, kerberos_probe=False):
    command = windows.rdp_command(host, account, port, kerberos_probe=kerberos_probe)
    if kerberos_probe:
        session.require_ticket()
        return subprocess.run(command, stdin=subprocess.DEVNULL, timeout=30).returncode
    if kerberos_session:
        command = windows.guarded_session(command, windows.help_text(command[0]))
        session.require_ticket()
        return subprocess.run(command, stdin=subprocess.DEVNULL, start_new_session=True).returncode
    if not sys.stdin.isatty():
        raise ValueError("Start FreeRDP from an interactive terminal")
    return subprocess.call(command)


def windows_prompt():
    if not sys.stdin.isatty():
        raise ValueError("Open this launcher from the Omarchy terminal")
    host = input("Windows certificate DNS name: ").strip()
    account = input("Windows account (local account or AD principal): ").strip()
    print("FreeRDP will request your password interactively. It is not stored.")
    return connect_windows(host, account, 3389)



def file_server_session(args, *, product=False):
    if args.action == "manager":
        return pilot_session.manager(SYSTEM_POLICY)
    if args.action == "rollback":
        return pilot_session.rollback()
    if args.action == "kerberos":
        available = pilot_session.ticket_available()
        print("Session ticket:", "available" if available else "unavailable")
        return int(not available)
    if args.action == "menu":
        print(serialize(pilot_session.menu()), end="")
        return 0
    if args.action == "login-refresh":
        return pilot_desktop.supervise_login(product=product)
    if args.action == "login-worker":
        return pilot_session.login_worker(SYSTEM_POLICY)
    return pilot_session.integrate(SYSTEM_POLICY)

def main():
    args = parser().parse_args()
    if args.command == "deploy":
        try:
            return deployment.execute(args)
        except (ValueError, OSError, subprocess.SubprocessError) as error:
            print(f"Deployment stopped: {error if isinstance(error, ValueError) else type(error).__name__}", file=sys.stderr)
            return 1
    if args.command == "ad-diagnostics":
        try:
            if args.machine != (os.geteuid() == 0):
                raise ValueError("Run machine diagnostics as administrator and session diagnostics as the session user")
            checks = ad_diagnostics.report(machine=args.machine, controllers=args.dc)
            print(serialize(checks), end="")
            return 0 if ad_diagnostics.passed(checks) else 1
        except ValueError as error:
            print(f"omarchy-enterprise: {error}", file=sys.stderr)
            return 1
    if args.command == "publish-file-servers":
        return pilot_publication.execute(args, product=True)
    if os.geteuid() == 0:
        print("Run as an unprivileged user.", file=sys.stderr)
        return 1
    store = Store(args.state_dir)
    try:
        if args.command == "operational":
            return operational_cli.execute(args)
        if args.command == "phase11":
            return phase11_cli.execute(args)
        if args.command == "install":
            config = configuration(args)
            print(serialize(config), end="")
            if not args.dry_run:
                return install_profile(store, config)
        elif args.command == "uninstall":
            targets = Store.names if args.component == "all" else {f"{args.component}.json"}
            with store.locked():
                store.change(**dict.fromkeys(targets))
        elif args.command == "rollback":
            with store.locked():
                print("Rolled back." if store.rollback() else "No transaction to roll back.")
        elif args.command == "recover":
            with store.locked():
                if store.recover(abort=args.abort):
                    print("Interrupted transaction cancelled." if args.abort else "Recovered.")
                else:
                    print("No interrupted transaction.")
        elif args.command == "migration":
            if args.action == "discover" and args.commands:
                raise ValueError("Select commands with migration preview")
            print(serialize(migration.Migration().preview(args.commands)), end="")
        elif args.command == "hook-review":
            return legacy_review.review_command(args)
        elif args.command == "installation":
            if (args.action == "adopt") != bool(args.confirm):
                raise ValueError("Adoption requires the explicit installation review token")
            report = installation.adopt(store, args.confirm) if args.confirm else installation.review()
            print(serialize(report), end="")
        elif args.command == "doctor":
            if not args.summary and (args.image_root is not None or args.services):
                raise ValueError("--image-root and --services require --summary")
            if args.image_root is not None and args.services:
                raise ValueError("Image summaries cannot query running host services")
            if args.rdp_policy and not args.remote_desktop:
                raise ValueError("--rdp-policy requires --remote-desktop")
            if args.summary:
                if any((args.network, args.file_servers, args.remote_desktop, args.windows_storage,
                        args.windows_compose, args.btrfs_counters)):
                    raise ValueError("Enterprise summary is a separate offline check")
                report = enterprise_status.summary(store, SYSTEM_POLICY) if args.image_root is None else (
                    enterprise_status.image_summary(args.image_root))
                if args.services:
                    runtime = host_diagnostics.report(runtime=True)
                    report.update(services=runtime["services"], windows_runtime=runtime["windows_runtime"])
                print(serialize(report), end="")
                return 0
            if args.remote_desktop:
                if any((args.network, args.file_servers, args.windows_storage,
                        args.windows_compose, args.btrfs_counters)):
                    raise ValueError("Remote Desktop diagnostics are a separate offline check")
                candidate = remote_desktop.validate(policy.load_file(args.rdp_policy.absolute())) if args.rdp_policy else None
                report = remote_desktop.diagnostics(candidate)
                report.update(host_diagnostics.inbound_rdp(candidate))
                print(serialize(report), end="")
                return 0
            if args.file_servers:
                if any((args.network, args.windows_storage, args.windows_compose, args.btrfs_counters)):
                    raise ValueError("File Servers diagnostics are a separate offline check")
                return bookmarks.diagnostics(SYSTEM_POLICY)
            if args.windows_storage is not None:
                if args.network:
                    raise ValueError("Storage diagnostics do not use --network")
                report = windows_storage.diagnostics(args.windows_storage,
                                                     compose_path=args.windows_compose,
                                                     counters=args.btrfs_counters)
                print(serialize(report), end="")
                return 0
            if args.windows_compose is not None or args.btrfs_counters:
                raise ValueError("Specify the Windows storage path for storage diagnostics")
            return doctor(store, network=args.network)
        elif args.command == "desktop":
            from .control_center.launcher import run
            return run(store, SYSTEM_POLICY, lambda: desktop_console(store), force=args.zenity)
        elif args.command == "remote-desktop":
            document = policy.load_file(args.policy.absolute()) if args.policy else None
            if args.acknowledge_delegation:
                print(remote_desktop.DELEGATION_WARNING, file=sys.stderr)
                print(serialize(remote_desktop.acknowledge_delegation(document)), end="")
            else:
                candidate = remote_desktop.validate(document) if args.policy else None
                print(serialize(remote_desktop.diagnostics(candidate)), end="")
        elif args.command == "inventory":
            print(serialize(operations.inventory()), end="")
        elif args.command == "updates":
            return operations.updates()
        elif args.command in ("guard", "compliance"):
            with args.manifest.open(encoding="utf-8") as stream:
                manifest = json.load(stream)
            check = operations.guard if args.command == "guard" else operations.compliance
            checks = check(args.root, manifest)
            print(serialize(checks), end="")
            return 0 if all(checks.values()) else 1
        elif args.command == "certificate":
            operations.certificate(args.path)
        elif args.command == "print-file":
            operations.print_file(args.queue, args.path)
        elif args.command == "ad-config":
            files = directory.render(args.domain, args.workgroup, args.users, args.admins,
                                     preferred_dcs=args.preferred_dc,
                                     discovery_fallback=args.dc_discovery_fallback)
            if args.output_dir:
                directory.stage(args.output_dir, files)
            else:
                print(serialize(files), end="")
        elif args.command == "lab-provision":
            inputs = ((args.domain, args.workgroup, args.users, args.admins)
                      if args.lab_action == "apply" else ())
            changed = lab.run(args.lab_action, args.root, inputs, abort=getattr(args, "abort", False), expected_history=reviewed_history,
                                 component=getattr(args, "component", "all"))
            if not changed:
                print("No pending transaction or rollback.")
        elif args.command == "provision-image":
            return provision_image(args)
        elif args.command == "provision-wizard":
            from .control_center.launcher import run
            return run(store, SYSTEM_POLICY, lambda: wizard.run(args.root, dry_run=args.dry_run, store=store),
                       installer=True, root=args.root, dry_run=args.dry_run, force=args.zenity, require_native=args.native)
        elif args.command == "policy-refresh":
            status = graphical.apply_login_integrations() if args.login else 0
            resources = refresh(store, args.policy)
            if args.login:
                bookmarks.update(resources)
            return status
        elif args.command == "file-servers":
            if args.action in ("list", "refresh", "clear", "set", "remove"):
                return bookmarks.manage(args, SYSTEM_POLICY)
            return file_server_session(args, product=True)
        elif args.command in ("desktop-integration", "pilot-desktop"):
            return pilot_desktop.apply(args.target, args.action, args.confirm,
                                       product=args.command == "desktop-integration")
        elif args.command == "pilot-session":
            return file_server_session(args)
        elif args.command == "console":
            return console(store)
        elif args.command == "windows-plan":
            print(serialize(windows.compose(args.image, args.cpu, args.memory, args.disk,
                                            storage=args.storage_path, disk_io=args.disk_io,
                                            disk_cache=args.disk_cache, restart=args.restart)), end="")
        elif args.command == "rdp-capabilities":
            print(serialize(windows.capabilities()), end="")
        elif args.command == "windows-connect":
            return windows_prompt()
        elif args.command == "windows-lifecycle":
            if args.action == "status":
                print(serialize(host_diagnostics.report(runtime=True)["windows_runtime"]), end="")
                return 0
            return windows.lifecycle(args.action)
        elif args.command == "kerberos-smb-check":
            status = session.smb_status(args.uri)
            print(f"Kerberos SMB: {status}")
            return 0 if status == "PASS" else 1
        elif args.command == "rdp":
            return connect_windows(args.host, args.account, args.port,
                                   kerberos_session=args.kerberos_session,
                                   kerberos_probe=args.kerberos_probe)
    except (KeyboardInterrupt, EOFError):
        print("\nCancelled.", file=sys.stderr)
        return 130
    except subprocess.SubprocessError:
        print("omarchy-enterprise: A required command failed or timed out.", file=sys.stderr)
        return 1
    except (OSError, ValueError) as error:
        message = ("Hook review stopped. Check the reviewed input and use a private staging directory."
                   if args.command == "hook-review" and isinstance(error, OSError) else str(error))
        print(f"omarchy-enterprise: {message}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
