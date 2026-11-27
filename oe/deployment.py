# SPDX-License-Identifier: MIT
"""Allowlisted live deployment for explicitly authorized Omarchy lab guests."""

from contextlib import contextmanager
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import tempfile

from . import __version__, enrollment, policy, profiles, provision, state

STATE = "var/lib/omarchy-enterprise/deployment"
CONFIG = "etc/omarchy-enterprise"
MARKER = "etc/omarchy-enterprise-lab.identity"
# Keep directory/authentication candidates inert until their separate acceptance gate.
DESTINATIONS = {
    name: (f"{CONFIG}/candidates/{name}", mode)
    for name, (_, mode) in provision.DESTINATIONS.items()
}
for _name in ("profile.json", "printer-monitor-host"):
    DESTINATIONS[_name] = provision.DESTINATIONS[_name]
DESTINATIONS["policy.json"] = (f"{CONFIG}/smb-policy.json", 0o644)
PACKAGES = ("omarchy", "bash", "python", "omarchy-enterprise")
AD_PACKAGES = ("samba", "sssd", "krb5", "sudo", "sddm", "bind")
OPTIONAL = ("zenity", "cups", "net-snmp", "openssl", "gvfs-smb", "snapper", "audit")


def dependency_plan(profile, printing=False):
    return (PACKAGES + (AD_PACKAGES if profile != "standalone" else ())
            + (("cups",) if printing else ()))


def command(*args, capture=False, kerberos_config=None):
    environment = {"PATH": "/usr/bin:/usr/sbin", "LC_ALL": "C", "HOME": "/nonexistent"}
    if kerberos_config is not None:
        environment["KRB5_CONFIG"] = str(kerberos_config)
    return subprocess.run(
        args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, text=True, timeout=25, check=False,
        env=environment, umask=0o077,
    )


def safe_path(root, relative, *, directory=False, create=False):
    """Traverse only administrator-controlled parents and reject special files."""
    parts = Path(relative)
    if parts.is_absolute() or not parts.parts or ".." in parts.parts:
        raise ValueError("Unexpected deployment path")
    root = Path(root)
    if not root.is_absolute() or ".." in root.parts or root.resolve() != root:
        raise ValueError("Unexpected deployment root")
    info = root.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
            or info.st_gid != os.getegid() or info.st_mode & 0o022):
        raise ValueError("Deployment root has unsafe ownership, permissions or type")
    path = root
    for index, part in enumerate(parts.parts):
        path /= part
        parent = directory or index < len(parts.parts) - 1
        try:
            meta = path.lstat()
        except FileNotFoundError:
            if parent and create:
                path.mkdir(mode=0o755)
                state.sync_directory(path.parent)
                meta = path.lstat()
            else:
                continue
        expected = stat.S_ISDIR if parent else stat.S_ISREG
        if (not expected(meta.st_mode) or meta.st_uid != os.geteuid() or meta.st_gid != os.getegid()
                or meta.st_mode & 0o022 or (not parent and meta.st_nlink != 1)):
            raise ValueError("Deployment path has unsafe ownership, permissions or type")
    return path


class DeploymentStore(state.Store):
    names = set(DESTINATIONS)
    empty = dict.fromkeys(DESTINATIONS)

    def __init__(self, root):
        self.root = root
        ledger = safe_path(root, STATE, directory=True)
        super().__init__(ledger)

    def validate_directory(self):
        safe_path(self.root, self.directory.relative_to(self.root), directory=True)
        return super().validate_directory()

    @contextmanager
    def locked(self, *, nonblocking=False):
        self.validate_directory()
        lock = (self.directory / ".lock").relative_to(self.root)
        safe_path(self.root, lock)
        with super().locked(nonblocking=nonblocking):
            safe_path(self.root, lock)
            yield

    def file_path(self, name):
        destination, mode = DESTINATIONS[name]
        path = safe_path(self.root, destination)
        if path.exists() and stat.S_IMODE(path.lstat().st_mode) != mode:
            raise ValueError("Managed deployment file has unexpected permissions")
        return path

    def set_file(self, name, content):
        path = self.file_path(name)
        if content is not None:
            parent = path.parent.relative_to(self.root)
            safe_path(self.root, parent, create=True, directory=True)
        state.write(path, content, mode=DESTINATIONS[name][1])

    def snapshot_expected(self):
        history = self.history()
        return history["after"] if history else self.empty

    def plan(self, files):
        self.validate_directory()
        if os.path.lexists(self.journal):
            raise ValueError("Resolve the pending file transaction with recover")
        expected = self.snapshot_expected()
        config = safe_path(self.root, CONFIG, directory=True)
        if config.is_dir() and expected == self.empty and any(
            entry.name not in {"candidates", "profile.json", "printer-monitor-host"}
            for entry in config.iterdir()
        ):
            raise ValueError("An unmanaged Enterprise configuration already exists")
        for name in sorted(self.names):
            path = self.file_path(name)
            before = expected[name]
            if (before is None and os.path.lexists(path)) or (before is not None and state.read(path) != before):
                raise ValueError("Deployment conflicts with an unmanaged or edited file")
        return tuple(DESTINATIONS[name][0] for name in sorted(files) if expected[name] != files[name])


def require_guest(root):
    if (os.geteuid() != 0 or os.getegid() != 0
            or Path(__file__).resolve().parent != Path("/usr/lib/omarchy-enterprise/oe")):
        raise ValueError("Run live deployment as administrator from the installed package")
    if root != Path("/"):
        raise ValueError("Unexpected live deployment target")
    marker = safe_path(root, MARKER)
    if not marker.is_file() or stat.S_IMODE(marker.stat().st_mode) != 0o644:
        raise ValueError("Expected the reviewed lab guest identity marker")
    guest = command("/usr/bin/systemd-detect-virt", "--vm", capture=True)
    if guest.returncode or guest.stdout.strip() not in {"kvm", "qemu"}:
        raise ValueError("Deployment requires a separately authorized KVM/QEMU guest")
    identity = marker.read_text(encoding="ascii").splitlines()
    product = (root / "sys/class/dmi/id/product_name").read_text(encoding="ascii").strip()
    if (len(identity) != 2 or identity != [product, "workstation"]
            or not re.fullmatch(r"OE-LAB-[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}", product)):
        raise ValueError("Lab marker does not match the workstation guest identity")
    for family in ("-4", "-6"):
        route = command("/usr/bin/ip", family, "route", "show", "default", capture=True)
        if route.returncode or route.stdout.strip():
            raise ValueError("Disconnect laboratory egress before deployment")


def system_preflight(root, required):
    if platform.machine() != "x86_64" or platform.freedesktop_os_release().get("ID") not in {"arch", "omarchy"}:
        raise ValueError("Expected an Arch-compatible x86_64 Omarchy guest")
    result = command("/usr/bin/pacman", "-Q", "omarchy", capture=True)
    if result.returncode or not re.fullmatch(r"omarchy 4\.5\.[0-9]+-[0-9.]+\s*", result.stdout):
        raise ValueError("The deployment lab currently targets Omarchy 4.5.x")
    if command("/usr/bin/pacman", "-T", *required).returncode:
        raise ValueError("Required packages are missing; review the dependency plan")
    if shutil.disk_usage(root).free < 1024**3:
        raise ValueError("At least 1 GiB of free space is required")
    memory = (root / "proc/meminfo").read_text(encoding="ascii")
    total = re.search(r"^MemTotal:\s+(\d+) kB$", memory, re.MULTILINE)
    if not total or int(total[1]) < 4 * 1024**2:
        raise ValueError("At least 4 GiB of physical memory is required")
    mount = command("/usr/bin/findmnt", "-n", "-o", "FSTYPE", "--target", "/", capture=True)
    if mount.returncode or mount.stdout.strip() not in {"btrfs", "ext4", "xfs"}:
        raise ValueError("Expected a supported local filesystem in the lab guest")


def bundle(args):
    if args.profile not in profiles.PROFILES:
        raise ValueError("Choose a deployment profile")
    files = provision.render(args.profile, domain=args.domain, workgroup=args.workgroup,
                             users=args.users, admins=args.admins, printer=args.printer,
                             preferred_dcs=args.preferred_dc,
                             file_servers=policy.load_file(args.file_servers.absolute()) if args.file_servers else None,
                             rdp_policy=policy.load_file(args.rdp_policy.absolute()) if args.rdp_policy else None)
    if args.file_servers is None:
        files["policy.json"] = None
    if files["sssd.conf"] is not None:
        files["sssd.conf"] += "ad_maximum_machine_account_password_age = 0\n"
    profile = json.loads(files["profile.json"])
    profile["deployment_version"] = __version__
    files["profile.json"] = provision.serialized(profile)
    return files


def validate_bundle(files):
    if files["smb.conf"] is None:
        return
    with tempfile.TemporaryDirectory(prefix="oe-deployment-", dir="/tmp") as temporary:
        stage = Path(temporary)
        for name, argv in (("smb.conf", ("/usr/bin/testparm", "-s")),
                           ("enterprise-sudoers", ("/usr/bin/visudo", "-cf"))):
            candidate = stage / name
            state.write(candidate, files[name])
            if command(*argv, str(candidate)).returncode:
                raise ValueError("Native validation rejected the proposed configuration")


def mutate(store, action, files=None):
    with store.locked():
        if os.path.lexists(store.directory / enrollment.INTENT):
            record = store.read_record(store.directory / enrollment.INTENT)
            if record.get("status") != "isolated-left":
                raise ValueError("Reconcile external enrollment before making deployment file changes")
        if os.path.lexists(store.directory / "cups.pending"):
            raise ValueError("Restore the recorded CUPS activation before changing files")
        if action == "recover" or action == "abort":
            if not store.recover(abort=action == "abort"):
                raise ValueError("There is no pending file transaction")
        elif action == "rollback":
            store.plan(store.snapshot_expected())
            if not store.rollback():
                raise ValueError("There is no managed deployment to roll back")
        else:
            if action == "apply" and files["policy.json"] is None:
                files = files | {"policy.json": store.snapshot_expected()["policy.json"]}
            store.plan(files)
            if action == "apply":
                validate_bundle(files)
            store.change(**files)
        store.plan(store.snapshot_expected())


def cups_action(store, start):
    """Start only a disabled/inactive unit and register how to undo the change."""
    def query(property_name):
        result = command("/usr/bin/systemctl", "show", "--property", property_name,
                         "--value", "cups.service", capture=True)
        if result.returncode:
            raise ValueError("Cannot verify CUPS service state")
        return result.stdout.strip()

    with store.locked():
        marker = store.directory / "cups.pending"
        recorded = state.read(marker, private=True)
        if query("UnitFileState") != "disabled":
            raise ValueError("CUPS enablement is not the expected disabled state")
        active = query("ActiveState")
        if start:
            store.plan(store.snapshot_expected())
            if store.snapshot_expected()["profile.json"] is None:
                raise ValueError("Apply a managed profile before starting CUPS")
            if recorded is not None or active != "inactive":
                raise ValueError("CUPS already has runtime state; refusing to adopt it")
            if command("/usr/bin/cupsd", "-t").returncode:
                raise ValueError("Existing CUPS configuration failed native validation")
            state.write(marker, "disabled/inactive\n")
            if command("/usr/bin/systemctl", "start", "cups.service").returncode or query("ActiveState") != "active":
                raise ValueError("CUPS did not start; use restore-cups to resolve its recorded state")
        else:
            if recorded != "disabled/inactive\n":
                raise ValueError("No valid CUPS activation record")
            if active in {"active", "failed"}:
                if command("/usr/bin/systemctl", "stop", "cups.service").returncode:
                    raise ValueError("Unable to restore CUPS; activation record retained")
            if query("ActiveState") != "inactive":
                raise ValueError("CUPS still has runtime state; activation record retained")
            state.write(marker, None)


def report_status(store):
    pending = os.path.lexists(store.journal)
    if pending:
        configuration = "recovery required"
    else:
        recorded = store.snapshot_expected()
        store.plan(recorded)
        configuration = "managed files verified" if recorded["profile.json"] else "not installed"
    enrollment_record = store.read_record(store.directory / enrollment.INTENT) or {}
    statuses = {
        "isolated-ads-verified": "ADS previously verified in the isolated trial",
        "isolated-keytab-verified": "ADS and machine Kerberos previously verified in the isolated trial",
        "isolated-left": "isolated leave previously completed",
    }
    trust = statuses.get(enrollment_record.get("status")) if isinstance(enrollment_record.get("status"), str) else None
    print("Configuration:", configuration)
    print("Trust:", trust or ("reconciliation required" if enrollment_record else "not enrolled"))
    print("CUPS:", "runtime change recorded; use restore-cups"
          if os.path.lexists(store.directory / "cups.pending") else "no managed runtime change")
    print("System identity, authentication and desktop activation: not deployed by this executor")
    print("Windows and inbound Remote Desktop activation: blocked")


def execute(args):
    if args.action == "plan":
        files = bundle(args)
        print("Offline plan for an authorized lab guest")
        print("Required packages:", " ".join(dependency_plan(args.profile)))
        print("Optional packages:", " ".join(OPTIONAL))
        for name in sorted(files):
            if files[name] is not None:
                print(DESTINATIONS[name][0])
        print("Domain enrollment, login activation and Windows runtime are separate gates.")
        if args.rdp_policy:
            selected = json.loads(files["profile.json"])["remote_desktop"]
            print("Remote Desktop policy mode:", selected.get("mode", "legacy review"))
            print("Remote Desktop policy metadata only; activation is blocked.")
        return 0

    root = Path("/")
    require_guest(root)
    if not args.confirm_lab or not args.local_recovery_ready:
        raise ValueError("Confirm the authorized lab and independent local recovery access")
    store = DeploymentStore(root)
    if args.action == "apply":
        files = bundle(args)
        system_preflight(root, dependency_plan(args.profile))
        store.plan(files)
    elif not store.validate_directory():
        raise ValueError("No live deployment state exists")
    elif args.action == "status":
        report_status(store)
        return 0
    elif args.action in {"prepare-keytab", "verify-trust", "leave"}:
        if args.action == "leave" and not args.confirm_disable_lab_account:
            raise ValueError("Confirm that the isolated leave may disable the synthetic computer account")
        enrollment.lifecycle(store, args.action, run=command, check_path=safe_path)
        print({
            "prepare-keytab": "Isolated machine keytab generated and verified.",
            "verify-trust": "Isolated ADS and machine Kerberos verified.",
            "leave": "Isolated leave completed with account retention requested. Do not reuse the isolated keytab.",
        }[args.action])
        return 0
    elif args.action == "enroll":
        system_preflight(root, dependency_plan("active-directory"))

        def create_private(path):
            path.mkdir(mode=0o700)
            state.sync_directory(path.parent)

        enrollment.enroll(store, args, run=command, safe_directory=create_private)
        print("Isolated Samba ADS trust verified. System identity and login were not activated.")
        return 0
    elif args.action in {"start-cups", "restore-cups"}:
        if args.action == "start-cups" and command("/usr/bin/pacman", "-T", "cups").returncode:
            raise ValueError("CUPS is not installed")
        cups_action(store, args.action == "start-cups")
        print("CUPS runtime state verified. Persistent enablement was not changed.")
        return 0
    else:
        files = store.empty if args.action == "remove" else None
    mutate(store, args.action, files)
    print("Managed files verified. Authentication and desktop activation remain pending.")
    return 0


def add_parser(commands):
    deploy = commands.add_parser("deploy", help="offline plan or explicit installed laboratory deployment")
    actions = deploy.add_subparsers(dest="action", required=True)
    for action in ("plan", "apply", "remove", "rollback", "recover", "abort", "start-cups",
                   "restore-cups", "enroll", "prepare-keytab", "verify-trust", "leave", "status"):
        item = actions.add_parser(action)
        if action in {"plan", "apply"}:
            item.add_argument("--profile", choices=profiles.PROFILES, required=True)
            for field in ("domain", "workgroup", "users", "admins", "printer"):
                item.add_argument(f"--{field}")
            item.add_argument("--preferred-dc", action="append", default=[])
            item.add_argument("--file-servers", type=Path)
            item.add_argument("--rdp-policy", type=Path)
        if action == "enroll":
            for field in ("principal", "computer", "controller"):
                item.add_argument(f"--{field}", required=True)
            item.add_argument("--ou")
        if action == "leave":
            item.add_argument("--confirm-disable-lab-account", action="store_true")
        if action != "plan":
            item.add_argument("--confirm-lab", action="store_true")
            item.add_argument("--local-recovery-ready", action="store_true")
