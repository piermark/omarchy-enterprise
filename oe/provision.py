# SPDX-License-Identifier: MIT
"""Prepare and transactionally install profile-owned files in a disposable image."""

import json
import os
from pathlib import Path
import platform
import shutil
import stat

from . import directory, policy, profiles, remote_desktop, windows, windows_storage
from .state import Store, read, write

CONFIG = "etc/omarchy-enterprise"
REMOVABLE = {"file-servers": "policy.json", "printer": "printer-monitor-host",
             "windows": "windows.compose.json"}
DESTINATIONS = {
    "profile.json": (f"{CONFIG}/profile.json", 0o600),
    "smb.conf": (f"{CONFIG}/ad/smb.conf", 0o600),
    "sssd.conf": (f"{CONFIG}/ad/sssd.conf", 0o600),
    "krb5.conf": (f"{CONFIG}/ad/krb5.conf", 0o600),
    "enterprise-sudoers": (f"{CONFIG}/ad/enterprise-sudoers", 0o440),
    "enterprise-session-auth.pam": (f"{CONFIG}/ad/enterprise-session-auth.pam", 0o644),
    "enterprise-auth.pam": (f"{CONFIG}/ad/enterprise-auth.pam", 0o644),
    "enterprise-polkit.rules": (f"{CONFIG}/ad/enterprise-polkit.rules", 0o644),
    "LoginIdentity.js": ("usr/share/sddm/themes/omarchy-enterprise-lab/LoginIdentity.js", 0o644),
    "enterprise-sddm.conf": (f"{CONFIG}/ad/enterprise-sddm.conf", 0o644),
    "Main.qml": ("usr/share/sddm/themes/omarchy-enterprise-lab/Main.qml", 0o644),
    "theme.conf": ("usr/share/sddm/themes/omarchy-enterprise-lab/theme.conf", 0o644),
    "metadata.desktop": ("usr/share/sddm/themes/omarchy-enterprise-lab/metadata.desktop", 0o644),
    "nsswitch.enterprise": (f"{CONFIG}/ad/nsswitch.enterprise", 0o644),
    "provision.json": (f"{CONFIG}/provision.json", 0o644),
    "policy.json": (f"{CONFIG}/policy.json", 0o644),
    "printer-monitor-host": (f"{CONFIG}/printer-monitor-host", 0o644),
    "55-omarchy-enterprise.rules": ("etc/audit/rules.d/55-omarchy-enterprise.rules", 0o640),
    "90-omarchy-enterprise-guard.hook": (f"{CONFIG}/90-omarchy-enterprise-guard.hook", 0o644),
    "windows.compose.json": (f"{CONFIG}/windows/compose.json", 0o600),
}
PRINTER = ("lp", "openssl")
AD = ("dig", "testparm", "sssctl", "klist", "visudo")
FULL = ("auditctl",)
WINDOWS = ("docker", "xfreerdp")

PAM_AUTH_ACCOUNT = """# Candidate PAM branch. Validate before connecting a service.
auth       [success=1 default=ignore] pam_localuser.so
auth       [success=done default=die] pam_sss.so
auth       include    system-auth
account    [success=1 default=ignore] pam_localuser.so
account    [success=done default=die] pam_sss.so
account    include    system-auth
"""
PAM = PAM_AUTH_ACCOUNT + """password   include    system-auth
session    [success=1 default=ignore] pam_localuser.so
session    required   pam_mkhomedir.so skel=/etc/skel umask=0077
session    include    system-login
"""
SDDM_METADATA = """[SddmGreeterTheme]
Name=Omarchy Enterprise Lab
Type=sddm-theme
MainScript=Main.qml
ConfigFile=theme.conf
QtVersion=6
"""
SDDM_CONFIG = """[Theme]
Current=omarchy-enterprise-lab

[Users]
RememberLastUser=false
RememberLastSession=true

[Autologin]
User=
Session=
Relogin=false
"""
NSS = """# Review against distribution defaults before activating.
passwd: files systemd sss
group: files systemd sss
shadow: files
"""
PACMAN_HOOK = """[Trigger]
Operation = Upgrade
Type = Package
Target = samba
Target = sssd
Target = pam
Target = sddm

[Action]
Description = Checking the Enterprise Guard baseline
When = PreTransaction
Exec = /usr/bin/omarchy-enterprise-guard check
AbortOnFail
"""


def serialized(value):
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def render(profile, *, domain=None, workgroup=None, users=None, admins=None,
           printer=None, image=None, cpu=4, memory=8, disk=128, preferred_dcs=(),
           discovery_fallback=False, storage=None, windows_base=None, disk_io=None, disk_cache=None,
           restart=None, existing_windows=None, file_servers=None, rdp_policy=None):
    if profile not in profiles.PROFILES:
        raise ValueError("Select a supported provisioning profile")
    files = dict.fromkeys(DESTINATIONS)
    if printer:
        if not policy.HOST.fullmatch(printer):
            raise ValueError("Provide a fully qualified printer hostname")
        files["printer-monitor-host"] = printer.lower() + "\n"
    if profile != "standalone":
        if not all((domain, workgroup, users, admins)):
            raise ValueError("Domain, workgroup, users and admins are required for an AD profile")
        files.update(directory.render(domain, workgroup, users, admins, preferred_dcs=preferred_dcs,
                                      discovery_fallback=discovery_fallback))
        files["provision.json"] = serialized({
            "domain": domain.lower(), "admin_group": f"{admins}@{domain.lower()}",
        })
        files["policy.json"] = serialized({"version": 1, "shares": []})
        files["enterprise-auth.pam"] = PAM
        files["enterprise-session-auth.pam"] = PAM_AUTH_ACCOUNT
        files["nsswitch.enterprise"] = NSS
        assets = Path(__file__).with_name("assets")
        files["Main.qml"] = (assets / "EnterpriseLogin.qml").read_text(encoding="utf-8")
        files["LoginIdentity.js"] = (assets / "LoginIdentity.js").read_text(encoding="utf-8")
        files["enterprise-sddm.conf"] = SDDM_CONFIG
        files["theme.conf"] = f"[General]\ndomain={domain.lower()}\nworkgroup={workgroup.upper()}\n"
        files["metadata.desktop"] = SDDM_METADATA
        group = json.dumps(f"{admins}@{domain.lower()}")
        files["enterprise-polkit.rules"] = f"""polkit.addRule(function(action, subject) {{
    if (action.id === "org.freedesktop.systemd1.manage-units" &&
        action.lookup("unit") === "cups.service" && action.lookup("verb") === "restart" &&
        subject.local && subject.active && subject.isInGroup({group})) {{
        return polkit.Result.AUTH_SELF;
    }}
}});
"""
    elif any((domain, workgroup, users, admins, preferred_dcs, discovery_fallback)):
        raise ValueError("Standalone does not accept AD settings")
    if profile == "full-enterprise":
        files["55-omarchy-enterprise.rules"] = "-w /etc/omarchy-enterprise/ -p wa -k oe_config\n"
    if file_servers is not None:
        policy.shares(file_servers, set())
        files["policy.json"] = serialized(file_servers)
    if image:
        files["windows.compose.json"] = serialized(windows.compose(
            image, cpu, memory, disk, storage=storage, base_dir=windows_base, disk_io=disk_io,
            disk_cache=disk_cache, restart=restart, existing=existing_windows))
    elif any(value is not None for value in (storage, disk_io, disk_cache, restart)):
        raise ValueError("Windows storage settings require a Windows image")
    files["90-omarchy-enterprise-guard.hook"] = PACMAN_HOOK
    settings = {"profile": profile, "windows": bool(image)}
    if rdp_policy is not None:
        reserved = (f"{users}@{domain}", f"{admins}@{domain}") if domain else ()
        candidate = remote_desktop.validate(rdp_policy, domain=domain, reserved_groups=reserved)
        if profile == "standalone" and (candidate["enabled"] or candidate.get("mode", "off") != "off"):
            raise ValueError("Remote Desktop review requires an AD profile")
        settings["remote_desktop"] = candidate
    files["profile.json"] = serialized(settings)
    return files


def health(profile, windows_enabled):
    try:
        os_id = platform.freedesktop_os_release().get("ID")
    except OSError:
        os_id = None
    checks = {"x86_64 architecture": platform.machine() == "x86_64",
              "Arch-compatible operating system": os_id in ("arch", "omarchy")}
    requirements = PRINTER
    if profile != "standalone":
        requirements += AD
    if profile == "full-enterprise":
        requirements += FULL
    if windows_enabled:
        requirements += WINDOWS[:1]
        checks["FreeRDP"] = bool(shutil.which("xfreerdp3") or shutil.which(WINDOWS[1]))
        checks["KVM device access"] = os.access("/dev/kvm", os.R_OK | os.W_OK)
    return checks | {command: bool(shutil.which(command)) for command in requirements}


def safe_directory(root, components, *, create=False):
    path = root
    for component in components:
        path /= component
        if create:
            path.mkdir(mode=0o755, exist_ok=True)
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o022):
            raise ValueError("Provisioning directories must be owned, non-writable by others, and free of symlinks")
    return path


class ImageStore(Store):
    names = set(DESTINATIONS)
    empty = dict.fromkeys(DESTINATIONS)

    def __init__(self, root):
        if root.is_symlink():
            raise ValueError("Choose a disposable directory without symlinks")
        self.root = root.resolve(strict=True)
        info = self.root.stat()
        if (self.root == Path("/") or not stat.S_ISDIR(info.st_mode)
                or info.st_uid != os.getuid() or info.st_mode & 0o077):
            raise ValueError("Choose a private, user-owned disposable root (mode 0700)")
        super().__init__(self.root / ".omarchy-enterprise-state")

    def file_path(self, name):
        destination, mode = DESTINATIONS[name]
        relative = Path(destination)
        parent = safe_directory(self.root, relative.parts[:-1])
        path = parent / relative.name
        try:
            info = path.lstat()
        except FileNotFoundError:
            return path
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != mode):
            raise ValueError(f"Managed file has unexpected ownership, type, or permissions: {relative}")
        return path

    def windows_settings(self):
        self.validate_directory()
        if os.path.lexists(self.journal):
            raise ValueError("Recover or abort the pending transaction before planning")
        history = self.history()
        content = history["after"]["windows.compose.json"] if history else None
        return windows_storage.plan_service(content) if content is not None else None

    def plan(self, files):
        self.validate_directory()
        if os.path.lexists(self.journal):
            raise ValueError("Recover or abort the pending transaction before planning")
        history = self.history()
        expected = history["after"] if history else self.empty
        changes = {}
        for name, (destination, _mode) in sorted(DESTINATIONS.items()):
            path = self.file_path(name)
            before, after = expected[name], files[name]
            if before is None:
                matches = not os.path.lexists(path)
            else:
                matches = read(path) == before
            if not matches:
                changes[destination] = "CONFLICT"
            elif after is None and before is not None:
                changes[destination] = "REMOVE"
            elif after is not None:
                changes[destination] = ("UNCHANGED" if before == after else
                                        "CREATE" if before is None else "UPDATE")
        return changes

    def set_file(self, name, content):
        path = self.file_path(name)
        if content is not None:
            safe_directory(self.root, path.parent.relative_to(self.root).parts, create=True)
        write(path, content, mode=DESTINATIONS[name][1])


def mutate(root, action, files=None, *, abort=False, expected_history=None, component="all"):
    store = ImageStore(root)
    if action != "apply" and not store.directory.exists():
        raise ValueError("No provisioning journal exists in the selected directory")
    with store.locked():
        if action in {"remove", "rollback"} and os.path.lexists(store.journal):
            raise ValueError("Recover or abort the pending transaction before requesting another change")
        if expected_history is not None and store.history() != expected_history[0]:
            raise ValueError("Provisioning changed since preview; review again")
        if action == "apply":
            if "CONFLICT" in store.plan(files).values():
                raise ValueError("Resolve provisioning conflicts before applying")
            store.change(**files)
        elif action == "remove":
            if component == "all":
                store.change(**store.empty)
            else:
                updates = {REMOVABLE[component]: None}
                current = store.snapshot()
                if component == "windows" and current["profile.json"] is not None:
                    profile = json.loads(current["profile.json"])
                    updates["profile.json"] = serialized(profile | {"windows": False})
                store.change(**updates)
        elif action == "recover":
            store.recover(abort=abort)
        elif action == "rollback":
            store.rollback()
        actual = store.snapshot()
        history = store.history()
        if actual != (history["after"] if history else store.empty):
            raise ValueError("Post-install state verification failed")
    return [DESTINATIONS[name][0] for name, content in sorted(actual.items()) if content is not None]
