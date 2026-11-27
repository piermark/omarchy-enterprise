# SPDX-License-Identifier: MIT
"""Redacted offline overview, independent of live authentication and services."""
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess

from . import diagnostics, policy, profiles, provision, remote_desktop

UNITS = ("cups.service", "sddm.service", "sssd.service", "docker.service")
ACTIVE_STATES = {"active", "reloading", "inactive", "failed", "activating", "deactivating", "maintenance", "refreshing"}

COMMANDS = {
    "Package tools": ("bash", "python3", "pacman"),
    "AD and Kerberos": ("net", "wbinfo", "sssctl", "klist"),
    "Enterprise desktop": ("sddm", "Hyprland", "omarchy-launch-tui"),
    "File Servers": ("nautilus", "gio"),
    "Windows VM": ("docker", "findmnt", "btrfs"),
    "Printing": ("lp", "lpstat", "snmpget"),
}


def _metadata(path):
    try:
        policy.safe_directory(path.parent, system=True)
        metadata = path.lstat()
    except FileNotFoundError:
        return "NOT CONFIGURED"
    except (ValueError, OSError):
        return "BLOCKED"
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022:
        return "BLOCKED"
    return "CONFIGURED"


def summary(store, source, *, root=Path("/"), which=shutil.which):
    profile = {}
    history = None
    state = "NOT CONFIGURED"
    try:
        if store.validate_directory():
            if os.path.lexists(store.journal):
                state = "BLOCKED"
            else:
                actual = store.snapshot()
                history = store.history()
                if (actual != (history["after"] if history else store.empty)
                        or history != store.history() or os.path.lexists(store.journal)):
                    raise ValueError
                profile = json.loads(actual["profile.json"] or "{}")
                if (not isinstance(profile, dict) or
                        profile and profile.get("profile") not in profiles.PROFILES):
                    raise ValueError
                state = "CONFIGURED" if profile else state
    except (ValueError, TypeError, OSError):
        state, profile = "BLOCKED", {}
    smb = _metadata(source)
    if smb == "CONFIGURED":
        try:
            policy.shares(policy.load_file(source, system=True), set())
        except (ValueError, OSError):
            smb = "BLOCKED"
    host = diagnostics.report(root=root)
    material = host["configuration"]
    prerequisites = provision.health(profile.get("profile", "standalone"), bool(profile.get("windows")))
    return {
        "saved_profile": state,
        "configuration": material | {"File Servers policy": smb},
        "dependencies": {feature: {name: "AVAILABLE" if which(name) else "UNAVAILABLE"
                                    for name in commands} for feature, commands in COMMANDS.items()},
        "installer": {"prerequisites": prerequisites, "live_activation": "BLOCKED",
                      "rollback": "BLOCKED" if state == "BLOCKED" else
                                  "AVAILABLE" if history else "UNAVAILABLE"},
        "desktop_entries": {name: _metadata(root / "usr/share/applications" / name) for name in (
            "omarchy-enterprise.desktop", "omarchy-enterprise-installer.desktop")},
        "service_units": {name: _metadata(root / "usr/lib/systemd/system" / name) for name in UNITS},
        "desktop_hooks": "NOT TESTED",
        "services": "NOT TESTED",
        "windows_runtime": host["windows_runtime"],
        "configuration_validation": host["configuration_validation"],
        "functional_acceptance": host["functional_acceptance"],
        "inbound_rdp": {**remote_desktop.diagnostics(), **diagnostics.inbound_rdp(profile.get("remote_desktop"))},
    }


def service_status(*, executable="/usr/bin/systemctl", run=subprocess.run):
    """Request categorical states from systemd without querying service logs."""
    results = {}
    for unit in UNITS:
        try:
            result = run([executable, "--system", "show", "--property=ActiveState", "--value", unit],
                         env={"PATH": "/usr/bin", "LC_ALL": "C"}, stdin=subprocess.DEVNULL,
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=2)
            value = result.stdout.strip() if result.returncode == 0 else ""
        except (OSError, subprocess.TimeoutExpired):
            value = ""
        results[unit] = value if value in ACTIVE_STATES else "UNKNOWN"
    return results


def image_summary(root):
    """Inspect only project-owned staged files and report categorical findings."""
    from . import windows, windows_storage

    target = provision.ImageStore(root)
    result = {
        "transaction": "NOT CONFIGURED", "rollback": "UNAVAILABLE",
        "managed_configuration": "NOT CONFIGURED",
        "file_servers": "NOT CONFIGURED", "printer_monitor": "NOT CONFIGURED",
        "windows_plan": "NOT CONFIGURED", "windows_storage": "NOT TESTED",
        "windows_restart_policy": "UNKNOWN",
        "desktop_integration": "NOT TESTED", "services": "NOT TESTED",
        "inbound_rdp": diagnostics.inbound_rdp(),
    }
    try:
        target.validate_directory()
        if os.path.lexists(target.journal):
            result.update(transaction="RECOVERY REQUIRED", rollback="BLOCKED")
            return result
        history = target.history()
        if history is None:
            return result
        actual = target.snapshot()
        if actual != history["after"] or history != target.history() or os.path.lexists(target.journal):
            raise ValueError
        profile = json.loads(actual["profile.json"] or "{}")
        name = profile.get("profile", "standalone")
        enabled = profile.get("windows", False)
        if name not in profiles.PROFILES or type(enabled) is not bool:
            raise ValueError
        result.update(transaction="CONSISTENT", rollback="AVAILABLE",
                      managed_configuration="STAGED" if profile else "NOT CONFIGURED",
                      prerequisites=provision.health(name, enabled),
                      inbound_rdp=diagnostics.inbound_rdp(profile.get("remote_desktop")))
    except (OSError, AttributeError, TypeError, ValueError, RecursionError):
        result.update(transaction="BLOCKED", rollback="BLOCKED")
        return result
    if actual["policy.json"] is not None:
        try:
            policy.shares(json.loads(actual["policy.json"]), set())
            result["file_servers"] = "VALID STAGED POLICY"
        except (TypeError, ValueError, RecursionError):
            result["file_servers"] = "INVALID"
    if actual["printer-monitor-host"] is not None:
        result["printer_monitor"] = (
            "VALID STAGED HOST" if policy.HOST.fullmatch(actual["printer-monitor-host"].removesuffix("\n"))
            else "INVALID")
    if actual["windows.compose.json"] is not None:
        try:
            plan = windows_storage.plan_service(actual["windows.compose.json"])
            if not enabled or not windows.IMAGE.fullmatch(plan.get("image", "")):
                raise ValueError
            restart = plan.get("restart", "no")
            if restart not in windows_storage.RESTART:
                raise ValueError
            result["windows_plan"] = "MANUAL START" if restart == "no" else "EXPLICIT RESTART POLICY"
            result["windows_restart_policy"] = {"state": "VERIFIED", "scope": "STAGED PLAN", "value": restart}
            environment = plan.get("environment", {})
            io, cache = environment.get("DISK_IO"), environment.get("DISK_CACHE")
            if (io is not None and io not in windows_storage.DISK_IO or
                    cache is not None and cache not in windows_storage.DISK_CACHE):
                result["windows_storage"] = "INVALID STAGED OPTIONS"
            else:
                result["windows_storage"] = "STAGED OPTIONS VALID; TARGET NOT TESTED"
        except (TypeError, ValueError):
            result["windows_plan"] = "INVALID"
    elif enabled:
        result["windows_plan"] = "MISSING"
    if all(actual[item] is not None for item in ("Main.qml", "metadata.desktop", "enterprise-sddm.conf")):
        result["desktop_integration"] = "LOGIN THEME STAGED"
    return result
