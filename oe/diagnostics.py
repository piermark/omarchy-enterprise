# SPDX-License-Identifier: MIT
"""Redacted host diagnostics. Authentication acceptance is a separate check."""
import grp
import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess

from . import installation, sddm_review

AD_CONFIG = {
    "SSSD": ("etc/sssd/sssd.conf",),
    "Samba": ("etc/samba/smb.conf",),
    "PAM": ("etc/pam.d/omarchy-enterprise", "etc/pam.d/system-auth-ad"),
}
UNITS = ("sssd.service", "smb.service", "winbind.service", "sddm.service",
         "docker.service", "cups.service")
TOOLS = ("sssctl", "net", "wbinfo", "sddm", "systemctl", "docker", "findmnt", "btrfs")
IMAGE = re.compile(r"(?:docker\.io/)?dockurr/windows(?::[\w.-]+|@sha256:[a-f0-9]{64})?")


def sssd_owner(uid, gid):
    if (uid, gid) == (0, 0):
        return True
    try:
        account = pwd.getpwnam("sssd")
        group = grp.getgrnam("sssd")
    except (KeyError, OSError):
        return False
    return uid == account.pw_uid and gid == account.pw_gid == group.gr_gid


def configuration(root):
    rows = {}
    for label, paths in AD_CONFIG.items():
        sources = {}
        for relative in paths:
            state, signature = installation.metadata(root, relative)
            ownership = permissions = "NOT TESTED"
            if signature:
                mode, uid, gid = signature[2:5]
                owner_ok = sssd_owner(uid, gid) if label == "SSSD" else uid == 0
                mode_ok = stat.S_IMODE(mode) == 0o600 if label == "SSSD" else not mode & 0o022
                ownership = "CONFIGURED" if owner_ok else "FAILED"
                permissions = "CONFIGURED" if mode_ok else "FAILED"
            sources[Path(relative).name] = {
                "presence": "CONFIGURED" if signature else (
                    "NOT TESTED" if state == "ACCESS RESTRICTED" else state),
                "metadata": "CONFIGURED" if signature else state,
                "readability": state if signature else "NOT TESTED",
                "ownership": ownership,
                "permissions": permissions,
            }
        rows[label] = sources
    rows["SDDM"] = sddm_review.discover(root)
    return rows


def probe(arguments, run=subprocess.run):
    try:
        result = run(arguments, env={"PATH": "/usr/bin", "LC_ALL": "C"},
                     stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=4)
        return result
    except FileNotFoundError:
        return "UNAVAILABLE"
    except PermissionError:
        return "ACCESS RESTRICTED"
    except (OSError, subprocess.SubprocessError, UnicodeError):
        return "FAILED"


def services(run=subprocess.run, *, units=UNITS):
    report = {}
    for unit in units:
        result = probe(["/usr/bin/systemctl", "--system", "show", "--property=LoadState",
                        "--property=ActiveState", "--", unit], run)
        row = {"unit": "NOT TESTED", "activity": "NOT TESTED"}
        if isinstance(result, str):
            row["unit"] = result
        else:
            properties = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
            loaded = properties.get("LoadState")
            active = properties.get("ActiveState")
            if loaded == "not-found":
                row["unit"] = "UNAVAILABLE"
            elif result.returncode == 0 and loaded == "loaded":
                row["unit"] = "CONFIGURED"
                if active in {"active", "inactive", "activating", "deactivating", "reloading", "failed"}:
                    row["activity"] = active.upper()
            else:
                row["unit"] = "FAILED"
        report[unit] = row
    return report


def windows_runtime(*, root=Path("/"), activity="NOT TESTED", query=False, run=subprocess.run):
    executable = root / "usr/bin/docker"
    socket = root / "run/docker.sock"
    installed = os.access(executable, os.X_OK)
    report = {"executable": "CONFIGURED" if installed else "UNAVAILABLE", "service": activity,
              "access": "NOT TESTED", "containers": "NOT TESTED", "storage": "NOT TESTED",
              "restart_policy": "UNKNOWN", "desired_start_policy": "MANUAL START ONLY"}
    if not query or not installed:
        return report
    try:
        if not stat.S_ISSOCK(socket.lstat().st_mode):
            report["access"] = "FAILED"
            return report
    except FileNotFoundError:
        report["access"] = "UNAVAILABLE"
        return report
    except PermissionError:
        report["access"] = "ACCESS RESTRICTED"
        return report
    except OSError:
        report["access"] = "FAILED"
        return report
    if not os.access(socket, os.W_OK):
        report["access"] = "ACCESS RESTRICTED"
        return report
    result = probe([str(executable), "--host", f"unix://{socket}", "container", "ls", "--all",
                    "--format", "{{.Image}}\t{{.State}}"], run)
    if isinstance(result, str):
        report["access"] = result
    elif result.returncode:
        report["access"] = ("ACCESS RESTRICTED" if "permission denied" in result.stderr.lower()
                            else "FAILED")
    else:
        states = set()
        for line in result.stdout.splitlines():
            image, _, state = line.partition("\t")
            if IMAGE.fullmatch(image):
                states.add(state)
        report["access"] = "CONFIGURED"
        categories = {"running": "RUNNING", "exited": "STOPPED", "created": "STOPPED",
                      "dead": "FAILED", "paused": "PAUSED", "restarting": "RESTARTING",
                      "removing": "REMOVING"}
        report["containers"] = sorted({categories.get(state, "FAILED") for state in states}) or ["ABSENT"]
    return report



def windows_restart_policy(container_id, *, run=subprocess.run):
    """Report only the restart policy of an explicitly selected Dockur container."""
    if not re.fullmatch(r"[a-f0-9]{64}", container_id):
        raise ValueError("Supply the full 64-character lowercase container ID")
    result = probe(["/usr/bin/docker", "--host", "unix:///run/docker.sock", "container", "inspect",
                    "--format", "{{.Config.Image}}\t{{.HostConfig.RestartPolicy.Name}}",
                    "--", container_id], run)
    policy = "UNKNOWN"
    access = result if isinstance(result, str) else "FAILED"
    if not isinstance(result, str) and result.returncode == 0:
        image, separator, value = result.stdout.removesuffix("\n").partition("\t")
        if separator and IMAGE.fullmatch(image) and value in {"no", "always", "unless-stopped", "on-failure"}:
            policy, access = value, "CONFIGURED"
        else:
            access = "UNVERIFIED WINDOWS CONTAINER OR POLICY"
    return {"access": access, "restart_policy": policy,
            "desired_start_policy": "MANUAL START ONLY",
            "manual_start_verified": policy == "no"}


def windows_admin_main():
    import argparse

    parser = argparse.ArgumentParser(description="Inspect restart policy of one selected Dockur container")
    parser.add_argument("container_id")
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.exit(1, "Administrator execution required.\n")
    try:
        report = windows_restart_policy(args.container_id)
    except ValueError as error:
        parser.error(str(error))
    print(json.dumps(report))
    return int(report["access"] != "CONFIGURED")

def inbound_rdp(policy=None):
    configured = "NOT TESTED"
    if policy is not None:
        enabled = policy.get("enabled") if isinstance(policy, dict) else None
        configured = ("ENABLE REQUESTED" if enabled else "OFF") if type(enabled) is bool else "INVALID"
    return {
        "product_capability": "DISABLED",
        "qualified_backend": False,
        "configured_policy": configured,
        "runtime_state": "NOT TESTED",
    }


def report(*, root=Path("/"), runtime=False):
    units = services() if runtime else {}
    executables = {tool: "CONFIGURED" if os.access(root / "usr/bin" / tool, os.X_OK)
                   else "UNAVAILABLE" for tool in TOOLS}
    return {"configuration": configuration(root), "services": units or "NOT TESTED",
            "executables": executables,
            "windows_runtime": windows_runtime(root=root,
                                                activity=units.get("docker.service", {}).get(
                                                    "activity", "NOT TESTED")),
            "configuration_validation": {"SSSD": "NOT TESTED"},
            "functional_acceptance": {name: "NOT TESTED" for name in (
                "AD authentication", "Samba join", "Winbind trust", "PAM login", "SDDM login")},
            "inbound_rdp": inbound_rdp()}


def admin_main():
    import argparse

    parser = argparse.ArgumentParser(description="Redacted SSSD configuration validation")
    parser.parse_args()
    if os.geteuid() != 0:
        parser.exit(1, "Administrator execution required.\n")
    result = validate_sssd()
    print(json.dumps({"SSSD configuration validation": result, "AD authentication": "NOT TESTED"}))
    return int(result != "CONFIGURED")


def validate_sssd(run=subprocess.run):
    result = probe(["/usr/bin/sssctl", "config-check"], run)
    if not isinstance(result, str):
        # sssctl releases can report issues alongside a zero return code.
        counts = re.findall(r"(?m)^(?:Issues identified by validators|Messages generated during "
                            r"configuration merging): ([0-9]+)\s*$", result.stdout)
        result = ("CONFIGURED" if result.returncode == 0 and counts == ["0", "0"] else "FAILED")
    return result
