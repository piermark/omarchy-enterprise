# SPDX-License-Identifier: MIT
"""Render the user console with native GTK dialogs through Zenity."""

from pathlib import Path
import os
import shutil
import subprocess

from . import session


class Dialog:
    def __init__(self):
        self.executable = shutil.which("zenity")
        if not self.executable:
            raise ValueError("Install Zenity or use the terminal console")

    def show(self, *arguments, text=None):
        result = subprocess.run([self.executable, "--title=Omarchy Enterprise", *arguments],
                                text=True, input=text, stdout=subprocess.PIPE, check=False)
        if result.returncode == 1:
            return None
        result.check_returncode()
        return result.stdout.rstrip("\n")

    def choose(self, entries):
        rows = [cell for key, label in entries for cell in (str(key), label)]
        return self.show("--list", "--column=ID", "--column=Action", "--hide-column=1",
                         "--print-column=1", "--width=460", "--height=400", "--", *rows)

    def report(self, content):
        self.show("--text-info", "--width=640", "--height=420", text=content)


REFERENCE_ACTIONS = {
    "doctor": "Doctor",
    "guard": "Guard integrity (administrator approval)",
    "inventory": "Hardware and software inventory",
    "compliance": "Compliance",
    "auditstatus": "Audit status",
    "updates": "Update checks",
    "printers": "Printer management",
    "printermonitor": "Printer monitoring",
    "certificates": "Certificates",
    "provision": "Provision enterprise menu",
    "policy": "Group Policy Manager",
    "adtestjoin": "Active Directory machine trust (administrator approval)",
}
REFERENCE_VIEW = Path("/usr/bin/omarchy-enterprise-view")
TERMINAL_LAUNCHER = Path("/usr/bin/omarchy-launch-tui")


def reference_available():
    return all(os.access(path, os.X_OK) for path in (REFERENCE_VIEW, TERMINAL_LAUNCHER))


def printer_available():
    return all(os.access(path, os.X_OK) for path in (
        "/usr/bin/omarchy-enterprise-printers", "/usr/bin/system-config-printer"))


def launch_printer():
    if not printer_available():
        raise ValueError("Install the reviewed printer command and system-config-printer")
    return subprocess.Popen(["/usr/bin/omarchy-enterprise-printers", "gui"], start_new_session=True)


UPDATE_GUIDANCE = """Use Update checks to review available updates.
Ask an administrator to review preflight and confirm a tested recovery path.
Host snapshot and recovery are administrator actions. Verify that local recovery
and SSH access work before applying system changes.

For an offline installer target, use provision-image --root DIRECTORY rollback --yes.
For an interrupted transaction, review provision-image --root DIRECTORY recover --help.
Neither operation is a workstation snapshot restore.
"""

WINDOWS_GUIDANCE = """Manual start is the desired policy.
Ask the VM administrator to verify the selected container with
omarchy-enterprise-admin windows-restart-policy CONTAINER_ID.
The managed start, stop and restart controls remain blocked.
"""


def launch_reference(action):
    if action not in REFERENCE_ACTIONS:
        raise ValueError("Unknown reference console action")
    return subprocess.Popen([TERMINAL_LAUNCHER, REFERENCE_VIEW, action], start_new_session=True)


LOGIN_INTEGRATIONS = (
    (Path("/etc/omarchy-enterprise/policy.json"), "/usr/bin/omarchy-enterprise-policy", "apply"),
    (Path("/etc/omarchy-enterprise/provision.json"), "/usr/bin/omarchy-enterprise-provision-user"),
)


def apply_login_integrations():
    session.import_kerberos_collection()
    failed = False
    for configuration, *command in LOGIN_INTEGRATIONS:
        if configuration.exists() and os.access(command[0], os.X_OK):
            try:
                result = subprocess.run(command, timeout=30)
                failed |= result.returncode != 0
            except (OSError, subprocess.TimeoutExpired):
                failed = True
    return int(failed)


DIAGNOSTIC_STATES = (
    "CONFIGURED indicates presence or a completed configuration check.\n"
    "NOT CONFIGURED indicates an absent configuration.\n"
    "ACCESS RESTRICTED indicates insufficient read or query access.\n"
    "LEGACY DETECTED indicates existing configuration without verified management.\n"
    "NOT TESTED indicates a check with no current evidence.\n"
    "UNAVAILABLE indicates a missing executable, unit, or endpoint.\n"
    "FAILED indicates an invalid, unsafe, or unsuccessful check.\n"
    "Service activity and authentication acceptance are reported separately.\n\n"
)


def migration_preview(dialog):
    import json
    from .migration import Migration

    manager = Migration()
    discovery = manager.preview()
    dialog.report("Migration is blocked pending consumer review and Guard coverage verification.\n\n"
                  + json.dumps(discovery, indent=2))
    options = [(name, name) for name, row in discovery["commands"].items()
               if row["state"] in {"IDENTICAL", "REVIEW REQUIRED"}]
    if options and (command := dialog.choose(options)):
        dialog.report(json.dumps(manager.preview([command]), indent=2))
