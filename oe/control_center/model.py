"""Categorical desktop views over the reviewed backend interfaces."""
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

from .. import (__version__, ad_diagnostics, diagnostics, graphical, installation,
                operations, pilot_session, remote_desktop, windows)
from .jobs import run_process
from .localization import _

PAGES = {
    "overview": (_("Overview"), "view-grid-symbolic", _("Installation, services and workstation readiness.")),
    "directory": (_("Active Directory"), "system-users-symbolic", _("Configuration, services and login evidence.")),
    "files": (_("File Servers"), "folder-remote-symbolic", _("Authorized resources and managed Nautilus bookmarks.")),
    "printers": (_("Printers"), "printer-symbolic", _("CUPS configuration and queue availability.")),
    "windows": (_("Windows VM"), "computer-symbolic", _("Manual-start workspace and client connection guidance.")),
    "remote": (_("Remote Desktop"), "network-workgroup-symbolic", _("Inbound capability and qualification.")),
    "security": (_("Security"), "security-high-symbolic", _("Integrity, audit, compliance and certificates.")),
    "inventory": (_("Inventory"), "drive-harddisk-symbolic", _("Hardware and software summary.")),
    "updates": (_("Updates & Recovery"), "software-update-available-symbolic", _("Package integrity and recovery readiness.")),
    "installer": (_("Installer"), "system-software-install-symbolic", _("Review the workstation or stage a disposable installation.")),
}

STATES = {
    "ACTIVE": _("Active"), "AVAILABLE": _("Available"), "PASS": _("Current verified result"),
    "RECORDED": _("Previously recorded result"), "CONFIGURED": _("Configured"),
    "ACCESS RESTRICTED": _("Access restricted"), "NOT CONFIGURED": _("Not configured"),
    "NOT TESTED": _("Not tested"), "UNAVAILABLE": _("Unavailable"), "FAILED": _("Failed"),
    "DISABLED": _("Disabled"), "BLOCKED": _("Blocked"), "UNKNOWN": _("Unknown"),
    "INACTIVE": _("Inactive"), "OFF": _("Off"), "UNVERIFIED": _("Unverified"),
    "ACTIVATING": _("Activating"), "DEACTIVATING": _("Deactivating"), "RELOADING": _("Reloading"),
    "RUNNING": _("Running"), "STOPPED": _("Stopped"), "PAUSED": _("Paused"),
    "RESTARTING": _("Restarting"), "REMOVING": _("Removing"), "ABSENT": _("Absent"),
    "MANUAL START ONLY": _("Manual start only"), "NO_VALID_CACHE": _("No valid ticket"),
    "OPERATION NOT PERMITTED": _("Access restricted"),
    "TIMEOUT": _("Timed out"), "CLEAN INSTALLATION": _("Clean installation"),
    "EXISTING STANDALONE": _("Existing standalone"), "EXISTING AD-INTEGRATED": _("Existing AD integration"),
    "LEGACY ENTERPRISE": _("Existing Enterprise review"), "MANAGED UPGRADE": _("Managed upgrade"),
    "OMARCHY ENTERPRISE": _("Omarchy Enterprise"), "CUSTOM THEME CONFIGURED": _("Custom theme configured"),
    "EMPTY THEME CONFIGURED": _("Empty theme setting"), "NO CURRENT THEME FOUND": _("No current theme found"),
}
PROFILE_NAMES = {"standalone": _("Standalone"), "active-directory": _("Active Directory integration preview"),
                 "full-enterprise": _("Full Enterprise")}


def prerequisite_label(key):
    names = {
        "x86_64 architecture": _("x86_64 architecture"),
        "Arch-compatible operating system": _("Arch-compatible operating system"),
        "KVM device access": _("KVM device access"),
    }
    return names.get(key, key)


@dataclass(frozen=True)
class Status:
    code: str

    @property
    def text(self):
        return STATES.get(self.code, STATES["UNKNOWN"])


@dataclass(frozen=True)
class View:
    rows: tuple
    advanced: dict | None = None


def state(code):
    return Status(code)


def service(units, name):
    row = units.get(name + ".service", {})
    return state(row.get("activity") if row.get("unit") == "CONFIGURED" else row.get("unit", "UNKNOWN"))


def command_ready(name):
    return state("AVAILABLE" if os.access("/usr/bin/" + name, os.X_OK) else "UNAVAILABLE")


def admin(name):
    return state("ACCESS RESTRICTED" if os.access("/usr/bin/" + name, os.X_OK) else "UNAVAILABLE")


def configured(rows):
    codes = {row.get("metadata", "UNKNOWN") for row in rows.values()}
    return state(next((code for code in ("FAILED", "ACCESS RESTRICTED", "UNVERIFIED", "CONFIGURED")
                       if code in codes), "NOT CONFIGURED"))


def queues():
    server = diagnostics.probe(["/usr/bin/lpstat", "-r"])
    if isinstance(server, str):
        return state(server), []
    if server.returncode:
        return probe_status(server), []
    if server.stdout.strip() != "scheduler is running":
        return state("INACTIVE"), []
    result = diagnostics.probe(["/usr/bin/lpstat", "-p"])
    if isinstance(result, str):
        return state(result), []
    if result.returncode:
        if "no destinations added" in result.stderr.lower():
            return state("NOT CONFIGURED"), []
        return probe_status(result), []
    rows = []
    for line in result.stdout.splitlines():
        match = re.fullmatch(r"printer ([A-Za-z0-9][A-Za-z0-9_.-]{0,126}) (.*)", line)
        if match:
            name, message = match.groups()
            code = ("DISABLED" if re.search(r"\bdisabled\b", message) else
                    "AVAILABLE" if message.startswith(("is idle", "now printing")) else "UNKNOWN")
            rows.append((name, state(code)))
    return state("AVAILABLE" if rows else "NOT CONFIGURED"), rows


def probe_status(result):
    if isinstance(result, str):
        return state(result)
    if not result.returncode:
        return state("PASS")
    restricted = any(phrase in result.stderr.lower() for phrase in
                     ("permission denied", "operation not permitted", "not authorized", "forbidden"))
    return state("ACCESS RESTRICTED" if restricted else "FAILED")


def private_profile(store):
    try:
        if not store.validate_directory():
            return state("NOT CONFIGURED")
        if os.path.lexists(store.journal):
            return state("BLOCKED")
        history = store.history()
        actual = store.snapshot()
        if actual != (history["after"] if history else store.empty) or history != store.history():
            return state("BLOCKED")
        name = json.loads(actual["profile.json"] or "{}").get("profile")
        return PROFILE_NAMES.get(name, state("NOT CONFIGURED" if name is None else "FAILED"))
    except (AttributeError, OSError, ValueError, TypeError):
        return state("BLOCKED")


class Backend:
    def __init__(self, store, source):
        self.store, self.source = store, source

    def resources(self):
        try:
            return state("CONFIGURED"), pilot_session.active_resources(self.source)
        except FileNotFoundError:
            return state("NOT CONFIGURED"), {}
        except PermissionError:
            return state("ACCESS RESTRICTED"), {}
        except (ValueError, OSError):
            return state("FAILED"), {}

    def open_share(self, label, uri):
        pilot_session.session_ready()
        if pilot_session.active_resources(self.source).get(label) != uri:
            raise PermissionError
        subprocess.Popen(["/usr/bin/nautilus", "--", uri], stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)

    def recorded_review(self, host):
        try:
            if not self.store.validate_directory():
                return state("NOT CONFIGURED")
            receipt = self.store.read_record(self.store.directory / "installation-adoption.json")
        except PermissionError:
            return state("ACCESS RESTRICTED")
        except (OSError, ValueError):
            return state("FAILED")
        if receipt is None:
            return state("NOT CONFIGURED")
        if receipt.get("schema") != 1 or receipt.get("scope") != "metadata only" or receipt.get("managed") is not False:
            return state("FAILED")
        if receipt.get("review_token") != host["review_token"]:
            return state("UNVERIFIED")
        return state("RECORDED")

    def overview(self, token):
        host = installation.review()
        units = diagnostics.services()
        ad = diagnostics.configuration(Path("/"))
        printer = queues()[0] if not token.is_set() else state("NOT TESTED")
        rows = (
            (_("Installed Enterprise version"), __version__),
            (_("Saved installation profile"), private_profile(self.store)),
            (_("Workstation detection"), state(host["workflow"])),
            (_("Recorded installation review"), self.recorded_review(host)),
            (_("Host management ownership"), state("NOT TESTED")),
            (_("Active Directory configuration"), configured(ad["SSSD"] | ad["PAM"])),
            (_("Integrity Guard"), admin("omarchy-enterprise-guard")),
            (_("File Server policy"), self.resources()[0]),
            (_("Printer availability"), printer),
            (_("Windows start policy"), state("MANUAL START ONLY")),
            (_("Inbound Remote Desktop"), state("DISABLED")),
            (_("Update discovery tool"), command_ready("checkupdates")),
            (_("Update readiness"), state("NOT TESTED")),
        )
        return View(rows + tuple((unit.removesuffix(".service"), service(units, unit.removesuffix(".service")))
                                 for unit in units))

    def directory(self, token):
        report = diagnostics.report(runtime=True)
        units = report["services"]
        configuration = report["configuration"]
        sddm = configuration["SDDM"]
        rows = (
            (_("AD configuration presence"), configured(configuration["SSSD"] | configuration["PAM"])),
            (_("SSSD service"), service(units, "sssd")),
            (_("SSSD configuration validation"), admin("omarchy-enterprise-admin")),
            (_("Winbind service"), service(units, "winbind")),
            (_("Samba configuration"), configured(configuration["Samba"])),
            (_("PAM integration"), configured(configuration["PAM"])),
            (_("SDDM service"), service(units, "sddm")),
            (_("SDDM configuration"), configured(sddm["sources"])),
            (_("SDDM theme"), state(sddm["configured_theme"])),
            (_("Machine trust verification"), admin("omarchy-enterprise-ad-testjoin")),
            (_("AD authentication acceptance"), state(report["functional_acceptance"]["AD authentication"])),
            (_("PAM login acceptance"), state(report["functional_acceptance"]["PAM login"])),
            (_("SDDM login acceptance"), state(report["functional_acceptance"]["SDDM login"])),
        )
        return View(rows, report)

    def printers(self, token):
        ready, entries = queues()
        return View(((_("CUPS queues"), ready),
                     (_("Printer settings"), state("AVAILABLE" if graphical.printer_available() else "UNAVAILABLE")),
                     (_("Queue administration authorization"), state("NOT TESTED")), *entries))

    def windows(self, token):
        units = diagnostics.services()
        runtime = diagnostics.windows_runtime(activity=service(units, "docker").code, query=not token.is_set())
        container = runtime["containers"]
        return View((
            (_("Docker runtime"), state(runtime["executable"])),
            (_("Docker service"), state(runtime["service"])),
            (_("Container query access"), state(runtime["access"])),
            (_("Windows containers"), ", ".join(state(row).text for row in container)
             if isinstance(container, list) else state(container)),
            (_("Desired start policy"), state(runtime["desired_start_policy"])),
            (_("Effective restart policy"), state(runtime["restart_policy"])),
            (_("Storage readiness"), state(runtime["storage"])),
            (_("Managed launch"), state("BLOCKED")),
            (_("FreeRDP client"), state("AVAILABLE" if windows.client() else "UNAVAILABLE")),
        ), runtime)

    def remote(self, token):
        report = remote_desktop.diagnostics()
        rows = (
            (_("Inbound RDP"), state(report["activation"])),
            (_("Full inbound acceptance"), state("BLOCKED")),
            (_("Qualified inbound backend"), state("AVAILABLE" if report["qualified_backend"] else "UNAVAILABLE")),
            (_("Independent remote sessions"), state("BLOCKED")),
            (_("Peripheral redirection"), state("BLOCKED")),
            (_("Native mode"), state("BLOCKED")),
            (_("Compatibility mode"), state("BLOCKED")),
        )
        return View(rows, report)

    def security(self, token):
        return View((
            (_("Enterprise Guard"), admin("omarchy-enterprise-guard")),
            (_("Compliance"), admin("omarchy-enterprise-compliance")),
            (_("Audit service"), service(diagnostics.services(units=("auditd.service",)), "auditd")),
            (_("Audit rules and status"), admin("omarchy-enterprise-audit")),
            (_("Certificate management"), admin("omarchy-enterprise-certificates")),
            (_("Public certificate inspection"), command_ready("openssl")),
            (_("Security configuration review"), admin("omarchy-enterprise-updates")),
        ))

    def inventory(self, token):
        data = operations.inventory()
        return View(((_("Architecture"), data["architecture"]), (_("Kernel"), data["kernel"]),
                     (_("Logical CPUs"), str(data["logical_cpus"])),
                     (_("Installed package count"), str(data["installed_package_count"]))))

    def updates(self, token):
        return View((
            (_("Installed Enterprise version"), __version__),
            (_("Update discovery tool"), command_ready("checkupdates")),
            (_("Repository updates"), state("NOT TESTED")),
            (_("Live update readiness"), state("NOT TESTED")),
            (_("Package integrity"), state("NOT TESTED")),
            (_("Snapshot tool"), command_ready("snapper")),
            (_("Snapshot and backup readiness"), state("NOT TESTED")),
            (_("Recovery prerequisites"), state("NOT TESTED")),
            (_("Live legacy migration"), state("BLOCKED")),
        ))

    def discover_updates(self, token):
        executable = "/usr/bin/omarchy-enterprise-updates"
        if not os.access(executable, os.X_OK) or not shutil.which("checkupdates", path="/usr/bin"):
            return state("UNAVAILABLE")
        result = run_process([executable, "check"], token, timeout=195,
                             env={"PATH": "/usr/bin", "LC_ALL": "C"})
        if result.returncode:
            return probe_status(result)
        if "No repository updates available." in result.stdout.splitlines():
            return _("No updates found")
        found = re.search(r"(?m)^Available updates: ([0-9]+)$", result.stdout)
        return _("Available updates: {count}").format(count=found[1]) if found else state("UNKNOWN")

    def package_integrity(self, token):
        return probe_status(diagnostics.probe(["/usr/bin/pacman", "-Qk", "--", "omarchy-enterprise"]))

    def file_status(self, token):
        return self.resources(), state(ad_diagnostics.report()["Kerberos session cache"])

    def bookmark_preview(self, token):
        previous, resources, (_, desired) = pilot_session.bookmark_plan(self.source, read_only=True)
        return (previous, resources), tuple(previous[1]), tuple(desired)

    def apply_bookmarks(self, expected):
        pilot_session.integrate(self.source, expected=expected, confirm=lambda _: True)

    def rollback_bookmarks(self):
        pilot_session.rollback(confirm=lambda _: True)
