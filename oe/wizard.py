"""Guided graphical provisioning for an isolated installation target."""

from pathlib import Path
import shutil

from . import deployment, installation, graphical, pilot_session, policy, profiles, provision, remote_desktop

PROFILE_LABELS = {
    "standalone": "Standalone Enterprise",
    "active-directory": "Active Directory Enterprise",
    "full-enterprise": "Full Enterprise with optional Windows VM",
}


def preview(changes, checks, rdp_policy=None):
    lines = ["Files managed by this profile"]
    lines.extend(f"{action} {destination}" for destination, action in changes.items())
    lines.extend(("", "Prerequisite checks for this running host"))
    lines.extend(f"{'PASS' if passed else 'MISSING'} {name}" for name, passed in checks.items())
    if rdp_policy is not None:
        mode = remote_desktop.MODES.get(rdp_policy.get("mode"), "Legacy review")
        lines.extend(("", f"Remote Desktop policy: {mode} (activation OFF)."))
    return "\n".join(lines) + "\n"


def readiness(profile, *, windows_enabled=False, printing=False):
    checks = provision.health(profile, windows_enabled)
    checks["zenity"] = bool(shutil.which("zenity"))
    return checks, deployment.dependency_plan(profile, printing=printing)


def run(root=None, *, dry_run=False, store=None):
    dialog = graphical.Dialog()
    if root is None:
        dialog.report("Prepare configuration in an empty user-owned directory with mode 0700. "
                      "Choose a synthetic environment for AD testing. "
                      "The wizard stages files and previews dependencies.")
        host = installation.review()
        dialog.report("Running host: " + host["workflow"] + "\nInbound Remote Desktop is OFF.")
        if host["review_only"]:
            entries = [("stage", "Stage a separate disposable installation")]
            if store is not None and not dry_run and (host["ad_indicators"] or host["legacy_indicators"]):
                entries.append(("adopt", "Record review of existing integration (metadata only)"))
            action = dialog.choose(entries)
            if action == "adopt":
                if dialog.show("--question", "--text=Record your review in private user state?",
                               "--ok-label=Record review") is not None:
                    installation.adopt(store, host["review_token"])
                    dialog.report("Review recorded. Existing configuration is preserved.")
                return 0
            if action != "stage":
                return 0
        destination = dialog.show("--file-selection", "--directory")
        if destination is None:
            return 0
        root = Path(destination)
    target = provision.ImageStore(root)
    existing = installation.review(target.root, target=target)
    dialog.report("Selected target: " + existing["workflow"])
    if existing["review_only"]:
        dialog.report("Choose a clean staging directory. This target requires administrator review.")
        return 1
    profile = dialog.choose(PROFILE_LABELS.items())
    if profile is None:
        return 0
    if profile not in profiles.PROFILES:
        raise ValueError("Unknown profile selection")
    fields = {}
    if profile != "standalone":
        for key, label in (("domain", "DNS domain"), ("workgroup", "NetBIOS workgroup"),
                           ("users", "Allowed AD group"), ("admins", "AD administrator group")):
            value = dialog.show("--entry", f"--text={label}")
            if value is None:
                return 0
            fields[key] = value.strip()
        preferred = dialog.show("--entry", "--text=Preferred writable DCs (optional, separated by spaces)")
        if preferred is None:
            return 0
        fields["preferred_dcs"] = preferred.split()
        mode = dialog.choose(remote_desktop.MODES.items())
        if mode is None:
            return 0
        if mode not in remote_desktop.MODES:
            raise ValueError("Unknown Remote Desktop authentication mode")
        if mode != "off":
            dialog.report("Runtime activation is blocked. Select a review policy matching the chosen mode.")
            source = dialog.show("--file-selection", "--title=Choose a Remote Desktop policy")
            if not source:
                return 0
            candidate = policy.load_file(Path(source))
            if not isinstance(candidate, dict) or candidate.get("mode") != mode:
                raise ValueError("Remote Desktop policy must match the selected mode")
            if mode == "compatibility":
                if dialog.show("--question", f"--text={remote_desktop.DELEGATION_WARNING}",
                               "--ok-label=Acknowledge delegation", "--cancel-label=Cancel") is None:
                    return 0
                candidate = remote_desktop.acknowledge_delegation(candidate)
            fields["rdp_policy"] = candidate
    file_servers = dialog.choose((("skip", "Skip File Servers"), ("draft", "Configure File Servers draft"),
                                  ("load", "Use a reviewed File Servers policy")))
    if file_servers == "draft":
        draft = pilot_session.draft_editor(dialog, in_memory=True)
        if draft is None:
            return 0
        fields["file_servers"] = draft
    elif file_servers == "load":
        source = dialog.show("--file-selection", "--title=Choose a reviewed File Servers policy")
        if not source:
            return 0
        fields["file_servers"] = policy.load_file(Path(source))
    printing = dialog.choose((("skip", "Skip printer monitoring"),
                              ("monitor", "Configure a printer monitor host")))
    if printing == "monitor":
        printer = dialog.show("--entry", "--text=Fully qualified printer hostname")
        if printer is None:
            return 0
        fields["printer"] = printer.strip()
        if not fields["printer"]:
            raise ValueError("Provide a fully qualified printer hostname")
    history = target.history()
    if profile == "full-enterprise":
        image = dialog.show("--entry", "--text=Dockur image by SHA-256 digest (optional)")
        if image is None:
            return 0
        fields["image"] = image.strip() or None
        if fields["image"]:
            fields["windows_base"] = target.root / provision.CONFIG / "windows"
            fields["existing_windows"] = target.windows_settings()
    files = provision.render(profile, **fields)
    changes = target.plan(files)
    checks, packages = readiness(profile, windows_enabled=bool(fields.get("image")),
                                 printing=bool(fields.get("printer")))
    summary = preview(changes, checks, fields.get("rdp_policy"))
    summary += "\nLab package prerequisites: " + ", ".join(packages) + "\n"
    summary += ("\nLive installation still requires an authorized isolated guest and validated "
                "dependencies, storage, memory and recovery access. Domain enrollment, graphical "
                "login and Windows runtime require separate acceptance.\n"
                "Offline rollback: provision-image --root DIRECTORY rollback --yes. "
                "After an interruption, review provision-image --root DIRECTORY recover --help.\n")
    if fields.get("file_servers") is not None:
        summary += ("\nFile Servers policy is staged only. Central publication and native menu/login "
                    "integration require separate operator review.\n")
    summary += ("\nThis stages a disposable image. Missing dependencies must be resolved before installed-host use. "
                "Review local emergency login from an independent recovery path before any live activation.\n")
    dialog.report(summary)
    if "CONFLICT" in changes.values():
        return 1
    if dry_run:
        return 0
    if dialog.show("--question", "--text=Apply these files to the disposable directory?",
                   "--ok-label=Apply") is None:
        return 0
    if installation.review(target.root, target=target) != existing:
        raise ValueError("Installation detection changed. Review the selected target again.")
    result = provision.mutate(root, "apply", files, expected_history=(history,))
    dialog.report("Transaction verified\n\n" + "\n".join(result))
    return 0
