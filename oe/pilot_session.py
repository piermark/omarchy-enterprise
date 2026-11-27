"""Opt-in integration for an established graphical Enterprise session."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

from . import bookmarks, graphical, policy, state
from .directory import GROUP as GROUP_NAME

BACKUP = "pilot-recovery.json"


def session_ready(*, require_ticket=True):
    if os.geteuid() == 0:
        raise ValueError("Run the pilot in an ordinary desktop session")
    if not (os.environ.get("WAYLAND_DISPLAY") or os.environ.get("DISPLAY")):
        raise ValueError("Run this command inside the graphical session")
    if not all(shutil.which(command) for command in ("nautilus", "gio")):
        raise ValueError("Nautilus or GIO is unavailable")
    if not Path("/usr/lib/gvfsd-smb").is_file():
        raise ValueError("GVFS SMB support is unavailable")
    if require_ticket and not ticket_available():
        raise ValueError("No valid session ticket. Sign in to the domain and retry")


def ticket_available():
    if not shutil.which("klist"):
        return False
    try:
        return subprocess.run(["/usr/bin/klist", "-s"], stdin=subprocess.DEVNULL,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              timeout=5, check=False).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def active_resources(source, *, allow_groups=True):
    return policy.shares(policy.load_file(source, system=True),
                         policy.effective_groups() if allow_groups else set())


def approved(message):
    if shutil.which("zenity") and (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
        return graphical.Dialog().show("--question", f"--text={message}", "--ok-label=Apply") is not None
    print(message)
    return sys.stdin.isatty() and input("Type APPLY to confirm: ").strip() == "APPLY"


def bookmark_plan(source, *, config=None, automatic=False, read_only=False, operational=False):
    session_ready(require_ticket=operational or not automatic)
    book, ledger = bookmarks.locations(config, operational=operational)
    resources = active_resources(source, allow_groups=operational or not automatic or ticket_available())
    with bookmarks.locked(book):
        current = bookmarks.review(book, ledger, recover_pending=not read_only)
        return current, resources, bookmarks.planned_merge(book, ledger, current, resources)


def integrate(source, *, config=None, automatic=False, confirm=None, expected=None, operational=False):
    current, resources, (updated, desired) = bookmark_plan(
        source, config=config, automatic=automatic, read_only=expected is not None, operational=operational)
    if expected is not None and (current, resources) != expected:
        raise ValueError("Bookmarks or policy changed since preview; review again")
    if (updated, desired) == current:
        if not automatic:
            print("The managed bookmarks are already current.")
        return 0
    _, ledger = bookmarks.locations(config, operational=operational)
    if not automatic and not (confirm or approved)(
        f"Managed bookmarks after refresh: {len(desired)}. Existing ownership ledger: "
        f"{'present' if ledger.exists() else 'absent'}. Preserve personal entries and back up locally?"
    ):
        return 1

    stage_bookmarks(resources, config, current, automatic=automatic, operational=operational)
    if not automatic:
        print("Managed bookmarks refreshed and verified. The private rollback checkpoint is local.")
    return 0


def stage_bookmarks(resources, config, current, *, automatic=False, operational=False):
    """Apply reviewed resources with a private selective rollback checkpoint."""
    def backup(directory, text, previous, expected):
        # Keep one pre-change snapshot per explicit refresh. An automatic
        # refresh uses the same safety checks but retains existing recovery.
        if not automatic:
            old = state.read(directory / BACKUP, private=True)
            if old is not None:
                raise ValueError("A rollback checkpoint already exists; roll it back or retire it first")
            state.write(directory / BACKUP, json.dumps({
                "bookmarks_before": text,
                "owned_before": previous,
                "restore": [line for line in previous if text.splitlines(keepends=True).count(line) == 1],
                "expected": expected,
            }) + "\n")
        elif os.path.lexists(directory / BACKUP):
            raise ValueError("An explicit rollback checkpoint is pending")

    bookmarks.update(resources, config, expected=current, before_write=backup, operational=operational)


def login_worker(source, *, operational=False):
    if os.geteuid() == 0 or not source.is_file():
        return 0
    config = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
    lock = config / "omarchy-enterprise-login"
    try:
        policy.safe_directory(lock, create=True)
        with state.Store(lock).locked(nonblocking=True):
            integrate(source, config=config, automatic=True, operational=operational)
    except (OSError, ValueError):
        pass
    return 0


def _retire_checkpoint(directory, raw):
    if state.read(directory / BACKUP, private=True) != raw:
        raise ValueError("The rollback checkpoint changed; review locally")
    fd, saved = tempfile.mkstemp(dir=directory, prefix="pilot-retired-", suffix=".json")
    os.close(fd)
    os.replace(directory / BACKUP, saved)
    state.sync_directory(directory)


def bookmark_acceptance(*, config=None):
    """Review and finalize a verified operational sync before accepting another."""
    if os.geteuid() == 0:
        raise ValueError("Accept the checkpoint as the desktop user")
    book, ledger = bookmarks.locations(config, operational=True)

    def inspect():
        raw = state.read(ledger / BACKUP, private=True)
        current = bookmarks.review(book, ledger)
        checkpoint = json.loads(raw) if raw is not None else {}
        if (not isinstance(checkpoint, dict) or "expected" not in checkpoint
                or "rollback_target" in checkpoint or current[1] != checkpoint["expected"]
                or current == (checkpoint.get("bookmarks_before"), checkpoint.get("owned_before"))
                or any(current[0].splitlines(keepends=True).count(line) != 1 for line in current[1])):
            raise ValueError("No verified bookmark checkpoint can be finalized")
        return raw, current

    with bookmarks.locked(book):
        expected = inspect()

    def accept():
        with bookmarks.locked(book):
            if inspect() != expected:
                raise ValueError("Bookmarks or the checkpoint changed after review")
            _retire_checkpoint(ledger, expected[0])

    return accept


def rollback(*, config=None, confirm=None, quiet=False, operational=False):
    if os.geteuid() == 0:
        raise ValueError("Run rollback as the desktop user")
    _, ledger = bookmarks.locations(config, operational=operational)
    raw = state.read(ledger / BACKUP, private=True)
    if raw is None:
        raise ValueError("No pilot rollback checkpoint")
    checkpoint = json.loads(raw)
    current = bookmarks.preview(config, operational=operational)
    resumed = "rollback_target" in checkpoint and current[1] == checkpoint["rollback_target"]
    unapplied = ("rollback_target" not in checkpoint
                 and current == (checkpoint.get("bookmarks_before"), checkpoint.get("owned_before")))
    if not resumed and not unapplied and current[1] != checkpoint["expected"]:
        raise ValueError("Bookmark ownership changed after refresh; review locally")
    restore = {}
    for line in checkpoint["restore"]:
        uri, label = line.rstrip("\n").split(" ", 1)
        restore[label] = uri
    if not (confirm or approved)("Restore previous managed bookmarks and preserve personal edits?"):
        return 1
    def record_target(directory, _text, _previous, desired):
        nonlocal raw
        if state.read(directory / BACKUP, private=True) != raw:
            raise ValueError("The rollback checkpoint changed; review locally")
        raw = json.dumps(checkpoint | {"rollback_target": desired}) + "\n"
        state.write(directory / BACKUP, raw)

    def retire(directory):
        _retire_checkpoint(directory, raw)

    if resumed or unapplied:
        book, _ = bookmarks.locations(config, operational=operational)
        with bookmarks.locked(book):
            if bookmarks.review(book, ledger) != current:
                raise ValueError("Bookmarks changed since preview; review again")
            retire(ledger)
    else:
        bookmarks.update(restore, config, expected=current, before_write=record_target, after_write=retire,
                         operational=operational)
    if not quiet:
        print("Selective bookmark rollback finished. The private checkpoint was retained.")
    return 0


def edit(document, target, replacement):
    policy.shares(document, set())
    if document["version"] != 2:
        raise ValueError("Use a version 2 File Servers draft")
    key = policy.bookmark_uri(target) if target else None
    rows = [entry for entry in document["shares"] if policy.bookmark_uri(entry["uri"]) != key]
    if replacement:
        rows.append(replacement)
    result = {"version": 2, "shares": rows}
    policy.shares(result, set())
    return result


def normalize_uri(text):
    """Accept shorthand only in the editor. Keep stored policy canonical."""
    uri = text.strip(" ")
    if "://" not in uri:
        uri = "smb://" + uri
    if policy.HOST.fullmatch(uri.removeprefix("smb://")):
        uri += "/"
    policy.bookmark_uri(uri)
    return uri


def manager(source):
    if os.geteuid() == 0:
        raise ValueError("Run File Server Manager as the desktop user")
    dialog = graphical.Dialog() if shutil.which("zenity") and (
        os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")
    ) else TerminalDialog()
    choices = (("list", "List authorized file servers and shares"),
               ("draft", "Edit a private policy draft"), ("refresh", "Refresh Nautilus"),
               ("rollback", "Roll back managed bookmarks"), ("kerberos", "Kerberos diagnostics"))
    try:
        while (action := dialog.choose(choices)) is not None:
            try:
                if action == "list":
                    dialog.report(json.dumps(active_resources(source), indent=2))
                elif action == "refresh":
                    integrate(source)
                elif action == "rollback":
                    rollback()
                elif action == "kerberos":
                    dialog.report("Kerberos client: " + ("available" if shutil.which("klist") else "unavailable")
                                  + "\nSession ticket: " + ("available" if ticket_available() else "unavailable")
                                  + "\nSMB connection was not tested.")
                elif action == "draft":
                    draft_editor(dialog)
            except (OSError, ValueError, subprocess.SubprocessError):
                dialog.report("Operation unavailable. Check the policy, prerequisites or local recovery state.")
    except (KeyboardInterrupt, EOFError):
        print("\nCancelled. Central policy was not changed.")
    return 0


class TerminalDialog:
    def __init__(self):
        if not sys.stdin.isatty():
            raise ValueError("Open File Server Manager from an interactive terminal")

    def choose(self, entries):
        choices = list(entries)
        for number, (_, label) in enumerate(choices, 1):
            print(f"{number}. {label}")
        while True:
            selected = input("Choice (empty to return): ").strip()
            if not selected:
                return None
            if selected.isascii() and selected.isdecimal() and len(selected) <= 5:
                number = int(selected)
                if 1 <= number <= len(choices):
                    return choices[number - 1][0]
            self.report("Choose a displayed number or press Enter to go back.")

    def report(self, message):
        print(message)

    def show(self, operation, *options):
        prompt = next((value.removeprefix("--text=") for value in options if value.startswith("--text=")),
                      "Path to a private draft (empty to cancel)")
        if operation == "--question":
            return "" if input(f"{prompt} [y/N] ").strip().lower() == "y" else None
        default = next((value.removeprefix("--entry-text=") for value in options
                        if value.startswith("--entry-text=")), "")
        entered = input(f"{prompt}{f' [{default}]' if default else ''} (:back to cancel): ")
        return None if entered == ":back" else entered or default


def save_draft(document):
    policy.shares(document, set())
    config = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
    directory = config / "omarchy-enterprise-drafts"
    policy.safe_directory(directory, create=True)
    state.Store(directory).validate_directory()
    fd, path = tempfile.mkstemp(dir=directory, prefix="file-servers-", suffix=".json")
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(document, stream, indent=2)
    return Path(path)


def draft_editor(dialog, *, in_memory=False):
    document = {"version": 2, "shares": []}
    if dialog.show("--question", "--text=Load an existing reviewed draft?") is not None:
        selected = dialog.show("--file-selection")
        if not selected:
            return
        try:
            document = policy.load_file(Path(selected).absolute())
            policy.shares(document, set())
            document = {"version": 2, "shares": document["shares"]}
            policy.shares(document, set())
        except (OSError, ValueError):
            dialog.report("Draft could not be validated. Reopen the editor with a reviewed policy.")
            return
    while (action := dialog.choose((("add", "Add server or share"), ("edit", "Edit entry"),
                                    ("remove", "Remove entry"), ("save", "Review and save draft")))) is not None:
        if action == "save":
            dialog.report(json.dumps(document, indent=2))
            if in_memory:
                if dialog.show("--question", "--text=Use this draft in the disposable image plan?") is not None:
                    return document
                continue
            if dialog.show("--question", "--text=Save a new private draft for administrator review?") is None:
                return
            path = save_draft(document)
            dialog.report(f"Private draft saved for review:\n{path}\n"
                          "Ask an administrator to review and publish it in the trusted terminal. "
                          "The active policy has not changed. Visibility does not grant SMB access.")
            return
        target = None
        if action in ("edit", "remove"):
            target = dialog.choose((row["uri"], row["label"]) for row in document["shares"])
            if target is None:
                continue
        if action == "remove":
            document = edit(document, target, None)
            continue
        previous = next((row for row in document["shares"] if row["uri"] == target), None)
        defaults = previous or {"uri": "", "label": "", "groups": []}
        while True:
            uri = dialog.show("--entry", "--text=Server hostname, hostname/share, or SMB URI. "
                              "A hostname opens the server; a share opens that folder. Cancel to go back.",
                              f"--entry-text={defaults['uri']}")
            if not uri:
                break
            try:
                uri = normalize_uri(uri)
            except ValueError:
                dialog.report("Enter a fully qualified hostname and at most one share, without credentials.")
                continue
            label = dialog.show("--entry", "--text=Display name", f"--entry-text={defaults['label']}")
            if not label:
                break
            groups = dialog.show("--entry", "--text=Qualified AD groups separated by commas. "
                                 "Use * to explicitly select all. New entries may leave this blank.",
                                 "--entry-text=" + ", ".join(defaults["groups"]))
            if groups is None:
                break
            names = [name.strip() for name in groups.split(",")] if groups.strip() not in {"", "*"} else []
            if not names and defaults["groups"] and dialog.show(
                "--question", "--text=Show this resource to all users? Server permissions still apply."
            ) is None:
                continue
            if any(not GROUP_NAME.fullmatch(name) or not policy.HOST.fullmatch(domain)
                   for name, _, domain in (entry.partition("@") for entry in names)):
                dialog.report("Use qualified AD groups such as enterprise-admins@example.test.")
                continue
            try:
                document = edit(document, target, {"uri": uri, "label": label, "groups": names})
            except ValueError:
                dialog.report("Use a valid unique display name and resource URI. The draft is unchanged.")
                continue
            break


def menu():
    """Return a reviewed fragment; never open an existing user menu."""
    launcher = "/usr/bin/omarchy-launch-tui /opt/omarchy-enterprise-pilot-10d3/bin/omarchy-enterprise "
    return {
        f"enterprise.pilot.{key}": {"label": label, "action": launcher + action}
        for key, label, action in (
            ("manager", "File Server Manager", "pilot-session manager"),
            ("refresh", "Refresh File Servers", "pilot-session integrate"),
            ("kerberos", "Kerberos Diagnostics", "pilot-session kerberos"),
            ("rdp", "Remote Desktop Diagnostics", "doctor --remote-desktop"),
        )
    }
