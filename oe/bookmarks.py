"""Maintain exact managed lines in the native GTK bookmark file."""

from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import stat

from . import policy, state


def read_bookmarks(path):
    try:
        info = path.lstat()
    except FileNotFoundError:
        return ""
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or info.st_nlink != 1 or info.st_mode & 0o022 or info.st_size > 1048576):
        raise ValueError("Unsafe bookmark file")
    return state.read(path) or ""


def locations(config=None, *, operational=False):
    config = config or Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
    ledger = config / ("omarchy-enterprise-operational-bookmarks" if operational
                       else "omarchy-enterprise-bookmarks")
    gtk = config / "gtk-3.0"
    policy.safe_directory(ledger)
    policy.safe_directory(gtk)
    if ledger.exists():
        state.Store(ledger).validate_directory()
    return gtk / "bookmarks", ledger


def read_managed(ledger):
    raw = state.read(ledger / "managed.json", private=True)
    managed = json.loads(raw) if raw is not None else []
    validate_managed(managed)
    return managed


def snapshot(book, ledger):
    return read_bookmarks(book), read_managed(ledger)


def validate_managed(managed):
    if not isinstance(managed, list):
        raise ValueError("Invalid managed bookmark record")
    keys = set()
    for line in managed:
        if not isinstance(line, str) or not line.endswith("\n") or " " not in line:
            raise ValueError("Invalid managed bookmark record")
        uri, label = line[:-1].split(" ", 1)
        key = policy.bookmark_uri(uri).rstrip("/")
        if key in keys or not policy.LABEL.fullmatch(label):
            raise ValueError("Invalid managed bookmark record")
        keys.add(key)


def uri_key(line):
    return line.split(" ", 1)[0].strip().lower().rstrip("/")


def peer_ownership(book, ledger, *ownership):
    _, legacy = locations(book.parent.parent)
    _, operational = locations(book.parent.parent, operational=True)
    peer = operational if ledger == legacy else legacy
    if os.path.lexists(state.Store(peer).journal):
        raise ValueError("The other bookmark ledger has a pending transaction; review locally")
    managed = read_managed(peer)
    keys = {uri_key(line) for line in managed}
    if any(keys.intersection(uri_key(line) for line in lines) for lines in ownership):
        raise ValueError("Both bookmark ledgers claim the same SMB resource; review locally")
    return keys


def planned_merge(book, ledger, current, resources):
    original, managed = current
    peer = peer_ownership(book, ledger, managed)
    if peer.intersection(policy.bookmark_uri(uri).rstrip("/") for uri in resources.values()):
        raise ValueError("An SMB resource is managed by the other bookmark ledger; review locally")
    return merge(original, managed, resources)


def merge(original, managed, resources):
    personal = original.splitlines(keepends=True)
    for line in set(managed):
        if personal.count(line) > 1:
            raise ValueError("Duplicate managed bookmark lines require local review")
        if personal.count(line) == 1:
            personal.remove(line)
    present = {uri_key(line) for line in personal}
    desired = []
    for label, uri in resources.items():
        key = policy.bookmark_uri(uri).rstrip("/")
        if not policy.LABEL.fullmatch(label):
            raise ValueError("Invalid bookmark label")
        if key not in present:
            desired.append(f"{uri} {label}\n")
            present.add(key)
    content = "".join(personal)
    if desired and content and not content.endswith("\n"):
        content += "\n"
    return content + "".join(desired), desired


def recover(book, ledger):
    """Finish a pending two-file update while preserving concurrent GTK edits."""
    store = state.Store(ledger)
    record = store.read_record(store.journal)
    if record is None:
        return
    if not book.parent.is_dir():
        raise ValueError("GTK bookmark directory missing during recovery; review locally")
    if record.keys() != {"before", "after"}:
        raise ValueError("Invalid pending bookmark transaction")
    for entry in record.values():
        if (not isinstance(entry, list) or len(entry) != 2 or not isinstance(entry[0], str)
                or len(entry[0].encode("utf-8")) > 1048576):
            raise ValueError("Invalid pending bookmark transaction")
        validate_managed(entry[1])
    before, after = record["before"], record["after"]
    actual, owned = snapshot(book, ledger)
    peer = peer_ownership(book, ledger, before[1], after[1], owned)
    if ([line for line in before[0].splitlines(keepends=True) if uri_key(line) in peer]
            != [line for line in after[0].splitlines(keepends=True) if uri_key(line) in peer]):
        raise ValueError("Pending update would change resources in the other ledger; review locally")
    if actual not in (before[0], after[0]) or owned not in (before[1], after[1]):
        raise ValueError("Bookmarks changed during an interrupted update; review locally")
    if actual != after[0]:
        state.write(book, after[0])
    if owned != after[1]:
        state.write(ledger / "managed.json", json.dumps(after[1]) + "\n")
    if snapshot(book, ledger) != tuple(after):
        raise ValueError("Bookmark verification failed; pending update retained")
    state.write(store.journal, None)
    return True


@contextmanager
def locked(book):
    """Serialize Enterprise operations on the shared GTK directory inode."""
    try:
        fd = os.open(book.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except FileNotFoundError:
        yield
        return
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def review(book, ledger, *, recover_pending=False):
    if recover_pending:
        recover(book, ledger)
    journal = state.Store(ledger).journal
    if os.path.lexists(journal):
        raise ValueError("Recover the pending bookmark transaction before preview")
    current = snapshot(book, ledger)
    peer_ownership(book, ledger, current[1])
    if os.path.lexists(journal):
        raise ValueError("Bookmark transaction started during preview")
    return current


def preview(config=None, *, operational=False):
    book, ledger = locations(config, operational=operational)
    with locked(book):
        return review(book, ledger, recover_pending=True)


def update(resources, config=None, *, expected=None, before_write=None, after_write=None, operational=False):
    if os.geteuid() == 0:
        raise ValueError("Refresh bookmarks as the desktop user")
    book, ledger = locations(config, operational=operational)
    if not resources and not ledger.exists() and before_write is None:
        return
    policy.safe_directory(ledger, create=True)
    policy.safe_directory(book.parent, create=True)
    store = state.Store(ledger)
    with locked(book):
        recover(book, ledger)
        original, managed = snapshot(book, ledger)
        if expected is not None and (original, managed) != expected:
            raise ValueError("Bookmarks changed since preview; review again")
        content, desired = planned_merge(book, ledger, (original, managed), resources)
        if content != original or desired != managed:
            if len(content.encode("utf-8")) > 1048576:
                raise ValueError("Result exceeds the bookmark file size limit")
            if before_write is not None:
                before_write(ledger, original, managed, desired)
            if read_bookmarks(book) != original:
                raise ValueError("Bookmarks changed concurrently; refresh again")
            state.write(store.journal, json.dumps({
                "before": (original, managed), "after": (content, desired),
            }))
            recover(book, ledger)
        if after_write is not None:
            after_write(ledger)


def manage(args, source):
    if args.action in {"set", "remove"}:
        # Produce a reviewed draft on stdout. The desktop process has no
        # ability to install policy for other users.
        if args.draft is None or not args.uri:
            raise ValueError("Specify a draft path and SMB URI")
        draft = args.draft.absolute()
        try:
            document = policy.load_file(draft)
        except FileNotFoundError:
            if args.action == "remove":
                raise ValueError("No reviewed draft exists") from None
            document = {"version": 2, "shares": []}
        policy.shares(document, set())
        if document["version"] != 2:
            raise ValueError("Use a version 2 draft for File Server Manager changes")
        target = policy.bookmark_uri(args.uri)
        entries = [row for row in document["shares"] if policy.bookmark_uri(row["uri"]) != target]
        if args.action == "set":
            entries.append({"label": args.label, "uri": args.uri, "groups": args.group})
        document["shares"] = entries
        policy.shares(document, set())
        print(json.dumps(document, indent=2))
        return 0
    if args.draft is not None or args.uri is not None or args.label is not None or args.group:
        raise ValueError("Draft changes are separate from active resource actions")
    if args.action == "clear":
        update({})
        print("Managed bookmarks cleared. Personal bookmarks preserved.")
        return 0
    try:
        document = policy.load_file(source, system=True)
    except FileNotFoundError:
        document = {"version": 2, "shares": []}
    resources = policy.shares(document, policy.effective_groups())
    if args.action == "refresh":
        update(resources)
        print("Managed bookmarks refreshed.")
    else:
        print(json.dumps(resources, indent=2))
    return 0


def diagnostics(source):
    import shutil

    storage = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
    print("Nautilus:", "available" if shutil.which("nautilus") else "unavailable")
    print("GIO:", "available" if shutil.which("gio") else "unavailable")
    print("GVFS SMB backend:", "available" if Path("/usr/lib/gvfsd-smb").is_file() else "unavailable")
    print("Kerberos client:", "available" if shutil.which("klist") else "unavailable")
    try:
        policy.shares(policy.load_file(source, system=True), set())
        print("File Servers policy: valid")
    except FileNotFoundError:
        print("File Servers policy: not installed")
    except (OSError, ValueError):
        print("File Servers policy: invalid or inaccessible")
        return 1
    try:
        ledger = storage / "omarchy-enterprise-bookmarks"
        policy.safe_directory(ledger)
        book, ledger = locations(storage)
        with locked(book):
            if any(os.path.lexists(state.Store(locations(storage, operational=selected)[1]).journal)
                   for selected in (False, True)):
                print("Managed bookmark update: recovery pending")
                return 1
            _, managed = review(book, ledger)
        status = "valid" if managed else "empty"
        print("Managed bookmark record:", status)
    except (OSError, ValueError):
        print("Managed bookmark record: invalid or inaccessible")
        return 1
    return 0
