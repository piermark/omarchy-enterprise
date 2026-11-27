"""Bounded, redacted review of system integration files and offline hook staging."""

import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat
import tempfile

SYSTEMD_SUFFIXES = {
    ".service", ".socket", ".timer", ".path", ".target", ".mount", ".automount",
    ".slice", ".scope", ".swap", ".device", ".conf",
}
GUARD = "omarchy-enterprise-guard"
HOOK_NAME = "90-omarchy-enterprise-guard.hook"
SOURCES = {
    "package hooks": ("usr/share/libalpm/hooks", {".hook"}, False),
    "local hooks": ("etc/pacman.d/hooks", {".hook"}, False),
    "XDG autostart": ("etc/xdg/autostart", {".desktop"}, False),
    "desktop entries": ("usr/share/applications", {".desktop"}, True),
    "local desktop entries": ("usr/local/share/applications", {".desktop"}, True),
    "vendor systemd units": ("usr/lib/systemd/system", SYSTEMD_SUFFIXES, True),
    "local systemd units": ("etc/systemd/system", SYSTEMD_SUFFIXES, True),
    "systemd user units": ("etc/systemd/user", SYSTEMD_SUFFIXES, True),
    "vendor systemd user units": ("usr/lib/systemd/user", SYSTEMD_SUFFIXES, True),
    "Omarchy menu": ("usr/share/omarchy", {".json", ".jsonc", ".lua", ".sh"}, True),
    "Omarchy local menu": ("etc/omarchy", {".json", ".jsonc", ".lua", ".sh"}, True),
    "Enterprise automation": ("etc/omarchy-enterprise", {".sh", ".timer", ".hook", ".desktop"}, False),
    "scheduled automation": ("etc/cron.d", None, False),
}
LIMIT = 262144
EXECUTABLE_PREFIXES = ("/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/usr/local/bin/")


def read_file(root, relative, limit=LIMIT):
    from .migration import directory

    path = root / relative
    with directory(path.parent) as parent:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        with os.fdopen(fd, "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise ValueError("Expected a regular review file")
            data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError("Review file exceeds size limit")
    return data


def candidates(root, relative, suffixes, recursive=False):
    """Enumerate bounded directory scopes and leave symlinks unverified."""
    from .migration import directory

    pending = [Path(relative)]
    paths = []
    incomplete = False
    remaining = 4096
    while pending and remaining:
        current = pending.pop()
        try:
            with directory(root / current) as fd, os.scandir(fd) as entries:
                for entry in entries:
                    remaining -= 1
                    if entry.is_dir(follow_symlinks=False):
                        if recursive:
                            pending.append(current / entry.name)
                    elif suffixes is None or Path(entry.name).suffix in suffixes:
                        paths.append(current / entry.name)
                    elif recursive and entry.is_symlink():
                        incomplete = True
                    if not remaining:
                        incomplete = True
                        break
        except FileNotFoundError:
            incomplete |= current != Path(relative)
        except OSError:
            incomplete = True
    return sorted(paths), incomplete


def executable(root, command):
    path = Path(command)
    if (not path.is_absolute() or ".." in path.parts
            or not command.startswith(EXECUTABLE_PREFIXES)):
        return None
    try:
        resolved = (root / command.lstrip("/")).resolve(strict=True)
        if (not resolved.is_relative_to(root)
                or not str(resolved.relative_to(root)).startswith(("bin/", "sbin/", "usr/"))
                or not resolved.is_file()):
            return None
        return resolved if os.access(resolved, os.X_OK) else None
    except (OSError, RuntimeError):
        return None


def first_line(target):
    try:
        fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                return None
            return stream.readline(256)
    except OSError:
        return None


def header(root, target):
    first = first_line(target)
    if first is None:
        return "UNREADABLE TARGET"
    if first.startswith(b"\x7fELF"):
        return "ELF HEADER PRESENT"
    if first.endswith((b"\r\n", b"\r")):
        return "CRLF HEADER"
    if not first.startswith(b"#!"):
        return "MISSING SHEBANG"
    if len(first) == 256 or b"\0" in first:
        return "INVALID SHEBANG"
    try:
        words = first[2:].decode("ascii").strip(" \t\n").split(None, 1)
    except UnicodeError:
        return "INVALID SHEBANG"
    if not words or executable(root, words[0]) is None:
        return "INVALID OR UNAVAILABLE INTERPRETER"
    interpreter = Path(words[0]).name
    if interpreter == "env":
        return "ENV INTERPRETER REQUIRES MANUAL REVIEW"
    if interpreter in {"bash", "sh", "dash", "python", "python3", "perl", "ruby"}:
        return "SHEBANG PRESENT"
    return "INTERPRETER REQUIRES MANUAL REVIEW"


def hook_actions(content):
    section = ""
    actions = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line
        elif section == "[Action]":
            key, separator, value = line.partition("=")
            if separator and key.strip() == "Exec":
                actions.append(value.strip())
    return actions


def inspect_hook(root, content):
    actions = hook_actions(content)
    if len(actions) != 1:
        return {"target": "MISSING OR AMBIGUOUS EXEC", "guard": "UNVERIFIED"}
    try:
        argv = shlex.split(actions[0])
    except ValueError:
        return {"target": "INVALID EXEC", "guard": "UNVERIFIED"}
    if not argv:
        return {"target": "MISSING EXEC", "guard": "UNVERIFIED"}
    command = argv[0]
    target = executable(root, command)
    if target:
        state = header(root, target)
    elif command.startswith(EXECUTABLE_PREFIXES):
        state = "MISSING OR NONEXECUTABLE TARGET"
    else:
        state = "OUT-OF-SCOPE TARGET UNVERIFIED" if command.startswith("/") else "PATH TARGET UNVERIFIED"
    guard = "NO RECOGNIZED GUARD REFERENCE"
    guard_paths = {f"/usr/bin/{GUARD}", f"/usr/local/bin/{GUARD}"}
    if argv[0] in guard_paths:
        first = first_line(target) if state == "SHEBANG PRESENT" else None
        if first and first.rstrip(b"\n") not in {b"#!/bin/bash", b"#!/usr/bin/bash"}:
            guard = "INCORRECT OR UNREVIEWED GUARD INTERPRETER"
        elif first and argv[1:] == ["check"]:
            guard = "DIRECT CHECK CANDIDATE"
        else:
            guard = "REVIEW REQUIRED"
    elif len(argv) > 1 and argv[1] in guard_paths:
        if argv == ["/usr/bin/bash", f"/usr/local/bin/{GUARD}", "check"] and target:
            try:
                read_file(root, argv[1].lstrip("/"), limit=LIMIT)
                guard = "EXPLICIT LEGACY BASH CHECK REQUIRES ADMINISTRATOR TRUST REVIEW"
            except (OSError, ValueError):
                guard = "SCRIPT UNAVAILABLE"
        else:
            guard = "INCORRECT OR UNREVIEWED GUARD INTERPRETER"
    elif GUARD in actions[0]:
        guard = "UNVERIFIED"
    elif Path(argv[0]).name in {"bash", "sh", "python", "python3", "env"}:
        state += " / SCRIPT OR COMMAND ARGUMENTS UNVERIFIED"
    return {"target": state, "guard": guard}


def dependencies(content):
    from .migration import NAMES

    result = {}
    for name in (*NAMES, "omarchy-enterprise-windows"):
        suffix = r"(?![A-Za-z0-9_.-])"
        kinds = []
        for prefix, label in (("/usr/local/bin/", "LEGACY ABSOLUTE"),
                              ("/usr/bin/", "PACKAGED ABSOLUTE")):
            if re.search(re.escape(prefix + name) + suffix, content):
                kinds.append(label)
        if re.search(r"(?<![A-Za-z0-9_./-])" + re.escape(name) + suffix, content):
            kinds.append("POSSIBLE PATH DEPENDENCY")
        if kinds:
            result[name] = kinds
    return result


def consumers(root, ownership):
    scopes = {}
    for scope, (relative, suffixes, recursive) in SOURCES.items():
        paths, incomplete = candidates(root, relative, suffixes, recursive)
        rows = []
        unknown = 0
        for index, path in enumerate(paths, 1):
            hook = scope.endswith("hooks")
            try:
                content = read_file(root, path).decode("utf-8")
                if "\0" in content:
                    raise ValueError("Binary consumer")
            except (OSError, ValueError):
                unknown += 1
                if hook:
                    rows.append({"ordinal": index, "ownership": ownership(root / path),
                                 "target": "UNVERIFIED", "guard": "UNVERIFIED"})
                continue
            references = dependencies(content)
            if hook:
                rows.append({"ordinal": index, "ownership": ownership(root / path),
                             "references": references, **inspect_hook(root, content)})
            elif references:
                rows.append({"ordinal": index, "references": references})
        scopes[scope] = {"candidates": len(paths), "unreadable_or_unsupported": unknown,
                         "enumeration_incomplete": incomplete, "findings": rows}
    return {
        "scopes": scopes,
        "unverified": ["User files and user-specific Omarchy menus", "Custom pacman HookDir paths",
                       "Indirect, generated, dynamic and out-of-scope consumers"],
        "consumer_review": "UNVERIFIED",
        "guard_parity": "UNVERIFIED",
        "plan": [
            "Review each finding locally in its numbered scope, ordered by path.",
            "Review effective hook precedence, custom directories, user menus and service overrides.",
            "Confirm which binary resolves for each PATH dependency in its actual execution context.",
            "Compare reviewed Guard manifests and retain every protected resource pending explicit review.",
            "Record checks against the existing baseline before scheduling any migration.",
        ],
    }


def guard_parity(legacy, packaged):
    """Compare administrator-reviewed path lists without returning their contents."""
    def paths(manifest):
        values = manifest.splitlines()
        if not values or len(values) != len(set(values)) or any(
                not re.fullmatch(r"/[A-Za-z0-9_./-]+", value)
                or str(Path(value)) != value or ".." in Path(value).parts
                or value.startswith("//") or value == "/" for value in values):
            raise ValueError("Expected unique literal absolute protected paths")
        return set(values)

    old, new = paths(legacy), paths(packaged)
    return {"legacy_count": len(old), "packaged_count": len(new),
            "legacy_only": len(old - new), "package_only": len(new - old),
            "combined_coverage_count": len(old | new),
            "path_parity": "MATCH" if old == new else "REVIEW REQUIRED",
            "live_apply": "BLOCKED"}


def stage_hook(root, action, content):
    from .migration import directory

    if root == Path("/") or os.geteuid() == 0:
        raise ValueError("Use a private disposable directory as an ordinary user")
    with directory(root) as parent:
        info = os.fstat(parent)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError("Use a private disposable directory (mode 0700)")
        fcntl.flock(parent, fcntl.LOCK_EX)
        # Use an inert suffix. Activation requires a separate administrator procedure.
        name = HOOK_NAME + ".example"
        if action == "rollback":
            if read_file(root, name) != content:
                raise ValueError("Staged hook changed. Review it before removal")
            os.unlink(name, dir_fd=parent)
        elif action == "stage":
            with tempfile.NamedTemporaryFile(dir=f"/proc/self/fd/{parent}") as staging:
                staging.write(content)
                staging.flush()
                os.fsync(staging.fileno())
                os.link(Path(staging.name).name, name, src_dir_fd=parent, dst_dir_fd=parent)
        else:
            raise ValueError("Unknown staging action")
        os.fsync(parent)
    return {"action": action, "artifact": name, "sha256": hashlib.sha256(content).hexdigest()}


def review_command(args):
    if args.action == "guard-parity":
        result = guard_parity(*(read_file(Path("/"), path.absolute().relative_to("/")).decode("utf-8")
                                for path in (args.legacy, args.packaged)))
    else:
        from .provision import PACMAN_HOOK

        content = PACMAN_HOOK.encode("ascii")
        result = stage_hook(args.directory.absolute(), args.action, content)
    print(json.dumps(result, indent=2))
    return 0
