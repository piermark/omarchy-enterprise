"""Resolve centrally assigned SMB resources from current Unix group membership."""

import grp
import json
from pathlib import Path
import stat
import os
import re
from urllib.parse import urlsplit

HOST = re.compile(r"(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?")
LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._()-]{0,79}")
SHARE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,79}")


def effective_groups():
    names = set()
    for gid in {*os.getgroups(), os.getegid()}:
        try:
            names.add(grp.getgrgid(gid).gr_name.casefold())
        except KeyError:
            continue
        except OSError:
            return set()
    return names


def bookmark_uri(value):
    if not isinstance(value, str) or any(not char.isprintable() for char in value):
        raise ValueError("Invalid SMB URI")
    try:
        parsed = urlsplit(value)
    except ValueError:
        raise ValueError("Invalid SMB URI") from None
    if (not HOST.fullmatch(parsed.netloc)
            or (parsed.path != "/" and not SHARE.fullmatch(parsed.path.removeprefix("/")))
            or value != f"smb://{parsed.netloc}{parsed.path}"):
        raise ValueError("Expected an SMB server or share URL with a fully qualified DNS name")
    return value.lower()


def shares(policy, groups):
    if not isinstance(policy, dict) or set(policy) != {"version", "shares"}:
        raise ValueError("Expected a versioned SMB policy")
    version = policy["version"]
    if type(version) is not int or version not in (1, 2) or not isinstance(policy["shares"], list):
        raise ValueError("Unsupported SMB policy format")
    result = {}
    seen = set()
    targets = set()
    for row in policy["shares"]:
        if (not isinstance(row, dict) or set(row) != {"label", "uri", "groups"}
                or not isinstance(row["label"], str) or not LABEL.fullmatch(row["label"])
                or not isinstance(row["groups"], list) or (version == 1 and not row["groups"])
                or any(not isinstance(group, str) or not group.strip() or not group.isprintable()
                       for group in row["groups"])):
            raise ValueError("Invalid SMB policy entry")
        target = bookmark_uri(row["uri"])
        if version == 1 and target.endswith("/"):
            raise ValueError("Version 1 requires an SMB share")
        key = row["label"].casefold()
        if key in seen or (version == 2 and target in targets):
            raise ValueError("Duplicate SMB resource")
        seen.add(key)
        targets.add(target)
        if not row["groups"] or groups.intersection(group.casefold() for group in row["groups"]):
            result[row["label"]] = row["uri"]
    return result


def safe_directory(path, *, create=False, system=False):
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("Expected a safe absolute directory")
    owners = {0} if system else {0, os.getuid()}
    for directory in (*reversed(path.parents), path):
        try:
            info = directory.lstat()
        except FileNotFoundError:
            if not create:
                continue
            directory.mkdir(mode=0o700)
            info = directory.lstat()
        if directory == Path("/") and stat.S_ISDIR(info.st_mode):
            continue
        if directory == Path("/tmp") and stat.S_ISDIR(info.st_mode) and info.st_mode & stat.S_ISVTX and not system:
            continue
        if not stat.S_ISDIR(info.st_mode) or info.st_uid not in owners or info.st_mode & 0o022:
            raise ValueError("Unsafe directory ownership, path or permissions")


def load_file(path, *, system=False):
    path = Path(path)
    safe_directory(path.parent, system=system)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        owners = {0} if system else {0, os.getuid()}
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid not in owners
                or metadata.st_nlink != 1 or metadata.st_mode & 0o022):
            raise ValueError("Unsafe resource policy file")
        content = stream.read(262145)
    if len(content) > 262144:
        raise ValueError("Resource policy is too large")
    try:
        return json.loads(content)
    except (ValueError, RecursionError):
        raise ValueError("Invalid resource policy JSON") from None
