"""Validated resource definitions for the disposable administration backend."""

import re
from urllib.parse import urlsplit

from . import policy, profiles

IDENTIFIER = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,47}")
GROUP = re.compile(r"[a-z][a-z0-9_-]{0,47}(?:@(?:[a-z0-9-]+\.)*example\.com)?")
EMPTY_SHARES = {"version": 2, "shares": []}
EMPTY_PRINTERS = {"printers": [], "default": None}


def fields(value, names):
    if not isinstance(value, dict) or value.keys() != set(names.split()):
        raise ValueError("Unexpected or missing configuration fields")


def identifier(value):
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise ValueError("Invalid resource identifier")
    return value


def example_host(host):
    if not host or not policy.HOST.fullmatch(host) or not (
        host == "example.com" or host.endswith(".example.com")
    ):
        raise ValueError("Use a synthetic example.com endpoint")


def groups(values):
    if (not isinstance(values, list) or len(values) > 64
            or any(not isinstance(group, str) or not GROUP.fullmatch(group) for group in values)):
        raise ValueError("Invalid synthetic groups")
    return set(values)


def shares(document):
    policy.shares(document, set())
    if document["version"] != 2 or len(document["shares"]) > 64:
        raise ValueError("Expected a bounded version 2 share policy")
    for row in document["shares"]:
        example_host(urlsplit(row["uri"]).hostname)
        groups(row["groups"])
    return document


def printers(document):
    fields(document, "printers default")
    rows = document["printers"]
    if not isinstance(rows, list) or len(rows) > 64:
        raise ValueError("Invalid printer list")
    names = set()
    for row in rows:
        fields(row, "name uri")
        name = identifier(row["name"])
        if name.casefold() in names:
            raise ValueError("Duplicate printer queue")
        names.add(name.casefold())
        uri = row["uri"]
        if not isinstance(uri, str) or not re.fullmatch(
                r"ipps?://[a-z0-9.-]+(?::631)?/ipp/[A-Za-z0-9_-]{1,48}", uri):
            raise ValueError("Use an IPP or IPPS driverless printer endpoint")
        example_host(urlsplit(uri).hostname)
    if document["default"] is not None and identifier(document["default"]) not in [
        row["name"] for row in rows
    ]:
        raise ValueError("Default printer must name a configured queue")
    return document


def vm(document):
    fields(document, "name cpu ram_mib disk_gib storage network")
    identifier(document["name"])
    identifier(document["storage"])
    for key, minimum, maximum in (("cpu", 1, 64), ("ram_mib", 1024, 262144),
                                  ("disk_gib", 32, 4096)):
        value = document[key]
        if type(value) is not int or not minimum <= value <= maximum:
            raise ValueError(f"Invalid VM sizing for {key}")
    if document["network"] not in ("isolated", "nat"):
        raise ValueError("Network preview must be isolated or NAT")
    return document | {"start_policy": "manual", "published_ports": [],
                       "inbound_rdp": False}


def deployment(document):
    fields(document, "profile capabilities shares printers windows")
    profile = document["profile"]
    if not isinstance(profile, str) or profile not in profiles.PROFILES:
        raise ValueError("Unknown deployment profile")
    windows = None if document["windows"] is None else vm(document["windows"])
    if windows is not None and profile != "full-enterprise":
        raise ValueError("Windows requires the Full Enterprise profile")
    share_policy = shares(document["shares"])
    print_policy = printers(document["printers"])
    required = ["omarchy", "python"]
    if profile != "standalone":
        required += ["directory-preview", "kerberos-preview"]
    if share_policy["shares"]:
        required.append("gvfs-smb")
    if print_policy["printers"]:
        required.append("cups")
    if windows:
        required += ["virtualization", "windows-license"]
    declared = document["capabilities"]
    known = {"omarchy", "python", "directory-preview", "kerberos-preview",
             "gvfs-smb", "cups", "virtualization", "windows-license"}
    if (not isinstance(declared, list) or len(declared) > len(known)
            or any(not isinstance(item, str) or item not in known for item in declared)
            or len(set(declared)) != len(declared)):
        raise ValueError("Expected a list of synthetic capabilities")
    prerequisites = {name: name in declared for name in required}
    return profile, prerequisites, share_policy, print_policy, windows
