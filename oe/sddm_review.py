# SPDX-License-Identifier: MIT
"""Discover SDDM configuration and redact values outside the known theme."""

import configparser
from pathlib import Path

from .installation import metadata
from .legacy_review import candidates, read_file


def discover(root):
    rows = {}
    theme = "NO CURRENT THEME FOUND"
    certain = True
    locations = ("usr/lib/sddm/sddm.conf.d", "etc/sddm.conf.d")
    groups = [(location, *candidates(root, location, {".conf"})) for location in locations]
    groups.append(("etc", [Path("etc/sddm.conf")], False))
    for location, paths, incomplete in groups:
        if incomplete:
            rows[location] = {"metadata": "UNVERIFIED"}
            certain = False
        for index, path in enumerate(paths, 1):
            key = str(path) if path.name in {"sddm.conf", "zz-enterprise.conf", "enterprise-sddm.conf"} else (
                f"{location} entry {index}")
            row = {"presence": "CONFIGURED", "metadata": "NOT TESTED", "readability": "NOT TESTED",
                   "ownership": "NOT TESTED", "permissions": "NOT TESTED", "theme": "UNVERIFIED"}
            rows[key] = row
            state, signature = metadata(root, path)
            if signature is None:
                row["presence"] = state if state == "NOT CONFIGURED" else "UNVERIFIED"
                row["metadata"] = state
                certain &= state == "NOT CONFIGURED" and path == Path("etc/sddm.conf")
                continue
            mode, uid, _ = signature[2:5]
            row["metadata"] = "CONFIGURED"
            row["ownership"] = "CONFIGURED" if uid == 0 else "REVIEW REQUIRED"
            row["permissions"] = "CONFIGURED" if not mode & 0o022 else "REVIEW REQUIRED"
            try:
                content = read_file(root, path).decode("utf-8")
                config = configparser.ConfigParser(interpolation=None, strict=False, delimiters=("=",),
                                                       default_section=None)
                config.optionxform = str
                config.read_string(content)
                row["readability"] = "CONFIGURED"
                current = config.get("Theme", "Current", fallback=None)
                if current is None:
                    row["theme"] = "NO CURRENT THEME SET"
                else:
                    theme = ("OMARCHY ENTERPRISE" if current == "omarchy-enterprise" else
                             "CUSTOM THEME CONFIGURED" if current else "EMPTY THEME CONFIGURED")
                    row["theme"] = theme
            except PermissionError:
                row["readability"] = "ACCESS RESTRICTED"
                certain = False
            except (OSError, ValueError, configparser.Error):
                row["readability"] = "UNVERIFIED"
                certain = False
    return {"sources": rows, "configured_theme": theme if certain else "UNVERIFIED"}
