# SPDX-License-Identifier: MIT
"""Selective Omarchy menu and native post-boot integration."""

import json
import os
from pathlib import Path
import re
import subprocess

from . import bookmarks, policy, state

LAUNCHER = "/opt/omarchy-enterprise-pilot-10d4/bin/omarchy-enterprise"
SYSTEM_LAUNCHER = "/usr/bin/omarchy-enterprise"
TARGETS = {
    "menu": "omarchy/extensions/omarchy-menu.jsonc",
    "login": "omarchy/hooks/post-boot.d/70-omarchy-enterprise-pilot",
}
HOOK = "#!/bin/bash\nexec " + LAUNCHER + " pilot-session login-refresh\n"
TOKENS = re.compile(r'"(?:[^"\\]|\\.)*"|//[^\n]*|/\*[\s\S]*?\*/|[^\s]')
COMMENT = re.compile(r'"(?:[^"\\]|\\.)*"|//[^\n]*|/\*[\s\S]*?\*/')
COMMA = re.compile(r'"(?:[^"\\]|\\.)*"|,(?=\s*[}\]])')


def fragment(*, product=False):
    base = "enterprise.file-servers"
    entries = {base: {"label": "File Servers"}}
    for key, label, args in (
        ("available", "Available Shares", "file-servers list"),
        ("manager", "File Server Manager", "pilot-session manager"),
        ("refresh", "Refresh Nautilus", "pilot-session integrate"),
        ("kerberos", "Kerberos Diagnostics", "pilot-session kerberos"),
        ("recovery", "Bookmark Recovery", "pilot-session rollback"),
    ):
        entries[f"{base}.{key}"] = {
            "label": label, "action": f"/usr/bin/omarchy-launch-tui {LAUNCHER} {args}",
        }
    if product:
        entries = {key: (value | {"action": value["action"].replace(
            LAUNCHER, SYSTEM_LAUNCHER).replace("pilot-session ", "file-servers ")})
                   if "action" in value else value for key, value in entries.items()}
        for key, label, args in (
            ("status", "Enterprise Status", "doctor --summary"),
            ("directory", "Active Directory", "ad-diagnostics"),
            ("windows", "Windows VM Status", "windows-lifecycle status"),
            ("printing", "Printing", "doctor --summary"),
            ("rdp", "Inbound Remote Desktop", "doctor --remote-desktop"),
            ("security", "Security and Diagnostics", "doctor --summary"),
            ("recovery", "Recovery Preview", "desktop-integration menu preview"),
        ):
            entries[f"enterprise.{key}"] = {"label": label,
                "action": f"/usr/bin/omarchy-launch-tui {SYSTEM_LAUNCHER} {args}"}
    return entries


def unique(pairs):
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ValueError("Duplicate keys in menu; review locally")
    return result


def append_menu(original, *, product=False):
    text = original or ""
    tokens = [token for token in TOKENS.finditer(text) if not token.group().startswith(("//", "/*"))]
    entries = fragment(product=product)
    inserted = json.dumps(entries, indent=2)
    if not tokens:
        return text + "\n" + inserted + "\n"
    clean = COMMENT.sub(lambda m: m[0] if m[0].startswith('"') else "", text)
    clean = COMMA.sub(lambda m: "" if m[0] == "," else m[0], clean)
    try:
        current = json.loads(clean, object_pairs_hook=unique)
    except ValueError:
        raise ValueError("Unsupported or invalid Omarchy menu; review locally") from None
    if not isinstance(current, dict) or set(entries) & current.keys():
        raise ValueError("Existing File Servers menu keys are unmanaged; review locally")
    close = tokens[-1].start()
    separator = "," if current and tokens[-2].group() != "," else ""
    return text[:close] + "\n" + separator + inserted[1:-1] + text[close:]


def apply(target, action, confirm, *, config=None, product=False):
    if os.geteuid() == 0:
        raise ValueError("Run desktop integration as the ordinary user")
    # Omarchy 4.5 looks in HOME/.config, independently of GTK's XDG path.
    config = config or Path.home() / ".config"
    relative = TARGETS[target]
    if target == "login":
        generic = relative.removesuffix("-pilot")
        other = config / (relative if product else generic)
        policy.safe_directory(other.parent)
        if action != "disable" and os.path.lexists(other):
            raise ValueError("An existing Enterprise hook requires an explicit migration")
        if product:
            relative = generic
    destination = config / relative
    directory = config / "omarchy-enterprise-desktop"
    policy.safe_directory(destination.parent)
    policy.safe_directory(directory)
    if directory.exists():
        state.Store(directory).validate_directory()
    record = directory / f"{target}.json"
    if product and target == "login":
        record = directory / "product-login.json"

    def inspect():
        content = bookmarks.read_bookmarks(destination) if os.path.lexists(destination) else None
        mode = destination.stat().st_mode & 0o777 if content is not None else None
        saved = state.Store(directory).read_record(record)
        if saved is not None and (
            set(saved) != {"before", "after", "mode", "enabled_mode"}
            or saved["before"] is not None and not isinstance(saved["before"], str)
            or not isinstance(saved["after"], str)
            or saved["mode"] is not None and (type(saved["mode"]) is not int or saved["mode"] & ~0o755)
            or type(saved["enabled_mode"]) is not int or saved["enabled_mode"] & ~0o755
        ):
            raise ValueError("Invalid desktop recovery record; review locally")
        if saved is not None and (content, mode) not in (
            (saved["before"], saved["mode"]), (saved["after"], saved["enabled_mode"]),
        ):
            raise ValueError("Desktop configuration drift; preserve local edits and review")
        return content, mode, saved

    before, mode, saved = inspect()
    if target == "menu" and saved is not None and (
            (SYSTEM_LAUNCHER in saved["after"]) != product):
        raise ValueError("An existing Enterprise menu checkpoint requires an explicit migration")
    if action == "preview":
        print(f"{relative}: {'checkpoint exists' if saved else 'review required'}")
        if saved is None:
            if target == "menu":
                append_menu(before, product=product)
            elif before is not None:
                raise ValueError("An unmanaged pilot login hook already exists")
        print("Proposed: " + ("add the File Servers submenu; preserve all other entries" if target == "menu"
                              else "add a separate bounded native post-boot hook"))
        return 0
    if not confirm:
        raise ValueError("Review preview and pass --confirm to change desktop integration")
    if action == "disable" and saved is None:
        return 0
    policy.safe_directory(directory, create=True)
    policy.safe_directory(destination.parent, create=True)
    with state.Store(directory).locked():
        if inspect() != (before, mode, saved):
            raise ValueError("Desktop configuration changed since review")
        if action == "enable":
            if saved is None:
                if target == "login" and before is not None:
                    raise ValueError("An unmanaged pilot login hook already exists")
                after = append_menu(before, product=product) if target == "menu" else (
                    f"#!/bin/bash\nexec {SYSTEM_LAUNCHER} file-servers login-refresh\n" if product else HOOK)
                saved = {"before": before, "mode": mode, "after": after,
                         "enabled_mode": mode if mode is not None else 0o600}
                state.write(record, json.dumps(saved) + "\n")
            if before != saved["after"]:
                state.write(destination, saved["after"], mode=saved["enabled_mode"])
            if inspect()[:2] != (saved["after"], saved["enabled_mode"]):
                raise ValueError("Could not verify native desktop integration")
        elif action == "disable":
            if before != saved["before"]:
                state.write(destination, saved["before"], mode=saved["mode"] or 0o600)
            if inspect()[:2] != (saved["before"], saved["mode"]):
                raise ValueError("Could not verify restored desktop configuration")
            state.write(record, None)
    print(f"Enterprise {target} integration {action} complete.")
    return 0


def supervise_login(*, product=False):
    if os.geteuid() == 0:
        return 1
    try:
        subprocess.run(["/usr/bin/timeout", "--kill-after=2s", "12s",
                        SYSTEM_LAUNCHER if product else LAUNCHER,
                        "file-servers" if product else "pilot-session", "login-worker"], check=False,
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except OSError:
        pass
    return 0
