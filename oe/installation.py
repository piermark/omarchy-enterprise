"""Classify existing installations from fixed metadata and verified image state."""
import hashlib
import json
import os
from pathlib import Path
import stat

from .migration import NAMES, encode
from .state import read, write

AD = ("etc/sssd/sssd.conf", "etc/samba/smb.conf", "etc/pam.d/system-auth-ad",
      "etc/pam.d/omarchy-enterprise")
LEGACY = tuple("usr/local/bin/" + name for name in NAMES)
MARKERS = ("usr/bin/omarchy-launch-tui", "etc/omarchy-enterprise/policy.json",
           "etc/omarchy-enterprise/provision.json")


def metadata(root, relative):
    path = root
    try:
        for component in Path(relative).parts[:-1]:
            path /= component
            if not stat.S_ISDIR(path.lstat().st_mode):
                return "FAILED", None
        path = root / relative
        info = path.lstat()
    except FileNotFoundError:
        return "NOT CONFIGURED", None
    except PermissionError:
        return "ACCESS RESTRICTED", None
    except OSError:
        return "FAILED", None
    if not stat.S_ISREG(info.st_mode):
        return "FAILED", None
    signature = [info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_ctime_ns]
    return ("CONFIGURED" if os.access(path, os.R_OK) else "ACCESS RESTRICTED"), signature


def review(root=Path("/"), *, target=None):
    observations = {name: metadata(root, name) for name in (*AD, *LEGACY, *MARKERS)}
    managed = False
    staged = None
    if target is not None and target.validate_directory():
        history = target.history()
        if os.path.lexists(target.journal):
            raise ValueError("Recover the image transaction before installation review")
        if history and target.snapshot() != history["after"]:
            raise ValueError("Managed image differs from its transaction record")
        staged = history["after"]["profile.json"] if history else None
        managed = staged is not None
    def present(entries):
        return any(observations[name][0] != "NOT CONFIGURED" for name in entries)

    # A standalone Samba configuration alone is insufficient evidence of AD.
    legacy, ad = present(LEGACY + MARKERS[1:]), present((AD[0], *AD[2:]))
    if managed:
        workflow = "MANAGED UPGRADE"
    elif legacy:
        workflow = "LEGACY ENTERPRISE"
    elif ad:
        workflow = "EXISTING AD-INTEGRATED"
    elif present(MARKERS[:1]):
        workflow = "EXISTING STANDALONE"
    else:
        workflow = "CLEAN INSTALLATION"
    review_only = not managed and (legacy or ad)
    if any(state == "FAILED" for state, _ in observations.values()):
        review_only = True
    token = hashlib.sha256(encode([observations, staged, workflow, review_only])).hexdigest()
    return {"workflow": workflow, "managed": managed, "ad_indicators": ad,
            "legacy_indicators": legacy, "review_only": review_only, "review_token": token}


def adopt(store, token, *, root=Path("/")):
    """Record explicit review in user state, without taking ownership of files."""
    with store.locked():
        report = review(root)
        if report["review_token"] != token or not (report["ad_indicators"] or report["legacy_indicators"]):
            raise ValueError("Review the current existing-installation findings first")
        receipt = {"schema": 1, "review_token": token, "workflow": report["workflow"],
                   "scope": "metadata only", "managed": False}
        path = store.directory / "installation-adoption.json"
        content = json.dumps(receipt, sort_keys=True) + "\n"
        if read(path, private=True) != content:
            write(path, content)
        return receipt
