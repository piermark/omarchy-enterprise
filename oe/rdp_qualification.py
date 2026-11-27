# SPDX-License-Identifier: MIT
"""Offline evidence and a fail-closed boundary for inbound RDP adapters."""

from dataclasses import dataclass
from pathlib import Path
import re
import stat
import subprocess


@dataclass(frozen=True)
class Backend:
    command: str
    package: str
    upstream_ref: str
    tls: bool
    nla: bool | None
    ad_nla: bool | None
    independent_hyprland: bool | None
    drive_server: bool | None
    scope: str


BACKENDS = {
    "waydesk": Backend("waydesk-server", "waydesk-server", "c7771778b99ffada47106d9cd07c057c3d4e9183",
                       True, True, False, True, False, "NLA file credentials and TLS/PAM are separate modes"),
    "hypr-rdp": Backend("hypr-rdp", "hypr-rdp", "v0.1.9", True, True, False, False, False,
                        "shares a running Hyprland instance; PAM mode has no NLA"),
    "wrdp": Backend("wrdp", "wrdp", "93cf7c40f4b2d4c4e99dd500061cd8c54a56431d",
                    True, False, False, False, None, "managed labwc sessions; no domain authentication or NLA"),
    "xrdp": Backend("xrdp", "xrdp", "v0.10.6.1", True, False, False, False, True,
                    "xorgxrdp/Xvnc sessions and upstream RDPDR/FUSE; no mandatory NLA mode"),
    "wayrdp": Backend("wayrdp", "wayrdp", "4e04701c232a7366b32f1aa8fa976cd2bdfa8875",
                      True, False, False, False, None, "shares a running wlroots session; no PAM or NLA"),
    "gnome-remote-desktop": Backend("grdctl", "gnome-remote-desktop", "51.0",
                                   True, None, False, False, None, "GDM system login with a first-stage credential"),
}
REQUIRED = ("tls", "mandatory_nla", "ad_authentication", "ad_group_authorization",
            "independent_hyprland", "session_isolation", "reconnect_binding",
            "drive_server", "private_read_only_drives", "nautilus_drives",
            "clipboard_policy", "cleanup", "resource_limits", "mstsc", "audio",
            "microphone", "printer", "dynamic_resolution", "multiple_monitors",
            "keyboard_layout", "audit")
PACKAGE_VERSION = re.compile(r"(?:[0-9]+:)?[0-9][0-9A-Za-z.+_~-]{0,63}-[0-9]+(?:\.[0-9]+)*")


@dataclass(frozen=True)
class AdapterQualification:
    """Reviewed evidence for a specific installed package, never user policy."""
    package_version: str
    verified: frozenset[str]


# No candidate is allowed to activate. Future entries require verified
# integration and runtime acceptance, independent of command discovery.
QUALIFIED: dict[str, AdapterQualification] = {}


def trusted_executable(path):
    for item in (*reversed(path.parents), path):
        try:
            info = item.lstat()
        except FileNotFoundError:
            return "absent"
        except OSError:
            return "unknown"
        expected = stat.S_ISREG if item == path else stat.S_ISDIR
        if (not expected(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022
                or (item == path and not info.st_mode & 0o111)):
            return "untrusted"
    return "trusted"


def package_query(*args):
    if trusted_executable(Path("/usr/bin/pacman")) != "trusted":
        return None
    try:
        result = subprocess.run(["/usr/bin/pacman", *args], env={
            "PATH": "/usr/bin", "LC_ALL": "C", "HOME": "/nonexistent",
        }, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=3, text=True, check=False)
    except (OSError, subprocess.SubprocessError, UnicodeError):
        return None
    return result.stdout.strip() if not result.returncode else None


def detect(backend, *, version=True):
    executable = Path("/usr/bin") / backend.command
    trust = trusted_executable(executable)
    if trust != "trusted":
        return {"executable": trust, "package_version": None}
    if not version:
        return {"executable": "trusted; package not queried", "package_version": None}
    owner = package_query("-Qoq", "--", str(executable))
    if owner != backend.package:
        return {"executable": "package ownership unverified", "package_version": None}
    entry = package_query("-Q", "--", backend.package) or ""
    name, _, version = entry.partition(" ")
    return {"executable": "trusted", "package_version": version
            if name == backend.package and PACKAGE_VERSION.fullmatch(version) else None}


def readiness(backend, installed):
    approved = QUALIFIED.get(backend) if backend in BACKENDS else None
    missing = [name for name in REQUIRED if approved is None or name not in approved.verified]
    reasons = []
    if approved is None:
        reasons.append("no qualified adapter")
    elif installed.get("executable") != "trusted" or installed.get("package_version") != approved.package_version:
        reasons.append("installed release or executable trust not qualified")
    if missing:
        reasons.append("mandatory runtime evidence incomplete")
    return {"ready": not reasons, "reasons": reasons, "unverified_requirements": missing}


MODE_REQUIREMENTS = {
    "compatibility": (
        "exclusive_kerberos_before_credential_receipt", "same_peer_credssp_tls_binding",
        "delegated_identity_binding", "bounded_password_ownership_and_cleanup",
        "fresh_ad_and_pam_authorization", "private_kerberos_cache_and_gvfs_sso",
        "native_server_and_mstsc_acceptance",
    ),
    "strict": (
        "exclusive_remote_guard_before_credential_receipt", "same_peer_kerberos_and_tls_binding",
        "rdpear_server_channel", "redirected_key_authority_review",
        "session_bound_cifs_and_revocation", "native_server_and_mstsc_acceptance",
    ),
}


def mode_readiness(mode):
    """Release-owned gates. Legacy backend evidence cannot qualify either mode."""
    required = MODE_REQUIREMENTS.get(mode, ())
    return {
        "ready": False,
        "reasons": ["administratively disabled" if mode == "off" else "authentication mode unqualified"],
        "unverified_requirements": list(required),
    }
