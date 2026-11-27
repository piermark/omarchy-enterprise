# SPDX-License-Identifier: MIT
"""Propagate shared per-user Kerberos collections without exposing credentials."""

import os
import subprocess
from urllib.parse import urlsplit

from . import ad_diagnostics, policy


def shared_collection(name, uid):
    if not name:
        return False
    return name in ("KCM:", f"KCM:{uid}", f"KEYRING:persistent:{uid}")


def import_kerberos_collection():
    if not shared_collection(os.environ.get("KRB5CCNAME"), os.getuid()):
        return False
    try:
        process = subprocess.run(
            ["/usr/bin/systemctl", "--user", "import-environment", "KRB5CCNAME"],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=5, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return process.returncode == 0


def smb_status(uri):
    parsed = urlsplit(uri)
    share = parsed.path.removeprefix("/")
    if (not policy.HOST.fullmatch(parsed.netloc) or not policy.SHARE.fullmatch(share)
            or uri != f"smb://{parsed.netloc}/{share}"):
        raise ValueError("Specify smb:// followed by a fully qualified host and one share name")
    cache = ad_diagnostics.report()["Kerberos session cache"]
    if cache != "PASS":
        return cache
    status, _ = ad_diagnostics.execute("smbclient", f"//{parsed.netloc}/{share}",
                                       "--use-kerberos=required", "--no-pass", "-c", "quit")
    return status


def require_ticket():
    state = ad_diagnostics.report()["Kerberos session cache"]
    if state == "NO_VALID_CACHE":
        raise ValueError("The Kerberos ticket is missing or expired. Sign in again or use interactive RDP.")
    if state != "PASS":
        raise ValueError("The Kerberos cache check is unavailable. Use interactive RDP.")
