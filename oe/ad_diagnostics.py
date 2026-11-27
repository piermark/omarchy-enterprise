# SPDX-License-Identifier: MIT
"""Bounded AD diagnostic probes with redacted, protocol-specific results."""

import os
import re
import shutil
import subprocess

from .directory import dc_names

TIMEOUT = re.compile(r"timed? out|timeout|nt_status_io_timeout", re.IGNORECASE)
AUTH = re.compile(
    r"nt_status_(logon_failure|access_denied|wrong_password|trusted_relationship_failure|"
    r"trust_failure|account_disabled)|authentication failed|preauthentication failed|"
    r"client not found in kerberos database|wbc_err_auth_error",
    re.IGNORECASE,
)
NETWORK = re.compile(
    r"no_logon_servers|domain_controller_not_found|cannot contact any kdc|"
    r"connection refused|network is unreachable|failed to find (a |the )?dc|"
    r"didn't find the cldap server",
    re.IGNORECASE,
)
WRITABLE = re.compile(r"^\s*Is writable:\s*(yes|no)\s*$", re.IGNORECASE | re.MULTILINE)


def execute(command, *args):
    executable = shutil.which(command, path="/usr/bin:/usr/sbin")
    if not executable:
        return "UNAVAILABLE", ""
    environment = ({"PATH": "/usr/bin:/usr/sbin", "LC_ALL": "C", "HOME": "/nonexistent"}
                   if os.geteuid() == 0 else dict(os.environ, LC_ALL="C"))
    try:
        result = subprocess.run([executable, *args], stdin=subprocess.DEVNULL,
                                capture_output=True, text=True, errors="replace",
                                env=environment, timeout=12, check=False)
    except subprocess.TimeoutExpired:
        return "TIMEOUT", ""
    except OSError:
        return "UNAVAILABLE", ""
    if result.returncode == 0:
        return "PASS", result.stdout
    diagnostic = result.stderr + "\n" + result.stdout
    if TIMEOUT.search(diagnostic):
        return "TIMEOUT", ""
    if "NT_STATUS_NO_TRUST_SAM_ACCOUNT" in diagnostic.upper():
        return "TRUST_ACCOUNT_UNAVAILABLE", ""
    if AUTH.search(diagnostic):
        return "AUTHENTICATION_FAILED", ""
    if NETWORK.search(diagnostic):
        return "UNREACHABLE", ""
    return "FAILED", ""


def controller_role(output):
    flags = {match.lower() for match in WRITABLE.findall(output)}
    if flags == {"yes"}:
        return "WRITABLE"
    if flags == {"no"}:
        return "READ_ONLY"
    return "UNKNOWN"


def report(*, machine=False, controllers=()):
    targets = dc_names(controllers)
    if not machine:
        if targets:
            raise ValueError("Explicit DC probes require machine diagnostics")
        status, _ = execute("klist", "-s")
        return {"Kerberos session cache": "NO_VALID_CACHE" if status == "FAILED" else status}

    checks = {}
    checks["ADS membership"], _ = execute("net", "--machine-pass", "ads", "testjoin")
    checks["RPC NETLOGON via Winbind"], _ = execute("wbinfo", "--check-secret")
    checks["Kerberos machine authentication"], _ = execute(
        "net", "--machine-pass", "--use-krb5-ccache=MEMORY:net",
        "ads", "kerberos", "kinit")
    for number, target in enumerate(targets, 1):
        label = f"DC {number}"
        status, output = execute("net", "--server", target, "ads", "lookup")
        role = controller_role(output) if status == "PASS" else status
        checks[f"{label} advertised role"] = role
        checks[f"{label} ADS membership"], _ = execute(
            "net", "--machine-pass", "--server", target, "ads", "testjoin")
        rpc, _ = execute("net", "--machine-pass", "--server", target, "rpc", "testjoin")
        checks[f"{label} RPC NETLOGON"] = rpc
        if role == "READ_ONLY" and rpc == "TRUST_ACCOUNT_UNAVAILABLE":
            checks[f"{label} guidance"] = "REVIEW_PREFERRED_WRITABLE_CONTROLLERS"
    return checks


def passed(checks):
    return all(value in {"PASS", "READ_ONLY", "WRITABLE"} for value in checks.values())
