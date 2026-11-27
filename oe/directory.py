"""Render administrator-reviewed Active Directory configuration files."""

import os
import re

from .policy import HOST

GROUP = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}")
AD_FILES = ("krb5.conf", "smb.conf", "sssd.conf", "enterprise-sudoers")
WORKGROUP = re.compile(r"[A-Z][A-Z0-9-]{0,14}")


def dc_names(values):
    names = []
    for value in values:
        host = value.removesuffix(".").lower()
        if not HOST.fullmatch(host):
            raise ValueError("Each preferred DC must be a fully qualified DNS hostname")
        if host not in names:
            names.append(host)
    if len(names) > 8:
        raise ValueError("Specify at most eight preferred DCs")
    return names


def render(domain, workgroup, users, admins, *, preferred_dcs=(), discovery_fallback=False):
    domain = domain.lower()
    workgroup = workgroup.upper()
    if not HOST.fullmatch(domain) or not WORKGROUP.fullmatch(workgroup):
        raise ValueError("Expected a DNS domain and its NetBIOS workgroup")
    if not GROUP.fullmatch(users) or not GROUP.fullmatch(admins) or users.casefold() == admins.casefold():
        raise ValueError("Use distinct AD group names containing letters, digits, dots, underscores or hyphens")
    controllers = dc_names(preferred_dcs)
    if discovery_fallback and not controllers:
        raise ValueError("Discovery fallback is only needed with preferred controllers")
    password_servers = " ".join(controllers + (["*"] if discovery_fallback else [])) or "*"
    realm = domain.upper()
    users = f"{users}@{domain}"
    admins = f"{admins}@{domain}"
    return {
        "krb5.conf": f"""[libdefaults]
    default_realm = {realm}
    dns_lookup_kdc = true
    dns_lookup_realm = false
    rdns = false
    forwardable = false

[domain_realm]
    {domain} = {realm}
    .{domain} = {realm}
""",
        "smb.conf": f"""[global]
    workgroup = {workgroup}
    realm = {realm}
    security = ads
    kerberos method = secrets and keytab
    password server = {password_servers}
    client min protocol = SMB2_02
    client signing = mandatory
""",
        "sssd.conf": f"""[sssd]
config_file_version = 2
services = nss, pam
domains = {domain}

[domain/{domain}]
id_provider = ad
auth_provider = ad
ad_domain = {domain}
krb5_realm = {realm}
use_fully_qualified_names = true
fallback_homedir = /home/%d/%u
access_provider = simple
simple_allow_groups = {users}, {admins}
cache_credentials = false
""",
        "enterprise-sudoers": f"""%{admins} ALL=(ALL:ALL) ALL
""",
    }


def stage(destination, files):
    destination.mkdir(mode=0o700)
    created = []
    try:
        for name, content in files.items():
            path = destination / name
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            created.append(path)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(content)
    except OSError:
        for path in created:
            path.unlink(missing_ok=True)
        destination.rmdir()
        raise
