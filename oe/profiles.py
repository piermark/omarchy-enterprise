# SPDX-License-Identifier: MIT
"""Installation profile definitions shared by the guided setup and diagnostics."""

STANDALONE = ("printing", "inventory", "security", "updates", "backup")
DIRECTORY = ("active-directory", "domain-login", "kerberos", "smb-policy", "role-mapping")
ENTERPRISE = ("audit", "compliance", "management-console")
PROFILES = {
    "standalone": STANDALONE,
    "active-directory": STANDALONE + DIRECTORY,
    "full-enterprise": STANDALONE + DIRECTORY + ENTERPRISE,
}


def modules(profile, windows):
    selected = PROFILES[profile]
    if windows:
        selected += ("windows",)
    return list(selected)
