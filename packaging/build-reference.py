"""Stage reviewed reference commands with explicit Arch-specific adaptations."""

import argparse
from pathlib import Path
import shlex

PREFIX = "omarchy-enterprise-"
COMMANDS = {
    "doctor": "",
    "guard": "check | list | backup",
    "view": "ACTION",
    "inventory": "[--json] [--software] [--network] [--export]",
    "compliance": "[--export]",
    "audit": "status | rules | identity | configuration | authentication | failures | summary",
    "updates": "check | preflight | snapshot | postflight | config-review | history",
    "printers": "status | list | jobs | discover | drivers | options | add-ipp | add-socket | default | set-system-default | remove | gui",
    "printer-monitor": "HOST",
    "certificates": "list | inspect FILE | install FILE SHA256 | remove SHA256",
    "provision-user": "[--is-admin] [--no-refresh]",
    "policy": "validate | plan | apply | open ID | self-test",
    "ad-testjoin": "",
}


def replace(text, old, new):
    if old not in text:
        raise ValueError(f"Reference adaptation no longer matches: {old[:80]}")
    return text.replace(old, new, 1)


NATIVE_MENU = """
categories = {
    "identity-authentication": ("Identity and Authentication", "identity kerberos"),
    "windows-integration": ("Windows Integration", "windows"),
    "network-resources": ("Network Resources", "network policy policyrefresh policyvalidate"),
    "security-compliance": ("Security and Compliance", "security guard compliance complianceexport"),
    "audit-log": ("Audit", "auditstatus auditrules auditidentity auditconfig auditauth auditfailures auditsummary"),
    "asset-inventory": ("Inventory", "inventory inventorysoftware inventorynetwork inventoryexport"),
    "printing": ("Printers", "printers printstatus printjobs printoptions printermonitor"),
    "certificate-tools": ("Certificates", "certificates"),
    "update-management": ("Updates", "updates updatepreflight updatepostflight updateconfigs updatehistory"),
    "backup-recovery": ("Backup and Recovery", "snapshots backup updatesnapshot"),
    "system-diagnostics": ("System Diagnostics", "doctor"),
}
for key, (label, actions) in categories.items():
    section = "enterprise." + key
    entries[section] = {"label": label}
    for name in actions.split():
        original = "enterprise." + name
        entries[section + "." + name] = entries.pop(original)
entries["enterprise.console"] = {
    "label": "Enterprise Management Console",
    "action": "/usr/bin/omarchy-enterprise desktop",
}
entries["enterprise.windows-integration.connect"] = {
    "label": "Connect to Windows",
    "action": "omarchy-launch-tui /usr/bin/omarchy-enterprise windows-connect",
    "when": admin_condition,
}
for action, label in (("start", "Start Windows"), ("stop", "Stop Windows"),
                      ("restart", "Restart Windows"), ("status", "Windows Status"),
                      ("settings", "Windows Settings")):
    entries["enterprise.windows-integration." + action] = {
        "label": label,
        "action": "omarchy-launch-tui /usr/bin/omarchy-enterprise windows-lifecycle " + action,
        "when": admin_condition,
    }
entries["enterprise.system-diagnostics.remote-desktop"] = {
    "label": "Remote Desktop diagnostics (offline)",
    "action": "omarchy-launch-tui /usr/bin/omarchy-enterprise doctor --remote-desktop",
}
entries["enterprise.network-resources.bookmarks"] = {
    "label": "Refresh Nautilus bookmarks",
    "action": "omarchy-launch-tui /usr/bin/omarchy-enterprise file-servers refresh",
}
"""


def python_adapt(name, body, usage):
    if name == "inventory":
        # Keep the original argparse-generated help and option handling.
        help_code = ""
    else:
        help_code = f'\nif __import__("sys").argv[1:] == ["--help"]:\n    print({usage!r})\n    raise SystemExit(0)\n'
    if name in {"inventory", "compliance"}:
        body = replace(body, "import os\n", 'import os\n\nif os.geteuid() == 0:\n    os.environ["PATH"] = "/usr/bin:/usr/sbin"\n')
    if name == "provision-user":
        body = replace(body, "import subprocess\n", "import stat\nimport subprocess\n")
        body = replace(body, '''config = json.loads(
    Path("/etc/omarchy-enterprise/provision.json").read_text()
)''', '''configuration = Path("/etc/omarchy-enterprise/provision.json")
try:
    metadata = configuration.lstat()
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0
            or metadata.st_mode & 0o022):
        sys.exit("Unsafe provisioning configuration permissions.")
    config = json.loads(configuration.read_text(encoding="utf-8"))
except (OSError, ValueError):
    sys.exit("Install a valid enterprise provisioning configuration first.")
if (not isinstance(config, dict)
        or any(not isinstance(config.get(key), str) or not config[key].strip()
               for key in ("domain", "admin_group"))):
    sys.exit("Provisioning requires a domain and an admin_group.")''')
        body = replace(body, 'menu.parent.mkdir(parents=True, exist_ok=True)',
                       'menu.parent.mkdir(parents=True, exist_ok=True)\n'
                       'if menu.is_symlink() or menu.parent.is_symlink():\n'
                       '    sys.exit("Refusing a symlinked Omarchy menu or extensions directory.")')
        body = replace(body, '# Parse JSONC without removing comments',
                       NATIVE_MENU + '\n# Parse JSONC without removing comments')
    if name == "policy":
        body = replace(body, '    directory.mkdir(parents=True, exist_ok=True)',
                       '    if directory.is_symlink():\n'
                       '        raise PermissionError("Refusing a symlinked applications directory.")\n'
                       '    directory.mkdir(parents=True, exist_ok=True)')
    if name == "printer-monitor":
        body = replace(body, "import subprocess\n", "import atexit\nimport subprocess\nimport tempfile\nfrom pathlib import Path\n")
        body = replace(body, 'if not community:\n    sys.exit("SNMP community is required.")',
                       'if not re.fullmatch(r"[A-Za-z0-9_.:@+-]+", community):\n'
                       '    sys.exit("Use a nonempty SNMP community with supported token characters.")')
        body = replace(body, 'env = dict(os.environ, LC_ALL="C")', '''settings = tempfile.TemporaryDirectory(prefix="oe-snmp-")
atexit.register(settings.cleanup)
settings_file = Path(settings.name) / "snmp.conf"
settings_file.touch(mode=0o600, exist_ok=False)
settings_file.write_text("defCommunity " + community + "\\n", encoding="utf-8")
del community
env = dict(os.environ, LC_ALL="C", SNMPCONFPATH=settings.name)''')
        body = replace(body, '"-v2c", "-c", community,', '"-v2c",')
    return "#!/usr/bin/python3 -I\n" + help_code + body


def shell_adapt(name, body, usage):
    if name == "ad-testjoin":
        body = '''if (( EUID != 0 )); then
    echo "Run the machine trust check with administrator approval." >&2
    exit 1
fi
''' + body
    if name == "guard":
        create = 'install -d -o root -g root -m 700 "$BASE"'
        body = replace(body, create + "\n", "")
        body = replace(body, "    backup)\n", "    backup)\n        " + create + "\n")
    if name == "view":
        body = replace(body, "    kerberos)\n", '''    adtestjoin)
        sudo /usr/bin/omarchy-enterprise-ad-testjoin
        ;;

    provision)
        /usr/bin/omarchy-enterprise-provision-user
        ;;

    kerberos)
''')
        body = replace(body, 'DEFAULT_HOST=$(cat /etc/omarchy-enterprise/printer-monitor-host)',
                       'DEFAULT_HOST=""\n        if [[ -r /etc/omarchy-enterprise/printer-monitor-host ]]; then\n            IFS= read -r DEFAULT_HOST < /etc/omarchy-enterprise/printer-monitor-host\n        fi')
        body = replace(body, 'read -rp "Press ENTER to close..."',
                       'read -rp "Press ENTER to close..." || true\nexit "$action_status"')
        body = replace(body, 'esac\n\necho\nread', 'esac\naction_status=$?\n\necho\nread')
    return ("#!/bin/bash\n"
            f'if [[ ${{1:-}} == --help ]]; then printf "%s\\n" {shlex.quote(usage)}; exit 0; fi\n'
            'export PATH=/usr/bin:/usr/sbin\n' + body)


def adapt(name, text):
    interpreter, _, body = text.lstrip("\n").partition("\n")
    usage = f"Usage: {PREFIX}{name} {COMMANDS[name]}".rstrip()
    # Keep internal command calls on the package-owned Arch paths.
    body = body.replace("/usr/local/bin/" + PREFIX, "/usr/bin/" + PREFIX)
    body = body.replace("PATH=/usr/local/bin:/usr/bin:/usr/sbin", "PATH=/usr/bin:/usr/sbin")
    body = body.replace("/usr/bin/python3 /usr/bin/" + PREFIX, "/usr/bin/" + PREFIX)
    if interpreter == "#!/usr/bin/python3":
        return python_adapt(name, body, usage)
    if interpreter == "#!/bin/bash":
        return shell_adapt(name, body, usage)
    raise ValueError(f"Unsupported interpreter for {name}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    expected = {PREFIX + name for name in COMMANDS}
    if {path.name for path in args.source.iterdir()} != expected:
        parser.error("Reference import inventory differs from the reviewed command list")
    args.destination.mkdir(parents=True, exist_ok=True)
    for name in COMMANDS:
        filename = PREFIX + name
        source = (args.source / filename).read_text(encoding="utf-8")
        destination = args.destination / filename
        destination.write_text(adapt(name, source), encoding="utf-8")
        destination.chmod(0o755)


if __name__ == "__main__":
    main()
