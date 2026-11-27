# SPDX-License-Identifier: MIT
"""Generate a Dockur deployment plan and build strict FreeRDP arguments."""

from pathlib import Path
import re
import shutil
import subprocess

from . import windows_storage
from .policy import HOST

IMAGE = re.compile(r"(?:docker\.io/)?dockurr/windows@sha256:[0-9a-f]{64}")
BOOTSTRAP_SETTINGS = {"AUTOLOGIN": "N", "WEB": "N", "DISPLAY": "none", "SAMBA": "N"}


def compose(image, cpu, memory, disk, *, storage=None, base_dir=None,
            disk_io=None, disk_cache=None, restart=None, existing=None):
    if not IMAGE.fullmatch(image):
        raise ValueError("Supply a reviewed dockurr/windows SHA-256 image digest")
    if not 2 <= cpu <= 64 or not 4 <= memory <= 256 or not 64 <= disk <= 4096:
        raise ValueError("Expected 2–64 CPUs, 4–256 GiB RAM and 64–4096 GiB storage")
    previous = existing if existing is not None else {}
    settings = dict(previous.get("environment", {}))
    bootstrap = {key: value for key, value in BOOTSTRAP_SETTINGS.items()
                 if existing is None or settings.get(key) == value}
    if storage is not None:
        path = windows_storage.storage_path(storage).absolute()
        volumes = [{"type": "bind", "source": str(path), "target": "/storage",
                    "bind": {"create_host_path": False}}]
    else:
        path = Path(base_dir or ".") / "windows"
        volumes = previous.get("volumes", ["./windows:/storage"])
    if existing is None or storage is not None:
        filesystem = windows_storage.inspect(path)["filesystem"]
        if existing is None and filesystem == "btrfs" and disk_io is None and disk_cache is None:
            disk_io, disk_cache = "threads", "writeback"
    if disk_io is not None:
        settings["DISK_IO"] = disk_io
    if disk_cache is not None:
        settings["DISK_CACHE"] = disk_cache
    storage_settings = {key: settings[key] for key in ("DISK_IO", "DISK_CACHE") if key in settings}
    restart_policy = {}
    if restart is not None:
        restart_policy["restart"] = restart
    elif "restart" in previous:
        restart_policy["restart"] = previous["restart"]
    elif existing is None:
        restart_policy["restart"] = "no"
    for value, choices in ((storage_settings.get("DISK_IO"), windows_storage.DISK_IO),
                           (storage_settings.get("DISK_CACHE"), windows_storage.DISK_CACHE),
                           (restart_policy.get("restart"), windows_storage.RESTART)):
        if value is not None and value not in choices:
            raise ValueError("Unsupported Windows storage or restart setting")
    return {
        "services": {"windows": {
            "image": image,
            "environment": {"VERSION": "11", "CPU_CORES": str(cpu),
                            "RAM_SIZE": f"{memory}G", "DISK_SIZE": f"{disk}G",
                            **bootstrap, **storage_settings},
            "devices": ["/dev/kvm", "/dev/net/tun"],
            "cap_add": ["NET_ADMIN"],
            "volumes": volumes,
            **restart_policy,
            "stop_grace_period": "2m",
        }},
    }


def client():
    executable = shutil.which("xfreerdp3") or shutil.which("xfreerdp")
    if executable is None:
        raise ValueError("FreeRDP is unavailable")
    return executable


def help_text(executable):
    environment = {
        "LC_ALL": "C", "PATH": "/usr/bin:/bin", "HOME": "/nonexistent",
        "XDG_CONFIG_HOME": "/nonexistent", "XDG_CACHE_HOME": "/nonexistent",
        "XDG_DATA_HOME": "/nonexistent", "XDG_STATE_HOME": "/nonexistent",
        "XDG_RUNTIME_DIR": "/nonexistent",
    }
    result = subprocess.run([executable, "/help"], env=environment, stdin=subprocess.DEVNULL,
                            capture_output=True, text=True, timeout=10, check=False)
    return result.stdout + result.stderr


def option_supported(options, name):
    return re.search(r"(?:^|[\s,])(?:/|[+-])" + re.escape(name) + r"(?=[:\s,]|$)", options) is not None


def capabilities():
    help_output = help_text(client())
    options = {
        "NLA selector": "sec",
        "Certificate verification selector": "cert",
        "Dynamic resolution": "dynamic-resolution",
        "Clipboard": "clipboard",
        "Audio": "sound",
        "Microphone": "microphone",
        "Remote Credential Guard": "remoteGuard",
        "Authentication package selector": "auth-pkg-list",
    }
    return {label: option_supported(help_output, option) for label, option in options.items()}


def rdp_command(host, account, port, *, kerberos_probe=False):
    if not HOST.fullmatch(host) or not 1 <= port <= 65535:
        raise ValueError("Specify the RDP certificate DNS name and a valid port")
    if not account or not account.isprintable() or "/" in account:
        raise ValueError("Specify a local Windows account or an AD principal")
    command = [client(), f"/v:{host}:{port}", f"/u:{account}", "/cert:deny", "/sec:nla"]
    if kerberos_probe:
        return command + ["/auth-pkg-list:none,kerberos", "+auth-only",
                          "-credentials-delegation", "+force-console-callbacks"]
    return command + ["/dynamic-resolution", "/sound", "/microphone", "+clipboard",
                      "/from-stdin:force"]


def guarded_session(command, supported_help):
    """Enable Remote Credential Guard only on clients exposing the required flags."""
    if not all(option_supported(supported_help, option) for option in ("remoteGuard", "auth-pkg-list")):
        raise ValueError("This FreeRDP build does not expose Remote Credential Guard")
    account = next(argument.removeprefix("/u:") for argument in command if argument.startswith("/u:"))
    principal, separator, domain = account.rpartition("@")
    if not separator or not principal or not HOST.fullmatch(domain):
        raise ValueError("Specify an AD user principal for Remote Credential Guard")
    media = [argument for argument in command if argument != "/from-stdin:force"]
    return [*media, "/auth-pkg-list:none,kerberos", "/remoteGuard",
            "+force-console-callbacks"]


def lifecycle(action):
    """Fail closed until a managed Windows runtime transport is qualified."""
    if action in {"status", "settings"}:
        print("Managed Windows runtime unavailable. Review the offline Windows plan and storage diagnostics.")
        return 1
    if action in {"start", "stop", "restart"}:
        print("Action blocked: no authorized Windows runtime controller is configured.")
        print("Contact the VM administrator. Use a graceful guest shutdown before storage recovery.")
        return 1
    raise ValueError("Unknown Windows lifecycle action")
