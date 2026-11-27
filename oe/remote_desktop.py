"""Offline policy for an inbound RDP service. No backend has been qualified."""

import hashlib
import ipaddress
import json
from pathlib import PurePosixPath
import re
import shutil

from . import directory, policy, rdp_qualification

BACKENDS = rdp_qualification.BACKENDS
DEVICES = ("drive", "drive_read_only", "clipboard_text", "clipboard_file", "printer",
           "audio", "microphone", "dynamic_resolution", "multiple_monitors", "smart_card")
CHANNEL_CAPABILITIES = {
    "drive": ("drive_server", "private_read_only_drives", "nautilus_drives"),
    "clipboard_text": ("clipboard_policy",), "clipboard_file": ("clipboard_policy", "clipboard_file"),
    "printer": ("printer",), "audio": ("audio",), "microphone": ("microphone",),
    "dynamic_resolution": ("dynamic_resolution",), "multiple_monitors": ("multiple_monitors",),
    "smart_card": ("smart_card",),
}
PRIVATE_NETWORKS = tuple(map(ipaddress.ip_network, (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7",
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32",
)))
TLS_DIR = PurePosixPath("/etc/omarchy-enterprise/rdp")
MODES = {
    "off": "Disabled (recommended)",
    "compatibility": "Enterprise Compatibility Mode",
    "strict": "Enterprise Strict Security Mode",
}
DELEGATION_WARNING = (
    "Compatibility Mode temporarily receives a reusable AD password through CredSSP. "
    "Process memory, swap, crash dumps and library copies can expose it. "
    "Consent applies only to this policy. Runtime activation is blocked."
)
CONSENT_REVISION = 1
MATERIAL = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}\.pem")


def defaults():
    return {"version": 2, "mode": "off", "delegation_consent": None, "enabled": False, "backend": None, "listen": "127.0.0.1",
            "port": 3389, "sources": [], "authorization_group": None,
            "local_accounts": False, "autostart": False, "remote_root": False,
            "tls_required": True, "nla_required": True, "certificate": None, "key": None,
            "hostname": None, "max_connections": 4, "idle_timeout": 900, "drive_write": False,
            "devices": dict.fromkeys(DEVICES, False)}


def private_subnet(network):
    return any(network.version == candidate.version and network.subnet_of(candidate)
               for candidate in PRIVATE_NETWORKS)


def _delegation_consent(values):
    """Bind a recorded acknowledgement to the full normalized review policy."""
    payload = {key: value for key, value in values.items() if key != "delegation_consent"}
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("ascii")
    return {"revision": CONSENT_REVISION, "policy_sha256": hashlib.sha256(encoded).hexdigest()}


def acknowledge_delegation(document):
    """Use only after the operator explicitly accepts DELEGATION_WARNING."""
    if not isinstance(document, dict) or document.get("mode") != "compatibility":
        raise ValueError("Delegation acknowledgement requires Compatibility Mode")
    return _validate(document, acknowledge=True)


def validate(document, *, domain=None, reserved_groups=()):
    return _validate(document, domain=domain, reserved_groups=reserved_groups)


def _validate(document, *, domain=None, reserved_groups=(), acknowledge=False):
    base = defaults()
    if (not isinstance(document, dict) or document.keys() - base.keys()
            or type(document.get("version")) is not int or document["version"] not in (1, 2)):
        raise ValueError("Invalid Remote Desktop policy schema")
    legacy = document["version"] == 1
    if legacy and document.keys() & {"mode", "delegation_consent"}:
        raise ValueError("Legacy Remote Desktop policy cannot select an authentication mode")
    if not legacy and (type(document.get("mode")) is not str or document["mode"] not in MODES):
        raise ValueError("Select an explicit Remote Desktop authentication mode")
    values = base | document
    if legacy:
        del values["mode"], values["delegation_consent"]
    elif values["enabled"] is not False:
        raise ValueError("Authentication modes are available for offline review only")
    elif values["mode"] != "compatibility" and values["delegation_consent"] is not None:
        raise ValueError("Delegation consent applies only to Compatibility Mode")
    for field in ("enabled", "local_accounts", "autostart", "remote_root", "tls_required", "nla_required", "drive_write"):
        if type(values[field]) is not bool:
            raise ValueError("Expected Boolean Remote Desktop controls")
    if values["autostart"] or values["remote_root"] or not values["tls_required"] or not values["nla_required"]:
        raise ValueError("Remote Desktop planning requires TLS and NLA, with remote root and autostart disabled")
    if values["local_accounts"]:
        raise ValueError("No qualified local-account authorization mechanism is available")
    backend = values["backend"]
    if backend is not None and (not isinstance(backend, str) or backend not in BACKENDS):
        raise ValueError("Unknown Remote Desktop backend candidate")
    for field, lower, upper in (("port", 1024, 65535), ("max_connections", 1, 64),
                                 ("idle_timeout", 60, 86400)):
        if type(values[field]) is not int or not lower <= values[field] <= upper:
            raise ValueError("Invalid Remote Desktop numeric setting")
    try:
        listen = ipaddress.ip_address(values["listen"]) if isinstance(values["listen"], str) else None
        raw_networks = values["sources"]
        if (listen is None or "%" in values["listen"] or not isinstance(raw_networks, list)
                or len(raw_networks) > 16
                or any(not isinstance(item, str) or "/" not in item or "%" in item for item in raw_networks)):
            raise ValueError
        networks = [ipaddress.ip_network(item) for item in raw_networks]
    except ValueError:
        raise ValueError("Expected an explicit listener IP and bounded source CIDRs") from None
    if ((not listen.is_loopback and not private_subnet(ipaddress.ip_network(str(listen))))
            or any(item.version != listen.version or not private_subnet(item) for item in networks)
            or (not listen.is_loopback and not networks)):
        raise ValueError("Use loopback or an explicitly scoped private listener; public access is refused")
    group = values["authorization_group"]
    if group is not None:
        name, separator, suffix = group.partition("@") if isinstance(group, str) else ("", "", "")
        if (not separator or not directory.GROUP.fullmatch(name) or not policy.HOST.fullmatch(suffix)
                or (domain and suffix.casefold() != domain.casefold())
                or group.casefold() in {item.casefold() for item in reserved_groups}):
            raise ValueError("Use a distinct qualified Remote Desktop group in the configured AD domain")
    if values["hostname"] is not None and (
        not isinstance(values["hostname"], str) or not policy.HOST.fullmatch(values["hostname"])
    ):
        raise ValueError("Use a fully qualified TLS hostname")
    for field in ("certificate", "key"):
        if values[field] is None:
            continue
        if not isinstance(values[field], str):
            raise ValueError("Expected a managed TLS material path")
        path = PurePosixPath(values[field])
        if str(path) != values[field] or path.parent != TLS_DIR or not MATERIAL.fullmatch(path.name):
            raise ValueError("TLS material must use a filename in the managed Remote Desktop directory")
    if any(values[field] is not None for field in ("certificate", "key", "hostname")) and (
        not all(values[field] for field in ("certificate", "key", "hostname"))
        or values["certificate"] == values["key"]
    ):
        raise ValueError("Specify a hostname and distinct certificate and key files together")
    devices = values["devices"]
    if (not isinstance(devices, dict) or devices.keys() - set(DEVICES)
            or any(type(value) is not bool for value in devices.values())):
        raise ValueError("Invalid Remote Desktop device policy")
    values["devices"] = base["devices"] | devices
    drive = values["devices"]["drive"]
    if values["drive_write"]:
        raise ValueError("Redirected drives must be read-only")
    if not drive and devices.get("drive_read_only"):
        raise ValueError("Inconsistent redirected drive policy")
    values["devices"]["drive_read_only"] = drive
    requested = {cap for channel, capabilities in CHANNEL_CAPABILITIES.items()
                 if values["devices"][channel] for cap in capabilities}
    qualification = rdp_qualification.QUALIFIED.get(backend)
    if requested and (not values["enabled"] or qualification is None
                      or not requested <= qualification.verified):
        raise ValueError("Device redirection is blocked until its controls are qualified")
    if values["enabled"] and not all((backend, group, values["certificate"], networks)):
        raise ValueError("A review request requires a backend, AD group, source CIDRs and TLS references")
    if values.get("mode") == "compatibility":
        expected = _delegation_consent(values)
        if acknowledge:
            values["delegation_consent"] = expected
        consent = values["delegation_consent"]
        if (type(consent) is not dict or type(consent.get("revision")) is not int
                or consent != expected):
            raise ValueError("Compatibility Mode requires current administrator consent for this policy")
    return values


def normalize_identity(value, domain, workgroup):
    if not directory.WORKGROUP.fullmatch(workgroup.upper()) or not policy.HOST.fullmatch(domain):
        raise ValueError("Use a qualified AD identity")
    if "\\" in value:
        realm, name = value.split("\\", 1)
        valid = realm.casefold() == workgroup.casefold()
    else:
        name, separator, realm = value.partition("@")
        valid = bool(separator) and realm.casefold() == domain.casefold()
    if not valid or not directory.GROUP.fullmatch(name) or name.casefold() == "root":
        raise ValueError("Use a qualified AD identity other than root")
    return f"{name.casefold()}@{domain.casefold()}"


def group_allows(groups, required):
    """Policy predicate for authenticated identity results; no session adapter calls it."""
    return bool(required and groups and required.casefold() in {group.casefold() for group in groups})


def diagnostics(values=None):
    collect_versions = values is not None
    values = values if values is not None else defaults()
    candidates = {}
    for key, backend in BACKENDS.items():
        candidates[key] = {
            "command_available": bool(shutil.which(backend.command)),
            "scope": backend.scope,
            "upstream_ref": backend.upstream_ref,
            "installed": rdp_qualification.detect(backend, version=collect_versions),
            "upstream_capabilities": {
                "tls": backend.tls, "nla": backend.nla, "ad_nla": backend.ad_nla,
                "independent_hyprland": backend.independent_hyprland, "drive_server": backend.drive_server,
            },
        }
    selected = values["backend"]
    mode = values.get("mode")
    decision = (rdp_qualification.mode_readiness(mode) if mode is not None else
                rdp_qualification.readiness(selected, candidates.get(selected, {}).get("installed", {})))
    return {
        "activation": "BLOCKED" if values["enabled"] else "OFF",
        "mode": mode or ("legacy-review" if values["enabled"] else "off"),
        "mode_qualification": {name: rdp_qualification.mode_readiness(name) for name in MODES},
        "delegation_consent_recorded": mode == "compatibility" and values["delegation_consent"] is not None,
        "qualified_backend": decision["ready"],
        "deployment_readiness": decision,
        "candidates": candidates,
        "authentication": "dedicated AD group and PAM required; session adapter unavailable",
        "group_configured": values["authorization_group"] is not None,
        "tls": "required; material references configured" if values["certificate"] else "required; material not configured",
        "nla": "required; no qualified adapter",
        "ad_credssp_provider": "unavailable; no qualified server integration",
        "drive_redirection": "BLOCKED" if values["devices"]["drive"] else "OFF",
        "session_runtime": "blocked; no qualified session supervisor",
        "native_transport": "experimental; offline peer and channel contexts only",
        "provider_admission": "implemented; offline Unix socketpair tests only",
        "session_limits": {"sessions": values["max_connections"], "timeout_seconds": values["idle_timeout"]},
        "requested_channels": [channel for channel in CHANNEL_CAPABILITIES if values["devices"][channel]],
        "fuse_helper_available": bool(shutil.which("fusermount3")),
        "nautilus_available": bool(shutil.which("nautilus")),
        "hyprland_available": bool(shutil.which("Hyprland")),
        "audit": "policy metadata covered by existing managed configuration controls; no live RDP events",
        "service": "unmanaged; no service probe executed",
    }
