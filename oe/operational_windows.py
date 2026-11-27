# SPDX-License-Identifier: MIT
"""Local Dockur command adapter. Lifecycle execution requires separate qualification."""

from dataclasses import dataclass
import os
from pathlib import Path
import re
import stat

from . import operational, windows, windows_storage

DOCKER = ("/usr/bin/docker", "--host", "unix:///var/run/docker.sock")
NAME = "omarchy-enterprise-phase12-windows"
LOCAL_NETWORK = "omarchy-enterprise-windows-local"
STORAGE = Path("/var/lib/omarchy-enterprise/operational-windows")
IDENTITY = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True)
class Settings:
    image: str
    cpu: int
    memory: int
    disk: int

    def __post_init__(self):
        if not isinstance(self.image, str) or not windows.IMAGE.fullmatch(self.image):
            raise ValueError("A reviewed Dockur digest is required")
        for value, low, high in ((self.cpu, 2, 64), (self.memory, 4, 256), (self.disk, 64, 4096)):
            if type(value) is not int or not low <= value <= high:
                raise ValueError("Windows CPU, memory or disk size is out of range")


def storage_empty(path):
    with windows_storage.nearest_directory(path, allow_missing=False) as (fd, _):
        info = os.fstat(fd)
        if info.st_uid != 0 or info.st_mode & 0o077:
            raise ValueError("Windows storage must be private and administrator-owned")
        with os.scandir(fd) as entries:
            return next(entries, None) is None


def device_ready(path):
    try:
        return stat.S_ISCHR(Path(path).stat().st_mode) and os.access(path, os.R_OK | os.W_OK)
    except OSError:
        return False


class Dockur:
    def __init__(self, runner=operational.command, probe=windows_storage.inspect,
                 empty=storage_empty, device=device_ready):
        self.run = runner
        self.probe = probe
        self.empty = empty
        self.device = device

    def query(self, *args, timeout=15):
        status, output = self.run((*DOCKER, *args), timeout=timeout)
        if status:
            raise ValueError("Local Docker operation failed; verify local daemon access and state")
        return output.strip()

    def create_plan(self, settings):
        return self._creation_plan(settings, STORAGE, "11")

    def _creation_plan(self, settings, path, edition):
        storage = self.probe(path).copy()
        args = ["container", "create", "--name", NAME, "--label",
                "org.omarchy-enterprise.adapter=phase12", "--pull", "never",
                "--restart", "no", "--network", "none", "--stop-timeout", "120",
                "--device", "/dev/kvm", "--device", "/dev/net/tun", "--cap-add", "NET_ADMIN",
                "--mount", f"type=bind,src={path},dst=/storage"]
        env = {"VERSION": edition, "CPU_CORES": settings.cpu, "RAM_SIZE": f"{settings.memory}G",
               "DISK_SIZE": f"{settings.disk}G", **windows.BOOTSTRAP_SETTINGS}
        if storage["filesystem"] == "btrfs":
            env.update(DISK_IO="threads", DISK_CACHE="writeback")
        for key, value in env.items():
            args.extend(("--env", f"{key}={value}"))
        storage["sufficient_space"] = (storage.pop("available_bytes") or 0) >= settings.disk * 1024**3
        return {"command": [*DOCKER, *args, settings.image], "storage": storage,
                "disk_gib": settings.disk, "kvm": self.device("/dev/kvm"),
                "tun": self.device("/dev/net/tun"), "manual_start": True,
                "rdp": "No endpoint published; review connectivity before using FreeRDP"}

    def configuration_review(self, settings, *, edition="11", storage=STORAGE,
                             local_port=None, certificate_name="", account=""):
        """Plan a new VM without changing the legacy lifecycle contract."""
        if edition not in {"11", "11l", "11e"}:
            raise ValueError("Select a supported Windows 11 edition")
        storage = windows_storage.storage_path(storage)
        if not storage.is_absolute() or "," in str(storage):
            raise ValueError("Choose an absolute dedicated storage path without commas")
        plan = self._creation_plan(settings, storage, edition)
        plan["storage_path"] = str(storage)
        plan["edition"] = edition
        if local_port is not None:
            client = loopback_client(certificate_name, account, local_port)
            args = plan["command"]
            args[args.index("--network") + 1] = LOCAL_NETWORK
            args[-1:-1] = ["--publish", f"127.0.0.1:{local_port}:3389/tcp"]
            plan["rdp"] = f"127.0.0.1:{local_port}"
            plan["certificate_name"] = certificate_name
            plan["client"] = client
            plan["qualification"] = "blocked"
            plan["required_network"] = {"name": LOCAL_NETWORK, "driver": "bridge", "internal": True}
            plan["requires_licensed_offline_media"] = True
        return plan

    def discover(self):
        ids = self.query("container", "ls", "--all", "--no-trunc", "--quiet",
                         "--filter", "label=org.omarchy-enterprise.adapter=phase12",
                         "--filter", f"name=^/{NAME}$").splitlines()
        if len(ids) > 1:
            raise ValueError("Managed container inventory is ambiguous")
        return {identity: self.status(identity) for identity in ids}

    def create(self, settings, token, *, checkpoint, authorize=operational.qualification_required):
        authorize()
        plan = self.create_plan(settings)
        operational.require_approval(plan, token)
        storage = plan["storage"]
        if (not plan["kvm"] or not plan["tun"] or storage["nearest_parent_used"]
                or storage["filesystem"] not in {"btrfs", "ext4", "xfs", "zfs"}
                or not storage["sufficient_space"]
                or not self.empty(STORAGE)):
            raise ValueError("Dedicated empty storage, free space or virtualization is unavailable")
        if self.query("container", "ls", "--all", "--filter", f"volume={STORAGE}", "--quiet"):
            raise ValueError("Storage is already referenced by a Docker container")
        self.query("image", "inspect", "--format", "{{.Id}}", settings.image)
        checkpoint({"status": "pending", "operation": "create", "name": NAME})
        identity = self.query(*plan["command"][len(DOCKER):])
        if not IDENTITY.fullmatch(identity):
            raise ValueError("Creation result is uncertain; review the local daemon manually")
        checkpoint({"status": "complete", "identity": identity})
        return identity

    def create_managed(self, settings, token, journal, *, authorize=operational.qualification_required):
        authorize()
        operational.administrator()
        operational.require_approval(self.create_plan(settings), token)
        return journal.run(lambda checkpoint: self.create(settings, token, checkpoint=checkpoint,
                                                          authorize=operational.administrator))

    def status(self, identity):
        if not isinstance(identity, str) or not IDENTITY.fullmatch(identity):
            raise ValueError("A full managed container ID is required")
        template = (
            '{{.Id}} {{.Name}} {{index .Config.Labels "org.omarchy-enterprise.adapter"}} '
            '{{.HostConfig.RestartPolicy.Name}} {{.HostConfig.NetworkMode}} '
            '{{len .HostConfig.PortBindings}} {{.State.Status}}'
        )
        data = self.query("container", "inspect", "--format", template, identity).split()
        if data[:-1] != [identity, "/" + NAME, "phase12", "no", "none", "0"] or data[-1:] not in (
                ["created"], ["running"], ["exited"]):
            raise ValueError("Managed container identity or runtime settings differ")
        return data[-1]

    def lifecycle_plan(self, identity, action):
        current = self.status(identity)
        if action == "start" and current in {"created", "exited"}:
            args = ("container", "start", identity)
        elif action == "stop" and current == "running":
            args = ("container", "stop", "--timeout", "120", identity)
        else:
            raise ValueError("Lifecycle action is unsuitable for the current state")
        return {"command": [*DOCKER, *args], "current": current}

    def lifecycle(self, identity, action, token, *, checkpoint, authorize=operational.qualification_required):
        authorize()
        plan = self.lifecycle_plan(identity, action)
        operational.require_approval(plan, token)
        checkpoint({"status": "pending", "operation": action, "identity": identity})
        self.query(*plan["command"][len(DOCKER):], timeout=135)
        observed = self.status(identity)
        if observed != {"start": "running", "stop": "exited"}[action]:
            raise ValueError("Unexpected Windows runtime state; review the daemon manually")
        checkpoint({"status": "complete", "identity": identity, "runtime": observed})
        return observed


    def lifecycle_managed(self, identity, action, token, journal, *, authorize=operational.qualification_required):
        authorize()
        operational.administrator()
        operational.require_approval(self.lifecycle_plan(identity, action), token)
        return journal.run(lambda checkpoint: self.lifecycle(identity, action, token, checkpoint=checkpoint,
                                                             authorize=operational.administrator),
                           identity=identity)


def connection_plan(host, account, port):
    return windows.rdp_command(host, account, port)


def loopback_client(certificate_name, account, port, *, supported_help=None):
    if type(port) is not int or not 1024 <= port <= 65535:
        raise ValueError("Choose an unprivileged local RDP port")
    if supported_help is not None and not all(windows.option_supported(supported_help, flag)
            for flag in ("server-name", "cert", "sec", "from-stdin")):
        raise ValueError("FreeRDP cannot verify the guest certificate identity over loopback")
    client = connection_plan(certificate_name, account, port)[:5]
    client[1] = f"/v:127.0.0.1:{port}"
    return [*client, f"/server-name:{certificate_name}", "/from-stdin:force"]
