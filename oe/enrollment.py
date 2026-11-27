"""Isolated Samba ADS enrollment. This does not install system trust."""

import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from . import ad_diagnostics, policy, state

INTENT = "enrollment.json"
LAB_DOMAINS = {"example.com", "example.test"}
ACCOUNT = re.compile(r"[A-Za-z][A-Za-z0-9._-]{0,63}")
COMPUTER = re.compile(r"[A-Za-z][A-Za-z0-9-]{0,14}")
OU_COMPONENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9 _-]{0,62}")
PRIVATE = "samba-enrollment"
KEYTAB = "machine.keytab"


def parameters(domain, principal, computer, controller, ou):
    if domain not in LAB_DOMAINS:
        raise ValueError("Use a documented synthetic laboratory domain")
    name, separator, realm = principal.partition("@")
    if not separator or realm.casefold() != domain or not ACCOUNT.fullmatch(name):
        raise ValueError("Specify a delegated test account as a qualified principal")
    if not COMPUTER.fullmatch(computer):
        raise ValueError("Specify a valid synthetic NetBIOS computer name")
    if not policy.HOST.fullmatch(controller) or not controller.lower().endswith("." + domain):
        raise ValueError("Select a writable controller in the synthetic domain")
    if ou and not all(OU_COMPONENT.fullmatch(component) for component in ou.split("/")):
        raise ValueError("Specify the OU from top to bottom using slash-separated simple names")
    return name + "@" + domain.upper(), computer.upper(), controller.lower()


def join_command(config, principal, controller, ou):
    return ("/usr/bin/net", f"--configfile={config}", f"--server={controller}",
            "--use-kerberos=required", f"--user={principal}", "ads", "join", "--no-dns-updates",
            *(() if not ou else (f"createcomputer={ou}",)))


def samba_settings(base, computer, private, *, keytab=False):
    settings = base.replace("kerberos method = secrets and keytab", "kerberos method = secrets only", 1)
    sync = (f"{private / KEYTAB}:account_name:spn_prefixes=host:sync_kvno:machine_password"
            if keytab else "disabled")
    return (settings + f"    netbios name = {computer}\n"
            f"    sync machine password to keytab = {sync}\n"
            f"    private dir = {private}\n"
            f"    state directory = {private}\n"
            f"    lock directory = {private}\n"
            f"    cache directory = {private}\n")


def write_intent(store, status, **metadata):
    state.write(store.directory / INTENT, json.dumps({"status": status, **metadata}) + "\n")


def enroll(store, args, *, run, safe_directory):
    with store.locked():
        managed = store.snapshot_expected()
        store.plan(managed)
        if os.path.lexists(store.directory / INTENT):
            raise ValueError("An enrollment record already exists; reconcile trust manually before retrying")
        if not managed["smb.conf"] or not managed["provision.json"]:
            raise ValueError("Apply an Active Directory configuration before enrollment")
        if any(os.path.lexists(store.root / path) for path in (
            "etc/krb5.keytab", "var/lib/samba/private/secrets.tdb", "etc/sssd/sssd.conf",
        )):
            raise ValueError("Existing system identity artifacts require administrator review")
        domain = json.loads(managed["provision.json"])["domain"]
        principal, computer, controller = parameters(
            domain, args.principal, args.computer, args.controller, args.ou)
        if not all(stream.isatty() for stream in (sys.stdin, sys.stdout, sys.stderr)):
            raise ValueError("An attended terminal is required for delegated enrollment")
        if run("/usr/bin/timedatectl", "show", "--property=NTPSynchronized",
               "--value", capture=True).stdout.strip() != "yes":
            raise ValueError("Verify synchronized guest time before enrollment")
        lookup = run("/usr/bin/dig", "+short", "+time=2", "+tries=1",
                     f"_ldap._tcp.dc._msdcs.{domain}", "SRV", capture=True)
        advertised = {row[3].rstrip(".").lower() for line in lookup.stdout.splitlines()
                      if len(row := line.split()) == 4 and row[2] == "389"}
        if lookup.returncode or controller not in advertised:
            raise ValueError("The selected controller was not found in synthetic domain DNS")

        private = store.directory / PRIVATE
        if os.path.lexists(private):
            raise ValueError("Existing Samba enrollment data requires manual reconciliation")
        kerb = store.file_path("krb5.conf")
        with tempfile.TemporaryDirectory(prefix="oe-ads-preflight-", dir="/tmp") as temporary:
            probe = Path(temporary) / "smb.conf"
            state.write(probe, samba_settings(managed["smb.conf"], computer, Path(temporary)))
            if run("/usr/bin/testparm", "-s", str(probe)).returncode:
                raise ValueError("Isolated Samba configuration failed native validation")
            dc = run("/usr/bin/net", f"--configfile={probe}", f"--server={controller}", "ads",
                     "lookup", capture=True, kerberos_config=kerb)
            if dc.returncode or ad_diagnostics.controller_role(dc.stdout) != "WRITABLE":
                raise ValueError("Could not confirm a writable controller; enrollment stopped")
        safe_directory(private)
        config = private / "smb.conf"
        state.write(config, samba_settings(managed["smb.conf"], computer, private))
        common = ("/usr/bin/net", f"--configfile={config}", f"--server={controller}")
        metadata = {"computer": computer, "domain": domain, "controller": controller}
        write_intent(store, "review-required", **metadata)
        # Samba itself reads the secret from the controlling terminal. Python
        # never reads it, stores it or passes it in argv or environment.
        result = subprocess.run(
            join_command(config, principal, controller, args.ou), check=False, umask=0o077,
            env={"PATH": "/usr/bin:/usr/sbin", "LC_ALL": "C", "HOME": "/nonexistent",
                 "KRB5_CONFIG": str(kerb),
                 "KRB5_KTNAME": f"FILE:{private / KEYTAB}",
                 "KRB5CCNAME": "MEMORY:oe-enrollment"},
        )
        trust = run(*common, "--machine-pass", "ads", "testjoin",
                    kerberos_config=kerb) if not result.returncode else None
        if trust is None or trust.returncode:
            raise ValueError("Enrollment or trust verification failed; reconcile local and remote state manually")
        write_intent(store, "isolated-ads-verified", **metadata)


def lifecycle(store, action, *, run, check_path):
    """Run explicit operations against the isolated Samba database only."""
    with store.locked():
        managed = store.snapshot_expected()
        store.plan(managed)
        record = store.read_record(store.directory / INTENT)
        if not record or record.get("status") not in {"isolated-ads-verified", "isolated-keytab-verified"}:
            raise ValueError("Verified isolated trust is required; reconcile ambiguous state manually")
        if not all(isinstance(record.get(field), str) for field in ("domain", "computer", "controller")):
            raise ValueError("The isolated enrollment record requires manual reconciliation")
        domain = record["domain"]
        if not managed["provision.json"] or json.loads(managed["provision.json"])["domain"] != domain:
            raise ValueError("The recorded enrollment and current AD profile differ")
        _, computer, controller = parameters(domain, f"fixture@{domain}", record["computer"],
                                             record["controller"], None)
        metadata = {"computer": computer, "domain": domain, "controller": controller}
        private = check_path(store.root, (store.directory / PRIVATE).relative_to(store.root), directory=True)
        if not private.is_dir() or private.stat().st_mode & 0o077:
            raise ValueError("The isolated Samba directory is unavailable or unsafe")
        config = check_path(store.root, (private / "smb.conf").relative_to(store.root))
        expected = samba_settings(managed["smb.conf"], computer, private)
        if state.read(config, private=True) != expected:
            raise ValueError("The isolated Samba configuration differs from the verified enrollment")
        net = ("/usr/bin/net", f"--configfile={config}", f"--server={controller}", "--machine-pass")
        kerb = store.file_path("krb5.conf")
        if run(*net, "ads", "testjoin", kerberos_config=kerb).returncode:
            raise ValueError("ADS trust could not be verified; no lifecycle changes were attempted")
        if action == "leave":
            write_intent(store, "leave-review-required", **metadata)
            if run(*net, "ads", "leave", "--keep-account", kerberos_config=kerb).returncode:
                raise ValueError("Isolated leave outcome is ambiguous; reconcile with the directory administrator")
            write_intent(store, "isolated-left", **metadata)
            return
        if action not in {"prepare-keytab", "verify-trust"}:
            raise ValueError("Unknown isolated trust operation")

        keytab = check_path(store.root, (private / KEYTAB).relative_to(store.root))
        if action == "prepare-keytab":
            if record["status"] != "isolated-ads-verified" or os.path.lexists(keytab):
                raise ValueError("Refusing to replace or regenerate an existing keytab")
            version = run("/usr/bin/net", "--version", capture=True)
            if version.returncode or not re.match(r"^Version 4\.25\.", version.stdout):
                raise ValueError("Keytab trial requires the reviewed Samba 4.25 series")
            generator = check_path(store.root, (private / "keytab-smb.conf").relative_to(store.root))
            if os.path.lexists(generator):
                raise ValueError("Existing keytab generator configuration requires review")
            state.write(generator, samba_settings(managed["smb.conf"], computer, private, keytab=True))
            if run("/usr/bin/testparm", "-s", str(generator)).returncode:
                raise ValueError("Keytab generation configuration failed native validation")
            write_intent(store, "keytab-review-required", **metadata)
            if run("/usr/bin/net", f"--configfile={generator}", f"--server={controller}",
                   "--machine-pass", "ads", "keytab", "create", kerberos_config=kerb).returncode:
                raise ValueError("Keytab generation failed; inspect isolated state before retrying")
            check_path(store.root, keytab.relative_to(store.root))
        elif record["status"] != "isolated-keytab-verified":
            raise ValueError("ADS trust passed; a verified isolated keytab is still required")

        if not keytab.is_file() or keytab.stat().st_mode & 0o077:
            raise ValueError("The isolated keytab is missing or has unsafe permissions")
        if run("/usr/bin/kinit", "-k", "-t", str(keytab), "-c", "MEMORY:oe-trust",
               f"{computer}$@{domain.upper()}", kerberos_config=kerb).returncode:
            raise ValueError("Machine Kerberos verification failed; do not restore old credentials")
        if action == "prepare-keytab":
            write_intent(store, "isolated-keytab-verified", **metadata)
