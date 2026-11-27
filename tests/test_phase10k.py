# SPDX-License-Identifier: MIT
import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from oe import diagnostics, installation, migration, provision, wizard
from oe.__main__ import desktop_console, parser
from oe.state import Store


class MigrationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.local = self.root / "usr/local/bin"
        self.package = self.root / "usr/bin"
        self.local.mkdir(parents=True)
        self.package.mkdir(parents=True)
        self.names = migration.NAMES[:2]
        self.uid = os.getuid()
        self.manager = migration.Migration(self.root, lambda path:
                                           "unowned" if path.parent == self.local else migration.PACKAGE)
        for name in self.names:
            (self.local / name).write_text("# synthetic legacy\n")
            (self.package / name).write_text("# synthetic package\n")
            (self.package / name).chmod(0o755)
        (self.local / "unmanaged").write_text("keep")

    def token(self):
        return self.manager.preview(self.names, administrator=self.uid)["confirmation"]

    def operate(self, action, token=None):
        return self.manager._transact(action, self.names, token, administrator=self.uid, trusted_paths=False)

    def test_fingerprint_ignores_only_access_time_during_read(self):
        name = self.names[0]
        info = (self.local / name).stat()
        fields = {field: getattr(info, field) for field in (
            "st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink",
            "st_size", "st_mtime_ns", "st_ctime_ns", "st_atime_ns",
        )}
        with migration.directory(self.local) as fd:
            expected = migration.fingerprint(fd, name)
            for field in fields:
                with self.subTest(field=field):
                    changed = SimpleNamespace(**(fields | {field: fields[field] + 1}))
                    with patch.object(migration.os, "stat", return_value=info), patch.object(
                            migration.os, "fstat", side_effect=[info, changed]):
                        if field == "st_atime_ns":
                            self.assertEqual(migration.fingerprint(fd, name), expected)
                        else:
                            with self.assertRaisesRegex(ValueError, "changed during inspection"):
                                migration.fingerprint(fd, name)

    def test_live_apply_stays_blocked(self):
        with patch.object(migration.os, "geteuid", return_value=0), patch.object(
                migration.Migration, "_transact") as transact:
            with self.assertRaisesRegex(ValueError, "Guard protected-path differences"):
                migration.Migration().transact("apply", self.names, "token")
        transact.assert_not_called()
        report = self.manager.preview(self.names, administrator=self.uid)
        self.assertEqual(report["live_apply"], "BLOCKED")
        self.assertEqual(report["package_integrity"], "NOT TESTED")

    def test_round_trip_and_idempotence(self):
        path = self.local / self.names[0]
        before = path.stat()
        token = self.token()
        self.assertEqual(self.operate("apply", token), "APPLIED")
        self.assertEqual(self.operate("apply", token), "ALREADY APPLIED")
        private = self.local / migration.PRIVATE
        self.assertEqual(private.stat().st_mode & 0o777, 0o700)
        self.assertEqual((private / "journal.json").stat().st_mode & 0o777, 0o600)
        self.assertFalse(path.exists())
        self.assertEqual(self.operate("rollback"), "ROLLED BACK")
        self.assertEqual(self.operate("rollback"), "NO PENDING MIGRATION")
        self.assertEqual(path.stat().st_ino, before.st_ino)
        self.assertEqual(path.stat().st_uid, before.st_uid)
        self.assertEqual((self.local / "unmanaged").read_text(), "keep")

    def test_stale_preview_symlinks_and_unverified_ownership(self):
        token = self.token()
        path = self.local / self.names[0]
        path.write_text("external change")
        with self.assertRaises(ValueError):
            self.operate("apply", token)
        self.assertFalse((self.local / migration.PRIVATE).exists())
        path.unlink()
        path.symlink_to(self.package / self.names[0])
        self.manager.ownership = lambda path: "unknown"
        rows = self.manager.preview(administrator=self.uid)["commands"]
        self.assertEqual(rows[self.names[0]]["state"], "BLOCKED")
        self.assertEqual(rows[self.names[1]]["state"], "CONFLICT")

    def test_interrupted_apply_recovers_and_refuses_external_replacement(self):
        token = self.token()
        original = migration.relocate

        def interrupted(local, backup, files, destination):
            original(local, backup, dict(list(files.items())[:1]), destination)
            raise OSError("synthetic interruption")

        with patch.object(migration, "relocate", side_effect=interrupted), self.assertRaises(OSError):
            self.operate("apply", token)
        path = self.local / self.names[0]
        path.write_text("external replacement")
        with self.assertRaises(ValueError):
            self.operate("recover")
        self.assertEqual(path.read_text(), "external replacement")
        path.unlink()
        self.assertEqual(self.operate("recover"), "ROLLED BACK")
        self.assertTrue(all((self.local / name).exists() for name in self.names))


class DiagnosticTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def file(self, relative, mode=0o600):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("synthetic fixture")
        path.chmod(mode)
        return path

    def test_installation_workflows_and_metadata_adoption(self):
        self.assertEqual(installation.review(self.root)["workflow"], "CLEAN INSTALLATION")
        self.file("usr/bin/omarchy-launch-tui")
        self.assertEqual(installation.review(self.root)["workflow"], "EXISTING STANDALONE")
        pam = self.file("etc/pam.d/system-auth-ad")
        report = installation.review(self.root)
        self.assertEqual(report["workflow"], "EXISTING AD-INTEGRATED")
        receipt = installation.adopt(Store(self.root / "user-state"), report["review_token"], root=self.root)
        self.assertFalse(receipt["managed"])
        self.assertEqual(pam.read_text(), "synthetic fixture")
        self.file(installation.LEGACY[0])
        self.assertEqual(installation.review(self.root)["workflow"], "LEGACY ENTERPRISE")
        with self.assertRaises(ValueError):
            installation.adopt(Store(self.root / "user-state"), report["review_token"], root=self.root)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            provision.mutate(root, "apply", provision.render("standalone"))
            self.assertEqual(installation.review(root, target=provision.ImageStore(root))["workflow"],
                             "MANAGED UPGRADE")

    def test_metadata_service_and_acceptance_are_independent(self):
        self.file("etc/sssd/sssd.conf")
        with patch("oe.installation.os.access", return_value=False), patch("oe.diagnostics.services",
                return_value={"sssd.service": {"activity": "ACTIVE", "unit": "CONFIGURED"}}):
            result = diagnostics.report(root=self.root, runtime=True)
        sssd = result["configuration"]["SSSD"]["sssd.conf"]
        self.assertEqual(sssd["presence"], "CONFIGURED")
        self.assertEqual(sssd["readability"], "ACCESS RESTRICTED")
        self.assertEqual(sssd["metadata"], "CONFIGURED")
        self.assertEqual(result["configuration_validation"]["SSSD"], "NOT TESTED")
        self.assertEqual(result["functional_acceptance"]["AD authentication"], "NOT TESTED")

    def test_sssd_protected_ownership_and_mode(self):
        self.file("etc/sssd/sssd.conf")
        root_metadata = [1, 2, 0o100600, 0, 0, 3]
        service_metadata = [1, 2, 0o100600, 456, 789, 3]
        with patch.object(diagnostics.pwd, "getpwnam", return_value=Mock(pw_uid=456, pw_gid=789)), patch.object(
                diagnostics.grp, "getgrnam", return_value=Mock(gr_gid=789)):
            for metadata, owner, mode in (
                (root_metadata, "CONFIGURED", "CONFIGURED"),
                (service_metadata, "CONFIGURED", "CONFIGURED"),
                ([1, 2, 0o100600, 457, 789, 3], "FAILED", "CONFIGURED"),
                ([1, 2, 0o100600, 456, 790, 3], "FAILED", "CONFIGURED"),
                ([1, 2, 0o100640, 456, 789, 3], "CONFIGURED", "FAILED"),
                ([1, 2, 0o104600, 0, 0, 3], "CONFIGURED", "FAILED"),
            ):
                with self.subTest(metadata=metadata), patch.object(
                        installation, "metadata", return_value=("ACCESS RESTRICTED", metadata)):
                    rows = diagnostics.configuration(self.root)
                    sssd = rows["SSSD"]["sssd.conf"]
                    self.assertEqual((sssd["ownership"], sssd["permissions"]), (owner, mode))
                    if metadata == service_metadata:
                        self.assertEqual(rows["Samba"]["smb.conf"]["ownership"], "FAILED")
        with patch.object(diagnostics.pwd, "getpwnam", side_effect=KeyError):
            self.assertFalse(diagnostics.sssd_owner(456, 789))
        with patch.object(installation, "metadata", return_value=("ACCESS RESTRICTED", None)):
            sssd = diagnostics.configuration(self.root)["SSSD"]["sssd.conf"]
            self.assertEqual(sssd["metadata"], "ACCESS RESTRICTED")
            self.assertEqual(sssd["permissions"], "NOT TESTED")

    def test_inbound_rdp_policy_and_runtime_are_independent(self):
        for policy, expected in ((None, "NOT TESTED"), ({"enabled": False}, "OFF"),
                                 ({"enabled": True}, "ENABLE REQUESTED")):
            with self.subTest(policy=policy):
                self.assertEqual(diagnostics.inbound_rdp(policy), {
                    "product_capability": "DISABLED", "configured_policy": expected,
                    "qualified_backend": False, "runtime_state": "NOT TESTED",
                })

    def test_sssd_validator_counts_and_missing_unit_states(self):
        success = "Issues identified by validators: 0\nMessages generated during configuration merging: 0\n"
        for stdout, expected in ((success, "CONFIGURED"), (success.replace(": 0", ": 1"), "FAILED"),
                                 ("example.com", "FAILED")):
            run = Mock(return_value=subprocess.CompletedProcess([], 0, stdout, "example.com"))
            self.assertEqual(diagnostics.validate_sssd(run=run), expected)
        run = Mock(return_value=subprocess.CompletedProcess([], 1, "LoadState=not-found\n", ""))
        self.assertEqual(diagnostics.services(run=run)["sssd.service"],
                         {"unit": "UNAVAILABLE", "activity": "NOT TESTED"})

    def test_docker_query_is_local_read_only_and_redacted(self):
        self.file("usr/bin/docker", 0o755)
        endpoint = self.root / "run/docker.sock"
        endpoint.parent.mkdir()
        # Mock socket metadata; never open a listener.
        with patch.object(Path, "lstat", return_value=Mock(st_mode=0o140660)), patch(
                 "oe.diagnostics.os.access", side_effect=[True, False]):
            self.assertEqual(diagnostics.windows_runtime(root=self.root, query=True)["access"],
                             "ACCESS RESTRICTED")
        run = Mock(return_value=subprocess.CompletedProcess([], 0,
                   "dockurr/windows:latest\texited\ndockurr/windows:latest\trunning\nexample.com/image\trunning\n", ""))
        with patch.object(Path, "lstat", return_value=Mock(st_mode=0o140660)), patch(
                "oe.diagnostics.os.access", return_value=True):
            result = diagnostics.windows_runtime(root=self.root, query=True, run=run)
        self.assertEqual(result["containers"], ["RUNNING", "STOPPED"])
        self.assertEqual(result["restart_policy"], "UNKNOWN")
        self.assertEqual(result["desired_start_policy"], "MANUAL START ONLY")
        self.assertIn("ls", run.call_args.args[0])
        self.assertNotIn("inspect", run.call_args.args[0])
        self.assertNotIn("example.com", json.dumps(result))

    def test_desktop_entry_points_with_mock_dialogs(self):
        wizard_dialog = Mock()
        wizard_dialog.choose.side_effect = ["standalone", "skip", "skip"]
        with patch("oe.graphical.Dialog", return_value=wizard_dialog):
            self.assertEqual(wizard.run(self.root, dry_run=True), 0)
        wizard_dialog.report.assert_any_call("Selected target: CLEAN INSTALLATION")
        self.assertEqual(list(self.root.iterdir()), [])
        console_dialog = Mock()
        console_dialog.choose.side_effect = ["installation-review", "legacy-preview", "windows-status",
                                             "file-servers-manager", "remote-desktop", None]
        with patch("oe.graphical.Dialog", return_value=console_dialog), patch(
                "oe.__main__.refresh", return_value={}), patch("oe.graphical.reference_available",
                return_value=False), patch("oe.graphical.migration_preview") as preview, patch(
                "oe.installation.review", return_value={"workflow": "LEGACY ENTERPRISE"}), patch(
                "oe.pilot_session.manager") as file_manager, patch("oe.diagnostics.report",
                return_value={"windows_runtime": {"desired_start_policy": "MANUAL START ONLY"}}):
            self.assertEqual(desktop_console(Store(self.root / "state")), 0)
        preview.assert_called_once_with(console_dialog)
        file_manager.assert_called_once()
        for filename, command in (("omarchy-enterprise", "desktop"),
                                  ("omarchy-enterprise-installer", "provision-wizard")):
            entry = (Path(__file__).resolve().parents[1] / "templates" / (filename + ".desktop")).read_text()
            self.assertIn("Exec=/usr/bin/omarchy-enterprise " + command, entry)
            self.assertEqual(parser().parse_args([command]).command, command)
