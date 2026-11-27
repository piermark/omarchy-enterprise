# SPDX-License-Identifier: MIT
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from oe import provision, state, wizard

ROOT = Path(__file__).resolve().parents[1]
AD = dict(domain="example.com", workgroup="EXAMPLE", users="employees", admins="workstation-admins")
IMAGE = "dockurr/windows@sha256:" + "0" * 64


class ImageProvisionTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def test_all_profiles_upgrade_remove_and_rollback(self):
        standalone = provision.render("standalone", printer="printer.example.com")
        ad = provision.render("active-directory", **AD)
        full = provision.render("full-enterprise", image=IMAGE, **AD)
        path = self.root / "personal.txt"
        path.write_text("preserved")
        provision.mutate(self.root, "apply", standalone)
        self.assertTrue((self.root / "etc/omarchy-enterprise/printer-monitor-host").is_file())
        provision.mutate(self.root, "apply", ad)
        base = self.root / "etc/omarchy-enterprise"
        self.assertFalse((base / "printer-monitor-host").exists())
        self.assertEqual((base / "ad/sssd.conf").stat().st_mode & 0o777, 0o600)
        self.assertIn("employees@example.com", (base / "ad/sssd.conf").read_text())
        self.assertFalse((self.root / "etc/pam.d").exists())
        provision.mutate(self.root, "apply", full)
        journal = provision.ImageStore(self.root)
        history = journal.history()
        self.assertIn("sha256", (base / "windows/compose.json").read_text())
        self.assertTrue((self.root / "etc/audit/rules.d/55-omarchy-enterprise.rules").exists())
        provision.mutate(self.root, "apply", full)
        self.assertEqual(history, journal.history())
        provision.mutate(self.root, "remove")
        self.assertFalse((base / "ad/sssd.conf").exists())
        provision.mutate(self.root, "rollback")
        self.assertEqual(full, journal.snapshot())
        self.assertEqual(path.read_text(), "preserved")

    def test_abort_interrupted_profile_installation(self):
        store = provision.ImageStore(self.root)
        apply = store.set_file

        def interrupt(name, content):
            if name == "profile.json":
                raise OSError("synthetic failure")
            apply(name, content)

        with store.locked(), patch.object(store, "set_file", side_effect=interrupt):
            with self.assertRaises(OSError):
                store.change(**provision.render("active-directory", **AD))
        self.assertTrue(store.journal.exists())
        pending = store.journal.read_bytes()
        for action in ("remove", "rollback"):
            with self.subTest(action=action), self.assertRaisesRegex(ValueError, "pending transaction"):
                provision.mutate(self.root, action)
            self.assertEqual(store.journal.read_bytes(), pending)
        self.assertEqual(provision.mutate(self.root, "recover", abort=True), [])
        self.assertFalse(store.journal.exists())
        self.assertEqual(store.snapshot(), store.empty)

    def test_existing_and_symlinked_configuration_is_preserved(self):
        config = self.root / "etc/omarchy-enterprise"
        config.mkdir(parents=True)
        existing = config / "profile.json"
        existing.write_text("custom")
        existing.chmod(0o600)
        with self.assertRaises(ValueError):
            provision.mutate(self.root, "apply", provision.render("standalone"))
        self.assertEqual(existing.read_text(), "custom")
        outside = self.root / "outside"
        outside.mkdir()
        (config / "ad").symlink_to(outside)
        with self.assertRaises(ValueError):
            provision.mutate(self.root, "apply", provision.render("active-directory", **AD))
        self.assertEqual(list(outside.iterdir()), [])

    def test_gui_dry_run_and_confirmation(self):
        mock = Mock()
        mock.choose.return_value = "standalone"
        with patch("oe.wizard.graphical.Dialog", return_value=mock), patch("oe.wizard.provision.health", return_value={}):
            self.assertEqual(wizard.run(self.root, dry_run=True), 0)
            self.assertEqual(list(self.root.iterdir()), [])
            mock.show.return_value = None
            self.assertEqual(wizard.run(self.root), 0)
            self.assertEqual(list(self.root.iterdir()), [])
            mock.show.return_value = ""
            self.assertEqual(wizard.run(self.root), 0)
            self.assertTrue((self.root / "etc/omarchy-enterprise/profile.json").exists())

    def test_gui_printer_monitor_preview_and_apply(self):
        dialog = Mock()
        printer_file = self.root / "etc/omarchy-enterprise/printer-monitor-host"
        with (patch("oe.wizard.graphical.Dialog", return_value=dialog),
              patch("oe.wizard.provision.health", return_value={})):
            dialog.choose.side_effect = ["standalone", "skip", "monitor"]
            dialog.show.return_value = "Printer.Example.Com"
            self.assertEqual(wizard.run(self.root, dry_run=True), 0)
            self.assertIn("printer-monitor-host", dialog.report.call_args.args[0])
            self.assertFalse(printer_file.exists())

            dialog.choose.side_effect = ["standalone", "skip", "monitor"]
            dialog.show.return_value = "../invalid"
            with self.assertRaisesRegex(ValueError, "fully qualified"):
                wizard.run(self.root)
            self.assertFalse(printer_file.exists())

            dialog.choose.side_effect = ["standalone", "skip", "monitor"]
            dialog.show.side_effect = ["printer.example.com", ""]
            self.assertEqual(wizard.run(self.root), 0)
            self.assertEqual(printer_file.read_text(), "printer.example.com\n")

    @unittest.skipIf(os.geteuid() == 0, "Use an unprivileged user")
    def test_cli_applies_only_after_confirmation(self):
        arguments = [ROOT / "bin/omarchy-enterprise", "provision-image", "--root", self.root,
                     "apply", "--profile", "standalone"]
        for options in (["--dry-run"], []):
            result = subprocess.run(arguments + options, capture_output=True, stdin=subprocess.DEVNULL)
            self.assertEqual(result.returncode, 0 if options else 1)
            self.assertEqual(list(self.root.iterdir()), [])
        result = subprocess.run(arguments + ["--yes"], capture_output=True, check=True)
        self.assertIn(b"Transaction verified", result.stdout)

    def test_read_only_preview_shows_upgrade_and_removal(self):
        store = provision.ImageStore(self.root)
        initial = provision.render("standalone", printer="printer.example.com")
        self.assertEqual(store.plan(initial)["etc/omarchy-enterprise/profile.json"], "CREATE")
        self.assertEqual(list(self.root.iterdir()), [])
        provision.mutate(self.root, "apply", initial)
        upgraded = provision.render("active-directory", **AD)
        before = store.history()
        plan = store.plan(upgraded)
        self.assertEqual(plan["etc/omarchy-enterprise/profile.json"], "UPDATE")
        self.assertEqual(plan["etc/omarchy-enterprise/printer-monitor-host"], "REMOVE")
        self.assertEqual(plan["etc/omarchy-enterprise/ad/sssd.conf"], "CREATE")
        self.assertEqual(store.history(), before)
        provision.mutate(self.root, "remove")
        self.assertEqual(store.plan(upgraded)["etc/omarchy-enterprise/profile.json"], "CREATE")
        provision.mutate(self.root, "apply", upgraded)
        self.assertTrue(all(action == "UNCHANGED" for action in store.plan(upgraded).values()))

    def test_unmanaged_preview_conflict_never_reads_file(self):
        store = provision.ImageStore(self.root)
        path = self.root / "etc/omarchy-enterprise/profile.json"
        path.parent.mkdir(parents=True)
        path.write_text("synthetic unmanaged data")
        path.chmod(0o600)
        with patch("oe.provision.read") as read_file:
            plan = store.plan(provision.render("standalone"))
            self.assertEqual(plan["etc/omarchy-enterprise/profile.json"], "CONFLICT")
            read_file.assert_not_called()
        with patch("oe.state.read", wraps=state.read) as read_file:
            with self.assertRaisesRegex(ValueError, "Resolve provisioning conflicts"):
                provision.mutate(self.root, "apply", provision.render("standalone"))
            self.assertNotIn(path, [call.args[0] for call in read_file.call_args_list])
        self.assertEqual(path.read_text(), "synthetic unmanaged data")

    def test_preflight_handles_missing_os_metadata_and_dependencies(self):
        with (patch("oe.provision.platform.freedesktop_os_release", side_effect=OSError),
              patch("oe.provision.shutil.which", return_value=None),
              patch("oe.provision.os.access", return_value=False)):
            checks = provision.health("full-enterprise", True)
        for name in ("Arch-compatible operating system", "sssctl", "auditctl", "FreeRDP", "KVM device access"):
            self.assertFalse(checks[name])
