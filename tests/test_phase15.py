# SPDX-License-Identifier: MIT
"""Phase 15 regressions using temporary files and injected native adapters."""

import io
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from oe import bookmarks, bootstrap, operational, pilot_session
from oe import operational_cups as cups
from oe import operational_windows as windows
from oe import product


class BootstrapTests(unittest.TestCase):
    def test_supported_standalone_preflight_and_missing_dependencies(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "etc/omarchy").mkdir(parents=True)
            (root / "etc/os-release").write_text("ID=arch\n")
            (root / "etc/omarchy/version").write_text("4.5.0\n")
            run = Mock(side_effect=[(0, "btrfs rw"), (0, "ext4 rw"),
                                    (127, "python-gobject\n"),
                                    (1, "error: package 'omarchy-enterprise' was not found\n")])
            kwargs = {"run": run, "machine": lambda: "x86_64",
                      "disk": lambda _: SimpleNamespace(free=2**30)}
            self.assertEqual(bootstrap.preflight(root, **kwargs), (None, ["python-gobject"]))
            self.assertTrue({"docker", "samba", "sssd", "freerdp"}.isdisjoint(run.call_args_list[2].args[0]))
            run.side_effect = [(0, "ext4 ro")]
            with self.assertRaisesRegex(ValueError, "writable filesystem"):
                bootstrap.preflight(root, **kwargs)
            with self.assertRaisesRegex(ValueError, "x86_64"):
                bootstrap.preflight(root, **(kwargs | {"machine": lambda: "aarch64"}))

    def test_signature_pin_and_package_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            package, sig, keyring = (path / name for name in ("candidate", "candidate.sig", "release.gpg"))
            for file in (package, sig, keyring):
                file.write_bytes(b"fixture")
            fingerprint = "B" * 40
            status = f"[GNUPG:] VALIDSIG {'C' * 40} date epoch 0 4 0 1 8 00 {fingerprint}\n"
            metadata = f"{bootstrap.PACKAGE} {bootstrap.VERSION}\n"
            self.assertEqual(len(bootstrap.verify(package, keyring, fingerprint,
                                                 run=Mock(side_effect=[(0, status), (0, metadata)]))), 64)
            with self.assertRaisesRegex(ValueError, "authenticity"):
                bootstrap.verify(package, keyring, "D" * 40, run=Mock(return_value=(0, status)))
            with self.assertRaisesRegex(ValueError, "archive"):
                bootstrap.verify(package, keyring, fingerprint,
                                 run=Mock(side_effect=[(0, status), (0, "another 1-1")]))

    def test_consent_and_existing_candidate_handoff(self):
        args = ["--package", "/fixture", "--keyring", "/keyring", "--fingerprint", "B" * 40]
        with patch.multiple(bootstrap, preflight=Mock(return_value=(None, [])), verify=Mock()), \
             patch("oe.bootstrap.Path.resolve", lambda path, **_: path), \
             patch("sys.stdout", new_callable=io.StringIO) as out, patch("sys.stderr"), \
             patch("sys.stdin.isatty", return_value=True), patch("builtins.input", return_value="NO") as consent:
            self.assertEqual(bootstrap.main(args), 1)
            self.assertNotIn("pacman -U", out.getvalue())
            consent.return_value = "INSTALL"
            self.assertEqual(bootstrap.main(args), 0)
            self.assertIn("/usr/bin/pacman -U -- /fixture", out.getvalue())
            out.truncate(0)
            out.seek(0)
            consent.reset_mock()
            bootstrap.preflight.return_value = (bootstrap.VERSION, [])
            self.assertEqual(bootstrap.main(args), 0)
            self.assertIn("already installed", out.getvalue())
            consent.assert_not_called()


    def test_native_launch_and_interrupt(self):
        with patch.object(bootstrap, "preflight", return_value=(bootstrap.VERSION, [])), \
             patch("oe.bootstrap.os.getenv", return_value="fixture-display"), \
             patch("oe.bootstrap.os.execv", side_effect=KeyboardInterrupt) as launch, \
             patch("sys.stdout"), patch("sys.stderr"):
            self.assertEqual(bootstrap.main(["--launch"]), 130)
            launch.assert_called_once_with(bootstrap.INSTALLER[0], bootstrap.INSTALLER)
            self.assertIn("--native", bootstrap.INSTALLER)


class CupsUpdateTests(unittest.TestCase):
    name = "oe-demo"
    before = "ipps://old.example.com/ipp/print"
    after = "ipps://new.example.com/ipp/print"
    marker = "Omarchy Enterprise Phase 12 " + "0" * 32

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.journal = operational.ExternalJournal(Path(temporary.name) / "cups", "cups")
        self.receipt = {"status": "complete", "created": [self.name], "marker": self.marker,
                        "default": None, "previous_default": None}
        self.journal.run(lambda checkpoint: checkpoint(self.receipt))
        self.uri, self.jobs, self.calls = self.before, [], []
        self.partial = False
        self.adapter = cups.Cups(self.runner)

    def runner(self, arguments):
        tail = arguments[3:]
        if arguments[0] == cups.ADMIN[0]:
            self.calls.append(arguments)
            self.uri = tail[-1]
            return int(self.partial), ""
        return 0, {
            ("-r",): "scheduler is running",
            ("-c",): "",
            ("-v",): f"device for {self.name}: {self.uri}",
            ("-v", self.name): f"device for {self.name}: {self.uri}",
            ("-l", "-p", self.name): f"Description: {self.marker}",
            ("-W", "not-completed", "-o", self.name): "\n".join(self.jobs),
        }[tail]

    def apply(self, before, after, token, undo=False):
        with patch.object(operational, "administrator"):
            self.adapter.update(self.name, before, after, token, self.journal, undo=undo,
                                exclusive_administration=lambda: None)

    def test_update_and_selective_undo(self):
        plan = self.adapter.update_plan(self.receipt, self.name, self.before, self.after)
        with self.assertRaisesRegex(ValueError, "approval"):
            self.apply(self.before, self.after, "invalid")
        self.assertFalse(self.calls)
        self.apply(self.before, self.after, operational.approved(plan))
        self.assertEqual(self.uri, self.after)
        plan = self.adapter.update_plan(self.journal.read(), self.name, self.after, self.before, undo=True)
        self.apply(self.after, self.before, operational.approved(plan), undo=True)
        self.assertEqual(self.uri, self.before)
        self.assertEqual(self.journal.read(), self.receipt)

    def test_external_conflicts_and_interruption(self):
        plan = self.adapter.update_plan(self.receipt, self.name, self.before, self.after)
        self.jobs.append("waiting-job")
        with self.assertRaisesRegex(ValueError, "job state"):
            self.apply(self.before, self.after, operational.approved(plan))
        self.jobs.clear()
        self.marker = self.marker.replace("0", "1")
        with self.assertRaisesRegex(ValueError, "ownership"):
            self.apply(self.before, self.after, operational.approved(plan))
        self.marker = self.receipt["marker"]
        self.partial = True
        with self.assertRaisesRegex(ValueError, "partial"):
            self.apply(self.before, self.after, operational.approved(plan))
        self.assertEqual(self.journal.read()["status"], "pending")
        with self.assertRaisesRegex(ValueError, "unresolved"):
            self.apply(self.before, self.after, operational.approved(plan))
        self.assertEqual(len(self.calls), 1)
        recover = self.adapter.update_recovery_plan(self.journal.read())
        with patch.object(operational, "administrator"):
            self.adapter.recover_update(operational.approved(recover), self.journal,
                                        exclusive_administration=lambda: None)
        self.assertEqual(self.journal.read()["last_update"]["after"], self.after)
        self.assertEqual(len(self.calls), 1)


class OtherWorkflows(unittest.TestCase):
    def test_persistent_multiple_printer_definitions(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory)
            draft = product.PrinterDraft().edit("oe-a", "ipps://a.example.com/ipp/a")
            draft = draft.edit("oe-b", "ipp://b.example.com/ipp/b", default=True)
            product.printer_draft(config=config, save=draft)
            self.assertEqual(product.printer_draft(config=config).document(), draft.document())
            path = config / "omarchy-enterprise-printers/definitions.json"
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_bookmark_acceptance_rechecks_state_and_allows_selective_removal(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory)
            (config / "gtk-3.0").mkdir(mode=0o700)
            book, ledger = bookmarks.locations(config, operational=True)
            personal = "smb://personal.example.com/docs Personal\n"
            book.write_text(personal)
            initial = bookmarks.preview(config, operational=True)
            pilot_session.stage_bookmarks({"One": "smb://one.example.com/docs",
                                           "Two": "smb://two.example.com/docs"},
                                          config, initial, operational=True)
            accept = pilot_session.bookmark_acceptance(config=config)
            with book.open("a") as stream:
                stream.write("smb://other.example.com/docs Other\n")
            with self.assertRaisesRegex(ValueError, "changed"):
                accept()
            pilot_session.bookmark_acceptance(config=config)()
            self.assertFalse((ledger / pilot_session.BACKUP).exists())
            before = bookmarks.preview(config, operational=True)
            pilot_session.stage_bookmarks({"Two": "smb://two.example.com/docs"},
                                          config, before, operational=True)
            self.assertNotIn("smb://one.example.com", book.read_text())
            self.assertIn("smb://two.example.com", book.read_text())
            self.assertIn(personal, book.read_text())
            pilot_session.rollback(config=config, confirm=lambda _: True, quiet=True, operational=True)
            text, managed = bookmarks.preview(config, operational=True)
            self.assertEqual(managed, before[1])
            self.assertCountEqual(text.splitlines(), before[0].splitlines())
            self.assertEqual([line for line in text.splitlines(keepends=True) if line not in managed],
                             [line for line in before[0].splitlines(keepends=True) if line not in managed])

    @patch("oe.windows.client", return_value="/usr/bin/xfreerdp3")
    def test_guest_adapter_validates_client_flags(self, _client):
        with self.assertRaisesRegex(ValueError, "certificate"):
            windows.loopback_client("guest.example.com", "guest", 3390, supported_help="/sec:nla")
        command = windows.loopback_client("guest.example.com", "guest", 3390,
                                         supported_help="/sec:nla /server-name:DNS /cert:deny /from-stdin")
        self.assertEqual(command[0], "/usr/bin/xfreerdp3")
        self.assertEqual(command[1], "/v:127.0.0.1:3390")
        self.assertIn("/cert:deny", command)
        self.assertIn("/sec:nla", command)
        self.assertIn("/server-name:guest.example.com", command)
