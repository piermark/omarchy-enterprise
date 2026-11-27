# SPDX-License-Identifier: MIT
import json
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from oe import bookmarks, pilot_session, provision, state, status


class IndependentProductTest(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def test_bookmark_ledger_write_failure_recovers_without_claiming_personal_entry(self):
        config = self.root / "user"
        book, ledger = bookmarks.locations(config)
        book.parent.mkdir(parents=True)
        personal = "smb://files02.example.com/public My bookmark\n"
        book.write_text(personal)
        desired = {"Shared": "smb://files01.example.com/shared",
                   "Other": "smb://files02.example.com/public"}
        write = state.write

        def fail_ledger(path, *args, **kwargs):
            if path.name == "managed.json":
                raise OSError("synthetic interruption")
            return write(path, *args, **kwargs)

        with patch("oe.bookmarks.state.write", side_effect=fail_ledger), self.assertRaises(OSError):
            bookmarks.update(desired, config)
        self.assertTrue((ledger / "pending.json").is_file())
        book.write_text(book.read_text() + "file:///example Personal\n")
        with self.assertRaisesRegex(ValueError, "interrupted"):
            bookmarks.update(desired, config)
        self.assertIn("Personal", book.read_text())
        book.write_text(book.read_text().replace("file:///example Personal\n", ""))
        bookmarks.update(desired, config)
        self.assertFalse((ledger / "pending.json").exists())
        bookmarks.update({}, config)
        self.assertEqual(book.read_text(), personal)

    def test_image_preview_rejects_stale_confirmation_and_doctor_is_redacted(self):
        target = provision.ImageStore(self.root)
        before = (target.history(),)
        files = provision.render("standalone", printer="printer.example.com", file_servers={
            "version": 2, "shares": [{"label": "Shared", "uri": "smb://files.example.com/shared", "groups": []}],
        })
        provision.mutate(self.root, "apply", files)
        with self.assertRaisesRegex(ValueError, "changed since preview"):
            provision.mutate(self.root, "apply", provision.render("standalone"), expected_history=before)
        with patch("subprocess.run") as run:
            result = status.image_summary(self.root)
        run.assert_not_called()
        self.assertEqual(result["transaction"], "CONSISTENT")
        self.assertEqual(result["rollback"], "AVAILABLE")
        self.assertEqual(result["printer_monitor"], "VALID STAGED HOST")
        self.assertEqual(result["file_servers"], "VALID STAGED POLICY")
        self.assertEqual(result["services"], "NOT TESTED")
        self.assertNotIn("example.com", json.dumps(result))

    def test_selective_remove_rolls_back_and_preserves_unrelated_file(self):
        marker = self.root / "personal.txt"
        marker.write_text("preserve")
        files = provision.render("standalone", printer="printer.example.com")
        provision.mutate(self.root, "apply", files)
        target = provision.ImageStore(self.root)
        revision = target.history()
        provision.mutate(self.root, "apply", files)
        self.assertEqual(revision, target.history())
        provision.mutate(self.root, "remove", component="printer")
        self.assertIsNone(target.snapshot()["printer-monitor-host"])
        self.assertEqual(target.snapshot()["profile.json"], files["profile.json"])
        provision.mutate(self.root, "rollback")
        self.assertEqual(target.snapshot(), files)
        provision.mutate(self.root, "remove")
        self.assertEqual(target.snapshot(), target.empty)
        self.assertEqual(marker.read_text(), "preserve")

    def test_selective_bookmark_rollback_retries_after_interruption(self):
        config = self.root / "user"
        old = "smb://files01.example.com/shared"
        new = "smb://files02.example.com/shared"
        bookmarks.update({"Shared": old}, config)
        book, ledger = bookmarks.locations(config)
        original, managed = bookmarks.snapshot(book, ledger)
        desired = bookmarks.merge(original, managed, {"Shared": new})[1]
        state.write(ledger / pilot_session.BACKUP, json.dumps({"restore": managed, "expected": desired}))
        bookmarks.update({"Shared": new}, config)
        with book.open("a") as stream:
            stream.write("file:///example Personal\n")
        write = state.write

        def fail_ledger(path, *args, **kwargs):
            if path.name == "managed.json":
                raise OSError("synthetic interruption")
            return write(path, *args, **kwargs)

        with patch("oe.pilot_session.approved", return_value=True):
            with patch("oe.bookmarks.state.write", side_effect=fail_ledger), self.assertRaises(OSError):
                pilot_session.rollback(config=config)
            self.assertEqual(pilot_session.rollback(config=config), 0)
        self.assertEqual(book.read_text(), "file:///example Personal\n" + f"{old} Shared\n")
        self.assertFalse((ledger / pilot_session.BACKUP).exists())

    def test_service_state_probes_are_bounded_and_redact_unexpected_results(self):
        with patch("subprocess.run", side_effect=[
            subprocess.CompletedProcess([], 0, "active\n"),
            subprocess.CompletedProcess([], 0, "unexpected.example.com\n"),
            subprocess.TimeoutExpired([], 2),
            subprocess.CompletedProcess([], 1, "failed\n"),
        ]) as run:
            result = status.service_status(run=run)
        self.assertEqual(result, dict(zip(status.UNITS, ("active", "UNKNOWN", "UNKNOWN", "UNKNOWN"))))
        for call, unit in zip(run.call_args_list, status.UNITS, strict=True):
            self.assertEqual(call.args[0][-3:], ["--property=ActiveState", "--value", unit])
            self.assertEqual(call.kwargs["timeout"], 2)
            self.assertEqual(call.kwargs["stderr"], subprocess.DEVNULL)

    def test_selective_windows_uninstall_preserves_storage_and_compose_can_roll_back(self):
        image = "dockurr/windows@sha256:" + "0" * 64
        target = provision.ImageStore(self.root)
        base = self.root / provision.CONFIG / "windows"
        files = provision.render("full-enterprise", domain="example.com", workgroup="EXAMPLE",
                                 users="employees", admins="workstation-admins",
                                 image=image, windows_base=base)
        provision.mutate(self.root, "apply", files)
        disk = base / "windows/fixture.disk"
        disk.parent.mkdir()
        disk.write_text("synthetic disk")
        report = status.image_summary(self.root)
        self.assertEqual(report["windows_plan"], "MANUAL START")
        self.assertEqual(report["windows_storage"], "STAGED OPTIONS VALID; TARGET NOT TESTED")
        self.assertEqual(report["file_servers"], "VALID STAGED POLICY")
        provision.mutate(self.root, "remove", component="windows")
        self.assertIsNone(target.snapshot()["windows.compose.json"])
        self.assertFalse(json.loads(target.snapshot()["profile.json"])["windows"])
        self.assertEqual(disk.read_text(), "synthetic disk")
        provision.mutate(self.root, "rollback")
        self.assertEqual(target.snapshot(), files)
        self.assertEqual(disk.read_text(), "synthetic disk")
