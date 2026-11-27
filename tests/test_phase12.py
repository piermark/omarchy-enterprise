# SPDX-License-Identifier: MIT
"""Independent tests for the operational boundary, using synthetic inputs."""

import argparse
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from oe import bookmarks, operational as op, operational_cli, operational_cups as cups
from oe import operational_windows as vm, pilot_session


SHARES = {"version": 2, "shares": [
    {"label": "Team", "uri": "smb://files.example.com/team", "groups": ["staff"]},
    {"label": "Public", "uri": "smb://archive.example.com/", "groups": []},
]}
IMAGE = "dockurr/windows@sha256:" + "a" * 64
IDENTITY = "b" * 64
PRINTERS = {"printers": [{"name": "oe-example", "uri": "ipps://print.example.com/ipp/print"},
                         {"name": "oe-second", "uri": "ipp://second.example.com/ipp/print"}],
            "default": "oe-example"}


class DeploymentTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.store = op.Deployment(self.root)
        self.files = op.document("standalone", False, SHARES)
        self.packages = {"omarchy": True}

    def token(self, files=None):
        return op.approved(self.store.review(files or self.files, self.packages))

    def test_read_only_preview_and_rollback(self):
        token = self.token()
        self.assertEqual(list(self.root.iterdir()), [])
        self.store.transaction(self.files, self.packages, token)
        self.assertEqual(self.store.snapshot(), self.files)
        self.assertEqual(self.store.directory.stat().st_mode & 0o777, 0o700)
        self.assertTrue(self.store.rollback())
        self.assertEqual(self.store.snapshot(), self.store.empty)

    def test_unmanaged_and_edited_files_conflict(self):
        path = self.store.file_path("profile.json")
        path.parent.mkdir(parents=True)
        path.write_text(self.files["profile.json"])
        path.chmod(0o644)
        with self.assertRaisesRegex(ValueError, "Unmanaged"):
            self.token()
        path.unlink()
        self.store.transaction(self.files, self.packages, self.token())
        path.write_text("external update")
        with self.assertRaisesRegex(ValueError, "External"):
            self.store.rollback()
        self.assertEqual(path.read_text(), "external update")

    def test_pending_resume_and_abort(self):
        token = self.token()
        original = self.store.set_file

        def interrupted(name, content):
            if name == "profile.json":
                raise OSError("fixture interruption")
            original(name, content)

        with patch.object(self.store, "set_file", side_effect=interrupted):
            with self.assertRaises(OSError):
                self.store.transaction(self.files, self.packages, token)
        self.assertTrue(self.store.journal.exists())
        self.assertTrue(self.store.recover(abort=True))
        self.assertEqual(self.store.snapshot(), self.store.empty)
        with patch.object(self.store, "set_file", side_effect=interrupted):
            with self.assertRaises(OSError):
                self.store.transaction(self.files, self.packages, self.token())
        self.assertTrue(self.store.recover())
        self.assertEqual(self.store.snapshot(), self.files)

    def test_stale_and_missing_approval(self):
        plan = self.store.review(self.files, self.packages)
        with self.assertRaisesRegex(ValueError, "expired"):
            op.approved(plan, op.approved(plan, now=100), now=401)
        with self.assertRaisesRegex(ValueError, "Explicit"):
            self.store.transaction(self.files, self.packages, None)
        with self.assertRaisesRegex(ValueError, "changed"):
            self.store.transaction(self.files, {"omarchy": False}, self.token())
        self.assertEqual(self.store.snapshot(), self.store.empty)

    def test_external_receipt_blocks_retries_and_wrong_identity(self):
        journal = op.ExternalJournal(self.root / "external", "windows")

        def interrupt(checkpoint):
            checkpoint({"status": "pending", "operation": "create"})
            raise OSError("fixture interruption")

        with self.assertRaises(OSError):
            journal.run(interrupt)
        self.assertEqual(journal.read()["operation"], "create")
        retry = Mock()
        with self.assertRaisesRegex(ValueError, "unresolved"):
            journal.run(retry)
        retry.assert_not_called()
        other = op.ExternalJournal(self.root / "external", "cups")
        self.assertIsNone(other.read())

    def test_bounded_runner(self):
        self.assertEqual(op.command(("/usr/bin/true",)), (0, ""))
        with self.assertRaisesRegex(ValueError, "time limit"):
            op.command(("/usr/bin/sleep", "1"), timeout=0.02)

    def test_package_discovery_and_admin_boundary(self):
        runner = Mock(return_value=(1, "unused"))
        report = op.dependencies("full-enterprise", True, runner)
        self.assertFalse(report["docker"])
        self.assertFalse(report["cups"])
        for call in runner.call_args_list:
            self.assertEqual(call.args[0][:3], ("/usr/bin/pacman", "-Q", "--"))
        with patch("oe.operational.os.getuid", return_value=1000), patch(
                "oe.operational.os.geteuid", return_value=0), patch("oe.operational_cli.read_document") as read:
            with self.assertRaisesRegex(ValueError, "administrator"):
                operational_cli.admin_action(argparse.Namespace(operation="deploy"))
            read.assert_not_called()

    def test_bookmarks_keep_personal_and_legacy_lines(self):
        config = self.root / "config"
        book, legacy = bookmarks.locations(config)
        _, ledger = bookmarks.locations(config, operational=True)
        self.assertNotEqual(legacy, ledger)
        book.parent.mkdir(parents=True)
        original = "file:///tmp/example Personal\nsmb://archive.example.com/ Legacy\n"
        book.write_text(original)
        eligible = {"Team": "smb://files.example.com/team",
                    "Public": "smb://archive.example.com/"}
        pilot_session.stage_bookmarks(eligible, config, (original, []), operational=True)
        self.assertEqual(book.read_text(), original + "smb://files.example.com/team Team\n")
        book.write_text(book.read_text() + "file:///tmp/later Later\n")
        pilot_session.rollback(config=config, operational=True, confirm=lambda _: True, quiet=True)
        self.assertEqual(book.read_text(), original + "file:///tmp/later Later\n")
        self.assertFalse(legacy.exists())

    def test_policy_groups_and_malformed_input(self):
        self.assertEqual(set(op.policy.shares(SHARES, {"staff"})), {"Team", "Public"})
        with self.assertRaises(ValueError):
            op.document("standalone", True, {"version": 2, "shares": [{"uri": "smb://invalid"}]})


class WindowsTests(unittest.TestCase):
    def setUp(self):
        self.runner = Mock(return_value=(0, IDENTITY))
        self.storage = {"filesystem": "btrfs", "available_bytes": 2**40, "nearest_parent_used": False}
        self.adapter = vm.Dockur(self.runner, probe=lambda _: dict(self.storage),
                                 empty=lambda _: True, device=lambda _: True)
        self.settings = vm.Settings(IMAGE, 4, 8, 64)

    def test_create_stays_stopped_and_pins_identity(self):
        review = self.adapter.create_plan(self.settings)
        args = review["command"]
        self.assertIn("never", args)
        self.assertIn("no", args)
        self.assertIn("none", args)
        self.assertIn("DISK_IO=threads", args)
        self.assertNotIn("--publish", args)
        self.runner.side_effect = [(0, ""), (0, IDENTITY), (0, IDENTITY)]
        checkpoint = Mock()
        result = self.adapter.create(self.settings, op.approved(review),
                                     checkpoint=checkpoint, authorize=lambda: None)
        self.assertEqual(result, IDENTITY)
        self.assertEqual(checkpoint.call_args.args[0]["identity"], IDENTITY)
        self.assertEqual(self.runner.call_count, 3)

    def test_existing_storage_and_missing_approval_are_preserved(self):
        self.adapter.empty = lambda _: False
        plan = self.adapter.create_plan(self.settings)
        with self.assertRaisesRegex(ValueError, "empty storage"):
            self.adapter.create(self.settings, op.approved(plan),
                                checkpoint=Mock(), authorize=lambda: None)
        with self.assertRaisesRegex(ValueError, "Explicit"):
            self.adapter.create(self.settings, None, checkpoint=Mock(), authorize=lambda: None)
        self.runner.assert_not_called()

    def test_managed_identity_and_graceful_stop(self):
        prefix = f"{IDENTITY} /{vm.NAME} phase12 no none 0 "
        self.runner.return_value = (0, prefix + "running")
        plan = self.adapter.lifecycle_plan(IDENTITY, "stop")
        self.assertEqual(plan["command"][-4:], ["stop", "--timeout", "120", IDENTITY])
        self.runner.side_effect = [(0, prefix + "running"), (0, IDENTITY), (0, prefix + "exited")]
        self.assertEqual(self.adapter.lifecycle(IDENTITY, "stop", op.approved(plan),
                         checkpoint=Mock(), authorize=lambda: None), "exited")
        with self.assertRaises(ValueError):
            self.adapter.status("--help")
        with self.assertRaises(ValueError):
            vm.Settings(IMAGE, True, 8, 64)

    def test_interruption_leaves_pending_record(self):
        plan = self.adapter.create_plan(self.settings)
        self.runner.side_effect = [(0, ""), (0, IDENTITY), (1, "")]
        checkpoint = Mock()
        with self.assertRaises(ValueError):
            self.adapter.create(self.settings, op.approved(plan), checkpoint=checkpoint,
                                authorize=lambda: None)
        self.assertEqual(checkpoint.call_args.args[0]["status"], "pending")


class CupsTests(unittest.TestCase):
    def setUp(self):
        self.created = ["Existing"]
        self.default = "Existing"
        self.commands = []
        self.markers = {}
        self.adapter = cups.Cups(self.runner)

    def runner(self, command):
        if command[0] == cups.STAT[0]:
            if "-p" in command:
                return 0, f"    Description: {self.markers.get(command[-1], '')}"
            if "-o" in command or "-c" in command:
                return 0, ""
            return 0, {"-r": "scheduler is running", "-d": f"system default destination: {self.default}",
                       "-v": "\n".join(f"device for {name}: ipp://print.example.com/ipp/print"
                                       for name in self.created)}[command[-1]]
        self.commands.append(command)
        if command[3] == "-p":
            self.created.append(command[4])
            self.markers[command[4]] = command[-1]
        elif command[3] == "-x":
            self.created.remove(command[4])
        else:
            self.default = command[4]
        return 0, ""

    def test_driverless_approval_default_and_rollback_review(self):
        plan = self.adapter.review(PRINTERS)
        self.assertFalse(self.commands)
        checkpoint = Mock()
        result = self.adapter.execute(PRINTERS, op.approved(plan), checkpoint=checkpoint,
                                      exclusive_administration=lambda: None)
        self.assertEqual(result, ["oe-example", "oe-second"])
        self.assertEqual(self.default, "oe-example")
        rollback = self.adapter.rollback_plan(checkpoint.call_args.args[0])
        self.assertEqual(rollback["commands"][0][-2:], ["-d", "Existing"])
        self.assertEqual([cmd[-1] for cmd in rollback["commands"][1:]], result)
        with tempfile.TemporaryDirectory() as temporary:
            journal = op.ExternalJournal(Path(temporary) / "external", "cups")
            journal.run(lambda record: record(checkpoint.call_args.args[0]))
            with patch("oe.operational.administrator"):
                self.adapter.rollback(op.approved(rollback), journal,
                                      exclusive_administration=lambda: None)
            self.assertEqual(self.created, ["Existing"])
            self.assertEqual(self.default, "Existing")
            self.assertEqual(journal.read()["operation"], "rollback")
        self.assertNotIn((*cups.ADMIN, "-x", "Existing"), self.commands)

    def test_existing_queue_malformed_uri_and_isolation(self):
        self.created.append("OE-EXAMPLE")
        with self.assertRaisesRegex(ValueError, "conflicts"):
            self.adapter.review(PRINTERS)
        with self.assertRaises(ValueError):
            cups.validate({"printers": [{"name": "oe-test",
                           "uri": "ipp://print.example.com/ipp/test?unsafe=1"}], "default": None})
        with self.assertRaises(PermissionError):
            self.adapter.execute(PRINTERS, None, checkpoint=Mock(),
                                 exclusive_administration=Mock(side_effect=PermissionError))
        self.assertFalse(self.commands)


class RoutingTests(unittest.TestCase):
    def test_main_cli_and_gtk_routes(self):
        from oe.__main__ import parser
        args = parser().parse_args(["operational", "dependencies", "standalone"])
        self.assertEqual(args.operation, "dependencies")
        base = Path(__file__).resolve().parents[1] / "oe/control_center"
        self.assertIn("operational.panel(self)", (base / "app.py").read_text())
        panel = (base / "operational.py").read_text()
        self.assertIn("Gtk.Expander", panel)
        self.assertNotIn(".execute(", panel)
        self.assertNotIn(".lifecycle(", panel)
