# SPDX-License-Identifier: MIT
"""Targeted operational regressions using disposable state and injected adapters."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import importlib.util
import json
import os
from pathlib import Path
import sys
import stat
from tempfile import TemporaryDirectory
from threading import Event
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from oe import bookmarks, operational, operational_cli, pilot_session, state


LEGACY = {"Legacy": "smb://files.example.com/legacy"}
OPERATIONAL = {"Team": "smb://files.example.com/team"}
PERSONAL = "file:///example Personal\n"


class BookmarkTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.config = Path(temporary.name)
        self.book, self.legacy = bookmarks.locations(self.config)
        _, self.operational = bookmarks.locations(self.config, operational=True)
        self.book.parent.mkdir()
        self.book.write_text(PERSONAL)
        bookmarks.update(LEGACY, self.config)

    def stage(self):
        current = bookmarks.preview(self.config, operational=True)
        pilot_session.stage_bookmarks(OPERATIONAL, self.config, current, operational=True)

    def rollback(self):
        return pilot_session.rollback(config=self.config, operational=True,
                                      confirm=lambda _: True, quiet=True)

    def test_rollback_with_both_ledgers_and_other_pending(self):
        self.stage()
        original = self.book.read_text()
        legacy = bookmarks.snapshot(self.book, self.legacy)
        pending = state.Store(self.legacy).journal
        state.write(pending, json.dumps({"before": legacy, "after": legacy}))
        pending_text = pending.read_text()
        with self.assertRaisesRegex(ValueError, "other bookmark ledger"):
            self.rollback()
        self.assertEqual(pending.read_text(), pending_text)
        self.assertEqual(self.book.read_text(), original)
        bookmarks.preview(self.config)
        self.assertEqual(self.rollback(), 0)
        self.assertEqual(bookmarks.snapshot(self.book, self.legacy), (PERSONAL + legacy[1][0], legacy[1]))
        self.assertEqual(bookmarks.snapshot(self.book, self.operational)[1], [])

    def test_overlapping_resources_and_conflicting_ownership(self):
        uri = next(iter(LEGACY.values())).upper().replace("SMB:", "smb:")
        with self.assertRaisesRegex(ValueError, "managed by the other"):
            bookmarks.update({"Different": uri}, self.config, operational=True)
        current, managed = bookmarks.snapshot(self.book, self.legacy)
        state.write(self.operational / "managed.json", json.dumps(managed))
        for selected in (False, True):
            with self.subTest(operational=selected), self.assertRaisesRegex(ValueError, "Both"):
                bookmarks.update({}, self.config, operational=selected)
        self.assertEqual(self.book.read_text(), current)

    def test_recovery_rejects_peer_changes(self):
        self.stage()
        original, owned = bookmarks.snapshot(self.book, self.operational)
        pending = state.Store(self.operational).journal
        state.write(pending, json.dumps({"before": [original, owned],
                                        "after": [PERSONAL + owned[0], owned]}))
        with self.assertRaisesRegex(ValueError, "would change"):
            bookmarks.preview(self.config, operational=True)
        self.assertTrue(pending.exists())
        self.assertEqual(self.book.read_text(), original)

    def test_concurrent_overlap_serializes_on_shared_file(self):
        entered = Event()
        release = Event()
        contender = Event()

        def pause(*_):
            entered.set()
            if not release.wait(5):
                raise RuntimeError("Fixture synchronization timed out")

        def compete():
            contender.set()
            return bookmarks.update(OPERATIONAL, self.config)

        with ThreadPoolExecutor(2) as executor:
            first = executor.submit(bookmarks.update, OPERATIONAL, self.config,
                                    operational=True, before_write=pause)
            try:
                self.assertTrue(entered.wait(5))
                second = executor.submit(compete)
                self.assertTrue(contender.wait(5))
                self.assertFalse(second.done())
            finally:
                release.set()
            first.result(timeout=5)
            with self.assertRaisesRegex(ValueError, "managed by the other"):
                second.result(timeout=5)
        self.assertEqual(self.book.read_text().count(next(iter(OPERATIONAL.values()))), 1)

    def test_interruption_before_bookmark_journal_can_retire_checkpoint(self):
        before = self.book.read_text()
        write = state.write

        def interrupt(path, data, **kwargs):
            if path == self.operational / "pending.json":
                raise OSError("Fixture interruption")
            write(path, data, **kwargs)

        with patch.object(state, "write", side_effect=interrupt), self.assertRaises(OSError):
            self.stage()
        self.assertEqual(self.rollback(), 0)
        self.assertEqual(self.book.read_text(), before)
        self.assertFalse((self.operational / pilot_session.BACKUP).exists())
        self.assertEqual(len(list(self.operational.glob("pilot-retired-*.json"))), 1)

    def test_duplicate_managed_line_requires_review(self):
        original, managed = bookmarks.snapshot(self.book, self.legacy)
        self.book.write_text(original + managed[0])
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            bookmarks.update({}, self.config)
        self.assertEqual(self.book.read_text(), original + managed[0])


class DeploymentTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.store = operational.Deployment(self.root)
        self.a = self.files("standalone", "archive")
        self.b = self.files("active-directory", "team")
        self.packages = {"omarchy": True}

    @staticmethod
    def files(profile, share):
        return operational.document(profile, False, {"version": 2, "shares": [
            {"uri": f"smb://files.example.com/{share}", "label": "Example", "groups": []},
        ]})

    def deploy(self, files):
        token = operational.approved(self.store.review(files, self.packages))
        self.store.transaction(files, self.packages, token)

    def test_single_checkpoint_and_subsequent_deploy(self):
        self.deploy(self.a)
        self.deploy(self.b)
        self.assertTrue(self.store.rollback())
        self.assertEqual(self.store.snapshot(), self.a)
        self.assertFalse(self.store.rollback())
        self.assertFalse(operational_cli.recovery_plan(self.store, "rollback")["exists"])
        self.assertEqual(self.store.snapshot(), self.a)
        self.deploy(self.b)
        self.assertTrue(self.store.rollback())
        self.assertEqual(self.store.snapshot(), self.a)

    def interrupt_rollback(self):
        write = self.store.set_file

        def interrupt(name, content):
            if name == "profile.json":
                raise OSError("Fixture interruption")
            write(name, content)

        with patch.object(self.store, "set_file", side_effect=interrupt), self.assertRaises(OSError):
            self.store.rollback()
        self.assertEqual(self.store.snapshot(), self.b | {"file-servers.json": self.a["file-servers.json"]})

    def test_interrupted_rollback_abort_then_resume(self):
        self.deploy(self.a)
        self.deploy(self.b)
        self.interrupt_rollback()
        self.assertTrue(self.store.recover(abort=True))
        self.assertEqual(self.store.snapshot(), self.b)
        self.interrupt_rollback()
        self.assertTrue(self.store.recover())
        self.assertEqual(self.store.snapshot(), self.a)
        self.assertFalse(self.store.rollback())

    def test_legacy_empty_predecessor_requires_review(self):
        self.deploy(self.a)
        history = self.store.history()
        del history["checkpoint_version"]
        state.write(self.store.directory / "history.json", operational.encode(history))
        with self.assertRaisesRegex(ValueError, "ambiguous predecessor"):
            self.store.rollback()
        self.assertEqual(self.store.snapshot(), self.a)
        self.deploy(self.b)
        self.assertTrue(self.store.rollback())

    def test_bad_approval_leaves_no_directories(self):
        plan = self.store.review(self.a, self.packages)
        tokens = (None, "", "malformed", operational.approved(plan, now=1),
                  operational.approved(self.store.review(self.b, self.packages)))
        for token in tokens:
            with self.subTest(token=token), self.assertRaises(ValueError):
                self.store.transaction(self.a, self.packages, token)
            self.assertEqual(list(self.root.iterdir()), [])

    def test_dependency_plan_revalidated_under_lock(self):
        token = operational.approved(self.store.review(self.a, self.packages))

        def changed():
            self.assertTrue((self.store.directory / ".lock").exists())
            return {"omarchy": False}

        with self.assertRaisesRegex(ValueError, "changed"):
            self.store.transaction(self.a, self.packages, token, refresh_packages=changed)
        self.assertEqual(self.store.snapshot(), self.store.empty)
        self.assertFalse(self.store.journal.exists())

    def test_recovery_state_hashes_reject_stale_approval(self):
        self.deploy(self.a)
        self.deploy(self.b)
        self.interrupt_rollback()
        plan = operational_cli.recovery_plan(self.store, "recover")
        self.store.set_file("profile.json", self.a["profile.json"])
        changed = operational_cli.recovery_plan(self.store, "recover")
        self.assertEqual(plan["record_sha256"], changed["record_sha256"])
        self.assertNotEqual(plan["current_sha256"], changed["current_sha256"])
        with patch.object(operational, "administrator"), patch.object(
                operational, "Deployment", return_value=self.store):
            with self.assertRaisesRegex(ValueError, "changed"):
                operational_cli.admin_action(argparse.Namespace(
                    operation="recover", approve=operational.approved(plan)))
        self.assertTrue(self.store.journal.exists())
        self.store.set_file("profile.json", "External edit")
        for action in ("recover", "abort"):
            with self.assertRaisesRegex(ValueError, "changed during recovery"):
                operational_cli.recovery_plan(self.store, action)

    def test_rollback_preview_checks_current_managed_files(self):
        self.deploy(self.a)
        plan = operational_cli.recovery_plan(self.store, "rollback")
        self.assertEqual(plan["current_sha256"], operational.snapshot_hashes(self.a))
        self.store.set_file("profile.json", "External edit")
        with self.assertRaisesRegex(ValueError, "External change"):
            operational_cli.recovery_plan(self.store, "rollback")

    def test_unsafe_root_directory_and_managed_file(self):
        self.root.chmod(0o770)
        with self.assertRaisesRegex(ValueError, "Deployment root"):
            operational.Deployment(self.root)
        self.root.chmod(0o700)
        self.deploy(self.a)
        path = self.store.file_path("profile.json")
        actual_lstat = Path.lstat

        def wrong_owner(candidate):
            info = actual_lstat(candidate)
            if candidate != path:
                return info
            return SimpleNamespace(st_mode=info.st_mode, st_uid=os.geteuid() + 1,
                                   st_gid=info.st_gid, st_nlink=info.st_nlink)

        with patch.object(Path, "lstat", wrong_owner), self.assertRaisesRegex(ValueError, "ownership"):
            self.store.snapshot()
        path.chmod(0o600)
        with self.assertRaisesRegex(ValueError, "permissions"):
            self.store.snapshot()
        path.unlink()
        outside = self.root / "outside"
        outside.write_text("fixture")
        path.symlink_to(outside)
        with self.assertRaisesRegex(ValueError, "unsafe"):
            self.store.snapshot()
        self.assertEqual(outside.read_text(), "fixture")

    def test_unsafe_ledger_and_lock(self):
        self.deploy(self.a)
        original = self.store.directory
        original.chmod(stat.S_IRWXU | stat.S_IRGRP)
        with self.assertRaisesRegex(ValueError, "private"):
            operational_cli.recovery_plan(self.store, "rollback")
        original.chmod(0o700)
        lock = original / ".lock"
        lock.unlink()
        lock.symlink_to(original / "history.json")
        with self.assertRaisesRegex(ValueError, "unsafe"):
            self.deploy(self.b)
        self.assertEqual(self.store.snapshot(), self.a)


class StructuredFormTests(unittest.TestCase):
    def setUp(self):
        self.gtk = Mock()
        self.adw = Mock()
        self.gtk.DropDown.new_from_strings.side_effect = lambda _: Mock(get_selected=Mock(return_value=0))
        repository = SimpleNamespace(Gtk=self.gtk, Adw=self.adw, Pango=Mock())
        name = "oe.control_center.synthetic"
        source = Path(__file__).resolve().parents[1] / "oe/control_center/synthetic.py"
        spec = importlib.util.spec_from_file_location(name, source)
        self.form = importlib.util.module_from_spec(spec)
        with patch.dict(sys.modules, {"gi.repository": repository}):
            spec.loader.exec_module(self.form)

    def test_samples_are_independent_nested_copies(self):
        f = self.form
        sample = f.sample(f.Action.DEPLOY, "standalone")
        sample["shares"]["shares"].append({})
        sample["printers"]["printers"].append({})
        sample["capabilities"].clear()
        clean = f.sample(f.Action.DEPLOY, "standalone")
        self.assertEqual(clean["shares"]["shares"], [])
        self.assertEqual(clean["printers"]["printers"], [])
        self.assertEqual(clean["capabilities"], ["omarchy", "python"])
        f.sample(f.Action.WINDOWS, "standalone")["cpu"] = 99
        self.assertEqual(f.sample(f.Action.WINDOWS, "standalone")["cpu"], 4)

    def test_open_diagnostics_never_overrides_structured_review(self):
        f = self.form
        center = Mock(route="windows", dry_run=True, synthetic_target="/tmp/example",
                      setup=SimpleNamespace(profile="standalone"))
        rows = {}
        actions = {}
        advanced = self.gtk.Expander.return_value
        advanced.get_expanded.return_value = True

        def entry(_group, title, value, changed=None):
            rows[title] = (Mock(get_text=Mock(return_value=value)), changed)
            return rows[title][0]

        def button(title, callback, **_):
            actions[title] = callback
            return Mock()

        with patch.multiple(f, entry=entry, button=button, label=Mock(), _=lambda text: text):
            f.panel(center)
            cpu, changed = rows["Virtual CPUs"]
            cpu.get_text.return_value = "6"
            changed("6")
            buffer = self.gtk.TextView.return_value.get_buffer.return_value
            self.assertEqual(json.loads(buffer.set_text.call_args.args[0])["cpu"], 6)
            self.assertFalse(self.gtk.TextView.call_args.kwargs["editable"])
            buffer.get_text.return_value = '{"cpu":99}'
            actions["Preview synthetic action"]()
        work = center.work.call_args.args[0]
        with patch.object(f, "Workspace") as backend:
            backend.return_value.plan.return_value = ({},)
            work(None)
        request = backend.return_value.plan.call_args.args[0]
        self.assertEqual(request.payload["cpu"], 6)
        buffer.get_text.assert_not_called()
