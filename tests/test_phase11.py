"""Independent Phase 11 tests. All mutations target disposable fixtures."""

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import shutil
import unittest
from unittest.mock import patch

from oe import bookmarks, phase11_resources as resources, state
from oe.phase11 import Action, Request, Role, Workspace

SHARE = {"uri": "smb://files.example.com/team", "label": "Team", "groups": ["staff"]}
PUBLIC = {"uri": "smb://files.example.com/public", "label": "Public", "groups": []}
PRINTERS = {"printers": [{"name": "One", "uri": "ipp://one.example.com/ipp/print"},
                         {"name": "Two", "uri": "ipps://two.example.com/ipp/print"}],
            "default": "Two"}
VM = {"name": "Example", "cpu": 4, "ram_mib": 8192, "disk_gib": 64,
      "storage": "ExampleDisk", "network": "nat"}


def deployment(profile="standalone", **updates):
    return {"profile": profile, "shares": resources.EMPTY_SHARES,
            "capabilities": ["omarchy", "python", "directory-preview", "kerberos-preview",
                             "virtualization", "windows-license", "gvfs-smb", "cups"],
            "printers": resources.EMPTY_PRINTERS, "windows": None} | updates


class Phase11Test(unittest.TestCase):
    def setUp(self):
        self.workspace = Workspace.create()
        self.addCleanup(shutil.rmtree, self.workspace.directory)

    def preview(self, action, payload=None, role=Role.ADMIN):
        request = Request(action, role, payload if payload is not None else {})
        return request, self.workspace.plan(request)[0]

    def apply(self, action, payload=None, role=Role.ADMIN):
        request, preview = self.preview(action, payload, role)
        return self.workspace.apply(request, preview["approval"])

    def config(self, name):
        return self.workspace.status()["configuration"][name + ".json"]

    def test_each_profile_and_selected_optional_prerequisites(self):
        for profile in ("standalone", "active-directory", "full-enterprise"):
            with self.subTest(profile=profile):
                _, preview = self.preview(Action.DEPLOY, deployment(profile))
                self.assertEqual(preview["profile"], profile)
                self.assertEqual("directory-preview" in preview["prerequisites"], profile != "standalone")
                self.assertTrue(preview["ready"])
        request, preview = self.preview(Action.DEPLOY, deployment(
            "full-enterprise", windows=VM, printers=PRINTERS, capabilities=["omarchy", "python"]))
        self.assertFalse(preview["ready"])
        self.assertFalse(preview["prerequisites"]["windows-license"])
        self.assertFalse(preview["prerequisites"]["cups"])
        self.assertIsNone(preview["approval"])
        with self.assertRaises(ValueError):
            self.workspace.apply(request, "0" * 64)

    def test_dry_run_is_read_only_and_identical_reapply_keeps_history(self):
        request, preview = self.preview(Action.DEPLOY, deployment())
        self.assertEqual({p.name for p in self.workspace.directory.iterdir()}, {"identity"})
        self.workspace.apply(request, preview["approval"])
        revision = self.workspace.history()
        _, preview = self.preview(Action.DEPLOY, deployment())
        self.assertEqual(preview["changes"], {})
        self.apply(Action.DEPLOY, deployment())
        self.assertEqual(self.workspace.history(), revision)

    def test_configuration_rolls_back_and_retains_unmanaged_data(self):
        self.apply(Action.DEPLOY, deployment())
        self.apply(Action.PRINTERS, PRINTERS)
        personal = self.workspace.directory / "personal"
        personal.write_text("fixture")
        self.apply(Action.ROLLBACK)
        self.assertEqual(self.config("cups"), resources.EMPTY_PRINTERS)
        self.apply(Action.ROLLBACK)
        self.assertIsNone(self.config("deployment"))
        self.assertEqual(personal.read_text(), "fixture")

    def fail_after_first_write(self):
        original = self.workspace.set_file

        def interrupt(name, content):
            original(name, content)
            raise OSError("synthetic interruption after a managed write")

        with patch.object(self.workspace, "set_file", side_effect=interrupt), self.assertRaises(OSError):
            self.apply(Action.DEPLOY, deployment(printers=PRINTERS))
        self.assertTrue(self.workspace.status()["recovery_pending"])

    def test_recovery_finishes_partial_deployment(self):
        self.fail_after_first_write()
        with self.assertRaises(ValueError):
            self.preview(Action.DEPLOY, deployment())
        self.apply(Action.RESUME)
        self.assertEqual(self.config("cups"), PRINTERS)
        self.assertFalse(self.workspace.status()["recovery_pending"])

    def test_recovery_abort_restores_pretransaction_state(self):
        self.fail_after_first_write()
        self.apply(Action.ABORT)
        self.assertEqual(self.workspace.snapshot(), self.workspace.empty)
        self.assertFalse(self.workspace.status()["recovery_pending"])

    def test_recovery_refuses_third_party_edit(self):
        self.fail_after_first_write()
        state.write(self.workspace.directory / "cups.json", "{}")
        with self.assertRaisesRegex(ValueError, "during recovery"):
            self.apply(Action.RESUME)
        self.assertTrue(self.workspace.status()["recovery_pending"])

    def test_role_matrix_and_confused_approval_fail_closed(self):
        for action in Action:
            with self.subTest(action=action):
                with self.assertRaises(PermissionError):
                    Request(action, Role.VIEWER, {}).authorize()
                Request(action, Role.ADMIN, {}).authorize()
        with self.assertRaises(PermissionError):
            Request(Action.PRINTERS, Role.OPERATOR, {}).authorize()
        Request(Action.LOGIN_SYNC, Role.OPERATOR, {"groups": []}).authorize()
        request, preview = self.preview(Action.PRINTERS, PRINTERS, Role.VIEWER)
        self.assertFalse(preview["authorized"])
        with self.assertRaises(PermissionError):
            self.workspace.apply(request, "0" * 64)
        request, preview = self.preview(Action.PRINTERS, PRINTERS)
        for invalid in ("é", None, "0" * 64):
            with self.assertRaises(ValueError):
                self.workspace.apply(request, invalid)

    def test_approval_binds_payload_target_and_revision(self):
        request, preview = self.preview(Action.PRINTERS, PRINTERS)
        other = Workspace.create()
        self.addCleanup(shutil.rmtree, other.directory)
        with self.assertRaises(ValueError):
            other.apply(request, preview["approval"])
        with self.assertRaises(ValueError):
            self.workspace.apply(Request(Action.PRINTERS, Role.ADMIN, resources.EMPTY_PRINTERS),
                                 preview["approval"])
        self.apply(Action.DEPLOY, deployment())
        with self.assertRaises(ValueError):
            self.workspace.apply(request, preview["approval"])

    def test_concurrent_approvals_have_one_winner(self):
        request, preview = self.preview(Action.PRINTERS, PRINTERS)

        def run():
            try:
                return Workspace(self.workspace.directory).apply(request, preview["approval"])
            except ValueError:
                return False

        with ThreadPoolExecutor(2) as executor:
            self.assertEqual(sorted(executor.map(lambda _: run(), range(2))), [False, True])

    def test_windows_identity_manual_start_and_safe_lifecycle(self):
        self.apply(Action.DEPLOY, deployment("full-enterprise", windows=VM))
        vm = self.config("windows")
        self.assertEqual(vm["status"], "stopped")
        self.assertEqual(vm["definition"]["start_policy"], "manual")
        self.assertEqual(vm["definition"]["published_ports"], [])
        self.assertFalse(vm["definition"]["inbound_rdp"])
        with self.assertRaises(ValueError):
            self.preview(Action.START, {"identity": "wrong"}, Role.OPERATOR)
        with patch("subprocess.run", side_effect=AssertionError("host backend invoked")):
            self.apply(Action.START, {"identity": vm["identity"]}, Role.OPERATOR)
            self.assertEqual(self.config("windows")["status"], "running")
            with self.assertRaises(ValueError):
                self.preview(Action.WINDOWS, VM | {"cpu": 8})
            self.apply(Action.STOP, {"identity": vm["identity"]}, Role.OPERATOR)
        self.assertEqual(self.config("windows")["status"], "stopped")

    def test_windows_config_rollback_preserves_disk_fixture(self):
        self.apply(Action.DEPLOY, deployment("full-enterprise", windows=VM))
        disk = self.workspace.directory / "example.disk"
        disk.write_bytes(b"synthetic")
        identity = self.config("windows")["identity"]
        self.apply(Action.WINDOWS, VM | {"cpu": 8, "ram_mib": 16384, "network": "isolated"})
        self.assertEqual(self.config("windows")["identity"], identity)
        with self.assertRaises(ValueError):
            self.preview(Action.WINDOWS, VM | {"disk_gib": 128})
        with self.assertRaises(ValueError):
            self.preview(Action.WINDOWS, VM | {"storage": ".."})
        self.apply(Action.ROLLBACK)
        self.assertEqual(self.config("windows")["definition"]["cpu"], 4)
        self.apply(Action.ROLLBACK)
        self.assertIsNone(self.config("windows"))
        self.assertEqual(disk.read_bytes(), b"synthetic")

    def test_multiple_queues_default_and_validation_without_host_cups(self):
        with patch("subprocess.run", side_effect=AssertionError("CUPS host command invoked")):
            self.apply(Action.PRINTERS, PRINTERS)
            self.assertEqual(self.config("cups"), PRINTERS)
            for invalid in (PRINTERS | {"default": "Unknown"},
                            PRINTERS | {"printers": PRINTERS["printers"] * 2},
                            {"printers": [{"name": "One", "uri": "ipp://print.invalid/ipp/print"}],
                             "default": "One"}):
                with self.assertRaises(ValueError):
                    self.preview(Action.PRINTERS, invalid)
            self.apply(Action.PRINTERS, PRINTERS | {"default": "One"})
            self.assertEqual(self.config("cups")["default"], "One")

    def test_group_filtered_login_sync_and_selective_bookmark_rollback(self):
        for share in (SHARE, PUBLIC):
            self.apply(Action.SHARE_EDIT, {"target": None, "replacement": share})
        policy = self.config("shares")
        self.assertEqual(len(policy["shares"]), 2)
        book, _ = bookmarks.locations(self.workspace.directory)
        book.parent.mkdir()
        personal = "smb://files.example.com/public Personal public\n"
        book.write_text(personal)
        request, preview = self.preview(Action.LOGIN_SYNC, {"groups": []}, Role.OPERATOR)
        self.assertEqual(preview["authorized_shares"], {"Public": PUBLIC["uri"]})
        self.workspace.apply(request, preview["approval"])
        self.apply(Action.LOGIN_SYNC, {"groups": ["staff"]}, Role.OPERATOR)
        self.assertIn("Team", book.read_text())
        extra = "file:///example Personal edit\n"
        with book.open("a") as output:
            output.write(extra)
        self.apply(Action.BOOKMARK_ROLLBACK, role=Role.OPERATOR)
        self.assertEqual(book.read_text(), personal + extra)
        self.assertEqual(self.config("shares"), policy)

    def test_pending_bookmark_write_requires_explicit_recovery(self):
        self.apply(Action.SHARE_EDIT, {"target": None, "replacement": PUBLIC})
        original = state.write

        def interrupt(path, *args, **kwargs):
            if path.name == "managed.json":
                raise OSError("synthetic bookmark interruption")
            return original(path, *args, **kwargs)

        with patch("oe.state.write", side_effect=interrupt), self.assertRaises(OSError):
            self.apply(Action.LOGIN_SYNC, {"groups": []}, Role.OPERATOR)
        self.assertTrue(self.workspace.status()["bookmark_recovery_pending"])
        self.apply(Action.BOOKMARK_RECOVER, role=Role.OPERATOR)
        self.assertEqual(self.workspace.status()["managed_bookmarks"], 1)
        self.apply(Action.BOOKMARK_ROLLBACK, role=Role.OPERATOR)
        self.assertEqual(self.workspace.status()["managed_bookmarks"], 0)

    def test_recovery_discards_checkpoint_from_write_before_journal(self):
        self.apply(Action.SHARE_EDIT, {"target": None, "replacement": PUBLIC})
        original = state.write

        def interrupt(path, *args, **kwargs):
            if path.name == "pending.json":
                raise OSError("synthetic interruption before bookmark journal")
            return original(path, *args, **kwargs)

        with patch("oe.state.write", side_effect=interrupt), self.assertRaises(OSError):
            self.apply(Action.LOGIN_SYNC, {"groups": []}, Role.OPERATOR)
        self.assertTrue(self.workspace.status()["bookmark_recovery_pending"])
        self.apply(Action.BOOKMARK_RECOVER, role=Role.OPERATOR)
        self.assertFalse(self.workspace.status()["bookmark_recovery_pending"])
        self.apply(Action.LOGIN_SYNC, {"groups": []}, Role.OPERATOR)
        self.assertEqual(self.workspace.status()["managed_bookmarks"], 1)

    def test_target_and_endpoints_fail_closed(self):
        with self.assertRaises(ValueError):
            Workspace(Path("/"))
        with self.assertRaises(ValueError):
            self.preview(Action.SHARE_EDIT, {"target": None,
                         "replacement": SHARE | {"uri": "smb://user@files.example.com/team"}})
        state_file = self.workspace.directory / "shares.json"
        state_file.symlink_to("/dev/null")
        with self.assertRaises(ValueError):
            self.preview(Action.DEPLOY, deployment())
