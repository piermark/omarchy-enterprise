# SPDX-License-Identifier: MIT
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from oe import policy, state, windows
from oe.__main__ import refresh

ROOT = Path(__file__).resolve().parents[1]
POLICY = json.loads((ROOT / "templates/smb-policy.json").read_text(encoding="utf-8"))
SOURCE_REVIEW = ROOT / "tools/reviewed-source.py"


class PolicyTest(unittest.TestCase):
    def test_group_assignment_and_removal(self):
        self.assertEqual(policy.shares(POLICY, {"employees@example.com"}),
                         {"Team documents": "smb://files.example.com/documents"})
        self.assertEqual(policy.shares(POLICY, {"employees"}), {})
        self.assertEqual(policy.shares(POLICY, set()), {})

    def test_rejects_noncanonical_uris(self):
        for uri in ("file:///share", "smb://example.com:445/share",
                    "smb://example.com/share?query", "smb://example.com/../share",
                    "smb://example.com/share\n", "smb://person@example.com/share"):
            with self.subTest(uri=uri), self.assertRaises(ValueError):
                policy.shares({"version": 1, "shares": [POLICY["shares"][0] | {"uri": uri}]}, set())


class StateTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.store = state.Store(self.root / "state")

    def test_interrupted_commit_is_recoverable(self):
        real_write = state.write

        def interrupt(path, content):
            if path.name == "resources.json":
                raise OSError("synthetic interruption")
            real_write(path, content)

        with self.store.locked():
            updates = {"profile.json": "profile", "resources.json": "resources"}
            with patch.object(state, "write", side_effect=interrupt), self.assertRaises(OSError):
                self.store.change(**updates)
            self.assertEqual(self.store.snapshot()["profile.json"], "profile")
            self.assertTrue(self.store.recover())
            self.assertEqual(self.store.snapshot(), updates)
            self.assertFalse(self.store.recover())
            self.assertTrue(self.store.rollback())
            self.assertEqual(self.store.snapshot(), state.Store.empty)

    def test_idempotency_and_conflict_detection(self):
        with self.store.locked():
            self.store.change(**{"profile.json": "original"})
            history = self.store.history()
            self.store.change(**{"profile.json": "original"})
            self.assertEqual(self.store.history(), history)
            (self.store.directory / "profile.json").write_text("edited", encoding="utf-8")
            with self.assertRaises(ValueError):
                self.store.rollback()
            self.assertEqual(self.store.snapshot()["profile.json"], "edited")

    def test_policy_refresh_replaces_only_managed_resources(self):
        source = self.root / "policy.json"
        source.write_text(json.dumps(POLICY), encoding="utf-8")
        personal = self.root / "bookmarks"
        personal.write_text("personal", encoding="utf-8")
        with patch("oe.policy.effective_groups", return_value={"employees@example.com"}):
            self.assertIn("Team documents", refresh(self.store, source))
        with patch("oe.policy.effective_groups", return_value=set()):
            self.assertEqual(refresh(self.store, source), {})
        self.assertEqual(json.loads(self.store.snapshot()["resources.json"]), {})
        self.assertEqual(personal.read_text(encoding="utf-8"), "personal")

    def test_symlink_is_rejected(self):
        personal = self.root / "personal.txt"
        personal.write_text("personal", encoding="utf-8")
        with self.store.locked():
            (self.store.directory / "profile.json").symlink_to(personal)
            with self.assertRaises(ValueError):
                self.store.change(**{"profile.json": "replacement"})
        self.assertEqual(personal.read_text(encoding="utf-8"), "personal")


@unittest.skipIf(os.geteuid() == 0, "The CLI refuses root")
class CliTest(unittest.TestCase):
    setUp = StateTest.setUp

    def run_cli(self, *args):
        return subprocess.run(
            [ROOT / "bin/omarchy-enterprise", "--state-dir", self.store.directory, *args],
            cwd=self.root, capture_output=True, text=True, check=True)

    def test_dry_run_install_uninstall_rollback(self):
        result = self.run_cli("install", "--profile", "full-enterprise", "--domain",
                              "example.com", "--windows", "--dry-run")
        plan = json.loads(result.stdout)
        self.assertIn("windows", plan["planned_modules"])
        self.assertIn("active-directory", plan["planned_modules"])
        self.assertIn("audit", plan["planned_modules"])
        self.assertFalse(self.store.directory.exists())
        self.run_cli("install", "--profile", "standalone")
        self.run_cli("install", "--profile", "standalone")
        personal = self.store.directory / "personal.txt"
        personal.write_text("unchanged", encoding="utf-8")
        self.run_cli("uninstall", "--component", "profile")
        self.assertFalse((self.store.directory / "profile.json").exists())
        self.run_cli("rollback")
        self.assertTrue((self.store.directory / "profile.json").is_file())
        self.assertEqual(personal.read_text(encoding="utf-8"), "unchanged")


class WindowsTest(unittest.TestCase):
    def test_compose_plan_never_publishes_ports(self):
        image = "dockurr/windows@sha256:" + "0" * 64
        service = windows.compose(image, 4, 8, 128)["services"]["windows"]
        self.assertNotIn("ports", service)
        self.assertEqual(service["environment"]["RAM_SIZE"], "8G")
        self.assertEqual(service["volumes"], ["./windows:/storage"])
        with self.assertRaises(ValueError):
            windows.compose("dockurr/windows:latest", 4, 8, 128)

    @patch("oe.windows.shutil.which", return_value="/bin/xfreerdp3")
    def test_rdp_uses_interactive_nla_and_strict_certificate(self, _lookup):
        command = windows.rdp_command("windows.example.com", "employee@example.com", 3389)
        self.assertIn("/sec:nla", command)
        self.assertIn("/cert:deny", command)
        for option in ("/from-stdin:force", "/sound", "/microphone", "+clipboard", "/dynamic-resolution"):
            self.assertIn(option, command)
        self.assertFalse(any(argument.startswith("/p:") for argument in command))


class SourceReviewTest(unittest.TestCase):
    def test_only_exact_reviewed_bytes_can_be_exported(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "candidate.py"
            target = Path(directory) / "reviewed.py"
            source.write_text("# synthetic\n", encoding="utf-8")
            command = [sys.executable, SOURCE_REVIEW, source]
            digest = subprocess.check_output(command, text=True).strip()
            export = [*command, "--approved-sha256", digest, "--output", target]
            subprocess.run(export, capture_output=True, check=True)
            self.assertEqual(target.read_bytes(), source.read_bytes())
            self.assertNotEqual(subprocess.run(export, capture_output=True).returncode, 0)
            source.write_text("# changed\n", encoding="utf-8")
            target.unlink()
            self.assertNotEqual(subprocess.run(export, capture_output=True).returncode, 0)
            self.assertFalse(target.exists())
