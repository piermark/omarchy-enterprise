import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from oe import provision, windows, windows_storage

IMAGE = "dockurr/windows@sha256:" + "0" * 64
AD = dict(domain="example.com", workgroup="EXAMPLE", users="employees", admins="workstation-admins")


def response(output="", error="", status=0):
    return subprocess.CompletedProcess([], status, output, error)


class WindowsStorageTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    @patch("oe.windows_storage.run_probe", return_value=response("btrfs\n"))
    def test_missing_path_uses_existing_parent_without_creating_files(self, probe):
        from os import fstat

        def mount(binary, args, fd):
            self.assertEqual(binary, "/usr/bin/findmnt")
            self.assertEqual(fstat(fd).st_ino, self.root.stat().st_ino)
            return response("btrfs\n")

        probe.side_effect = mount
        result = windows_storage.inspect(self.root / "new" / "windows")
        self.assertTrue(result["nearest_parent_used"])
        self.assertEqual(result["filesystem"], "btrfs")
        self.assertGreaterEqual(result["available_bytes"], 0)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_invalid_paths_and_symlink_components_are_rejected(self):
        link = self.root / "link"
        link.symlink_to(self.root, target_is_directory=True)
        file = self.root / "ordinary"
        file.write_text("synthetic")
        for path in (link / "windows", file, "", ".", "/", self.root / ".." / "windows",
                     self.root / "new$variable", self.root / "invalid\nname"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                windows_storage.inspect(path)
        link.unlink()
        link.symlink_to(self.root / "absent")
        with self.assertRaises(ValueError):
            windows_storage.inspect(link)

    @patch("oe.windows_storage.run_probe")
    def test_btrfs_defaults_other_filesystems_and_unavailable_detector(self, probe):
        for result, expected in ((response("btrfs\n"), ("threads", "writeback")),
                                 (response("ext4\n"), (None, None)), (None, (None, None))):
            probe.return_value = result
            service = windows.compose(IMAGE, 4, 8, 128, storage=self.root / "windows")["services"]["windows"]
            env = service["environment"]
            self.assertEqual((env.get("DISK_IO"), env.get("DISK_CACHE")), expected)
            self.assertEqual(service["restart"], "no")
            self.assertEqual({key: env[key] for key in ("AUTOLOGIN", "WEB", "DISPLAY", "SAMBA")},
                             {"AUTOLOGIN": "N", "WEB": "N", "DISPLAY": "none", "SAMBA": "N"})
            self.assertFalse(service["volumes"][0]["bind"]["create_host_path"])
            self.assertNotIn("ports", service)

    @patch("oe.windows_storage.run_probe", return_value=response("btrfs"))
    def test_explicit_storage_and_startup_preferences_survive_reapplication(self, _probe):
        store = provision.ImageStore(self.root)
        paths = provision.render("full-enterprise", image=IMAGE, storage=self.root / "vm",
                                 disk_io="native", disk_cache="none", restart="unless-stopped", **AD)
        provision.mutate(self.root, "apply", paths)
        previous = store.windows_settings()
        rendered = provision.render("full-enterprise", image=IMAGE, existing_windows=previous, **AD)
        self.assertEqual(rendered["windows.compose.json"], paths["windows.compose.json"])
        self.assertTrue(all(action == "UNCHANGED" for action in store.plan(rendered).values()))
        previous.pop("restart")
        for name in ("DISK_IO", "DISK_CACHE"):
            previous["environment"].pop(name)
        previous["environment"].pop("AUTOLOGIN")
        old = windows.compose(IMAGE, 4, 8, 128, existing=previous)["services"]["windows"]
        self.assertNotIn("restart", old)
        self.assertNotIn("DISK_IO", old["environment"])
        self.assertNotIn("AUTOLOGIN", old["environment"])

    @patch("oe.windows_storage.inspect")
    def test_windows_remains_optional(self, inspect):
        for profile, settings in (("standalone", {}), ("active-directory", AD), ("full-enterprise", AD)):
            self.assertIsNone(provision.render(profile, **settings)["windows.compose.json"])
        with self.assertRaises(ValueError):
            provision.render("standalone", restart="always")
        inspect.assert_not_called()

    @patch("oe.windows_storage.run_probe")
    def test_historical_counters_redact_devices_and_never_reset(self, probe):
        probe.side_effect = [response("btrfs"), response(
            "[synthetic-private-device].corruption_errs 2\n[another-device].corruption_errs 3\n")]
        report = windows_storage.diagnostics(self.root, counters=True)
        self.assertEqual(report["btrfs_counters"]["totals"]["corruption_errs"], 5)
        self.assertIn("historical cumulative", report["btrfs_counters"]["status"])
        self.assertNotIn("synthetic-private-device", json.dumps(report))
        self.assertEqual(probe.call_args.args[1], ["device", "stats", "--"])

    @patch("oe.windows_storage.run_probe")
    def test_counter_tool_failure_is_sanitized(self, probe):
        for failure, label in ((None, "unavailable"), (response(error="Permission denied at synthetic-path",
                                                               status=1), "permission denied")):
            probe.side_effect = [response("btrfs"), failure]
            report = windows_storage.diagnostics(self.root, counters=True)
            self.assertEqual(report["btrfs_counters"]["status"], label)
            self.assertNotIn("synthetic-path", json.dumps(report))

    @patch("oe.windows_storage.run_probe", return_value=response("ext4"))
    def test_doctor_reads_only_known_settings_and_rejects_plan_symlinks(self, _probe):
        config = self.root / "compose.json"
        config.write_text(json.dumps({"services": {"windows": {
            "environment": {"DISK_IO": "threads", "DISK_CACHE": "writeback",
                            "UNRELATED": "synthetic-do-not-report"},
            "restart": "unrecognized-synthetic-value"}}}))
        report = windows_storage.diagnostics(self.root, compose_path=config)
        self.assertEqual((report["disk_io"], report["disk_cache"], report["restart"]),
                         ("threads", "writeback", "unrecognized"))
        self.assertNotIn("synthetic", json.dumps(report))
        alias = self.root / "alias.json"
        alias.symlink_to(config)
        with self.assertRaises(ValueError):
            windows_storage.diagnostics(self.root, compose_path=alias)
