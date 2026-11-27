import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from oe import __version__

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipIf(os.geteuid() == 0, "Beta entry points run as an ordinary user")
class BetaEntrypointsTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def invoke(self, script, *args):
        return subprocess.run([ROOT / script, *args], cwd=self.root,
                              env={"PATH": "/usr/bin:/bin", "HOME": str(self.root), "LC_ALL": "C"},
                              stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=10)

    def test_install_preview_confirmation_and_uninstall_for_each_profile(self):
        ad = ["--domain", "example.com", "--workgroup", "EXAMPLE",
              "--users", "employees", "--admins", "workstation-admins"]
        for profile, flags in (("standalone", []), ("active-directory", ad), ("full-enterprise", ad)):
            with self.subTest(profile=profile):
                destination = self.root / profile
                destination.mkdir(mode=0o700)
                prefix = ["--root", destination, "--profile", profile]
                preview = self.invoke("install.sh", *prefix, *flags, "--dry-run")
                self.assertEqual(preview.returncode, 0, preview.stderr)
                self.assertEqual(list(destination.iterdir()), [])
                refused = self.invoke("install.sh", *prefix, *flags)
                self.assertNotEqual(refused.returncode, 0)
                self.assertEqual(list(destination.iterdir()), [])
                apply = self.invoke("install.sh", *prefix, *flags, "--yes")
                self.assertEqual(apply.returncode, 0, apply.stderr)
                profile_path = destination / "etc/omarchy-enterprise/profile.json"
                self.assertTrue(profile_path.is_file())
                denied = self.invoke("uninstall.sh", "--root", destination)
                self.assertNotEqual(denied.returncode, 0)
                self.assertTrue(profile_path.is_file())
                removed = self.invoke("uninstall.sh", "--root", destination, "--yes")
                self.assertEqual(removed.returncode, 0, removed.stderr)
                self.assertFalse(profile_path.exists())

    def test_rejects_active_root_missing_journal_and_headless_empty_invocation(self):
        rejected = self.invoke("install.sh", "--root", "/", "--profile", "standalone", "--yes")
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("disposable root", rejected.stderr)
        removed = self.invoke("uninstall.sh", "--root", self.root, "--yes")
        self.assertIn("No provisioning journal", removed.stderr)
        self.assertEqual(list(self.root.iterdir()), [])
        fallback = self.invoke("install.sh")
        self.assertNotEqual(fallback.returncode, 0)
        self.assertIn("explicit --profile", fallback.stderr)

    def test_cli_and_arch_recipe_report_the_same_version(self):
        version = self.invoke("bin/omarchy-enterprise", "--version")
        self.assertEqual(version.returncode, 0, version.stderr)
        self.assertEqual(version.stdout.strip(), f"omarchy-enterprise v{__version__}")
        arch_version = __version__.replace("-beta.", "beta")
        self.assertIn(f"pkgver={arch_version}\n", (ROOT / "packaging/PKGBUILD").read_text())

    def test_terminal_wizard_can_preview_without_zenity_or_display(self):
        import pty

        master, terminal = pty.openpty()
        try:
            with subprocess.Popen(
                [ROOT / "install.sh", "--root", self.root, "--dry-run"],
                cwd=self.root, env={"PATH": "/usr/bin:/bin", "HOME": str(self.root), "LC_ALL": "C"},
                stdin=terminal, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            ) as process:
                os.write(master, b"1\n")
                stdout, stderr = process.communicate(timeout=10)
                self.assertEqual(process.returncode, 0, stderr)
            self.assertIn("Standalone Enterprise", stdout)
            self.assertIn("Files managed by this profile", stdout)
            self.assertEqual(list(self.root.iterdir()), [])
        finally:
            os.close(terminal)
            os.close(master)
