# SPDX-License-Identifier: MIT
import configparser
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from oe import diagnostics, legacy_review, migration, provision, wizard
from oe.__main__ import desktop_console
from oe.state import Store

SOURCE = Path(__file__).resolve().parents[1]


class Phase10L(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def put(self, path, data, executable=False):
        target = self.root / path.lstrip("/")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data.encode() if isinstance(data, str) else data)
        if executable:
            target.chmod(0o755)
        return target

    def test_hooks_review_headers_and_interpreters_without_execution(self):
        self.put("/usr/bin/bash", b"\x7fELF", True)
        path = "/usr/local/bin/omarchy-enterprise-guard"
        for contents, result in (
                ("\n#!/usr/bin/bash\n", "MISSING SHEBANG"),
                ("#!/usr/bin/bash\r\n", "CRLF HEADER"),
                ("#!/usr/bin/missing\n", "INVALID OR UNAVAILABLE INTERPRETER"),
                ("#!/usr/bin/bash\n", "SHEBANG PRESENT"),
                ("#!" + "/" * 256 + "\n", "INVALID SHEBANG")):
            with self.subTest(result=result):
                self.put(path, contents + "touch example.com\n", True)
                row = legacy_review.inspect_hook(self.root, f"[Action]\nExec = {path} check")
                self.assertEqual(row["target"], result)
        self.assertFalse((self.root / "example.com").exists())
        row = legacy_review.inspect_hook(self.root, f"[Action]\nExec = /usr/bin/bash {path} check")
        self.assertIn("ADMINISTRATOR TRUST REVIEW", row["guard"])
        row = legacy_review.inspect_hook(self.root, f"[Action]\nExec = /usr/bin/python3 {path} check")
        self.assertIn("INCORRECT", row["guard"])
        self.assertEqual(row["target"], "MISSING OR NONEXECUTABLE TARGET")
        row = legacy_review.inspect_hook(self.root, "[Action]\nExec = example\nExec = other")
        self.assertIn("AMBIGUOUS", row["target"])

    def test_consumers_redacted_and_migration_blocked(self):
        command = "omarchy-enterprise-doctor"
        self.put("usr/share/libalpm/hooks/vendor.hook", "[Action]\nExec=/usr/bin/" + command)
        self.put("etc/pacman.d/hooks/local.hook", "[Action]\nExec=/usr/local/bin/" + command)
        self.put("etc/xdg/autostart/example.desktop", "Exec=" + command)
        self.put("usr/share/applications/example.desktop", "Exec=" + command)
        self.put("etc/systemd/system/example.service.d/override.conf", "ExecStart=/usr/local/bin/" + command)
        self.put("etc/omarchy/extensions/menu.jsonc", '{"action":"' + command + '"}')
        self.put("etc/omarchy-enterprise/task.sh", command)
        link = self.root / "etc/xdg/autostart/redacted.desktop"
        link.symlink_to("/example.com")
        with patch("oe.legacy_review.read_file", wraps=legacy_review.read_file) as review:
            result = migration.Migration(self.root, lambda path: (
                "unowned" if path.name == "local.hook" else "other package")).preview()
        self.assertGreaterEqual(review.call_count, 8)
        self.assertEqual(result["live_apply"], "BLOCKED")
        dependencies = result["dependency_review"]
        self.assertEqual(dependencies["guard_parity"], "UNVERIFIED")
        scopes = dependencies["scopes"]
        self.assertEqual(scopes["XDG autostart"]["unreadable_or_unsupported"], 1)
        self.assertEqual(scopes["local hooks"]["findings"][0]["ownership"], "unowned")
        self.assertEqual(scopes["package hooks"]["findings"][0]["ownership"], "other package")
        for scope in ("XDG autostart", "desktop entries", "Omarchy local menu", "Enterprise automation"):
            self.assertEqual(scopes[scope]["findings"][0]["references"][command], ["POSSIBLE PATH DEPENDENCY"])
        self.assertEqual(scopes["local systemd units"]["findings"][0]["references"][command], ["LEGACY ABSOLUTE"])
        self.assertNotIn("example.com", str(result))

    def test_atomic_hook_staging_and_exact_rollback(self):
        template = SOURCE / "templates" / (legacy_review.HOOK_NAME + ".example")
        content = template.read_bytes()
        self.assertEqual(content, provision.PACMAN_HOOK.encode("ascii"))
        self.assertIn(b"AbortOnFail\n", content)
        self.assertIn(b"Exec = /usr/bin/omarchy-enterprise-guard check\n", content)
        staged = self.root / template.name
        with patch("oe.legacy_review.os.fsync", side_effect=OSError("simulated write failure")):
            with self.assertRaises(OSError):
                legacy_review.stage_hook(self.root, "stage", content)
        self.assertEqual(list(self.root.iterdir()), [])
        legacy_review.stage_hook(self.root, "stage", content)
        with self.assertRaises(FileExistsError):
            legacy_review.stage_hook(self.root, "stage", content)
        staged.write_bytes(b"edited")
        with self.assertRaises(ValueError):
            legacy_review.stage_hook(self.root, "rollback", content)
        self.assertEqual(staged.read_bytes(), b"edited")
        staged.write_bytes(content)
        legacy_review.stage_hook(self.root, "rollback", content)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_guard_path_parity_is_redacted_and_never_unlocks(self):
        report = legacy_review.guard_parity("/etc/example-old\n", "/etc/example-new\n")
        self.assertEqual(report["legacy_only"], 1)
        self.assertNotIn("/etc/", str(report))
        report = legacy_review.guard_parity("/etc/example\n", "/etc/example\n")
        self.assertEqual(report["path_parity"], "MATCH")
        self.assertEqual(report["live_apply"], "BLOCKED")
        with self.assertRaises(ValueError):
            legacy_review.guard_parity("/etc/../example\n", "/etc/example\n")

    def test_sddm_dropins_precedence_and_no_login_inference(self):
        self.put("usr/lib/sddm/sddm.conf.d/10-theme.conf", "[Theme]\nCurrent=example\n")
        self.put("etc/sddm.conf.d/zz-enterprise.conf", "[Theme]\nCurrent=omarchy-enterprise\n")
        with patch("oe.diagnostics.services", return_value={"sddm.service": {"activity": "ACTIVE"}}):
            report = diagnostics.report(root=self.root, runtime=True)
        sddm = report["configuration"]["SDDM"]
        self.assertEqual(sddm["configured_theme"], "OMARCHY ENTERPRISE")
        self.assertEqual(sddm["sources"]["etc/sddm.conf.d/zz-enterprise.conf"]["readability"], "CONFIGURED")
        self.assertEqual(report["functional_acceptance"]["SDDM login"], "NOT TESTED")
        self.put("etc/sddm.conf", "[Theme]\nCurrent=example.com\n")
        self.assertEqual(diagnostics.configuration(self.root)["SDDM"]["configured_theme"],
                         "CUSTOM THEME CONFIGURED")
        (self.root / "etc/sddm.conf.d/unverified.conf").symlink_to("/example.com")
        self.assertEqual(diagnostics.configuration(self.root)["SDDM"]["configured_theme"], "UNVERIFIED")

    def test_windows_selected_policy_only(self):
        identifier = "a" * 64
        run = Mock(return_value=subprocess.CompletedProcess([], 0, "dockurr/windows\tno\n", ""))
        self.assertTrue(diagnostics.windows_restart_policy(identifier, run=run)["manual_start_verified"])
        args = run.call_args.args[0]
        self.assertEqual(args[:6], ["/usr/bin/docker", "--host", "unix:///run/docker.sock",
                                    "container", "inspect", "--format"])
        self.assertEqual(args[-2:], ["--", identifier])
        self.assertEqual(args[6], "{{.Config.Image}}\t{{.HostConfig.RestartPolicy.Name}}")
        with self.assertRaises(ValueError):
            diagnostics.windows_restart_policy("--all", run=run)
        run.assert_called_once()
        run.return_value.stdout = "dockurr/windows\talways\n"
        self.assertFalse(diagnostics.windows_restart_policy(identifier, run=run)["manual_start_verified"])
        run.return_value.stdout = "example.com\tno\n"
        self.assertEqual(diagnostics.windows_restart_policy(identifier, run=run)["restart_policy"], "UNKNOWN")

    def test_graphical_new_routes_and_packaged_targets(self):
        dialog = Mock()
        dialog.choose.side_effect = ["guided-installer", "printer-admin", "update-readiness",
                                     "file-servers-refresh", None]
        store = Store(self.root / "state")
        shares = {"One": "smb://files.example.com/one", "Two": "smb://files.example.com/two"}
        with patch("oe.graphical.Dialog", return_value=dialog), patch(
                "oe.__main__.refresh", return_value=shares), patch(
                "oe.graphical.reference_available", return_value=False), patch(
                "oe.graphical.printer_available", return_value=True), patch(
                "oe.graphical.launch_printer") as printer, patch("oe.wizard.run") as installer, patch(
                "oe.bookmarks.update") as bookmarks:
            self.assertEqual(desktop_console(store), 0)
        installer.assert_called_once_with(store=store)
        printer.assert_called_once_with()
        bookmarks.assert_called_once_with(shares)
        self.assertTrue(any("offline installer target" in call.args[0] for call in dialog.report.call_args_list))
        for entry, subcommand in (("omarchy-enterprise", "desktop"),
                                  ("omarchy-enterprise-installer", "provision-wizard")):
            parsed = configparser.ConfigParser(interpolation=None)
            parsed.read(SOURCE / "templates" / f"{entry}.desktop")
            self.assertEqual(parsed["Desktop Entry"]["TryExec"], "/usr/bin/omarchy-enterprise")
            self.assertEqual(parsed["Desktop Entry"]["Exec"], f"/usr/bin/omarchy-enterprise {subcommand}")

    def test_wizard_readiness_reports_optional_windows_separately(self):
        with patch("oe.provision.health", return_value={"FreeRDP": False}) as health, patch(
                "oe.wizard.shutil.which", return_value=None):
            checks, required = wizard.readiness("full-enterprise", windows_enabled=True, printing=True)
        health.assert_called_once_with("full-enterprise", True)
        self.assertEqual(checks, {"FreeRDP": False, "zenity": False})
        self.assertIn("cups", required)
        self.assertIn("sssd", required)
