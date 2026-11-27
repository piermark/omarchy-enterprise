from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, patch

from oe import pilot_desktop, pilot_publication, provision, state, status
from oe.__main__ import file_server_session, main, parser


class ConsolidationTests(unittest.TestCase):
    def test_generic_desktop_preserves_existing_entries_and_rolls_back(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            menu = root / pilot_desktop.TARGETS["menu"]
            menu.parent.mkdir(parents=True)
            original = '{"personal":{"label":"Personal"}}\n'
            menu.write_text(original)
            pilot_desktop.apply("menu", "enable", True, config=root, product=True)
            updated = menu.read_text()
            self.assertIn("personal", updated)
            self.assertIn("/usr/bin/omarchy-enterprise file-servers manager", updated)
            self.assertNotIn("/opt/", updated)
            pilot_desktop.apply("menu", "enable", True, config=root, product=True)
            self.assertEqual(updated, menu.read_text())
            with self.assertRaisesRegex(ValueError, "migration"):
                pilot_desktop.apply("menu", "disable", True, config=root)
            pilot_desktop.apply("menu", "disable", True, config=root, product=True)
            self.assertEqual(original, menu.read_text())

    def test_legacy_hook_refuses_duplicate_and_generic_supervisor_is_bounded(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            legacy = root / pilot_desktop.TARGETS["login"]
            legacy.parent.mkdir(parents=True)
            legacy.write_text("existing")
            with self.assertRaisesRegex(ValueError, "migration"):
                pilot_desktop.apply("login", "enable", True, config=root, product=True)
            self.assertEqual(legacy.read_text(), "existing")
            self.assertFalse(legacy.with_name(legacy.name.removesuffix("-pilot")).exists())
        with patch("oe.pilot_desktop.subprocess.run", side_effect=OSError) as worker:
            self.assertEqual(pilot_desktop.supervise_login(product=True), 0)
        self.assertEqual(worker.call_args.args[0][-3:],
                         ["/usr/bin/omarchy-enterprise", "file-servers", "login-worker"])

    def test_unified_cli_reuses_manager_and_publication_requires_installed_path(self):
        args = parser().parse_args(["file-servers", "manager"])
        with patch("oe.pilot_session.manager", return_value=0) as manager:
            self.assertEqual(file_server_session(args, product=True), 0)
        manager.assert_called_once()
        with patch("oe.pilot_publication.os.geteuid", return_value=0), patch(
            "oe.pilot_publication.apply"
        ) as publish:
            self.assertEqual(pilot_publication.execute(parser().parse_args(
                ["publish-file-servers", "recover", "--expected", "absent", "--confirm"]),
                product=True), 1)
        publish.assert_not_called()

    def test_offline_summary_is_read_only_redacted_and_optional_components_fail_closed(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            store = state.Store(root / "state")
            with store.locked():
                store.change(**{"profile.json": json.dumps({"profile": "active-directory",
                                                            "domain": "example.test"})})
            before = store.snapshot()
            with patch("oe.status._metadata", return_value="NOT CONFIGURED"), patch(
                "oe.status.provision.health", return_value={"fixture": False}
            ) as health, patch("subprocess.run") as run:
                report = status.summary(store, root / "missing", root=root, which=Mock(return_value=None))
            self.assertEqual(store.snapshot(), before)
            health.assert_called_once_with("active-directory", False)
            run.assert_not_called()
            self.assertEqual(report["saved_profile"], "CONFIGURED")
            self.assertEqual(report["services"], "NOT TESTED")
            self.assertFalse(report["inbound_rdp"]["qualified_backend"])
            self.assertNotIn("example.test", json.dumps(report))

    def test_doctor_summary_cli_dispatch(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            store = state.Store(root / "state")
            with store.locked():
                store.change(**{"profile.json": json.dumps({"profile": "standalone"})})
            original_summary = status.summary
            output, errors = StringIO(), StringIO()
            with (
                patch("sys.argv", ["omarchy-enterprise", "--state-dir", str(root / "state"), "doctor", "--summary"]),
                patch("oe.__main__.SYSTEM_POLICY", root / "smb-policy.json"),
                patch.object(status, "summary", side_effect=lambda store, source:
                             original_summary(store, source, root=root)),
                redirect_stdout(output), redirect_stderr(errors),
            ):
                self.assertEqual(main(), 0)
            self.assertEqual(errors.getvalue(), "")
            self.assertNotIn("Traceback", output.getvalue())
            report = json.loads(output.getvalue())
            self.assertEqual(report["saved_profile"], "CONFIGURED")
            self.assertEqual(report["inbound_rdp"]["activation"], "OFF")
            self.assertFalse(report["inbound_rdp"]["qualified_backend"])

    def test_installer_preserves_v1_and_v2_policy_boundaries(self):
        for version in (1, 2):
            data = {"version": version, "shares": []}
            files = provision.render("standalone", file_servers=data)
            self.assertEqual(json.loads(files["policy.json"]), data)
        with self.assertRaises(ValueError):
            provision.render("standalone", file_servers={"version": 3, "shares": []})
