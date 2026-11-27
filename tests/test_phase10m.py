# SPDX-License-Identifier: MIT
"""Independent tests with synthetic profiles and temporary user state."""
import ast
import configparser
from pathlib import Path
from queue import Queue
import shutil
import subprocess
import tempfile
from threading import Event
import unittest
from unittest.mock import Mock, patch

from oe import bookmarks, diagnostics, pilot_session, policy, provision
from oe.control_center import localization, launcher, model
from oe.control_center.jobs import Jobs, run_process
from oe.control_center.setup import STEPS, Setup, add_share
from oe.state import Store

SOURCE = Path(__file__).resolve().parents[1]
EMPTY = {"version": 2, "shares": []}


class Phase10M(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.backend = model.Backend(Store(self.root / "state"), self.root / "smb.json")

    def test_overview_distinguishes_active_restricted_and_unavailable(self):
        units = {"sssd.service": {"unit": "CONFIGURED", "activity": "ACTIVE"},
                 "winbind.service": {"unit": "ACCESS RESTRICTED", "activity": "NOT TESTED"},
                 "docker.service": {"unit": "UNAVAILABLE", "activity": "NOT TESTED"}}
        with patch.object(diagnostics, "services", return_value=units), patch.object(
                diagnostics, "configuration", return_value={"SSSD": {}, "PAM": {}}), patch(
                "oe.installation.review", return_value={"workflow": "CLEAN INSTALLATION"}), patch(
                "oe.control_center.model.queues", return_value=(model.state("NOT CONFIGURED"), [])):
            rows = dict(self.backend.overview(Event()).rows)
        self.assertEqual(rows["sssd"].code, "ACTIVE")
        self.assertEqual(rows["winbind"].code, "ACCESS RESTRICTED")
        self.assertEqual(rows["docker"].code, "UNAVAILABLE")
        self.assertEqual(rows["Update readiness"].code, "NOT TESTED")
        self.assertEqual(rows["Inbound Remote Desktop"].code, "DISABLED")
        self.assertEqual(model.state("unexpected").text, model.state("UNKNOWN").text)

    def test_previously_recorded_review_is_separate_from_current_checks(self):
        from oe import installation
        marker = self.root / "etc/sssd/sssd.conf"
        marker.parent.mkdir(parents=True)
        marker.touch()
        host = installation.review(self.root)
        self.assertEqual(self.backend.recorded_review(host).code, "NOT CONFIGURED")
        installation.adopt(self.backend.store, host["review_token"], root=self.root)
        self.assertEqual(self.backend.recorded_review(host).code, "RECORDED")
        marker.unlink()
        self.assertEqual(self.backend.recorded_review(installation.review(self.root)).code, "UNVERIFIED")

    def test_printer_queues_and_authorization_failure(self):
        proc = subprocess.CompletedProcess
        with patch.object(diagnostics, "probe", side_effect=[proc([], 0, "scheduler is running\n", ""),
                proc([], 0, "printer One is idle. enabled since ...\nprinter Two disabled since ...\n", "")]):
            status, rows = model.queues()
        self.assertEqual(status.code, "AVAILABLE")
        self.assertEqual({name: result.code for name, result in rows}, {"One": "AVAILABLE", "Two": "DISABLED"})
        self.assertEqual(model.probe_status(proc([], 1, "", "Forbidden")).code, "ACCESS RESTRICTED")

    def test_service_activity_never_qualifies_ad_login(self):
        with patch.object(diagnostics, "services", return_value={
            "sssd.service": {"unit": "CONFIGURED", "activity": "ACTIVE"},
        }), patch.object(diagnostics, "configuration", return_value={
            "SSSD": {}, "Samba": {}, "PAM": {},
            "SDDM": {"sources": {}, "configured_theme": "UNVERIFIED"},
        }):
            rows = dict(self.backend.directory(Event()).rows)
        self.assertEqual(rows["SSSD service"].code, "ACTIVE")
        self.assertEqual(rows["AD authentication acceptance"].code, "NOT TESTED")
        self.assertEqual(rows["SDDM login acceptance"].code, "NOT TESTED")

    def test_routes_administrative_boundaries_and_rdp(self):
        for route in model.PAGES.keys() - {"installer", "files"}:
            self.assertTrue(callable(getattr(self.backend, route)), route)
        runtime = diagnostics.windows_runtime(root=self.root)
        with patch.object(diagnostics, "services", return_value={}), patch.object(
                diagnostics, "windows_runtime", return_value=runtime) as query, patch(
                "oe.windows.client", return_value="/usr/bin/xfreerdp3") as client:
            rows = dict(self.backend.windows(Event()).rows)
        query.assert_called_once_with(activity="UNKNOWN", query=True)
        client.assert_called_once_with()
        self.assertEqual(rows["FreeRDP client"].code, "AVAILABLE")
        self.assertEqual(rows["Desired start policy"].code, "MANUAL START ONLY")
        self.assertEqual(rows["Managed launch"].code, "BLOCKED")
        self.assertEqual(rows["Storage readiness"].code, "NOT TESTED")
        remote = dict(self.backend.remote(Event()).rows)
        for key in ("Full inbound acceptance", "Independent remote sessions", "Peripheral redirection"):
            self.assertEqual(remote[key].code, "BLOCKED")
        self.assertEqual(remote["Inbound RDP"].code, "OFF")
        with patch("os.access", return_value=True):
            self.assertEqual(model.admin("omarchy-enterprise-guard").code, "ACCESS RESTRICTED")

    def test_windows_page_reports_missing_freerdp_as_unavailable(self):
        runtime = diagnostics.windows_runtime(root=self.root)
        with patch.object(diagnostics, "services", return_value={}), patch.object(
                diagnostics, "windows_runtime", return_value=runtime), patch(
                "oe.windows.shutil.which", return_value=None) as which:
            rows = dict(self.backend.windows(Event()).rows)
        self.assertTrue(which.called)
        self.assertEqual(rows["FreeRDP client"].code, "UNAVAILABLE")
        self.assertEqual(rows["Managed launch"].code, "BLOCKED")

    def test_restricted_resources_and_open_rechecks_policy(self):
        with patch.object(pilot_session, "active_resources", side_effect=PermissionError):
            result, resources = self.backend.resources()
        self.assertEqual((result.code, resources), ("ACCESS RESTRICTED", {}))
        with patch.object(pilot_session, "session_ready"), patch.object(
                pilot_session, "active_resources", return_value={}), patch("subprocess.Popen") as start:
            with self.assertRaises(PermissionError):
                self.backend.open_share("Example", "smb://files.example.com/share")
        start.assert_not_called()

    def test_jobs_deliver_errors_and_discard_cancelled_results(self):
        events = Queue()
        outcomes = []
        jobs = Jobs(events.put)
        self.addCleanup(jobs.close)
        release = Event()
        self.addCleanup(release.set)
        started = Event()

        def slow(token):
            started.set()
            release.wait(2)
            return token.is_set()

        jobs.start(slow, lambda *result: outcomes.append(result))
        self.assertTrue(started.wait(2))
        self.assertTrue(jobs.cancel())
        release.set()
        events.get(timeout=2)()
        self.assertEqual(outcomes, [])
        jobs.start(Mock(side_effect=PermissionError("example.com")), lambda *result: outcomes.append(result),
                   cancellable=False)
        self.assertFalse(jobs.cancel())
        events.get(timeout=2)()
        self.assertIsInstance(outcomes[0][1], PermissionError)

    def test_cancelled_subprocess_is_not_started(self):
        token = Event()
        token.set()
        with patch("subprocess.Popen") as process, self.assertRaises(InterruptedError):
            run_process(["/usr/bin/false"], token, timeout=0.1, env={})
        process.assert_not_called()

    def test_draft_validation_never_overwrites_managed_policy(self):
        for uri in ("smb://user:password@files.example.com/share", "smb://files.example.com/one/two"):
            with self.assertRaises(ValueError):
                add_share(EMPTY, uri, "Example", "")
        first = add_share(EMPTY, "files.example.com/share", "Example", "staff@example.com")
        with self.assertRaises(ValueError):
            add_share(first, "storage.example.com/share", "Example", "")
        with patch.dict("os.environ", {"HOME": str(self.root), "XDG_CONFIG_HOME": str(self.root / "config")}):
            draft = pilot_session.save_draft(first)
        self.assertEqual(draft.stat().st_mode & 0o777, 0o600)
        self.assertEqual(policy.load_file(draft), first)
        self.assertEqual(self.backend.resources()[1], {})

    def test_bookmark_preview_apply_and_rollback_preserve_personal_lines(self):
        config = self.root / "config"
        current = {"One": "smb://files.example.com/one", "Two": "smb://storage.example.com/two"}
        with patch.dict("os.environ", {"HOME": str(self.root), "XDG_CONFIG_HOME": str(config)}), patch.object(
                pilot_session, "active_resources", return_value=current) as resources, patch.object(
                pilot_session, "session_ready"):
            book, _ledger = bookmarks.locations()
            book.parent.mkdir(parents=True)
            personal = "file:///example Personal\n"
            book.write_text(personal)
            expected, previous, desired = self.backend.bookmark_preview(Event())
            self.assertEqual(previous, ())
            self.assertEqual(len(desired), 2)
            self.assertEqual(book.read_text(), personal)
            resources.return_value = {}
            with self.assertRaises(ValueError):
                self.backend.apply_bookmarks(expected)
            self.assertEqual(book.read_text(), personal)
            resources.return_value = current
            self.backend.apply_bookmarks(expected)
            self.assertEqual(book.read_text(), personal + "".join(desired))
            extra = "file:///example2 Personal edit\n"
            with book.open("a") as stream:
                stream.write(extra)
            self.backend.rollback_bookmarks()
            self.assertEqual(book.read_text(), personal + extra)

    def test_bookmark_preview_leaves_pending_recovery_untouched(self):
        config = self.root / "config"
        with patch.dict("os.environ", {"HOME": str(self.root), "XDG_CONFIG_HOME": str(config)}), patch.object(
                pilot_session, "session_ready"):
            book, ledger = bookmarks.locations()
            ledger.mkdir(mode=0o700, parents=True)
            journal = Store(ledger).journal
            journal.write_text("synthetic pending transaction")
            with self.assertRaises(ValueError):
                self.backend.bookmark_preview(Event())
            self.assertEqual(journal.read_text(), "synthetic pending transaction")
            self.assertFalse(book.exists())

    def test_wizard_routes_validation_and_offline_rollback(self):
        setup = Setup(root=str(self.root))
        self.assertEqual(len(STEPS), 10)
        self.assertEqual([setup.move(1) for _ in range(3)], [1, 2, 4])
        self.assertEqual(setup.move(-1), 2)
        setup.profile = "active-directory"
        self.assertEqual(setup.move(1), 3)
        with self.assertRaises(ValueError):
            setup.move(1)
        setup.fields = dict(domain="example.com", workgroup="EXAMPLE", users="staff", admins="admins")
        self.assertEqual(setup.move(1), 4)
        self.assertEqual(setup.move(-1), 3)
        self.assertEqual(setup.fields["domain"], "example.com")
        setup.draft = add_share(EMPTY, "files.example.com/share", "Example", "")
        plan = setup.prepare()
        self.assertEqual(list(self.root.iterdir()), [])
        self.assertIn("etc/omarchy-enterprise/policy.json", plan.changes)
        plan.apply()
        self.assertIn("example.com", provision.ImageStore(self.root).snapshot()["sssd.conf"])
        plan.rollback()
        self.assertEqual(provision.ImageStore(self.root).snapshot(), provision.ImageStore.empty)

    def test_wizard_rollback_refuses_newer_transaction(self):
        setup = Setup(root=str(self.root))
        plan = setup.prepare()
        plan.apply()
        provision.mutate(self.root, "apply", provision.render("standalone", printer="printer.example.com"))
        with self.assertRaises(ValueError):
            plan.rollback()
        self.assertEqual(provision.ImageStore(self.root).snapshot()["printer-monitor-host"], "printer.example.com\n")

    def test_wizard_refuses_nonempty_target_and_review_path(self):
        (self.root / "personal").touch()
        setup = Setup(root=str(self.root))
        with self.assertRaises(ValueError):
            setup.prepare()
        setup.review = True
        self.assertEqual(setup.move(1), 9)
        self.assertEqual(setup.move(-1), 0)

    def test_fallback_and_packaged_launcher_resolution(self):
        fallback = Mock(return_value=47)
        for force in (False, True):
            with patch.dict("os.environ", {"OMARCHY_ENTERPRISE_ZENITY": ""}), patch.object(
                    launcher, "native", return_value=False) as native:
                self.assertEqual(launcher.run(None, None, fallback, force=force), 47)
                self.assertEqual(native.call_count, int(not force))
        for filename, action in (("omarchy-enterprise", "desktop"),
                                 ("omarchy-enterprise-installer", "provision-wizard")):
            parsed = configparser.ConfigParser(interpolation=None)
            parsed.read(SOURCE / "templates" / (filename + ".desktop"))
            self.assertEqual(parsed["Desktop Entry"]["Exec"], "/usr/bin/omarchy-enterprise " + action)
            self.assertEqual(parsed["Desktop Entry"]["TryExec"], "/usr/bin/omarchy-enterprise")
            self.assertEqual(parsed["Desktop Entry"]["Terminal"], "false")

    def test_italian_catalog_is_complete_and_english_falls_back(self):
        msgfmt = shutil.which("msgfmt")
        if not msgfmt:
            self.skipTest("gettext tools unavailable")
        source = SOURCE / "locale/it/LC_MESSAGES/omarchy-enterprise.po"
        destination = self.root / "it/LC_MESSAGES/omarchy-enterprise.mo"
        destination.parent.mkdir(parents=True)
        subprocess.run([msgfmt, "--check", "-o", destination, source], check=True)
        with patch.object(localization, "LOCALE", self.root):
            italian = localization.translation(["it"])
            english = localization.translation(["en"])
        strings = {node.args[0].value for path in (SOURCE / "oe/control_center").glob("*.py")
                   for node in ast.walk(ast.parse(path.read_text())) if isinstance(node, ast.Call)
                   and isinstance(node.func, ast.Name) and node.func.id == "_"}
        for message in strings:
            self.assertIn(message, italian._catalog)
            self.assertEqual(english.gettext(message), message)
        self.assertEqual(italian.gettext("Overview"), "Panoramica")
