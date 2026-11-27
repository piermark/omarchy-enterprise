"""Product workflows exercised with isolated fixtures and bounded fake adapters."""

import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from oe import operational, operational_cups, operational_windows, product, provision, state
from oe.control_center.setup import Setup, add_share


class SetupTests(unittest.TestCase):
    def test_profile_navigation_and_validation(self):
        for profile in operational.PROFILES:
            with self.subTest(profile=profile):
                setup = Setup(step=2, profile=profile)
                self.assertEqual(setup.move(1), 4 if profile == "standalone" else 3)
                if profile != "standalone":
                    with self.assertRaises(ValueError):
                        setup.move(1)
                    self.assertEqual(setup.step, 3)
                    setup.fields.update(domain="example.com", workgroup="EXAMPLE",
                                        users="users", admins="admins")
                    self.assertEqual(setup.move(1), 4)
                setup.step = 5
                self.assertEqual(setup.move(1), 6 if profile == "full-enterprise" else 7)
                files = setup.render()
                self.assertEqual(json.loads(files["profile.json"])["profile"], profile)

    def test_prerequisites_and_version_classification(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / "etc/omarchy").mkdir(parents=True)
            (root / "etc/omarchy/version").write_text("4.5.0\n")
            (root / "etc/samba").mkdir()
            (root / "etc/samba/smb.conf").touch()
            runner = Mock(side_effect=lambda args: (int(args[-1] == "cups"), ""))
            packages = operational.dependencies("full-enterprise", True, runner)
            review = product.workstation_review(root, packages=packages,
                                                space=lambda _: SimpleNamespace(free=1234))
            self.assertEqual(review["version"], "4.5.0")
            self.assertEqual(review["available_bytes"], 1234)
            self.assertFalse(review["packages"]["cups"])
            self.assertTrue(review["packages"]["docker"])
            self.assertIn(("etc/samba/smb.conf", "CONFIGURED"), review["configuration"])
            self.assertEqual(review["live_installation"], "BLOCKED")

    def test_staging_space_and_stale_review(self):
        with tempfile.TemporaryDirectory() as name:
            setup = Setup(root=name)
            with patch("oe.control_center.setup.shutil.disk_usage", return_value=SimpleNamespace(free=0)):
                with self.assertRaisesRegex(ValueError, "Insufficient"):
                    setup.prepare()
            plan = setup.prepare()
            (Path(name) / "external").touch()
            with self.assertRaises(ValueError):
                plan.apply()
            self.assertFalse((Path(name) / ".omarchy-enterprise-state").exists())

    def test_resume_abort_rollback_and_stale_recovery(self):
        for action in ("recover", "abort"):
            with self.subTest(action=action), tempfile.TemporaryDirectory() as name:
                setup = Setup(root=name)
                plan = setup.prepare()
                with patch.object(provision.ImageStore, "recover", side_effect=[False, InterruptedError]):
                    with self.assertRaises(InterruptedError):
                        plan.apply()
                reviewed = setup.prepare_recovery(action)
                target = plan.target()
                path = target.file_path("profile.json")
                path.parent.mkdir(parents=True, exist_ok=True)
                state.write(path, plan.files["profile.json"], mode=provision.DESTINATIONS["profile.json"][1])
                with self.assertRaisesRegex(ValueError, "changed since review"):
                    reviewed()
                setup.prepare_recovery(action)()
                self.assertFalse(target.journal.exists())
                self.assertEqual(target.snapshot(), plan.files if action == "recover" else target.empty)
                if action == "recover":
                    setup.prepare_recovery("rollback")()
                    self.assertEqual(target.snapshot(), target.empty)


class ResourceTests(unittest.TestCase):
    def test_two_servers_handoff_is_private_and_matches_helper(self):
        shares = add_share({"version": 2, "shares": []}, "files.example.com", "Files", "*")
        shares = add_share(shares, "smb://projects.example.com/work", "Projects", "staff@example.com")
        data = product.deployment_payload("active-directory", True, shares)
        files = operational.document(**json.loads(data))
        self.assertEqual(len(json.loads(files["file-servers.json"])["shares"]), 2)
        with tempfile.TemporaryDirectory(prefix="example handoff ") as name:
            with patch.dict("os.environ", {"XDG_CONFIG_HOME": name}):
                path = product.save_handoff(data)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(path.read_text(), data)
            command = product.administrator_commands(path)
            self.assertIn("--approve REVIEW_TOKEN", command)
            self.assertIn(f"'{path}'", command)

    def test_printer_draft_edit_default_and_collision(self):
        draft = product.PrinterDraft().edit("oe-a", "ipps://print.example.com/ipp/a", default=True)
        draft = draft.edit("oe-b", "ipp://print.example.com/ipp/b")
        self.assertEqual(draft.default, "oe-a")
        with self.assertRaises(ValueError):
            draft.edit("oe-A", "ipps://print.example.com/ipp/c")
        draft = draft.edit("oe-c", "ipps://print.example.com/ipp/c", previous="oe-a", default=True)
        self.assertEqual(draft.default, "oe-c")
        self.assertIsNone(draft.remove("oe-c").default)
        self.assertEqual(len(draft.rows), 2)

    def test_cups_render_and_conflict_without_mutation(self):
        outputs = {"-r": "scheduler is running", "-c": "",
                   "-v": "device for personal: ipps://print.example.com/ipp/a",
                   "-p": "printer personal disabled since Fri", "-d": "no system default destination"}
        runner = Mock(side_effect=lambda args: (0, outputs[args[-1]]))
        cups = operational_cups.Cups(runner)
        self.assertEqual(cups.queue_status(), {"personal": "Disabled"})
        draft = product.PrinterDraft().edit("oe-a", "ipps://print.example.com/ipp/a")
        draft = draft.edit("oe-b", "ipps://print.example.com/ipp/b", default=True)
        plan = cups.review(draft.document())
        self.assertEqual(len(plan["commands"]), 3)
        with self.assertRaisesRegex(ValueError, "qualification"):
            cups.execute(draft.document(), "", checkpoint=Mock())
        outputs["-v"] += "\ndevice for OE-B: ipps://print.example.com/ipp/b"
        with self.assertRaisesRegex(ValueError, "conflicts"):
            cups.review(draft.document())
        self.assertTrue(all(call.args[0][0] == "/usr/bin/lpstat" for call in runner.call_args_list))


class WindowsTests(unittest.TestCase):
    def test_loopback_identity_is_explicit_and_legacy_plan_stays_isolated(self):
        probe = Mock(return_value={"filesystem": "btrfs", "available_bytes": 128 * 1024**3,
                                   "nearest_parent_used": False})
        dockur = operational_windows.Dockur(runner=Mock(), probe=probe, device=lambda _: True)
        settings = operational_windows.Settings("dockurr/windows@sha256:" + "a" * 64, 4, 8, 128)
        isolated = dockur.create_plan(settings)
        with patch("oe.windows.client", return_value="/usr/bin/xfreerdp"):
            plan = dockur.configuration_review(settings, edition="11e", storage="/var/lib/example-vm",
                                              local_port=13389, certificate_name="windows.example.com",
                                              account="operator")
        self.assertIn("none", isolated["command"])
        self.assertNotIn("--publish", isolated["command"])
        self.assertIn("127.0.0.1:13389:3389/tcp", plan["command"])
        self.assertIn("VERSION=11e", plan["command"])
        self.assertIn("DISK_IO=threads", plan["command"])
        self.assertTrue(plan["storage"]["sufficient_space"])
        self.assertIn("/server-name:windows.example.com", plan["client"])
        self.assertIn("/cert:deny", plan["client"])
        self.assertIn("/sec:nla", plan["client"])
        self.assertEqual(plan["qualification"], "blocked")
        dockur.run.assert_not_called()
        with self.assertRaisesRegex(ValueError, "qualification"):
            dockur.create(settings, "", checkpoint=Mock())
        dockur.run.assert_not_called()

    def test_discovery_checks_complete_container_identity(self):
        identity = "b" * 64
        runner = Mock(side_effect=[
            (0, identity), (0, f"{identity} /{operational_windows.NAME} phase12 no none 0 exited"),
        ])
        self.assertEqual(operational_windows.Dockur(runner).discover(), {identity: "exited"})
        self.assertEqual(runner.call_args.args[0][3:5], ("container", "inspect"))


class InterfaceTests(unittest.TestCase):
    def test_gui_printer_route_exposes_draft_and_gated_review(self):
        repository = SimpleNamespace(Gtk=Mock(), Adw=Mock(), Pango=Mock())
        path = Path(__file__).resolve().parents[1] / "oe/control_center/operational.py"
        name = "oe.control_center.operational"
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        with patch.dict(sys.modules, {"gi.repository": repository}):
            spec.loader.exec_module(module)
        draft = product.PrinterDraft().edit("oe-a", "ipps://print.example.com/ipp/a")
        center = Mock(route="printers", printers=draft, operational_fields={})
        actions = {}

        def button(title, callback, **_):
            actions[title] = callback
            return Mock()

        with patch.multiple(module, button=button, forms=Mock(), _=lambda value: value):
            module.panel(center)
            actions["Review driverless queues"]()
        with patch.object(operational_cups, "Cups") as cups:
            center.work.call_args.args[0](None)
            cups.return_value.review.assert_called_once_with(draft.document())

    @unittest.skipUnless(shutil.which("msgfmt"), "gettext tooling unavailable")
    def test_product_catalog_translates_new_workflows(self):
        import gettext
        catalog = Path(__file__).resolve().parents[1] / "locale/it/LC_MESSAGES/omarchy-enterprise.po"
        with tempfile.TemporaryDirectory() as name:
            compiled = Path(name) / "catalog.mo"
            subprocess.run(["msgfmt", "--check", "-o", compiled, catalog], check=True)
            with compiled.open("rb") as stream:
                italian = gettext.GNUTranslations(stream)
            for caption in ("Add printer", "Save handoff", "Review workstation prerequisites"):
                self.assertNotEqual(italian.gettext(caption), caption)
                self.assertEqual(gettext.NullTranslations().gettext(caption), caption)


class AdministrationTests(unittest.TestCase):
    def test_status_reports_checkpoint_and_drift_without_disclosing_contents(self):
        from oe.operational_cli import deployment_status

        with tempfile.TemporaryDirectory() as name:
            store = operational.Deployment(Path(name))
            self.assertFalse(deployment_status(store)["ledger_present"])
            payload = operational.document("standalone", False, {"version": 2, "shares": []})
            packages = {"python": True}
            store.transaction(payload, packages, operational.approved(store.review(payload, packages)))
            status = deployment_status(store)
            self.assertTrue(status["rollback_checkpoint"])
            self.assertTrue(status["files"]["profile.json"])
            self.assertFalse(status["external_conflict"])
            store.set_file("profile.json", '{"external":true}\n')
            status = deployment_status(store)
            self.assertTrue(status["external_conflict"])
            self.assertNotIn('{"external":true}', operational.encode(status))

    def test_status_keeps_the_installed_administrator_boundary(self):
        from oe.operational_cli import admin_action

        with patch.object(operational.os, "geteuid", return_value=1000):
            with self.assertRaisesRegex(ValueError, "administrator"):
                admin_action(SimpleNamespace(operation="status", approve=None))
