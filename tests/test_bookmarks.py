from contextlib import redirect_stdout
from io import StringIO
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from oe import bookmarks, policy, provision, windows
from oe.__main__ import main, parser


DOCUMENT = {
    "version": 2,
    "shares": [
        {"label": "Server", "uri": "smb://fileserver.example.test/", "groups": []},
        {"label": "Public", "uri": "smb://fileserver.example.test/public", "groups": []},
        {"label": "Department", "uri": "smb://fileserver.example.test/department",
         "groups": ["employees@example.test"]},
        {"label": "Other", "uri": "smb://files02.example.test/documents", "groups": []},
    ],
}


@unittest.skipIf(os.geteuid() == 0, "Bookmark provisioning requires an ordinary user")
class BookmarksTest(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.config = self.root / "config"
        self.book = self.config / "gtk-3.0/bookmarks"

    def test_multiple_servers_and_group_filtering(self):
        self.assertEqual(set(policy.shares(DOCUMENT, set())), {"Server", "Public", "Other"})
        allowed = policy.shares(DOCUMENT, {"employees@example.test"})
        self.assertEqual(len(allowed), 4)
        self.assertEqual(allowed["Department"], DOCUMENT["shares"][2]["uri"])
        with patch("oe.policy.grp.getgrgid", side_effect=OSError):
            self.assertNotIn("Department", policy.shares(DOCUMENT, policy.effective_groups()))

    def test_newline_credential_and_path_injection_rejected(self):
        for uri in ("smb://name:secret@fileserver.example.test/", "smb://fileserver.example.test/%0a",
                    "smb://fileserver.example.test/../public", "smb://fileserver.example.test/\n"):
            with self.subTest(uri=uri), self.assertRaises(ValueError):
                policy.bookmark_uri(uri)
        with self.assertRaises(ValueError):
            bookmarks.update({"Fake\nAnother": "smb://fileserver.example.test/"}, self.config)

    def test_personal_matches_edits_idempotence_and_selective_removal(self):
        self.book.parent.mkdir(parents=True)
        personal = ("file:///fixture Personal\n"
                    "smb://fileserver.example.test/public My public bookmark\n"
                    "smb://files05.example.test/ Extra\n")
        self.book.write_text(personal)
        allowed = policy.shares(DOCUMENT, {"employees@example.test"})
        bookmarks.update(allowed, self.config)
        first = self.book.read_text()
        self.assertTrue(first.startswith(personal))
        self.assertEqual(first.count("smb://fileserver.example.test/public"), 1)
        bookmarks.update(allowed, self.config)
        self.assertEqual(self.book.read_text(), first)
        self.book.write_text(first.replace("files02.example.test/documents Other\n",
                                           "files02.example.test/documents My edit\n"))
        bookmarks.update(policy.shares(DOCUMENT, set()), self.config)
        self.assertNotIn("Department", self.book.read_text())
        bookmarks.update({}, self.config)
        self.assertEqual(self.book.read_text(), personal + "smb://files02.example.test/documents My edit\n")

    def test_unsafe_paths_and_user_isolation(self):
        other = self.root / "other"
        other.mkdir()
        self.config.symlink_to(other, target_is_directory=True)
        desired = policy.shares(DOCUMENT, set())
        with self.assertRaisesRegex(ValueError, "Unsafe"):
            bookmarks.update(desired, self.config)
        self.assertEqual(list(other.iterdir()), [])
        self.config.unlink()
        bookmarks.update(desired, self.config)
        bookmarks.update({}, other)
        self.assertEqual(list(other.iterdir()), [])
        self.assertTrue(self.book.is_file())

    def test_installer_stages_policy_and_editor_only_emits_draft(self):
        draft = self.root / "draft.json"
        draft.write_text(json.dumps(DOCUMENT))
        candidate = provision.render("standalone", file_servers=policy.load_file(draft))
        self.assertEqual(json.loads(candidate["policy.json"]), DOCUMENT)
        self.assertIsNone(candidate["windows.compose.json"])
        args = parser().parse_args(["file-servers", "remove", "--draft", str(draft),
                                    "--uri", DOCUMENT["shares"][0]["uri"]])
        with redirect_stdout(StringIO()) as result:
            self.assertEqual(bookmarks.manage(args, self.root / "active"), 0)
        self.assertEqual(len(json.loads(result.getvalue())["shares"]), 3)
        self.assertEqual(json.loads(draft.read_text()), DOCUMENT)

    def test_offline_login_does_not_probe_and_refreshes_bookmarks(self):
        draft = self.root / "draft.json"
        draft.write_text(json.dumps(DOCUMENT))
        args = ["omarchy-enterprise", "--state-dir", str(self.root / "state"),
                "policy-refresh", "--login", "--policy", str(draft)]
        with (patch("sys.argv", args), patch.dict(os.environ, {"XDG_CONFIG_HOME": str(self.config)}),
              patch("oe.graphical.apply_login_integrations", return_value=0),
              patch("oe.policy.effective_groups", return_value=set()),
              patch("socket.create_connection") as connect):
            self.assertEqual(main(), 0)
        connect.assert_not_called()
        self.assertIn("Other", self.book.read_text())
        self.assertNotIn("Department", self.book.read_text())

    def test_diagnostics_redacts_policy_data_and_does_not_write(self):
        with patch("shutil.which", return_value=None), redirect_stdout(StringIO()) as output:
            self.assertEqual(bookmarks.diagnostics(self.root / "missing"), 1)
        self.assertIn("Nautilus: unavailable", output.getvalue())
        self.assertNotIn(str(self.root), output.getvalue())
        self.assertEqual(list(self.root.iterdir()), [])

    def test_windows_actions_refuse_without_qualified_controller(self):
        with patch("oe.windows.subprocess.run") as run, redirect_stdout(StringIO()) as output:
            for action in ("start", "stop", "restart", "status", "settings"):
                self.assertEqual(windows.lifecycle(action), 1)
        self.assertIn("blocked", output.getvalue())
        run.assert_not_called()
