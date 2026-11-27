#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Open synthetic native pages and print a shareable, redacted summary.

Provide an isolated display explicitly. The fixture never loads installed
configuration, private state, service information or real policy.
"""
from pathlib import Path
import os
import sys
from tempfile import TemporaryDirectory

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from oe.control_center.launcher import native


def main():
    if os.environ.get("OE_CONTROL_CENTER_TEST_DISPLAY") != "1" or not native():
        print("Phase 10M synthetic GTK smoke: NOT TESTED (isolated display unavailable)")
        return 77

    from gi.repository import GLib
    from oe.control_center.app import Center
    from oe.control_center.model import PAGES, View, state
    from oe.state import Store

    class Fixture:
        def __getattr__(self, route):
            return lambda _: View(((PAGES[route][0], state("NOT TESTED")),
                                  ("Synthetic fixture", state("ACCESS RESTRICTED"))))

        def file_status(self, _):
            return (state("CONFIGURED"), {"Example Share": "smb://files.example.com/share"}), state("UNAVAILABLE")

    with TemporaryDirectory(prefix="oe-control-center-smoke-") as work:
        folder = Path(work)
        app = Center(Store(folder / "state"), folder / "policy.json", backend=Fixture())
        app.setup.requirements = lambda: ({"Synthetic prerequisite": True}, ())
        remaining = iter(PAGES)
        waiting = False
        completed = 0
        failure = False

        def advance():
            nonlocal waiting, completed, failure
            try:
                if not app.get_active_window() or app.jobs.current:
                    return True
                if waiting:
                    assert app.body.get_last_child() != app.body.get_first_child()
                    completed += 1
                    waiting = False
                route = next(remaining, None)
                if route:
                    app.sidebar.select_row(app.entries[route])
                    assert app.route == route
                    waiting = True
                    return True
                app.window.set_default_size(550, 560)
                app.setup_move(1)
                app.setup_move(1)
                app.setup_move(-1)
                assert app.setup.step == 1
            except Exception:
                failure = True
            app.quit()
            return False

        def timeout():
            app.quit()
            return False

        GLib.timeout_add(70, advance)
        GLib.timeout_add_seconds(8, timeout)
        result = app.run([])
        app.jobs.close()
        if result or failure or completed != len(PAGES):
            print("Phase 10M synthetic GTK smoke: FAIL")
            return 1
        print(f"Phase 10M synthetic GTK smoke: PASS ({completed} routes; installer forward/back)")
        print("Host configuration, services and physical workflows: NOT TESTED")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
