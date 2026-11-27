# SPDX-License-Identifier: MIT
import os
from pathlib import Path
import signal
import subprocess
import sys
from tempfile import TemporaryDirectory
from threading import Event
import unittest

from oe.local_runtime import LocalRuntime


class LocalRuntimeTest(unittest.TestCase):
    def setUp(self):
        parent = TemporaryDirectory()
        self.addCleanup(parent.cleanup)
        self.parent = Path(parent.name)

    def test_separate_instances_accounting_and_reconciliation(self):
        with LocalRuntime(self.parent) as first, LocalRuntime(self.parent) as second:
            stale = self.parent / "local-session-abcd1234"
            stale.mkdir(mode=0o700)
            (stale / ".lease").touch(mode=0o600)
            first.start([sys.executable, "-c", "print('first')"], timeout=2)
            second.start([sys.executable, "-c", "print('second')"], timeout=2)
            self.assertEqual(LocalRuntime.reconcile(self.parent), 1)
            self.assertNotEqual(first.directory, second.directory)
            self.assertEqual(first.directory.stat().st_mode & 0o777, 0o700)
            self.assertEqual(first.wait().output_bytes, 6)
            self.assertEqual(second.wait().returncode, 0)
            self.assertGreater(first.usage.peak_rss_kib, 0)
            self.assertEqual(first.output, b"first\n")
            self.assertEqual(second.output, b"second\n")
        self.assertFalse(first.directory.exists())
        self.assertFalse(second.directory.exists())

    def test_deadline_failed_startup_and_output_limit(self):
        argv = [sys.executable, "-c", "import time; time.sleep(30)"]
        with LocalRuntime(self.parent) as runtime:
            with self.assertRaisesRegex(TimeoutError, "startup"):
                runtime.start(argv, timeout=2, startup_timeout=0.05, ready=lambda _: False)
            self.assertIsNone(runtime.process)
        self.assertFalse(runtime.directory.exists())
        with LocalRuntime(self.parent) as runtime:
            runtime.start(argv, timeout=0.05)
            with self.assertRaisesRegex(TimeoutError, "deadline"):
                runtime.wait()
            self.assertEqual(runtime.usage.returncode, -signal.SIGTERM)
        with LocalRuntime(self.parent) as runtime:
            runtime.start([sys.executable, "-c", "print('excess')"], timeout=2, output_limit=1)
            with self.assertRaisesRegex(RuntimeError, "output limit"):
                runtime.wait()
            self.assertIsNone(runtime.process)

    def test_cancel_gracefully_and_escalate_for_unresponsive_child(self):
        for handler, expected in (("lambda *_: sys.exit(7)", 7), ("signal.SIG_IGN", -signal.SIGKILL)):
            with self.subTest(handler=handler), LocalRuntime(self.parent) as runtime:
                cancel = Event()
                code = ("import signal, sys, time; from pathlib import Path; "
                        f"signal.signal(signal.SIGTERM, {handler}); "
                        "Path('ready').touch(); time.sleep(30)")
                runtime.start([sys.executable, "-c", code], timeout=3, startup_timeout=2,
                              ready=lambda path: (path / "ready").exists(), cancelled=cancel)
                pid = runtime.process.pid
                cancel.set()
                with self.assertRaises(InterruptedError):
                    runtime.wait()
                self.assertEqual(runtime.usage.returncode, expected)
                with self.assertRaises(ChildProcessError):
                    os.waitpid(pid, os.WNOHANG)

    def test_inherited_lease_defers_cleanup_until_holder_exits(self):
        with LocalRuntime(self.parent) as runtime:
            lease_fd = runtime.lease.fileno()
            with subprocess.Popen([sys.executable, "-c", "input()"],
                                  stdin=subprocess.PIPE, pass_fds=(lease_fd,)) as holder:
                runtime.lease.close()
                self.assertEqual(LocalRuntime.reconcile(self.parent), 0)
                holder.communicate(b"done\n", timeout=2)
            self.assertEqual(LocalRuntime.reconcile(self.parent), 1)
