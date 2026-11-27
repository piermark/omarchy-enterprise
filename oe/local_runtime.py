# SPDX-License-Identifier: MIT
"""Bounded Linux process groups for trusted local fixtures."""
from dataclasses import dataclass
import errno
import fcntl
import math
import os
from pathlib import Path
import re
import shutil
import stat
import signal
import subprocess
import tempfile
from time import monotonic, sleep

from . import policy
from .state import Store

NAME = re.compile(r"local-session-[a-z0-9_]{8}")


@dataclass(frozen=True)
class Usage:
    returncode: int
    elapsed: float
    user_seconds: float
    system_seconds: float
    peak_rss_kib: int
    output_bytes: int


class LocalRuntime:
    """One process group, owned by this caller until the child is reaped.

    Commands must be trusted and keep descendants in the original group.
    An inherited lease protects directories during cooperating orphan activity.
    """

    def __init__(self, parent):
        self.parent = Store(Path(parent).absolute())
        self.directory = None
        self.process = None
        self.lease = None
        self.usage = None
        self.output = bytearray()

    @staticmethod
    def _remove_unleased(directory):
        try:
            if not Store(directory).validate_directory():
                return False
            fd = os.open(directory / ".lease", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, "rb") as lease:
                info = os.fstat(lease.fileno())
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                        or info.st_mode & 0o077 or info.st_nlink != 1):
                    return False
                fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
                shutil.rmtree(directory)
                return True
        except (FileNotFoundError, BlockingIOError, ValueError):
            return False
        except OSError as error:
            if error.errno == errno.ELOOP:
                return False
            raise

    @staticmethod
    def reconcile(parent):
        """Remove abandoned fixture directories with no surviving lease holder."""
        store = Store(Path(parent).absolute())
        policy.safe_directory(store.directory)
        with store.locked():
            return sum(LocalRuntime._remove_unleased(directory)
                       for directory in store.directory.iterdir() if NAME.fullmatch(directory.name))

    def __enter__(self):
        if self.directory is not None:
            raise ValueError("The local runtime instance has already been used")
        policy.safe_directory(self.parent.directory)
        with self.parent.locked():
            self.directory = Path(tempfile.mkdtemp(prefix="local-session-", dir=self.parent.directory))
            try:
                fd = os.open(self.directory / ".lease", os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                self.lease = os.fdopen(fd, "wb")
                fcntl.flock(self.lease, fcntl.LOCK_EX)
            except BaseException:
                if self.lease is not None:
                    self.lease.close()
                shutil.rmtree(self.directory)
                raise
        return self

    def __exit__(self, *_):
        self.stop()
        with self.parent.locked():
            self.lease.close()
            self._remove_unleased(self.directory)

    @staticmethod
    def _duration(value):
        if type(value) not in (int, float) or not math.isfinite(value) or not 0 < value <= 3600:
            raise ValueError("Use a positive deadline of at most one hour")
        return value

    def start(self, argv, *, timeout, startup_timeout=None, ready=None, cancelled=None,
              output_limit=65536, env=None):
        if (self.lease is None or self.lease.closed or self.process is not None
                or self.usage is not None or not 0 <= output_limit <= 1048576):
            raise ValueError("Expected a fresh local runtime and a bounded output limit")
        if (startup_timeout is None) != (ready is None):
            raise ValueError("Provide both a readiness check and startup timeout")
        self.started = monotonic()
        self.deadline = self.started + self._duration(timeout)
        startup = min(self.deadline, self.started + self._duration(startup_timeout)) if ready else None
        self.cancelled = cancelled
        self.output_limit = output_limit
        self._check(self.deadline, "Local process deadline expired")
        self.process = subprocess.Popen(argv, cwd=self.directory,
                                        env={"PATH": "/usr/bin", "LC_ALL": "C"} if env is None else env,
                                        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                        stderr=subprocess.DEVNULL, start_new_session=True,
                                        pass_fds=(self.lease.fileno(),))
        try:
            os.set_blocking(self.process.stdout.fileno(), False)
            if ready is not None:
                while True:
                    self._check(startup, "Local process startup deadline expired")
                    self._read()
                    if self._exited():
                        raise RuntimeError("Local process exited before readiness")
                    if ready(self.directory):
                        self._check(startup, "Local process startup deadline expired")
                        break
                    sleep(0.01)
        except BaseException:
            self.stop()
            raise

    def _check(self, deadline, message):
        if self.cancelled is not None and self.cancelled.is_set():
            raise InterruptedError("Local process cancelled")
        if monotonic() >= deadline:
            raise TimeoutError(message)

    def _read(self):
        chunk = self.process.stdout.read(65536)
        if chunk:
            if len(self.output) + len(chunk) > self.output_limit:
                raise RuntimeError("Local process exceeded its output limit")
            self.output.extend(chunk)
        return bool(chunk)

    def _exited(self):
        # Keep the leader PID reserved until all group signals have been sent.
        return os.waitid(os.P_PID, self.process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)

    def wait(self):
        if self.process is None:
            raise ValueError("No local process is running")
        try:
            while True:
                self._check(self.deadline, "Local process deadline expired")
                self._read()
                if self._exited():
                    while self._read():
                        self._check(self.deadline, "Local process deadline expired")
                    break
                sleep(0.01)
        finally:
            self.stop()
        return self.usage

    def _signal(self, sig):
        try:
            os.killpg(self.process.pid, sig)
        except ProcessLookupError:
            pass

    def stop(self, *, grace=0.25):
        if self.process is None:
            return
        grace = self._duration(grace)
        self._signal(signal.SIGTERM)
        deadline = monotonic() + grace
        while not self._exited() and monotonic() < deadline:
            sleep(0.01)
        # A leader may exit before its descendants.
        self._signal(signal.SIGKILL)
        deadline = monotonic() + 3
        while True:
            pid, code, usage = os.wait4(self.process.pid, os.WNOHANG)
            if pid:
                break
            if monotonic() >= deadline:
                raise TimeoutError("Local process could not be reaped")
            sleep(0.01)
        self.process.returncode = os.waitstatus_to_exitcode(code)
        self.usage = Usage(self.process.returncode, monotonic() - self.started,
                           usage.ru_utime, usage.ru_stime, usage.ru_maxrss, len(self.output))
        self.process.stdout.close()
        self.process = None
