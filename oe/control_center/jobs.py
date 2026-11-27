"""Run bounded backend probes off the UI thread and discard stale results."""
from concurrent.futures import ThreadPoolExecutor
import os
import signal
import subprocess
from time import monotonic
from threading import Event


class Jobs:
    def __init__(self, dispatch):
        self.dispatch = dispatch
        self.pool = ThreadPoolExecutor(max_workers=2)
        self.current = None
        self.closed = False

    def cancel(self):
        if self.current:
            token, future, cancellable = self.current
            if not cancellable:
                return False
            token.set()
            future.cancel()
            self.current = None
        return True

    def start(self, operation, completed, *, cancellable=True):
        if self.closed or not self.cancel():
            return False
        token = Event()
        future = self.pool.submit(operation, token)
        self.current = token, future, cancellable

        def deliver():
            if not self.closed and self.current and self.current[0] is token:
                self.current = None
                try:
                    value = future.result()
                except Exception as error:
                    completed(None, error)
                else:
                    completed(value, None)
            return False

        future.add_done_callback(lambda _: self.dispatch(deliver))
        return True

    def close(self):
        self.closed = True
        self.cancel()
        self.pool.shutdown(wait=False, cancel_futures=True)


def run_process(arguments, token, *, timeout, env):
    """Cancel a subprocess and its private group without leaving descendants."""
    if token.is_set():
        raise InterruptedError
    with subprocess.Popen(arguments, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, text=True, errors="replace",
                          start_new_session=True) as process:
        deadline = monotonic() + timeout
        try:
            while not token.is_set() and monotonic() < deadline:
                try:
                    output, errors = process.communicate(timeout=0.2)
                except subprocess.TimeoutExpired:
                    continue
                return subprocess.CompletedProcess(arguments, process.returncode, output, errors)
            if token.is_set():
                raise InterruptedError
            raise subprocess.TimeoutExpired(arguments, timeout)
        finally:
            if process.returncode is None:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                    process.communicate(timeout=0.6)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                except ProcessLookupError:
                    pass
