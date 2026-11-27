# SPDX-License-Identifier: MIT
"""Recoverable transactions for project-owned text files."""

import errno
import fcntl
import json
import os
import stat
import tempfile
from contextlib import contextmanager
from pathlib import Path


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def read(path, *, private=False):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    except OSError as error:
        if error.errno == errno.ELOOP:
            raise ValueError(f"Expected a regular file: {path}") from error
        raise
    with os.fdopen(fd, "r", encoding="utf-8", newline="") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise ValueError(f"Expected a regular file: {path}")
        if private and (info.st_uid != os.getuid() or info.st_mode & 0o077 or info.st_nlink != 1):
            raise ValueError("The transaction record must be private and user-owned")
        return stream.read()


def write(path, content, *, mode=0o600):
    if content is None:
        path.unlink(missing_ok=True)
    else:
        fd, temporary = tempfile.mkstemp(dir=path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(content)
                stream.flush()
                os.fchmod(stream.fileno(), mode)
                os.fsync(stream.fileno())
            os.replace(temporary, path)
        finally:
            Path(temporary).unlink(missing_ok=True)
    sync_directory(path.parent)


class Store:
    names = {"profile.json", "resources.json"}
    empty = {name: None for name in names}

    def __init__(self, directory):
        self.directory = directory
        self.journal = directory / "pending.json"

    def validate_directory(self):
        try:
            info = self.directory.lstat()
        except FileNotFoundError:
            return False
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o077):
            raise ValueError("State directory must be private and owned by the current user")
        return True

    @contextmanager
    def locked(self, *, nonblocking=False):
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.validate_directory()
        fd = os.open(self.directory / ".lock",
                     os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        with os.fdopen(fd, "r") as lock:
            metadata = os.fstat(lock.fileno())
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid()
                    or metadata.st_mode & 0o077 or metadata.st_nlink != 1):
                raise ValueError("The transaction lock must be a private, user-owned regular file")
            fcntl.flock(lock, fcntl.LOCK_EX | (fcntl.LOCK_NB if nonblocking else 0))
            yield

    def file_path(self, name):
        return self.directory / name

    def set_file(self, name, content):
        write(self.file_path(name), content)

    def snapshot(self):
        return {name: read(self.file_path(name)) for name in self.names}

    def valid_snapshot(self, value):
        return (isinstance(value, dict) and value.keys() == self.names
                and all(content is None or isinstance(content, str) for content in value.values()))

    def check_history(self, history):
        while history is not None:
            if (not isinstance(history, dict) or history.keys() != {"before", "after", "previous"}
                    or not self.valid_snapshot(history["before"])
                    or not self.valid_snapshot(history["after"])):
                raise ValueError("Invalid transaction history")
            history = history["previous"]

    def read_record(self, path):
        content = read(path, private=True)
        if content is None:
            return None
        try:
            record = json.loads(content)
        except (ValueError, RecursionError) as error:
            raise ValueError("Invalid transaction record") from error
        if not isinstance(record, dict):
            raise ValueError("Invalid transaction record")
        return record

    def history(self):
        history = self.read_record(self.directory / "history.json")
        self.check_history(history)
        return history

    def recovery_state(self, record):
        if (not {"before", "after", "history"} <= record.keys()
                or not self.valid_snapshot(record["before"])
                or not self.valid_snapshot(record["after"])):
            raise ValueError("Invalid pending transaction")
        self.check_history(record["history"])
        self.check_history(record.get("before_history"))
        history = record["history"]
        if record["after"] != (history["after"] if history else self.empty):
            raise ValueError("Pending transaction does not match its history")
        if "before_history" in record:
            previous = record["before_history"]
            if record["before"] != (previous["after"] if previous else self.empty):
                raise ValueError("Pending transaction does not match its previous history")
        if "aborted" in record and type(record["aborted"]) is not bool:
            raise ValueError("Invalid pending transaction")
        actual = self.snapshot()
        if any(actual[name] not in (record["before"][name], record["after"][name])
               for name in self.names):
            raise ValueError("Managed file changed during recovery")
        return actual

    def recover(self, *, abort=False):
        record = self.read_record(self.journal)
        if record is None:
            return False
        actual = self.recovery_state(record)
        if abort and not record.get("aborted"):
            if "before_history" not in record:
                raise ValueError("Complete the legacy transaction before rolling it back")
            record = {
                "before": record["after"],
                "after": record["before"],
                "history": record["before_history"],
                "aborted": True,
            }
            write(self.journal, json.dumps(record))
        for name in sorted(self.names):
            if actual[name] != record["after"][name]:
                self.set_file(name, record["after"][name])
        history = record["history"]
        write(self.directory / "history.json", json.dumps(history) if history else None)
        write(self.journal, None)
        return True

    def change(self, **updates):
        if set(updates) - self.names:
            raise ValueError("Unknown managed file")
        self.recover()
        before = self.snapshot()
        previous = self.history()
        expected = previous["after"] if previous else self.empty
        if before != expected:
            raise ValueError("Managed files differ from the recorded state")
        after = before | updates
        if before != after:
            history = {"before": before, "after": after, "previous": previous}
            self.commit(before, after, history)

    def commit(self, before, after, history):
        record = {"before": before, "after": after, "history": history,
                  "before_history": self.history()}
        write(self.journal, json.dumps(record))
        self.recover()

    def rollback(self):
        self.recover()
        history = self.history()
        if history is None:
            return False
        actual = self.snapshot()
        if actual != history["after"]:
            raise ValueError("Managed files differ from the recorded state")
        self.commit(actual, history["before"], history["previous"])
        return True
