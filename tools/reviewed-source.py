#!/usr/bin/env python3
"""Copy one explicitly selected and manually sanitized local source file."""

import argparse
import hashlib
import os
import re
import stat
from pathlib import Path

SUFFIXES = {".py", ".sh", ".md", ".json", ".desktop", ".service", ".timer"}
LIMIT = 512 * 1024


def read_candidate(path):
    if path.suffix not in SUFFIXES:
        raise ValueError("Unsupported source extension")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as file:
        if not stat.S_ISREG(os.fstat(file.fileno()).st_mode):
            raise ValueError("Expected a regular source file")
        data = file.read(LIMIT + 1)
    if len(data) > LIMIT or b"\0" in data:
        raise ValueError("Expected a bounded text source file")
    data.decode("utf-8")
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("candidate", type=Path)
    parser.add_argument("--approved-sha256")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if bool(args.approved_sha256) != bool(args.output):
        parser.error("Export requires both --approved-sha256 and --output")
    try:
        data = read_candidate(args.candidate)
        digest = hashlib.sha256(data).hexdigest()
        if args.output is None:
            print(digest)
            return 0
        if digest != args.approved_sha256:
            raise ValueError("The candidate differs from the reviewed bytes")
        if (args.output.suffix != args.candidate.suffix
                or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]*", args.output.name)):
            raise ValueError("Use a sanitized destination filename with the same extension")
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, "wb") as file:
                file.write(data)
                file.flush()
                os.fsync(file.fileno())
        except OSError:
            args.output.unlink(missing_ok=True)
            raise
    except (OSError, ValueError):
        parser.exit(1, "Source review failed. Check the file type, approval hash and destination.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
