"""Administrator-only policy publication for the separately installed pilot."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys

from . import policy, state

PREFIX = Path("/opt/omarchy-enterprise-pilot-10d4")
CENTRAL = Path("/etc/omarchy-enterprise/smb-policy.json")
LIMIT = 262144


def digest(text):
    return "absent" if text is None else hashlib.sha256(text.encode("utf-8")).hexdigest()


def apply(action, expected, document, *, central=CENTRAL):
    if os.geteuid() != 0:
        raise ValueError("Only an authorized administrator may publish central policy")
    policy.safe_directory(central.parent, system=True)
    if not central.parent.is_dir():
        raise ValueError("The approved central policy directory must already exist")
    directory = central.parent / ".pilot-policy-10d3"
    policy.safe_directory(directory, system=True)
    with state.Store(directory).locked():
        record = directory / "recovery.json"
        if os.path.lexists(central):
            policy.shares(policy.load_file(central, system=True), set())
        current = state.read(central)
        if digest(current) != expected:
            raise ValueError("Central policy drift; review the current local digest")
        saved = state.read(record, private=True)
        if action == "recover":
            if saved is None:
                raise ValueError("No pilot policy checkpoint")
            previous = json.loads(saved)
            if expected == previous["after"]:
                return  # Publication completed; retain the rollback record.
            if expected != digest(previous["before"]):
                raise ValueError("Policy diverged from both recorded states")
            state.write(record, None)
            return
        if action == "publish":
            if saved is not None:
                raise ValueError("An existing publication checkpoint requires rollback or local review")
            policy.shares(document, set())
            if document["version"] != 2:
                raise ValueError("The pilot publishes only version 2 policies")
            updated = json.dumps(document, indent=2) + "\n"
            state.write(record, json.dumps({"before": current, "after": digest(updated)}) + "\n")
        else:
            if saved is None:
                raise ValueError("No pilot policy checkpoint")
            previous = json.loads(saved)
            if expected != previous["after"]:
                raise ValueError("Published policy changed or was not installed; reconcile locally")
            updated = previous["before"]
            if updated is not None:
                policy.shares(json.loads(updated), set())
        if state.read(central) != current:
            raise ValueError("Central policy changed since validation")
        state.write(central, updated, mode=0o644)
        if state.read(central) != updated:
            raise ValueError("Policy verification failed; retain the private checkpoint")
        if action == "rollback":
            state.write(record, None)


def add_arguments(parser):
    parser.add_argument("action", choices=("publish", "rollback", "recover"))
    parser.add_argument("--expected", required=True)
    parser.add_argument("--confirm", action="store_true")
    return parser


def execute(args, *, product=False):
    expected_directory = (Path("/usr") if product else PREFIX) / "lib/omarchy-enterprise/oe"
    try:
        if os.geteuid() != 0 or Path(__file__).resolve().parent != expected_directory:
            raise ValueError("Use the authorized root-owned installed command")
        policy.safe_directory(Path(__file__).parent, system=True)
        if not args.confirm or not re.fullmatch(r"absent|[0-9a-f]{64}", args.expected):
            raise ValueError("Explicit authorization and the reviewed expected digest are required")
        document = None
        if args.action == "publish":
            raw = sys.stdin.buffer.read(LIMIT + 1)
            if len(raw) > LIMIT:
                raise ValueError("Policy draft is too large")
            document = json.loads(raw)
        apply(args.action, args.expected, document)
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        print("Policy operation stopped. Check authorization, validation, digest and private recovery locally.",
              file=sys.stderr)
        return 1
    print("Central policy operation verified.")
    return 0


def main():
    parser = add_arguments(argparse.ArgumentParser(description=__doc__))
    return execute(parser.parse_args())
