"""Command-line interface to the independent synthetic administration workflows."""

import json
from pathlib import Path
import sys

from .phase11 import Action, Request, Role, Workspace


def add_arguments(parser):
    commands = parser.add_subparsers(dest="operation", required=True)
    commands.add_parser("init")
    commands.add_parser("status").add_argument("target", type=Path)
    for name in ("preview", "apply"):
        command = commands.add_parser(name)
        command.add_argument("target", type=Path)
        command.add_argument("action", type=Action, choices=list(Action),
                             metavar="{" + ",".join(action.value for action in Action) + "}")
        command.add_argument("--role", type=Role, choices=list(Role), default=Role.VIEWER,
                             metavar="{viewer,operator,administrator}")
        command.add_argument("--input", action="store_true", help="read synthetic JSON from stdin")
        if name == "apply":
            command.add_argument("--approve", required=True, metavar="PREVIEW_TOKEN")


def execute(args):
    if args.operation == "init":
        result = {"target": str(Workspace.create().directory)}
    else:
        workspace = Workspace(args.target)
        if args.operation == "status":
            result = workspace.status()
        else:
            raw = sys.stdin.buffer.read(65537) if args.input else b"{}"
            if len(raw) > 65536:
                raise ValueError("Synthetic input exceeds the size limit")
            request = Request(args.action, args.role, json.loads(raw))
            if args.operation == "preview":
                result = workspace.plan(request)[0]
            else:
                workspace.apply(request, args.approve)
                result = workspace.status()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0
