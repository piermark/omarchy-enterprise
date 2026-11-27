# SPDX-License-Identifier: MIT
"""Local CUPS queue plans and bounded administration."""

import re
import secrets
from urllib.parse import urlsplit

from . import operational, policy, state

SERVER = "/run/cups/cups.sock"
STAT = ("/usr/bin/lpstat", "-h", SERVER)
ADMIN = ("/usr/bin/lpadmin", "-h", SERVER)
QUEUE = re.compile(r"oe-[A-Za-z0-9][A-Za-z0-9_-]{0,59}")
DESTINATION = re.compile(r"[^\s/#]{1,127}")


def validate(document):
    if not isinstance(document, dict) or document.keys() != {"printers", "default"}:
        raise ValueError("Expected a printer list and optional default queue")
    rows = document["printers"]
    if not isinstance(rows, list) or not 1 <= len(rows) <= 32:
        raise ValueError("Expected 1–32 managed queues")
    names = set()
    for row in rows:
        if not isinstance(row, dict) or row.keys() != {"name", "uri"}:
            raise ValueError("Invalid managed queue")
        name, uri = row["name"], row["uri"]
        if not isinstance(name, str) or not QUEUE.fullmatch(name) or name.casefold() in names:
            raise ValueError("Expected unique managed queue names prefixed with oe-")
        names.add(name.casefold())
        if not isinstance(uri, str) or not re.fullmatch(
                r"ipps?://[A-Za-z0-9.-]+(?::631)?/ipp/[A-Za-z0-9_-]{1,64}", uri):
            raise ValueError("Expected a driverless IPP or IPPS endpoint")
        if not policy.HOST.fullmatch(urlsplit(uri).hostname):
            raise ValueError("A printer DNS name is required")
    if document["default"] is not None and document["default"] not in [row["name"] for row in rows]:
        raise ValueError("Select a default from the reviewed queues")


class Cups:
    def __init__(self, runner=operational.command):
        self.run = runner

    def query(self, *options):
        code, output = self.run((*STAT, *options))
        if code:
            raise ValueError("Local CUPS discovery failed")
        return output.splitlines()

    def queues(self):
        if self.query("-r") != ["scheduler is running"]:
            raise ValueError("Local CUPS scheduler is unavailable")
        queues = {}
        for line in self.query("-c"):
            match = re.fullmatch(r"members of class ([^\s]+):", line)
            if match and DESTINATION.fullmatch(match[1]):
                queues[match[1].casefold()] = match[1]
        for line in self.query("-v"):
            match = re.fullmatch(r"device for ([^\s]+): .+", line)
            if not match or not DESTINATION.fullmatch(match[1]):
                raise ValueError("Unexpected CUPS queue discovery response")
            queues[match[1].casefold()] = match[1]
        return queues

    def queue_status(self):
        queues = self.queues()
        result = dict.fromkeys(queues.values(), "Unknown")
        for line in self.query("-p"):
            match = re.match(r"^printer (\S+) (?:is (idle|printing)|(?:is )?(disabled))\b", line)
            if match and match[1] in result:
                result[match[1]] = {"idle": "Idle", "printing": "Printing", "disabled": "Disabled"}[
                    match[2] or match[3]]
        return result

    def current_default(self):
        lines = self.query("-d")
        if lines == ["no system default destination"]:
            return None
        if len(lines) == 1:
            match = re.fullmatch(r"system default destination: (\S+)", lines[0])
            if match and DESTINATION.fullmatch(match[1]):
                return match[1]
        raise ValueError("Unexpected CUPS default discovery response")

    def review(self, document):
        validate(document)
        queues = self.queues()
        commands = []
        for row in document["printers"]:
            if row["name"].casefold() in queues:
                raise ValueError("A reviewed name conflicts with an existing CUPS queue")
            commands.append([*ADMIN, "-p", row["name"], "-v", row["uri"],
                             "-m", "everywhere", "-o", "printer-is-shared=false", "-E"])
        before = self.current_default() if document["default"] else None
        if document["default"]:
            commands.append([*ADMIN, "-d", document["default"]])
        return {"commands": commands, "previous_default": before, "default": document["default"]}

    def execute(self, document, token, *, checkpoint, exclusive_administration=operational.qualification_required):
        # lpadmin is an upsert. Qualification must provide exclusive administration.
        exclusive_administration()
        plan = self.review(document)
        operational.require_approval(plan, token)
        created = []
        marker = "Omarchy Enterprise Phase 12 " + secrets.token_hex(16)
        for command in plan["commands"]:
            if command[len(ADMIN)] == "-p":
                command = [*command, "-D", marker]
            checkpoint({"status": "pending", "created": list(created), "command": command,
                        "previous_default": plan["previous_default"], "marker": marker})
            code, _ = self.run(tuple(command))
            if code:
                raise ValueError("CUPS action failed or was partial; reconcile the pending record")
            if command[len(ADMIN)] == "-p":
                name = command[len(ADMIN) + 1]
                if name.casefold() not in self.queues() or not self.owned(name, marker):
                    raise ValueError("New queue could not be verified; reconcile the pending record")
                created.append(name)
            elif self.current_default() != plan["default"]:
                raise ValueError("Default queue could not be verified")
        checkpoint({"status": "complete", "created": created, "default": plan["default"],
                    "previous_default": plan["previous_default"], "marker": marker})
        return created

    def execute_managed(self, document, token, journal, *,
                        exclusive_administration=operational.qualification_required):
        exclusive_administration()
        operational.administrator()
        operational.require_approval(self.review(document), token)
        return journal.run(lambda checkpoint: self.execute(
            document, token, checkpoint=checkpoint, exclusive_administration=exclusive_administration))

    def owned(self, name, marker):
        lines = self.query("-l", "-p", name)
        return [line.strip() for line in lines].count(f"Description: {marker}") == 1

    def endpoint(self, name):
        lines = self.query("-v", name)
        prefix = f"device for {name}: "
        if len(lines) != 1 or not lines[0].startswith(prefix):
            raise ValueError("Managed queue endpoint could not be verified")
        return lines[0][len(prefix):]

    def update_plan(self, receipt, name, before, after, *, undo=False):
        for uri in (before, after):
            validate({"printers": [{"name": name, "uri": uri}], "default": None})
        if before == after:
            raise ValueError("Choose a different printer endpoint")
        if not isinstance(receipt, dict) or receipt.get("status") != "complete":
            raise ValueError("A completed CUPS ownership receipt is required")
        marker = self._verify_owned_endpoint(receipt, name, before)
        self._verify_transition(receipt, name, before, after, undo)
        return {"operation": "CUPS endpoint update", "queue": name, "before": before, "after": after,
                "undo": undo,
                "marker": marker, "receipt": receipt,
                "command": [*ADMIN, "-p", name, "-v", after]}

    def _verify_owned_endpoint(self, receipt, name, uri):
        marker = receipt.get("marker", "")
        names = receipt.get("created")
        if (not isinstance(marker, str)
                or not re.fullmatch(r"Omarchy Enterprise Phase 12 [0-9a-f]{32}", marker)
                or not isinstance(names, list) or name not in names
                or self.queues().get(name.casefold()) != name
                or not self.owned(name, marker)
                or self.endpoint(name) != uri
                or self.query("-W", "not-completed", "-o", name)):
            raise ValueError("Queue ownership, endpoint or job state prevents the update")
        return marker

    @staticmethod
    def _verify_transition(receipt, name, before, after, undo):
        previous = receipt.get("last_update")
        if undo:
            if previous != {"queue": name, "before": after, "after": before}:
                raise ValueError("The requested rollback does not match the last endpoint update")
        elif previous is not None:
            raise ValueError("Resolve the previous endpoint update before making another")

    def update(self, name, before, after, token, journal, *, undo=False,
               exclusive_administration=operational.qualification_required):
        exclusive_administration()
        operational.administrator()

        def execute(checkpoint):
            receipt = journal.read()
            plan = self.update_plan(receipt, name, before, after, undo=undo)
            operational.require_approval(plan, token)
            transition = {"queue": name, "before": before, "after": after}
            checkpoint(receipt | {"status": "pending", "operation": "endpoint update",
                                  "transition": transition, "undo": undo})
            code, _ = self.run(tuple(plan["command"]))
            if code or self.endpoint(name) != after or not self.owned(name, plan["marker"]):
                raise ValueError("CUPS update may be partial; reconcile the pending receipt")
            complete = receipt.copy()
            if undo:
                del complete["last_update"]
            else:
                complete["last_update"] = transition
            checkpoint(complete)

        return journal.run(execute, allow_complete=True)

    def update_recovery_plan(self, receipt):
        if (not isinstance(receipt, dict) or receipt.get("status") != "pending"
                or receipt.get("operation") != "endpoint update" or type(receipt.get("undo")) is not bool):
            raise ValueError("No interrupted endpoint update is available")
        transition = receipt.get("transition")
        if not isinstance(transition, dict) or transition.keys() != {"queue", "before", "after"}:
            raise ValueError("Invalid interrupted endpoint update receipt")
        name, before, after = (transition[key] for key in ("queue", "before", "after"))
        for uri in (before, after):
            validate({"printers": [{"name": name, "uri": uri}], "default": None})
        observed = self.endpoint(name)
        if observed not in (before, after):
            raise ValueError("The current endpoint differs from both recorded states")
        completed = {key: value for key, value in receipt.items()
                     if key not in {"operation", "transition", "undo"}} | {"status": "complete"}
        self._verify_transition(completed, name, before, after, receipt["undo"])
        self._verify_owned_endpoint(completed, name, observed)
        if observed == after:
            if receipt["undo"]:
                del completed["last_update"]
            else:
                completed["last_update"] = transition
        return {"operation": "Reconcile CUPS endpoint receipt", "receipt": receipt,
                "observed_endpoint": observed, "completed": completed}

    def recover_update(self, token, journal, *, exclusive_administration=operational.qualification_required):
        exclusive_administration()
        operational.administrator()
        with journal.store.locked():
            plan = self.update_recovery_plan(journal.read())
            operational.require_approval(plan, token)
            state.write(journal.path, operational.encode(plan["completed"]))

    def rollback_plan(self, receipt):
        if receipt.get("status") != "complete" or "created" not in receipt:
            raise ValueError("Reconcile the interrupted CUPS operation manually")
        marker = receipt.get("marker", "")
        if not isinstance(marker, str) or not re.fullmatch(r"Omarchy Enterprise Phase 12 [0-9a-f]{32}", marker):
            raise ValueError("Unexpected CUPS ownership receipt")
        if receipt.get("last_update") is not None:
            raise ValueError("Roll back the last endpoint update before removing managed queues")
        names = receipt["created"]
        if (not isinstance(names, list) or len(names) > 32
                or any(not isinstance(name, str) or not QUEUE.fullmatch(name) for name in names)):
            raise ValueError("Invalid CUPS ownership receipt")
        queues = self.queues()
        default = self.current_default()
        previous = receipt["previous_default"]
        approved_default = receipt["default"]
        if previous is not None and (not isinstance(previous, str) or not DESTINATION.fullmatch(previous)):
            raise ValueError("Invalid previous CUPS default")
        if default in names and (default != approved_default or previous is None
                                 or queues.get(previous.casefold()) != previous):
            raise ValueError("Resolve the current default manually before rolling back")
        commands = []
        if default in names:
            commands.append([*ADMIN, "-d", previous])
        for name in names:
            observed = queues.get(name.casefold())
            if observed is None:
                continue
            if (observed != name or not self.owned(name, marker)
                    or self.query("-W", "not-completed", "-o", name)):
                raise ValueError("Queue ownership changed or jobs remain; review manually")
            commands.append([*ADMIN, "-x", name])
        return {"operation": "CUPS rollback", "commands": commands,
                "observed_default": default, "marker": marker}

    def rollback(self, token, journal, *, exclusive_administration=operational.qualification_required):
        exclusive_administration()
        operational.administrator()

        def review():
            receipt = journal.read()
            if receipt is None:
                raise ValueError("No managed CUPS receipt")
            plan = self.rollback_plan(receipt)
            operational.require_approval(plan, token)
            return receipt, plan

        def execute(checkpoint):
            receipt, plan = review()
            for command in plan["commands"]:
                checkpoint(receipt | {"status": "pending", "operation": "rollback", "command": command})
                code, _ = self.run(tuple(command))
                if code:
                    raise ValueError("CUPS rollback may be partial; reconcile the pending receipt")
                if command[len(ADMIN)] == "-x" and command[-1].casefold() in self.queues():
                    raise ValueError("Queue removal could not be verified")
                if command[len(ADMIN)] == "-d" and self.current_default() != command[-1]:
                    raise ValueError("Default restoration could not be verified")
            checkpoint({"status": "complete", "operation": "rollback"})

        review()
        journal.run(execute, allow_complete=True)
