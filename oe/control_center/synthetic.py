# SPDX-License-Identifier: MIT
"""GTK review and approval for disposable administration actions."""

from copy import deepcopy
import json
from pathlib import Path

from gi.repository import Adw, Gtk

from ..phase11 import Action, Request, Role, Workspace
from ..phase11_resources import EMPTY_PRINTERS, EMPTY_SHARES
from .localization import _
from .widgets import button, dialog, entry, label, scrolled_text

ACTIONS = {
    "installer": (Action.DEPLOY, Action.ROLLBACK, Action.RESUME, Action.ABORT),
    "updates": (Action.ROLLBACK, Action.RESUME, Action.ABORT, Action.BOOKMARK_RECOVER),
    "files": (Action.SHARE_EDIT, Action.LOGIN_SYNC, Action.BOOKMARK_ROLLBACK, Action.BOOKMARK_RECOVER),
    "printers": (Action.PRINTERS,),
    "windows": (Action.WINDOWS, Action.START, Action.STOP),
}
ACTION_LABELS = {
    Action.DEPLOY: _("Plan deployment"),
    Action.ROLLBACK: _("Roll back configuration"),
    Action.RESUME: _("Resume transaction"),
    Action.ABORT: _("Abort transaction"),
    Action.SHARE_EDIT: _("Edit share policy"),
    Action.LOGIN_SYNC: _("Synchronize login bookmarks"),
    Action.BOOKMARK_ROLLBACK: _("Restore managed bookmarks"),
    Action.BOOKMARK_RECOVER: _("Recover bookmark transaction"),
    Action.PRINTERS: _("Configure printer queues"),
    Action.WINDOWS: _("Configure Windows VM"),
    Action.START: _("Simulate VM start"),
    Action.STOP: _("Simulate VM stop"),
}
ROLE_LABELS = (_("Viewer"), _("Operator"), _("Administrator"))

WINDOWS = {"name": "Example", "cpu": 4, "ram_mib": 8192, "disk_gib": 64,
           "storage": "ExampleDisk", "network": "isolated"}


def sample(action, profile):
    if action is Action.DEPLOY:
        capabilities = ["omarchy", "python"]
        if profile != "standalone":
            capabilities.extend(("directory-preview", "kerberos-preview"))
        if profile == "full-enterprise":
            capabilities.extend(("virtualization", "windows-license"))
        return {"profile": profile, "capabilities": capabilities, "shares": deepcopy(EMPTY_SHARES),
                "printers": deepcopy(EMPTY_PRINTERS), "windows": None}
    if action is Action.WINDOWS:
        return deepcopy(WINDOWS)
    if action in {Action.START, Action.STOP}:
        return {"identity": ""}
    if action is Action.SHARE_EDIT:
        return {"target": None, "replacement": {"uri": "smb://files.example.com/team",
                                                "label": "Example", "groups": ["staff"]}}
    if action is Action.LOGIN_SYNC:
        return {"groups": ["staff"]}
    if action is Action.PRINTERS:
        return {"printers": [{"name": "Example", "uri": "ipps://print.example.com/ipp/print"}],
                "default": "Example"}
    return {}


def rendered(value):
    return json.dumps(value, indent=2, sort_keys=True)


def panel(center):
    route = center.route
    actions = ACTIONS[route]
    container = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
    container.append(label(_("Disposable administration"), "heading"))
    form = Adw.PreferencesGroup()
    target = entry(form, _("Disposable target"), center.synthetic_target,
                   lambda value: setattr(center, "synthetic_target", value))
    container.append(form)

    def create():
        center.work(lambda _: Workspace.create(), use_target, cancellable=False)

    def use_target(workspace):
        center.synthetic_target = str(workspace.directory)
        center.refresh()

    def report(value):
        center.refresh()
        dialog(center.window, _("Disposable target status"), _("Synthetic backend"),
               child=scrolled_text(rendered(value)))

    def inspect():
        path = Path(target.get_text())
        center.work(lambda _: Workspace(path).status(), report)

    if not center.dry_run:
        container.append(button(_("Create disposable target"), create))
    container.append(button(_("Inspect disposable target"), inspect))
    action_selector = Gtk.DropDown.new_from_strings([ACTION_LABELS[action] for action in actions])
    role_selector = Gtk.DropDown.new_from_strings(list(ROLE_LABELS))
    for selector in (action_selector, role_selector):
        selector.set_halign(Gtk.Align.START)
    container.append(label(_("Action")))
    container.append(action_selector)
    container.append(label(_("Synthetic role")))
    container.append(role_selector)
    editor = Gtk.TextView(editable=False, monospace=True, wrap_mode=Gtk.WrapMode.WORD_CHAR)
    scroll = Gtk.ScrolledWindow(min_content_height=130, max_content_height=240,
                                propagate_natural_height=True, child=editor)
    advanced = Gtk.Expander(label=_("Advanced diagnostics"))
    advanced.set_child(scroll)
    structured = Adw.PreferencesGroup()
    container.append(structured)
    container.append(advanced)
    fields = []
    buffer = editor.get_buffer()

    def chosen():
        return actions[action_selector.get_selected()]

    def populate(*_signal):
        for row, _path, _initial in fields:
            structured.remove(row)
        fields.clear()
        value = sample(chosen(), center.setup.profile)
        specs = {
            Action.WINDOWS: [(("name",), _("VM name")), (("cpu",), _("Virtual CPUs")),
                             (("ram_mib",), _("Memory in MiB")), (("disk_gib",), _("Disk in GiB")),
                             (("storage",), _("Disposable storage name"))],
            Action.START: [(("identity",), _("Managed container ID"))],
            Action.STOP: [(("identity",), _("Managed container ID"))],
            Action.SHARE_EDIT: [(("target",), _("Existing SMB URL")),
                                (("replacement", "uri"), _("SMB hostname or share URL")),
                                (("replacement", "label"), _("Friendly label")),
                                (("replacement", "groups"), _("Qualified groups, comma separated"))],
            Action.LOGIN_SYNC: [(("groups",), _("Qualified groups, comma separated"))],
            Action.PRINTERS: [(("printers", 0, "name"), _("Managed queue name")),
                              (("printers", 0, "uri"), _("IPP or IPPS endpoint")),
                              (("default",), _("Default queue"))],
        }
        for path, title in specs.get(chosen(), ()):
            initial = value
            for part in path:
                initial = initial[part]
            text = ", ".join(initial) if isinstance(initial, list) else str(initial or "")
            fields.append((entry(structured, title, text, update_diagnostics), path, initial))
        buffer.set_text(rendered(value))

    def payload():
        value = sample(chosen(), center.setup.profile)
        for row, path, initial in fields:
            record = value
            for part in path[:-1]:
                record = record[part]
            text = row.get_text()
            if type(initial) is int:
                record[path[-1]] = int(text)
            elif isinstance(initial, list):
                record[path[-1]] = [item.strip() for item in text.split(",") if item.strip()]
            else:
                record[path[-1]] = (text or None) if initial is None or path == ("default",) else text
        return value

    def update_diagnostics(_value):
        try:
            buffer.set_text(rendered(payload()))
        except ValueError:
            buffer.set_text(_("Review the action fields."))

    action_selector.connect("notify::selected", populate)
    populate()

    def review():
        path = Path(target.get_text())
        action = chosen()
        role = tuple(Role)[role_selector.get_selected()]
        try:
            document = payload()
        except (ValueError, RecursionError):
            dialog(center.window, _("Invalid input"), _("Review the action fields."))
            return

        def preview(_):
            request = Request(action, role, document)
            backend = Workspace(path)
            return backend, request, backend.plan(request)[0]

        def confirm(result):
            backend, request, preview = result
            center.refresh()
            approval = preview.pop("approval")
            details = scrolled_text(rendered(preview))
            if approval and not center.dry_run:
                def apply(_):
                    backend.apply(request, approval)
                    return backend.status()

                dialog(center.window, _("Review synthetic changes"), _("Apply the reviewed action to this disposable target?"),
                       _("Apply"), lambda: center.work(apply, report, cancellable=False), child=details)
            else:
                dialog(center.window, _("Review synthetic changes"), _("Preview only"), child=details)

        center.work(preview, confirm)

    container.append(button(_("Preview synthetic action"), review, suggested=True))
    return container
