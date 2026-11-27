# SPDX-License-Identifier: MIT
"""Installed workflow reviews with no graphical privilege elevation."""

import platform
import shlex
from pathlib import Path

from gi.repository import Adw, Gtk

from .. import bookmarks, operational, operational_cups, operational_windows, pilot_session, product
from . import product as forms
from .localization import _
from .model import PROFILE_NAMES, state
from .widgets import button, dialog, entry, group, label, scrolled_text

ROUTES = frozenset(("installer", "files", "printers", "windows", "updates"))
PRINTER_STATES = {"Unknown": _("Unknown"), "Idle": _("Idle"), "Printing": _("Printing"),
                  "Disabled": _("Disabled")}
WINDOWS_STATES = {"created": _("created"), "running": _("running"), "exited": _("exited")}



def panel(center):
    container = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
    container.append(label(_("Installed administration"), "heading"))

    def show(title, rows, result):
        center.refresh()
        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        content.append(group(rows))
        advanced = Gtk.Expander(label=_("Advanced diagnostics"))
        advanced.set_child(scrolled_text(operational.encode(result)))
        content.append(advanced)
        dialog(center.window, title, _("Review the current plan and qualification status."), child=content)

    def preview(title, operation, summarize, capture=lambda: (), invalid=None):
        def click():
            args = capture()
            center.work(lambda _: operation(*args), lambda result: show(title, summarize(result), result),
                        invalid=invalid)

        container.append(button(title, click))

    fields = center.operational_fields

    def printing_option():
        check = Gtk.CheckButton(label=_("Include printing dependencies"), active=fields.get("printing", False))
        check.connect("toggled", lambda widget: fields.update(printing=widget.get_active()))
        container.append(check)
        return check

    if center.route == "installer":
        printing = printing_option()

        def inspect(profile, enabled):
            return product.workstation_review(Path("/"), packages=operational.dependencies(profile, enabled))

        def summary(result):
            rows = [(_("Workstation detection"), state(result["workflow"])),
                    (_("Omarchy version"), result["version"] or _("Unverified")),
                    (_("Architecture"), platform.machine()),
                    (_("Available system storage"), f'{result["available_bytes"] / 1024**3:.1f} GiB'),
                    (_("Live deployment"), state("BLOCKED"))]
            rows.extend((name, state(status)) for name, status in result["configuration"])
            rows.extend((name, state("AVAILABLE" if installed else "UNAVAILABLE"))
                        for name, installed in result["packages"].items())
            return rows

        enabled = lambda: printing.get_active() or bool(center.setup.printers.rows)
        preview(_("Review workstation prerequisites"), inspect, summary,
                lambda: (center.setup.profile, enabled()))
        if center.setup.step == 8:
            container.append(button(_("Review system policy handoff"), lambda: forms.handoff(
                center, center.setup.profile, enabled(), center.setup.draft)))
        container.append(label(_("Clean-host deployment unqualified. Domain enrollment blocked.")))
    elif center.route == "files":
        def review_bookmarks():
            source = operational.POLICY

            def review(_):
                before, resources, _ = pilot_session.bookmark_plan(source, read_only=True, operational=True)
                return before, resources

            def reviewed(result):
                center.refresh()
                before, resources = result

                def sync():
                    center.work(lambda _: pilot_session.integrate(
                        source, expected=(before, resources), confirm=lambda _: True, operational=True),
                        lambda _: completed(_("Managed bookmarks verified")), cancellable=False)

                dialog(center.window, _("Preview operational bookmarks"),
                       _("The preview uses the managed policy. Personal bookmarks are preserved."),
                       _("Synchronize login bookmarks"), sync,
                       child=group(list(resources.items()) or [(_("Eligible resources"), _("None"))]))

            center.work(review, reviewed)

        def completed(title):
            center.refresh()
            dialog(center.window, title, _("Personal bookmarks are preserved."))

        def recover(_):
            book, ledger = bookmarks.locations(operational=True)
            if not ledger.is_dir():
                return False
            with bookmarks.locked(book):
                return bool(bookmarks.recover(book, ledger))

        container.append(button(_("Preview operational bookmarks"), review_bookmarks))
        container.append(button(_("Restore managed bookmarks"), lambda: dialog(
            center.window, _("Roll back managed bookmarks?"), _("Personal bookmarks are preserved."),
            _("Restore managed bookmarks"), lambda: center.work(
                lambda _: pilot_session.rollback(confirm=lambda _: True, quiet=True, operational=True),
                lambda _: completed(_("Managed bookmarks verified")), cancellable=False))))
        container.append(button(_("Recover bookmark transaction"), lambda: dialog(
            center.window, _("Recover bookmark transaction"), _("Personal bookmarks are preserved."),
            _("Recover bookmark transaction"), lambda: center.work(
                recover, lambda result: completed(_("Managed bookmarks verified") if result else
                                                   _("No pending bookmark transaction")),
                cancellable=False))))
        def accept_bookmarks():
            def reviewed(accept):
                center.refresh()
                dialog(center.window, _("Accept managed bookmarks"),
                       _("Keep the current entries and finalize their rollback checkpoint."),
                       _("Accept managed bookmarks"), lambda: center.work(
                           lambda _: accept(), lambda _: completed(_("Managed bookmarks verified")),
                           cancellable=False))

            center.work(lambda _: pilot_session.bookmark_acceptance(), reviewed)

        container.append(button(_("Accept managed bookmarks"), accept_bookmarks))
        profiles = list(PROFILE_NAMES)
        selection = Gtk.DropDown.new_from_strings(list(PROFILE_NAMES.values()))
        selection.set_selected(profiles.index(fields.get("files_profile", "standalone")))
        selection.connect("notify::selected", lambda widget, _: fields.update(
            files_profile=profiles[widget.get_selected()]))
        container.append(label(_("Deployment profile")))
        container.append(selection)
        printing = printing_option()
        container.append(button(_("Review system policy handoff"), lambda: forms.handoff(
            center, profiles[selection.get_selected()], printing.get_active(), center.draft)))
        container.append(label("omarchy-enterprise operational login-plan", "monospace"))
    elif center.route == "printers":
        preview(_("Discover local CUPS queues"), lambda: operational_cups.Cups().queue_status(),
                lambda result: [(name, PRINTER_STATES[status]) for name, status in result.items()] or
                [(_("Installed queues"), _("None"))])
        container.append(forms.printer_editor(center, lambda: center.printers,
                          lambda value: setattr(center, "printers", value), center.refresh))

        def loaded(draft):
            center.printers = draft
            center.refresh()

        def saved(path):
            center.refresh()
            command = "/usr/bin/omarchy-enterprise-admin operational cups-create"
            source = shlex.quote(str(path))
            dialog(center.window, _("Printer definitions saved"),
                   _("Queue changes implemented but unqualified."),
                   child=scrolled_text(f"{command} < {source}"))

        def save_printers():
            draft = center.printers
            dialog(center.window, _("Save printer definitions"), _("Managed printer draft"),
                   _("Save"), lambda: center.work(lambda _: product.printer_draft(save=draft), saved,
                                                  cancellable=False))

        container.append(button(_("Save printer definitions"), save_printers))
        container.append(button(_("Load printer definitions"), lambda: center.work(
            lambda _: product.printer_draft(), loaded)))

        def review(document):
            return {"plan": operational_cups.Cups().review(document), **document}

        if center.printers.rows:
            preview(_("Review driverless queues"), review, lambda result: [
                (row["name"], row["uri"] + (" · " + _("Default") if row["name"] == result["default"] else ""))
                for row in result["printers"]
            ], lambda: (center.printers.document(),),
                    invalid=_("Check CUPS availability and choose queue names that are still free."))
        container.append(label(_("Queue changes implemented but unqualified.")))
    elif center.route == "windows":
        form = Adw.PreferencesGroup()
        container.append(form)
        specs = (
            ("image", _("Reviewed Dockur image digest"), ""),
            ("edition", _("Windows edition (11, 11l, 11e)"), "11"),
            ("cpu", _("Virtual CPUs"), "4"), ("memory", _("Memory in GiB"), "8"),
            ("disk", _("Disk in GiB"), "128"),
            ("storage", _("Dedicated storage directory"), str(operational_windows.STORAGE)),
            ("port", _("Loopback RDP port (optional)"), ""),
            ("certificate", _("Guest certificate DNS name"), ""),
            ("account", _("Guest account"), ""),
        )
        entries = [entry(form, title, fields.get(key, default), lambda value, key=key: fields.update({key: value}))
                   for key, title, default in specs]

        def windows(image, edition, cpu, memory, disk, storage, port, certificate, account):
            settings = operational_windows.Settings(image, int(cpu), int(memory), int(disk))
            return operational_windows.Dockur().configuration_review(
                settings, edition=edition, storage=storage, local_port=int(port) if port else None,
                certificate_name=certificate, account=account)

        preview(_("Review manually started Windows VM"), windows, lambda result: [
            (_("Disk in GiB"), str(result["disk_gib"])),
            (_("Storage filesystem"), result["storage"]["filesystem"]),
            (_("Available space"), _("Sufficient") if result["storage"]["sufficient_space"] else _("Insufficient")),
            (_("Windows guest connectivity"), result["rdp"]),
            (_("Startup policy"), state("MANUAL START ONLY")),
            (_("Lifecycle qualification"), state("BLOCKED")),
        ], lambda: tuple(row.get_text().strip() for row in entries),
                invalid=_("Check the image digest, resource sizes, storage path and optional guest endpoint."))
        preview(_("Discover managed Windows VM"), lambda: operational_windows.Dockur().discover(),
                lambda result: [(identity, WINDOWS_STATES[status]) for identity, status in result.items()] or
                [(_("Managed Windows VM"), _("None"))],
                invalid=_("Local managed-container discovery is unavailable in this session."))
        container.append(label("omarchy-enterprise operational windows-lifecycle-review CONTAINER_ID {start,stop}",
                               "monospace"))
        container.append(label(_("Container lifecycle implemented but unqualified. Inbound RDP blocked.")))
    else:
        container.append(label(_("Use a trusted administrator terminal to review drift and available rollback or recovery. Review a fresh token before approving each action.")))
        container.append(label("/usr/bin/omarchy-enterprise-admin operational status\n"
                               "/usr/bin/omarchy-enterprise-admin operational rollback\n"
                               "/usr/bin/omarchy-enterprise-admin operational recover\n"
                               "/usr/bin/omarchy-enterprise-admin operational abort\n"
                               "/usr/bin/omarchy-enterprise-admin operational ACTION --approve REVIEW_TOKEN",
                               "monospace"))
    return container
