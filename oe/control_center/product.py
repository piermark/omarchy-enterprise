# SPDX-License-Identifier: MIT
"""Structured product forms and explicit administrator handoff."""

from gi.repository import Adw, Gtk

from .. import directory, product
from .localization import _
from .widgets import button, dialog, entry, group, label, scrolled_text


def handoff(center, profile, printing, shares):
    try:
        data = product.deployment_payload(profile, printing, shares)
    except ValueError:
        dialog(center.window, _("Review unavailable"), _("Check the SMB entries and deployment profile."))
        return
    content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
    content.append(group(((_("Selected profile"), profile),
                          (_("Printing dependencies"), _("Included") if printing else _("Optional")))))
    content.append(group([(row["label"], row["uri"] + "\n" + (", ".join(row["groups"]) or _("All users")))
                          for row in shares["shares"]], _("File server draft")))
    if not shares["shares"]:
        content.append(label(_("An empty policy clears the managed share list after administrator approval.")))

    def saved(path):
        center.refresh()
        dialog(center.window, _("Administrator handoff saved"),
               _("In a trusted administrator terminal, run the first command to review ownership, conflicts and prerequisites. Use its fresh token in the second command only after approval."),
               child=scrolled_text(product.administrator_commands(path)))

    dialog(center.window, _("Review system policy handoff"),
           _("This saves a private draft for the installed administrator helper."),
           _("Save handoff"), lambda: center.work(lambda _: product.save_handoff(data), saved,
                                                  cancellable=False), child=content)


def printer_editor(center, read, write, redraw):
    section = Adw.PreferencesGroup(title=_("Managed printer draft"))

    def edit(previous=None):
        draft = read()
        record = draft.rows.get(previous, {})
        form = Adw.PreferencesGroup()
        name = entry(form, _("Managed queue name"), record.get("name", "oe-"))
        uri = entry(form, _("IPP or IPPS endpoint"), record.get("uri", ""))
        default = Gtk.CheckButton(label=_("Set as default in the plan"),
                                  active=previous is not None and previous == draft.default)
        form.add(default)
        message = label("", "error")
        form.add(message)
        candidate = None

        def save():
            write(candidate)
            redraw()

        popup = dialog(center.window, _("Edit managed printer"),
                       _("Use a unique oe- queue name and a driverless IPP or IPPS endpoint."),
                       _("Save entry"), save, child=form)

        def validate(*_args):
            nonlocal candidate
            try:
                candidate = read().edit(name.get_text().strip(), uri.get_text().strip(),
                                        previous=previous, default=default.get_active())
            except (ValueError, KeyError):
                candidate = None
            message.set_label("" if candidate else _("Correct the queue name and endpoint."))
            popup.set_response_enabled("confirm", candidate is not None)

        name.connect("changed", validate)
        uri.connect("changed", validate)
        default.connect("toggled", validate)
        validate()

    def remove(name):
        def apply():
            write(read().remove(name))
            redraw()
        dialog(center.window, _("Remove draft entry?"), name, _("Remove"), apply, destructive=True)

    draft = read()
    for name, record in draft.rows.items():
        subtitle = record["uri"] + (" · " + _("Default") if draft.default == name else "")
        row = Adw.ActionRow(title=name, subtitle=subtitle, use_markup=False)
        row.add_suffix(button(_("Edit"), lambda name=name: edit(name)))
        row.add_suffix(button(_("Remove"), lambda name=name: remove(name)))
        section.add(row)
    section.add(button(_("Add printer"), edit))
    return section


def directory_form(center):
    form = Adw.PreferencesGroup(title=_("Native configuration preview"))
    fields = [entry(form, caption) for caption in (
        _("DNS domain"), _("NetBIOS workgroup"), _("Allowed AD group"), _("AD administrator group"))]

    def preview():
        values = tuple(field.get_text().strip() for field in fields)
        try:
            files = directory.render(*values)
        except ValueError:
            dialog(center.window, _("Review unavailable"), _("Check the domain, workgroup and group names."))
            return
        dialog(center.window, _("Native configuration preview"),
               _("Enrollment and interactive login require separate qualification."),
               child=scrolled_text("\n\n".join(f"{name}\n{data}" for name, data in files.items())))

    form.add(button(_("Review directory settings"), preview))
    return form
