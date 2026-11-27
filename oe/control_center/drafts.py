"""Visual editor for private and in-memory file server policies."""
from gi.repository import Adw, Gio, Gtk

from .. import pilot_session, policy
from .localization import _
from .setup import add_share
from .widgets import button, dialog, entry, label


class DraftEditor:
    def __init__(self, window, read, write, redraw):
        self.window, self.read, self.write, self.redraw = window, read, write, redraw

    def widget(self):
        section = Adw.PreferencesGroup(title=_("File server draft"))
        rows = self.read()["shares"]
        if not rows:
            section.add(Adw.ActionRow(title=_("No draft entries")))
        for record in rows:
            row = Adw.ActionRow(title=record["label"], subtitle=record["uri"], use_markup=False)
            actions = Gtk.Box(spacing=6, valign=Gtk.Align.CENTER)
            actions.append(button(_("Edit"), lambda record=record: self.edit(record)))
            actions.append(button(_("Remove"), lambda record=record: self.remove(record)))
            row.add_suffix(actions)
            section.add(row)
        actions = Gtk.Box(spacing=6, margin_top=8)
        actions.append(button(_("Add server or share"), lambda: self.edit()))
        actions.append(button(_("Load reviewed draft"), self.load))
        section.add(actions)
        return section

    def replace(self, result):
        self.write(result)
        self.redraw()

    def edit(self, previous=None):
        record = previous or {"uri": "", "label": "", "groups": []}
        form = Adw.PreferencesGroup()
        uri = entry(form, _("SMB hostname or share URL"), record["uri"])
        name = entry(form, _("Friendly label"), record["label"])
        groups = entry(form, _("Qualified groups, comma separated"), ", ".join(record["groups"]))
        message = label("", "error")
        form.add(message)

        def save():
            self.replace(add_share(self.read(), uri.get_text(), name.get_text(), groups.get_text(),
                                   previous["uri"] if previous else None))

        popup = dialog(self.window, _("Edit file server entry"),
                       _("Use a fully qualified SMB hostname. A blank group list makes the resource visible to all."),
                       _("Save entry"), child=form)
        popup.set_response_enabled("confirm", False)

        def validate(*_args):
            try:
                add_share(self.read(), uri.get_text(), name.get_text(), groups.get_text(),
                          previous["uri"] if previous else None)
            except ValueError:
                message.set_label(_("Enter a unique label, a valid SMB address without credentials and valid groups."))
                popup.set_response_enabled("confirm", False)
            else:
                message.set_label("")
                popup.set_response_enabled("confirm", True)

        for row in (uri, name, groups):
            row.connect("changed", validate)
        popup.connect("response", lambda _, response: save() if response == "confirm" else None)
        validate()

    def remove(self, record):
        dialog(self.window, _("Remove draft entry?"), record["label"], _("Remove"),
               lambda: self.replace(pilot_session.edit(self.read(), record["uri"], None)), destructive=True)

    def load(self):
        chooser = Gtk.FileChooserNative(title=_("Load reviewed draft"), transient_for=self.window,
                                        action=Gtk.FileChooserAction.OPEN, modal=True)

        def selected(widget, response):
            if response == Gtk.ResponseType.ACCEPT:
                file = widget.get_file()
                try:
                    from pathlib import Path
                    if not isinstance(file, Gio.File) or not file.get_path():
                        raise ValueError
                    document = policy.load_file(Path(file.get_path()))
                    policy.shares(document, set())
                    document = {"version": 2, "shares": document["shares"]}
                    policy.shares(document, set())
                except (OSError, ValueError):
                    dialog(self.window, _("Draft could not be loaded"), _("Select a valid local SMB policy."))
                else:
                    self.replace(document)
            widget.destroy()

        chooser.connect("response", selected)
        chooser.show()
