"""Shared accessible GTK widgets and native dialogs."""
from gi.repository import Adw, Gtk, Pango

from .localization import _
from .model import Status

SYMBOLS = {
    "ACTIVE": "emblem-ok-symbolic", "AVAILABLE": "emblem-ok-symbolic", "PASS": "emblem-ok-symbolic",
    "ACCESS RESTRICTED": "changes-prevent-symbolic", "FAILED": "dialog-error-symbolic",
    "BLOCKED": "changes-prevent-symbolic", "DISABLED": "action-unavailable-symbolic",
    "OFF": "action-unavailable-symbolic", "UNAVAILABLE": "dialog-warning-symbolic",
    "NOT TESTED": "dialog-question-symbolic", "RECORDED": "document-open-recent-symbolic",
    "RUNNING": "media-playback-start-symbolic", "STOPPED": "media-playback-stop-symbolic",
}


def label(text, style=None):
    widget = Gtk.Label(label=text, xalign=0, wrap=True, selectable=False)
    if style:
        widget.add_css_class(style)
    return widget


def button(text, action, *, suggested=False):
    widget = Gtk.Button(label=text, use_underline=True, halign=Gtk.Align.START)
    widget.connect("clicked", lambda _: action())
    if suggested:
        widget.add_css_class("suggested-action")
    return widget


def group(rows, title=None):
    widget = Adw.PreferencesGroup()
    if title:
        widget.set_title(title)
    for key, value in rows:
        row = Adw.ActionRow(title=key, use_markup=False, title_lines=2)
        if isinstance(value, Status):
            suffix = Gtk.Box(spacing=7, valign=Gtk.Align.CENTER)
            suffix.append(Gtk.Image.new_from_icon_name(SYMBOLS.get(value.code, "dialog-information-symbolic")))
            status = label(value.text)
            status.set_wrap_mode(Pango.WrapMode.WORD_CHAR)
            status.set_max_width_chars(20)
            suffix.append(status)
        else:
            suffix = label(value)
            suffix.set_selectable(True)
            suffix.set_max_width_chars(36)
        row.add_suffix(suffix)
        widget.add(row)
    return widget


def entry(container, title, value="", changed=None):
    row = Adw.EntryRow(title=title, text=value)
    if changed:
        row.connect("changed", lambda widget: changed(widget.get_text()))
    container.add(row)
    return row


def dialog(parent, heading, body, action=None, callback=None, *, destructive=False, child=None):
    widget = Adw.MessageDialog(transient_for=parent, modal=True, heading=heading, body=body)
    if child is not None:
        widget.set_extra_child(child)
    widget.add_response("cancel", _("Close") if action is None else _("Cancel"))
    widget.set_close_response("cancel")
    if action is not None:
        widget.add_response("confirm", action)
        widget.set_response_appearance("confirm", Adw.ResponseAppearance.DESTRUCTIVE if destructive
                                       else Adw.ResponseAppearance.SUGGESTED)
    widget.set_default_response("cancel")
    if callback:
        widget.connect("response", lambda _, response: callback() if response == "confirm" else None)
    widget.present()
    return widget


def scrolled_text(content):
    view = Gtk.TextView(editable=False, monospace=True, wrap_mode=Gtk.WrapMode.WORD_CHAR)
    view.get_buffer().set_text(content)
    scroll = Gtk.ScrolledWindow(min_content_width=320, min_content_height=220)
    scroll.set_child(view)
    return scroll
