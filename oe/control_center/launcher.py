"""Select GTK when its typelibs and a usable display are available."""
import os
import sys

from .localization import _


def native():
    try:
        import gi
        gi.require_version("Gtk", "4.0")
        gi.require_version("Gdk", "4.0")
        gi.require_version("Adw", "1")
        from gi.repository import Adw, Gdk, Gtk
        if Gtk.get_minor_version() >= 8 and (Adw.get_major_version(), Adw.get_minor_version()) >= (1, 4):
            if Gtk.init_check() and Gdk.Display.get_default() is not None:
                return True
    except (ImportError, ValueError, RuntimeError):
        pass
    return False


def run(store, source, fallback, *, installer=False, root=None, dry_run=False, force=False, require_native=False):
    fallback_requested = force or (not require_native and os.environ.get("OMARCHY_ENTERPRISE_ZENITY"))
    if not fallback_requested and native():
        from .app import Center
        return Center(store, source, installer=installer, root=root, dry_run=dry_run).run([])
    if require_native:
        print(_("GTK4, Libadwaita or the graphical display is unavailable."), file=sys.stderr)
        return 1
    if not fallback_requested:
        print(_("GTK4, Libadwaita or the graphical display is unavailable. Using the Zenity fallback."),
              file=sys.stderr)
    return fallback()
