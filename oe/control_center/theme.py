"""Use Libadwaita defaults and the session's appearance preference."""
from gi.repository import Adw


def follow_session():
    Adw.StyleManager.get_default().set_color_scheme(Adw.ColorScheme.DEFAULT)
