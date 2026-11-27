"""Sidebar routing and adaptive content layout."""
from gi.repository import Adw, GObject, Gtk

from .localization import _
from .model import PAGES
from .widgets import label


def layout(window, routes, selected, content, navigate, title, controls=()):
    sidebar = Adw.ToolbarView()
    sidebar_header = Adw.HeaderBar(show_end_title_buttons=False)
    sidebar_header.set_title_widget(label(_("Navigation"), "heading"))
    sidebar.add_top_bar(sidebar_header)
    rows = Gtk.ListBox(selection_mode=Gtk.SelectionMode.SINGLE,
                       margin_top=8, margin_bottom=8, margin_start=8, margin_end=8)
    rows.add_css_class("navigation-sidebar")
    entries = {}
    for route in routes:
        caption, icon, _description = PAGES[route]
        item = Gtk.ListBoxRow()
        box = Gtk.Box(spacing=10, margin_top=9, margin_bottom=9, margin_start=9, margin_end=9)
        box.append(Gtk.Image.new_from_icon_name(icon))
        box.append(label(caption))
        item.set_child(box)
        rows.append(item)
        entries[route] = item
    scroll = Gtk.ScrolledWindow(hscrollbar_policy=Gtk.PolicyType.NEVER)
    scroll.set_child(rows)
    sidebar.set_content(scroll)

    toolbar = Adw.ToolbarView()
    header = Adw.HeaderBar(show_start_title_buttons=False)
    header.set_title_widget(label(title, "heading"))
    toolbar.add_top_bar(header)
    toolbar.set_content(content)
    for control in controls:
        header.pack_end(control)
    split = Adw.OverlaySplitView(sidebar=sidebar, content=toolbar, min_sidebar_width=221,
                                max_sidebar_width=251)
    toggle = Gtk.ToggleButton(icon_name="sidebar-show-symbolic", tooltip_text=_("Toggle navigation"))
    split.bind_property("show-sidebar", toggle, "active", GObject.BindingFlags.BIDIRECTIONAL | GObject.BindingFlags.SYNC_CREATE)
    header.pack_start(toggle)
    breakpoint = Adw.Breakpoint.new(Adw.BreakpointCondition.parse("max-width: 720sp"))
    breakpoint.add_setter(split, "collapsed", True)
    breakpoint.add_setter(toggle, "visible", True)
    toggle.set_visible(False)
    window.add_breakpoint(breakpoint)
    rows.select_row(entries[selected])

    def selected_row(_rows, row):
        if row is not None:
            navigate(routes[row.get_index()])
            if split.get_collapsed():
                split.set_show_sidebar(False)

    rows.connect("row-selected", selected_row)
    window.set_content(split)
    return entries, rows, header
