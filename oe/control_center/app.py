"""GTK lifecycle and composition for the Enterprise Control Center."""
import json

from gi.repository import Adw, Gio, GLib, Gtk

from .. import pilot_session, product as product_model
from . import navigation, operational, product, synthetic, theme
from .drafts import DraftEditor
from .jobs import Jobs
from .localization import _
from .model import Backend, PAGES, PROFILE_NAMES, View, prerequisite_label, state
from .setup import STEPS, Setup
from .widgets import button, dialog, entry, group, label, scrolled_text


PROFILE_DESCRIPTIONS = {
    "standalone": _("Workstation tools, printing and recovery."),
    "active-directory": _("Workstation tools with an offline directory and Kerberos planning profile."),
    "full-enterprise": _("Directory planning and enterprise administration with an optional Windows workspace."),
}


class Center(Adw.Application):
    def __init__(self, store, source, *, installer=False, root=None, dry_run=False, backend=None):
        identifier = "org.omarchy.EnterpriseInstaller" if installer else "org.omarchy.Enterprise"
        super().__init__(application_id=identifier, flags=Gio.ApplicationFlags.NON_UNIQUE)
        self.desktop_id = "omarchy-enterprise-installer" if installer else "omarchy-enterprise"
        self.backend = backend or Backend(store, source)
        self.route = "installer" if installer else "overview"
        self.routes = ("installer",) if installer else tuple(PAGES)
        self.setup = Setup(root=str(root) if root else "")
        self.dry_run = dry_run
        self.jobs = Jobs(GLib.idle_add)
        self.plan = None
        self.staged = False
        self.stage_summary = ()
        self.synthetic_target = ""
        self.draft = {"version": 2, "shares": []}
        self.printers = product_model.PrinterDraft()
        self.lab_visible = set()
        self.operational_fields = {}

    def do_activate(self):
        if self.get_active_window():
            self.get_active_window().present()
            return
        theme.follow_session()
        Gtk.Window.set_default_icon_name("preferences-system")
        self.window = Adw.ApplicationWindow(application=self, default_width=1050, default_height=730,
                                            title=_("Enterprise Control Center"))
        self.window.set_size_request(360, 430)
        self.window.connect("realize", self.identify_window)
        self.window.connect("close-request", self.close_window)
        scroll = Gtk.ScrolledWindow(hscrollbar_policy=Gtk.PolicyType.NEVER)
        self.body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=18, margin_top=24,
                            margin_bottom=28, margin_start=20, margin_end=20)
        clamp = Adw.Clamp(maximum_size=840, tightening_threshold=620, child=self.body)
        scroll.set_child(clamp)
        refresh = Gtk.Button(icon_name="view-refresh-symbolic", tooltip_text=_("Refresh current page"))
        refresh.connect("clicked", lambda _: self.refresh())
        self.entries, self.sidebar, self.header = navigation.layout(
            self.window, self.routes, self.route, scroll, self.navigate,
            _("Enterprise Control Center"), (refresh,))
        action = Gio.SimpleAction.new("refresh", None)
        action.connect("activate", lambda *_: self.refresh())
        self.add_action(action)
        self.set_accels_for_action("app.refresh", ["<Control>r", "F5"])
        self.refresh()
        self.window.present()

    def identify_window(self, window):
        # Keep the existing launcher filename as the Wayland desktop identity.
        surface = window.get_surface()
        if surface is not None and hasattr(surface, "set_application_id"):
            surface.set_application_id(self.desktop_id)

    def close_window(self, _window):
        if not self.jobs.cancel():
            return True
        self.jobs.close()
        return False

    def navigate(self, route):
        if route not in self.routes or route == self.route:
            return
        if not self.jobs.cancel():
            self.sidebar.select_row(self.entries[self.route])
            return
        self.route = route
        self.refresh()

    def page(self):
        while (child := self.body.get_first_child()) is not None:
            self.body.remove(child)
        title, _icon, description = PAGES[self.route]
        self.body.append(label(title, "title-1"))
        self.body.append(label(description, "dim-label"))

    def busy(self, cancel=True):
        self.page()
        box = Gtk.Box(spacing=10)
        spinner = Gtk.Spinner(spinning=True)
        box.append(spinner)
        box.append(label(_("Working…")))
        if cancel:
            box.append(button(_("Cancel"), self.cancel))
        self.body.append(box)

    def cancel(self):
        if self.jobs.cancel():
            self.page()
            self.body.append(label(_("Operation cancelled.")))
            self.body.append(button(_("Return to page"), self.refresh))

    def work(self, operation, success, *, cancellable=True, invalid=None):
        def completed(value, error):
            if error is None:
                success(value)
                return
            self.page()
            self.body.append(label(_("Access restricted") if isinstance(error, PermissionError) else
                                   (invalid or _("Operation failed. Review prerequisites and retry.")), "error"))
            self.body.append(button(_("Return to page"), self.refresh))

        if self.jobs.start(operation, completed, cancellable=cancellable):
            self.busy(cancellable)

    def refresh(self):
        if not self.jobs.cancel():
            return
        if self.route == "installer":
            self.show_setup()
        elif self.route == "files":
            self.work(self.backend.file_status, self.show_files)
        else:
            self.work(getattr(self.backend, self.route), self.show_view)

    def show_view(self, view):
        self.page()
        self.body.append(group(view.rows))
        if view.advanced is not None:
            self.body.append(button(_("Advanced diagnostics"), lambda: dialog(
                self.window, _("Advanced diagnostics"), _("Categorical backend diagnostics."),
                child=scrolled_text(json.dumps(view.advanced, indent=2)))))
        if self.route == "directory":
            self.body.append(label(_("Machine trust and SSSD validation require an administrator. Service activity and login acceptance are independent.")))
            self.body.append(label("omarchy-enterprise-admin diagnose", "monospace"))
            self.body.append(product.directory_form(self))
        elif self.route == "windows":
            self.body.append(label(_("Ask the VM administrator to verify the effective policy for the selected Dockur container.")))
            self.body.append(label("omarchy-enterprise-admin windows-restart-policy CONTAINER_ID", "monospace"))
            self.body.append(label(_("Connect to an approved endpoint using the existing FreeRDP client. Use the trusted terminal for the interactive connection.")))
            self.body.append(label("omarchy-enterprise windows-connect", "monospace"))
            self.body.append(label(_("Review storage on an approved path with the existing read-only diagnostics command.")))
            self.body.append(label("omarchy-enterprise doctor --windows-storage DIRECTORY", "monospace"))
        elif self.route == "security":
            self.body.append(label(_("Use the trusted administrator console for Guard checks, compliance, audit status and certificate management.")))
        elif self.route == "updates":
            self.body.append(button(_("Check installed package files"), lambda: self.update_result(
                view, _("Package integrity"), self.backend.package_integrity)))
            self.body.append(button(_("Check repository updates"), lambda: dialog(
                self.window, _("Check repository updates?"), _("The existing update check contacts package mirrors."),
                _("Check"), lambda: self.update_result(view, _("Repository updates"), self.backend.discover_updates))))
            self.body.append(label(_("Before maintenance, verify snapshots, backups, local recovery and SSH access with an administrator.")))
            self.body.append(label(_("For offline image rollback or interrupted transaction recovery, use the existing provisioning commands.")))
            self.body.append(label("omarchy-enterprise provision-image --root DIRECTORY rollback --yes\n"
                                   "omarchy-enterprise provision-image --root DIRECTORY recover --help", "monospace"))

        if self.route in operational.ROUTES:
            self.body.append(operational.panel(self))
        if self.route in synthetic.ACTIONS:
            self.show_lab_tools()

    def show_lab_tools(self):
        route = self.route
        expander = Gtk.Expander(label=_("Disposable laboratory tools"), expanded=route in self.lab_visible)

        def toggle(widget, *_):
            if widget.get_expanded():
                self.lab_visible.add(route)
                if widget.get_child() is None:
                    widget.set_child(synthetic.panel(self))
            else:
                self.lab_visible.discard(route)

        expander.connect("notify::expanded", toggle)
        toggle(expander)
        self.body.append(expander)

    def update_result(self, view, key, operation):
        self.work(operation, lambda result: self.show_view(View(tuple(
            (name, result if name == key else value) for name, value in view.rows))))

    def show_files(self, result):
        self.page()
        (policy, resources), ticket = result
        self.body.append(group(((_("Managed policy"), policy), (_("Kerberos session ticket"), ticket)),
                               _("Access and diagnostics")))
        shares = Adw.PreferencesGroup(title=_("Authorized servers and shares"))
        for name, uri in resources.items():
            row = Adw.ActionRow(title=name, subtitle=uri, use_markup=False)
            open_button = button(_("Open in Nautilus"), lambda name=name, uri=uri: self.work(
                lambda _: self.backend.open_share(name, uri), lambda _: self.refresh(), cancellable=False))
            open_button.set_valign(Gtk.Align.CENTER)
            open_button.set_sensitive(ticket.code == "PASS")
            row.add_suffix(open_button)
            shares.add(row)
        if not resources:
            shares.add(Adw.ActionRow(title=_("No authorized resources to show")))
        self.body.append(shares)
        self.body.append(label(_("The preview uses the managed policy. Personal bookmarks are preserved.")))
        preview = button(_("Preview Nautilus bookmark refresh"), lambda: self.work(
            self.backend.bookmark_preview, self.confirm_bookmarks))
        preview.set_sensitive(policy.code == "CONFIGURED" and ticket.code == "PASS")
        self.body.append(preview)
        self.body.append(button(_("Roll back managed bookmarks"), lambda: dialog(
            self.window, _("Roll back managed bookmarks?"),
            _("Restore the previous managed entries and preserve personal edits."),
            _("Roll back"), lambda: self.work(lambda _: self.backend.rollback_bookmarks(),
                                             lambda _: self.refresh(), cancellable=False), destructive=True)))
        self.body.append(label(_("Save drafts for administrator review. The managed policy controls authorized resources.")))
        editor = DraftEditor(self.window, lambda: self.draft, lambda value: setattr(self, "draft", value),
                             lambda: self.show_files(result))
        self.body.append(editor.widget())
        self.body.append(button(_("Save private draft"), lambda: dialog(
            self.window, _("Save private draft?"), _("Save a local policy draft for administrator review."),
            _("Save"), lambda: self.work(lambda _: pilot_session.save_draft(self.draft), self.saved_draft,
                                          cancellable=False))))

        self.body.append(operational.panel(self))
        self.show_lab_tools()

    def saved_draft(self, path):
        self.refresh()
        dialog(self.window, _("Private draft saved"), str(path))

    def confirm_bookmarks(self, result):
        expected, previous, desired = result
        self.refresh()
        removed = tuple(line for line in previous if line not in desired)
        added = tuple(line for line in desired if line not in previous)
        details = "{0}\n{1}\n\n{2}\n{3}".format(
            _("Remove managed entries"), "".join(removed) or _("None"),
            _("Add managed entries"), "".join(added) or _("None"))
        dialog(self.window, _("Apply managed bookmark changes?"),
               _("Nautilus will use the refreshed bookmarks. A private rollback checkpoint is kept."),
               _("Apply"), lambda: self.work(lambda _: self.backend.apply_bookmarks(expected),
                                           lambda _: self.refresh(), cancellable=False),
               child=scrolled_text(details))

    def setup_move(self, direction):
        if direction == 1 and self.setup.step in {3, 5, 6, 8}:
            self.work(lambda _: self.setup.move(direction), lambda _: self.show_setup(), cancellable=False,
                      invalid=_("Check the required AD fields, printer hostname or Windows image digest."))
        else:
            self.setup.move(direction)
            self.show_setup()

    def setup_entry(self, form, key, caption):
        entry(form, caption, self.setup.fields.get(key, ""), lambda value: self.setup.fields.__setitem__(key, value))

    def show_setup(self):
        self.page()
        setup = self.setup
        progress = Gtk.ProgressBar(fraction=(setup.step + 1) / len(STEPS))
        self.body.append(progress)
        self.body.append(label(_("Step {step} of {total} · {title}").format(
            step=setup.step + 1, total=len(STEPS), title=STEPS[setup.step]), "title-2"))
        if setup.step == 0:
            self.body.append(label(_("Prepare a disposable installation or review existing workstation metadata. Live deployment is blocked.")))
            selector = Gtk.DropDown.new_from_strings([_("Offline staging"), _("Existing Enterprise review")])
            selector.set_halign(Gtk.Align.START)
            selector.set_selected(int(setup.review))
            selector.connect("notify::selected", lambda widget, _: setattr(setup, "review", bool(widget.get_selected())))
            self.body.append(selector)
        elif setup.step == 1:
            checks, packages = setup.requirements()
            self.body.append(group(tuple((prerequisite_label(key), state("AVAILABLE" if value else "UNAVAILABLE"))
                                         for key, value in checks.items()), _("Local prerequisites")))
            self.body.append(label(_("Lab package prerequisites") + "\n" + ", ".join(packages)))
        elif setup.step == 2:
            profiles = list(PROFILE_NAMES)
            selector = Gtk.DropDown.new_from_strings(list(PROFILE_NAMES.values()))
            selector.set_halign(Gtk.Align.START)
            selector.set_selected(profiles.index(setup.profile))
            self.body.append(selector)
            description = label("")
            self.body.append(description)

            def describe(widget, *_):
                setup.profile = profiles[widget.get_selected()]
                _, packages = setup.requirements()
                description.set_text(PROFILE_DESCRIPTIONS[setup.profile] + "\n" + ", ".join(packages))

            selector.connect("notify::selected", describe)
            describe(selector)
        elif setup.step == 3:
            form = Adw.PreferencesGroup()
            for key, caption in (("domain", _("DNS domain")), ("workgroup", _("NetBIOS workgroup")),
                                 ("users", _("Allowed AD group")), ("admins", _("AD administrator group")),
                                 ("preferred_dcs", _("Preferred writable controllers (optional)"))):
                self.setup_entry(form, key, caption)
            self.body.append(form)
            self.body.append(label(_("Use synthetic settings for disposable AD testing. Domain enrollment and login require separate acceptance.")))
        elif setup.step == 4:
            editor = DraftEditor(self.window, lambda: setup.draft, lambda value: setattr(setup, "draft", value), self.show_setup)
            self.body.append(editor.widget())
        elif setup.step == 5:
            form = Adw.PreferencesGroup()
            self.setup_entry(form, "printer", _("Printer monitor hostname (optional)"))
            self.body.append(form)
            self.body.append(product.printer_editor(self, lambda: setup.printers,
                                                   lambda value: setattr(setup, "printers", value), self.show_setup))
            self.body.append(label(_("Queue drafts are for review. Staging does not create CUPS queues.")))
        elif setup.step == 6:
            form = Adw.PreferencesGroup()
            self.setup_entry(form, "image", _("Dockur image by SHA-256 digest (optional)"))
            for key, title in (("cpu", _("Virtual CPUs")), ("memory", _("Memory in GiB")),
                               ("disk", _("Disk in GiB")), ("storage", _("Dedicated storage directory"))):
                self.setup_entry(form, key, title)
            self.body.append(form)
            self.body.append(label(_("Windows is optional. The plan uses manual start and requires licensing and runtime review.")))
        elif setup.step == 7:
            self.body.append(group(((_("Inbound RDP"), state("OFF")), (_("Live deployment"), state("BLOCKED")))))
            self.body.append(label(_("This wizard stages policy files in a disposable directory. An administrator reviews recovery and policy before any deployment.")))
        elif setup.step == 8:
            checks, packages = setup.requirements()
            self.body.append(group(((_("Selected profile"), PROFILE_NAMES[setup.profile]),
                                    (_("Draft file server entries"), str(len(setup.draft["shares"]))),
                                    (_("Managed printer draft"), str(len(setup.printers.rows))),
                                    (_("Printer monitoring"), state("CONFIGURED" if setup.options().get("printer") else "NOT CONFIGURED")),
                                    (_("Windows plan"), state("MANUAL START ONLY" if setup.options().get("image") else "NOT CONFIGURED")))))
            self.body.append(group(tuple((prerequisite_label(key), state("AVAILABLE" if value else "UNAVAILABLE"))
                                         for key, value in checks.items()), _("Selected profile prerequisites")))
            self.body.append(label(_("Lab package prerequisites") + "\n" + ", ".join(packages)))
        elif setup.review:
            self.body.append(operational.panel(self))
        else:
            form = Adw.PreferencesGroup()
            root = entry(form, _("Absolute path to an empty private folder"), setup.root,
                         lambda value: setattr(setup, "root", value))
            root.set_editable(not self.staged)
            self.body.append(form)
            self.body.append(label(_("Use an empty, user-owned folder with mode 0700. Recovery commands apply to that folder only.")))
            if self.staged:
                self.body.append(label(_("Offline transaction verified."), "success"))
                self.body.append(group([(path, _("Staged")) for path in self.stage_summary]))
                self.body.append(button(_("Roll back this staging transaction"), lambda: dialog(
                    self.window, _("Roll back staging?"), _("Restore the disposable folder to its previous managed state."),
                    _("Roll back"), lambda: self.work(lambda _: self.plan.rollback(), self.rollback_complete,
                                                     cancellable=False), destructive=True)))
            else:
                self.body.append(button(_("Preview offline changes"), lambda: self.work(
                    lambda _: setup.prepare(), self.confirm_stage,
                    invalid=_("Use an empty private folder with mode 0700 and review all fields."))))
                for action, title in (("recover", _("Resume interrupted staging")),
                                      ("abort", _("Abort interrupted staging")),
                                      ("rollback", _("Roll back completed staging"))):
                    self.body.append(button(title, lambda action=action, title=title: self.review_recovery(action, title)))
            self.body.append(label("omarchy-enterprise provision-image --root DIRECTORY rollback --yes\n"
                                   "omarchy-enterprise provision-image --root DIRECTORY recover --help", "monospace"))
        buttons = Gtk.Box(spacing=8)
        if setup.step and not self.staged:
            buttons.append(button(_("_Back"), lambda: self.setup_move(-1)))
        if setup.step < len(STEPS) - 1:
            buttons.append(button(_("_Next"), lambda: self.setup_move(1), suggested=True))
        self.body.append(buttons)
        if setup.step in {0, 8} and not setup.review:
            self.body.append(operational.panel(self))
            self.show_lab_tools()

    def review_recovery(self, action, title):
        self.work(lambda _: self.setup.prepare_recovery(action), lambda plan: dialog(
            self.window, title, _("Only the reviewed disposable transaction can be changed."),
            None if self.dry_run else _("Continue"),
            lambda: self.work(lambda _: plan(), lambda _: self.show_setup(), cancellable=False),
            destructive=action != "recover"),
            invalid=_("Select the private staging folder and verify its transaction state."))

    def offline_preview_content(self, plan):
        actions = {"CREATE": _("CREATE"), "UPDATE": _("UPDATE"),
                   "REMOVE": _("REMOVE"), "UNCHANGED": _("UNCHANGED")}
        return "\n".join(f"{actions[change]}  {path}" for path, change in plan.changes.items())

    def confirm_stage(self, plan):
        self.show_setup()
        content = self.offline_preview_content(plan)
        if self.dry_run:
            dialog(self.window, _("Offline staging preview"), _("Preview mode. No files were staged."),
                   child=scrolled_text(content))
            return

        def apply():
            def completed(paths):
                self.stage_summary = tuple(paths)
                self.plan = plan
                self.staged = True
                self.show_setup()

            self.work(lambda _: plan.apply(), completed, cancellable=False)

        dialog(self.window, _("Stage files in the disposable folder?"),
               _("The transaction can be rolled back from this wizard."), _("Stage files"), apply,
               child=scrolled_text(content))

    def rollback_complete(self, _):
        self.staged = False
        self.show_setup()
        dialog(self.window, _("Offline rollback verified"), _("The previous managed state was restored."))
