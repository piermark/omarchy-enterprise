"""Navigation and transaction preparation for the offline wizard."""
from dataclasses import dataclass, field
from pathlib import Path
import shutil

from .. import deployment, installation, pilot_session, product, provision
from .localization import _

STEPS = (
    _("Welcome"), _("Prerequisites"), _("Enterprise profile"), _("Active Directory preview"),
    _("File server configuration"), _("Printer configuration"), _("Optional Windows plan"),
    _("Security and policy"), _("Installation summary"), _("Offline staging and rollback"),
)


@dataclass
class Setup:
    step: int = 0
    profile: str = "standalone"
    fields: dict = field(default_factory=lambda: {"cpu": "4", "memory": "8", "disk": "128"})
    draft: dict = field(default_factory=lambda: {"version": 2, "shares": []})
    printers: product.PrinterDraft = field(default_factory=product.PrinterDraft)
    root: str = ""
    review: bool = False

    def options(self):
        keys = ["printer"]
        if self.profile != "standalone":
            keys.extend(("domain", "workgroup", "users", "admins"))
        if self.profile == "full-enterprise":
            keys.append("image")
        fields = {key: self.fields[key].strip() for key in keys if self.fields.get(key, "").strip()}
        if self.profile != "standalone":
            fields["preferred_dcs"] = self.fields.get("preferred_dcs", "").split()
        if fields.get("image"):
            fields.update({name: int(self.fields.get(name, default))
                           for name, default in (("cpu", "4"), ("memory", "8"), ("disk", "128"))})
        if fields.get("image") and self.fields.get("storage", "").strip():
            storage = Path(self.fields["storage"].strip())
            if not storage.is_absolute():
                raise ValueError("Use an absolute Windows storage path")
            fields["storage"] = storage
        if self.draft["shares"]:
            fields["file_servers"] = self.draft
        return fields

    def render(self, root=None):
        fields = self.options()
        if fields.get("image") and root is not None:
            fields["windows_base"] = root / provision.CONFIG / "windows"
        return provision.render(self.profile, **fields)

    def move(self, direction):
        steps = {
            0: lambda: 9 if self.review else 1,
            2: lambda: 4 if self.profile == "standalone" else 3,
            5: lambda: 6 if self.profile == "full-enterprise" else 7,
        }
        if direction == 1:
            if self.step in {3, 5, 6, 8}:
                self.render()
            if self.step < len(STEPS) - 1:
                self.step = steps.get(self.step, lambda: self.step + 1)()
        elif direction == -1 and self.step:
            skips = {4: 2 if self.profile == "standalone" else 3,
                     7: 6 if self.profile == "full-enterprise" else 5,
                     9: 0 if self.review else 8}
            self.step = skips.get(self.step, self.step - 1)
        return self.step

    def requirements(self):
        fields = self.options()
        return (provision.health(self.profile, bool(fields.get("image"))),
                deployment.dependency_plan(self.profile, printing=bool(fields.get("printer") or self.printers.rows)))

    def prepare(self):
        if self.review or not self.root.strip() or not Path(self.root).is_absolute():
            raise ValueError
        target = provision.ImageStore(Path(self.root))
        if any(target.root.iterdir()) or installation.review(target.root, target=target)["review_only"]:
            raise ValueError
        files = self.render(target.root)
        available = shutil.disk_usage(target.root).free
        needed = sum(len(data.encode()) for data in files.values() if data)
        if available < 4 * needed:
            raise ValueError("Insufficient free space for configuration and rollback records")
        changes = target.plan(files)
        if "CONFLICT" in changes.values():
            raise ValueError
        info = target.root.stat()
        return Plan(target.root, files, changes, (info.st_dev, info.st_ino))

    def prepare_recovery(self, action):
        if self.review or not Path(self.root).is_absolute():
            raise ValueError("Select the private staging folder")
        return product.image_recovery(Path(self.root), action)


@dataclass(frozen=True)
class Plan:
    root: Path
    files: dict
    changes: dict
    identity: tuple

    def target(self):
        target = provision.ImageStore(self.root)
        info = target.root.stat()
        if (info.st_dev, info.st_ino) != self.identity:
            raise ValueError
        return target

    def apply(self):
        target = self.target()
        if any(target.root.iterdir()):
            raise ValueError
        return provision.mutate(self.root, "apply", self.files, expected_history=(None,))

    def rollback(self):
        self.target()
        expected = {"before": provision.ImageStore.empty, "after": self.files, "previous": None}
        return provision.mutate(self.root, "rollback", expected_history=(expected,))


def add_share(document, uri, label, groups, previous=None):
    from .. import directory, policy

    names = [] if groups.strip() in {"", "*"} else [name.strip() for name in groups.split(",")]
    if any(not directory.GROUP.fullmatch(name) or not policy.HOST.fullmatch(domain)
           for name, _, domain in (entry.partition("@") for entry in names)):
        raise ValueError
    return pilot_session.edit(document, previous, {
        "label": label.strip(), "uri": pilot_session.normalize_uri(uri), "groups": names,
    })
