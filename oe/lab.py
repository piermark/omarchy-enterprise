# SPDX-License-Identifier: MIT
"""Apply and roll back a managed AD bundle in an isolated lab filesystem."""

import os
import stat

from . import directory
from .state import Store


class LabStore(Store):
    names = set(directory.AD_FILES)
    empty = dict.fromkeys(directory.AD_FILES)


def require_private_directory(path):
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) & 0o022):
        raise ValueError("Lab root and its configuration directory must be owned by the current user")


def store_for(root):
    if root.is_symlink():
        raise ValueError("Select a regular disposable lab root")
    root = root.resolve(strict=True)
    if root == root.parent:
        raise ValueError("Live system configuration requires a separate laboratory procedure")
    require_private_directory(root)
    configuration = root / "etc"
    configuration.mkdir(mode=0o700, exist_ok=True)
    require_private_directory(configuration)
    return LabStore(configuration / "omarchy-enterprise")


def run(action, root, inputs, *, abort=False):
    store = store_for(root)
    with store.locked():
        if action == "apply":
            store.change(**directory.render(*inputs))
        elif action == "remove":
            store.change(**store.empty)
        elif action == "rollback":
            return store.rollback()
        elif action == "recover":
            return store.recover(abort=abort)
    return True
