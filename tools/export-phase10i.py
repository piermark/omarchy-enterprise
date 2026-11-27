#!/usr/bin/env python3
"""Stage the explicit Phase 10I source list and an archive without local metadata."""
import argparse
import gzip
import hashlib
import io
import os
from pathlib import Path
import re
from contextlib import ExitStack
from release_images import PNG_SIZES, validate_png
import tarfile

ROOT = Path(__file__).resolve().parents[1]
LIST = "packaging/phase10i-source.txt"
VERSION = "0.2.0lab10i"
PREFIX = "omarchy-enterprise"
PUBLIC_WORKFLOW = ".github/workflows/source-preview.yml"
EXCLUDED = {
    "oe/rdp_admission.py", "oe/rdp_identity.py", "oe/rdp_sessions.py",
    "oe/rdp_supervisor.py", "oe/rdp_drive_provider.py",
}


def collect(source_list, version_override):
    names = (ROOT / source_list).read_text().splitlines()
    if names != sorted(set(names)) or source_list not in names:
        raise ValueError("Expected a sorted explicit source list")
    for name in names:
        path = ROOT / name
        if (not re.fullmatch(r"[A-Za-z0-9_./-]+", name) or not path.is_relative_to(ROOT)
                or ".." in Path(name).parts or Path(name).as_posix() != name
                or path.resolve() != path or not path.is_file()
                or name in EXCLUDED or name.startswith("experiments/")
                or (name not in {PUBLIC_WORKFLOW, ".gitignore"} and any(part.startswith(".") for part in Path(name).parts))):
            raise ValueError("Unsafe or unavailable export input")
        data = path.read_bytes()
        if name in PNG_SIZES:
            validate_png(name, data)
            yield name, data, 0o644
            continue
        if name.endswith(".png"):
            raise ValueError("PNG asset must be explicitly approved")
        if len(data) > 1048576 or b"\0" in data:
            raise ValueError("Expected bounded source text")
        content = data.decode("utf-8")
        if version_override and name == "packaging/PKGBUILD":
            content = re.sub(r"^pkgver=.*$", f"pkgver={version_override}", content, flags=re.M)
        if version_override and name == "oe/__init__.py":
            content = re.sub(r"^__version__ = .*$", f'__version__ = "{version_override}"', content, flags=re.M)
        yield name, content.encode("utf-8"), 0o755 if path.stat().st_mode & 0o111 else 0o644


def main(source_list=LIST, version=VERSION, *, rewrite_version=True, compressed=False):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    if args.output.is_symlink() or not args.output.is_dir() or any(args.output.iterdir()):
        parser.error("Choose an empty output directory")
    if not (ROOT / source_list).is_file():
        parser.error(f"Source allowlist unavailable: {source_list}. Use export-phase15.py for the public preview.")
    os.umask(0o077)
    entries = list(collect(source_list, version if rewrite_version else None))
    manifest = "".join(f"{hashlib.sha256(data).hexdigest()}  {name}\n" for name, data, _ in entries)
    entries.append(("SOURCE-SHA256SUMS", manifest.encode(), 0o644))
    entries.sort()
    tree = args.output / PREFIX
    suffix = ".tar.gz" if compressed else ".tar"
    with ExitStack() as stack:
        output = stack.enter_context((args.output / f"{PREFIX}-{version}-source{suffix}").open("xb"))
        if compressed:
            output = stack.enter_context(gzip.GzipFile(fileobj=output, mode="wb", filename="", mtime=0))
        archive = stack.enter_context(tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT))
        for name, data, mode in entries:
            path = tree / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            path.chmod(mode)
            member = tarfile.TarInfo(f"{PREFIX}/{name}")
            member.size = len(data)
            member.mode = mode
            member.uid = member.gid = 0
            member.mtime = 0
            archive.addfile(member, io.BytesIO(data))


if __name__ == "__main__":
    main()
