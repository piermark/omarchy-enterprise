#!/usr/bin/env python3
"""Export the public preview source using the reviewed allowlist."""

import importlib.util
from pathlib import Path


def main():
    path = Path(__file__).with_name("export-phase10i.py")
    spec = importlib.util.spec_from_file_location("reviewed_export", path)
    exporter = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(exporter)
    exporter.main("packaging/phase15-source.txt", "0.5.0-preview.1", rewrite_version=False, compressed=True)


if __name__ == "__main__":
    main()
