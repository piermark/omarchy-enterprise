# Contributing

Use issues for documentation feedback and sanitized behavior reports. In pull
requests, explain the change, how to reproduce it with disposable fixtures and
which live workflows still need acceptance.

Use reserved example domains and documentation IP ranges. Keep credentials,
deployment settings, keytabs, logs, backups and guest disks out of changes.
For vulnerabilities, follow the [security policy](SECURITY.md).

Run `python -B -m unittest discover -s tests -v` as a regular user from the
source root. Gettext's `msgfmt` enables catalog checks. For source export
changes, review the explicit list in [packaging](packaging/phase15-source.txt),
then run `python -B tools/export-phase15.py EMPTY_DIRECTORY` and verify the
exported `SOURCE-SHA256SUMS`.
