# Quick start

Start on a disposable evaluation system as a regular user. Download the source
archive for `v0.5.0-preview.1` after the maintainer publishes it. Extract it,
open a terminal in the extracted `omarchy-enterprise` directory, and run:

```sh
sha256sum -c SOURCE-SHA256SUMS
stage=$(mktemp -d)
./install.sh --root "$stage" --profile standalone --dry-run
```

The dry run lists the files and health checks for a Standalone profile. It
uses no domain enrollment or service changes. To try writing the profile in
the same private directory, replace `--dry-run` with `--yes`. Review removal
with `./uninstall.sh --root "$stage"`.

Continue with [installation and verification](installation.md). The
[availability matrix](availability.md) shows which workflows need live
qualification.
