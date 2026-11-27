#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Build a review artifact without embedding host paths or package inventory.
set -euo pipefail
umask 077
[[ $EUID != 0 ]] || { echo 'Build as a regular user.' >&2; exit 1; }
[[ $# == 2 && -f $1 && -d $2 ]] || {
    echo 'Usage: build-beta-package.sh REVIEWED_SOURCE_ARCHIVE OUTPUT_DIRECTORY' >&2
    exit 2
}
archive=$(realpath -- "$1")
output=$(realpath -- "$2")
if [[ -n ${SOURCE_DATE_EPOCH:-} ]]; then
    # makepkg records absolute source and build paths in .BUILDINFO.
    work=/tmp/oe-reproducible-package
    mkdir -m 700 -- "$work"
else
    work=$(mktemp -d /tmp/oe-package.XXXXXXXX)
fi
trap 'rm -rf -- "$work"' EXIT
mkdir -- "$work/home" "$work/source" "$work/artifacts"
bsdtar --no-same-owner --strip-components 1 -xf "$archive" -C "$work/source"
(cd "$work/source" && sha256sum --quiet -c SOURCE-SHA256SUMS)
cat > "$work/pacman" <<'SH'
#!/usr/bin/env bash
if [[ $# == 1 && $1 == -Qi ]]; then
    # makepkg uses this query for .BUILDINFO's host-wide installed list.
    exit 0
fi
if [[ ${1:-} == -T ]]; then
    exec /usr/bin/pacman "$@"
fi
echo 'Unexpected package manager operation refused.' >&2
exit 1
SH
chmod 700 "$work/pacman"
(
    cd -- "$work/source/packaging"
    env -i SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-}" PATH=/usr/bin:/bin HOME="$work/home" LC_ALL=C.UTF-8 \
        XDG_CONFIG_HOME="$work/home/config" PACMAN="$work/pacman" \
        PACKAGER='Marco Porro <17280140+piermark@users.noreply.github.com>' \
        PKGDEST="$work/artifacts" makepkg --config /etc/makepkg.conf --noconfirm
)
set -- "$work/artifacts/"*.pkg.tar.zst
[[ $# == 1 && -f $1 ]] || { echo 'Expected one Arch artifact.' >&2; exit 1; }
metadata=$(bsdtar -xOf "$1" .BUILDINFO)
if grep -qE '^installed =|/home/' <<<"$metadata" \
    || ! grep -Fxq 'packager = Marco Porro <17280140+piermark@users.noreply.github.com>' <<<"$metadata"; then
    echo 'Host-specific build metadata detected; artifact withheld.' >&2
    exit 1
fi
install -m 0644 -- "$1" "$output/${1##*/}"
