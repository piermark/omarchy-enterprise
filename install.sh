#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'TEXT'
Usage:
  ./install.sh --bootstrap --package ARCHIVE --keyring KEYRING --fingerprint FINGERPRINT
  ./install.sh --bootstrap --launch

Offline staging:
  ./install.sh [--root PRIVATE_DIRECTORY] [--dry-run]
  ./install.sh --root PRIVATE_DIRECTORY --profile PROFILE [PROFILE_OPTIONS]
  ./install.sh --root PRIVATE_DIRECTORY --cli [--dry-run]

This beta provisions only an isolated, user-owned directory (mode 0700).
Use one of: standalone, active-directory, full-enterprise.
Use --yes after reviewing the operation for noninteractive confirmation.
The installer does not install packages, start services or enroll AD.
TEXT
}

if [[ ${1:-} == --help ]]; then
    usage
    exit 0
fi
(( EUID != 0 )) || { echo 'Run this beta installer as a regular user.' >&2; exit 1; }
base=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
if [[ ${1:-} == --bootstrap ]]; then
    shift
    exec /usr/bin/python -IB -c '
import runpy
import sys
sys.path.insert(0, sys.argv.pop(1))
runpy.run_module("oe.bootstrap", run_name="__main__")
' "$base" "$@"
fi
installer="$base/bin/omarchy-enterprise"
root=
if [[ ${1:-} == --root ]]; then
    [[ $# -ge 2 && -n $2 ]] || { usage >&2; exit 2; }
    root=$2
    shift 2
fi

if [[ ${1:-} == --profile || ${1:-} == --profile=* ]]; then
    [[ -n $root ]] || { echo 'Use --root before --profile.' >&2; exit 2; }
    exec "$installer" provision-image --root "$root" apply "$@"
fi

terminal=false
if [[ ${1:-} == --cli ]]; then
    terminal=true
    shift
fi
if [[ $# -gt 1 || ( $# -eq 1 && $1 != --dry-run ) ]]; then
    usage >&2
    exit 2
fi
if [[ $terminal == false && -n ${DISPLAY:-}${WAYLAND_DISPLAY:-} ]] && command -v zenity >/dev/null; then
    options=()
    if [[ -n $root ]]; then
        options=(--root "$root")
    fi
    exec "$installer" provision-wizard "${options[@]}" "$@"
fi

[[ -n $root && -t 0 ]] || {
    echo 'The graphical wizard is unavailable. Use a private directory and the explicit --profile form.' >&2
    usage >&2
    exit 2
}
printf '%s\n' '1) Standalone Enterprise' '2) Active Directory Enterprise' '3) Full Enterprise'
IFS= read -r -p 'Select a profile [1-3]: ' choice
options=()
case $choice in
    1) profile=standalone ;;
    2) profile=active-directory ;;
    3) profile=full-enterprise ;;
    *) echo 'Unknown profile.' >&2; exit 2 ;;
esac
if [[ $profile != standalone ]]; then
    IFS= read -r -p 'DNS domain: ' domain
    IFS= read -r -p 'NetBIOS workgroup: ' workgroup
    IFS= read -r -p 'Allowed AD group name: ' users
    IFS= read -r -p 'AD administrator group name: ' admins
    options=(--domain "$domain" --workgroup "$workgroup" --users "$users" --admins "$admins")
fi
if [[ $profile == full-enterprise ]]; then
    IFS= read -r -p 'Reviewed Dockur image digest (optional): ' image
    if [[ -n $image ]]; then
        options+=(--image "$image")
    fi
fi
exec "$installer" provision-image --root "$root" apply --profile "$profile" "${options[@]}" "$@"
