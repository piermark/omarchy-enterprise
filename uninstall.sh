#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'TEXT'
Usage: ./uninstall.sh --root PRIVATE_DIRECTORY [--component {all,file-servers,printer,windows}] [--yes]

Remove the beta's managed files from a previously provisioned isolated
directory. The installer journal permits recovery or rollback. This
does not remove an Arch package or change a live operating system.
TEXT
}

if [[ ${1:-} == --help ]]; then
    usage
    exit 0
fi
(( EUID != 0 )) || { echo 'Run removal as a regular user.' >&2; exit 1; }
if [[ $# -lt 2 || $1 != --root || -z $2 ]]; then
    usage >&2
    exit 2
fi
root=$2
shift 2
base=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
exec "$base/bin/omarchy-enterprise" provision-image --root "$root" remove "$@"
