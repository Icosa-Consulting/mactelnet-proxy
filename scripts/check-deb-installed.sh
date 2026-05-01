#!/usr/bin/env bash
#
# Compares a .deb file's version against the currently-installed
# version of the same package on this system.
#
# Exit codes:
#   0  installed and version matches → no install needed
#   1  not installed, or installed at a different version
#   2  invalid input / required tools missing
#
# Usage:
#   check-deb-installed.sh path/to/mactelnet-proxy_0.1.9_amd64.deb
#
# Example wrapper:
#   if ! check-deb-installed.sh "$DEB"; then
#       sudo dpkg -i "$DEB"
#   fi

set -euo pipefail

deb=${1:?usage: $0 <path-to-.deb>}

[[ -r $deb ]] || { echo "cannot read $deb" >&2; exit 2; }
command -v dpkg-deb   >/dev/null || { echo "dpkg-deb not found"   >&2; exit 2; }
command -v dpkg-query >/dev/null || { echo "dpkg-query not found" >&2; exit 2; }

pkg=$(dpkg-deb -f "$deb" Package)
deb_ver=$(dpkg-deb -f "$deb" Version)

# dpkg-query exits non-zero when the package has never been seen, and
# returns a row for "deinstall ok config-files" / "purge ok not-installed"
# too — check Status to distinguish those from a real install.
status_line=$(dpkg-query -W -f='${Status}|${Version}\n' "$pkg" 2>/dev/null) || status_line=

if [[ -z $status_line ]]; then
    echo "$pkg: not installed (deb is $deb_ver)"
    exit 1
fi

installed_status=${status_line%|*}
installed_ver=${status_line##*|}

if [[ $installed_status != "install ok installed" ]]; then
    echo "$pkg: $installed_status (deb is $deb_ver)"
    exit 1
fi

if [[ $installed_ver == "$deb_ver" ]]; then
    echo "$pkg: already at $deb_ver"
    exit 0
fi

echo "$pkg: installed=$installed_ver, deb=$deb_ver"
exit 1
