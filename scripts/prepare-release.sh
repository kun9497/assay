#!/bin/sh
# Prepare the commit a release is cut from (D137).
#
#   sh scripts/prepare-release.sh v0.12.0
#   git commit -am "chore: prepare v0.12.0" && git push origin main
#   # wait for CI on that commit, then:
#   git tag v0.12.0 && git push origin v0.12.0
#
# Set each installer's default to a release that ships its platform.
# The tag workflow uses --check to verify the same values without editing.
set -eu
check_only=false
if [ "${1:-}" = --check ]; then
	check_only=true
	shift
fi
if [ "$#" -ne 1 ] || ! printf '%s\n' "$1" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$'; then
	echo "usage: prepare-release.sh [--check] vX.Y.Z" >&2
	exit 2
fi
unix_version=$1
windows_version=$1
if [ "$unix_version" = v0.18.5 ]; then
	windows_version=v0.18.4
fi
here=$(cd "$(dirname "$0")/.." && pwd)
if [ "$check_only" = false ]; then
	sed -i.bak "s/^VERSION=\"v[^\"]*\"$/VERSION=\"$unix_version\"/" "$here/install.sh" && rm -f "$here/install.sh.bak"
	sed -i.bak "s/^\$DefaultVersion = 'v[^']*'$/\$DefaultVersion = '$windows_version'/" "$here/install.ps1" && rm -f "$here/install.ps1.bak"
fi
grep -Fxq "VERSION=\"$unix_version\"" "$here/install.sh" || {
	echo "prepare-release: install.sh must default to $unix_version" >&2
	exit 1
}
grep -Fxq "\$DefaultVersion = '$windows_version'" "$here/install.ps1" || {
	echo "prepare-release: install.ps1 must default to $windows_version" >&2
	exit 1
}
echo "Installer defaults verified: Unix $unix_version, Windows $windows_version." >&2
