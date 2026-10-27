#!/bin/sh
# Prepare the commit a release is cut from (D137).
#
#   sh scripts/prepare-release.sh v0.12.0
#   git commit -am "chore: prepare v0.12.0" && git push origin main
#   # wait for CI on that commit, then:
#   git tag v0.12.0 && git push origin v0.12.0
#
# The installer published with a release installs that release by default
# (install.sh's VERSION, install.ps1's $DefaultVersion), and the script is
# fetched by the commit the tag points at -- which cannot contain its own
# SHA, so both are set here, in the commit before the tag, and release.yml
# pins the README one-liners to that commit afterwards. The harnesses
# replace the version in every case they run, so they cannot tell a wrong
# one; what CI does check is that the two installers name the same release
# (install_test.ps1's C11), which is why the tag waits for CI.
set -eu
case "${1:-}" in
v[0-9]*.[0-9]*.[0-9]*) ;;
*)
	echo "usage: prepare-release.sh vX.Y.Z" >&2
	exit 2
	;;
esac
here=$(cd "$(dirname "$0")/.." && pwd)
sed -i.bak "s/^VERSION=\"v[^\"]*\"$/VERSION=\"$1\"/" "$here/install.sh" && rm -f "$here/install.sh.bak"
grep -q "^VERSION=\"$1\"$" "$here/install.sh" || {
	echo "prepare-release: install.sh's VERSION line was not updated" >&2
	exit 1
}
sed -i.bak "s/^\$DefaultVersion = 'v[^']*'$/\$DefaultVersion = '$1'/" "$here/install.ps1" && rm -f "$here/install.ps1.bak"
grep -q "^\$DefaultVersion = '$1'$" "$here/install.ps1" || {
	echo "prepare-release: install.ps1's \$DefaultVersion line was not updated" >&2
	exit 1
}
echo "install.sh and install.ps1 now install $1 by default; commit, tag $1, push the tag." >&2
