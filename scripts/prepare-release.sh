#!/bin/sh
# Prepare the commit a release is cut from (D137).
#
#   sh scripts/prepare-release.sh v0.12.0
#   git commit -am "chore: prepare v0.12.0" && git tag v0.12.0 && git push origin main v0.12.0
#
# The installer published with a release installs that release by default
# (install.sh's VERSION), and the script is fetched by the commit the tag
# points at -- which cannot contain its own SHA, so VERSION is set here, in
# the commit before the tag, and release.yml pins the README one-liner to
# that commit afterwards. The harness (scripts/install_test.sh) runs in CI on
# this commit, so a wrong VERSION fails before the tag is pushed.
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
echo "install.sh now installs $1 by default; commit, tag $1, push the tag." >&2
