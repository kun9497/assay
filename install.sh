#!/bin/sh
# assay installer. Downloads the right prebuilt binary for this OS/arch from
# the latest GitHub Release, verifies its SHA256 against the published
# checksums file, and installs it.
#
#   curl -sSfL https://raw.githubusercontent.com/kun9497/assay/main/install.sh | sh
#
# Flags (after `sh -s --`):
#   -b <dir>   install directory (default: ./bin)
#   <version>  a tag to pin, e.g. v0.1.0 (default: latest release)
#
# POSIX sh, no bashisms — needs curl (or wget), tar, and sha256sum (or
# shasum). It never runs anything it downloads; it only extracts one binary.
set -eu

REPO="kun9497/assay"
BINDIR="./bin"
VERSION="latest"

usage() {
	echo "usage: install.sh [-b <dir>] [<version>]" >&2
	exit 2
}

while [ $# -gt 0 ]; do
	case "$1" in
	-b)
		[ $# -ge 2 ] || usage
		BINDIR="$2"
		shift 2
		;;
	-h | --help) usage ;;
	v*)
		VERSION="$1"
		shift
		;;
	*) usage ;;
	esac
done

# --- detect platform ---------------------------------------------------------
os=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$os" in
linux | darwin) ;;
*)
	echo "assay: no prebuilt binary for OS '$os' — try 'go install github.com/${REPO}/cmd/assay@latest'" >&2
	exit 1
	;;
esac

arch=$(uname -m)
case "$arch" in
x86_64 | amd64) arch="amd64" ;;
aarch64 | arm64) arch="arm64" ;;
*)
	echo "assay: no prebuilt binary for arch '$arch' — try 'go install github.com/${REPO}/cmd/assay@latest'" >&2
	exit 1
	;;
esac

# --- download helper ---------------------------------------------------------
if command -v curl >/dev/null 2>&1; then
	fetch() { curl -sSfL "$1" -o "$2"; }
	fetch_stdout() { curl -sSfL "$1"; }
elif command -v wget >/dev/null 2>&1; then
	fetch() { wget -qO "$2" "$1"; }
	fetch_stdout() { wget -qO - "$1"; }
else
	echo "assay: need curl or wget to download" >&2
	exit 1
fi

# --- resolve version ---------------------------------------------------------
if [ "$VERSION" = "latest" ]; then
	# Follow the /releases/latest redirect to read the real tag without needing jq.
	VERSION=$(fetch_stdout "https://api.github.com/repos/${REPO}/releases/latest" |
		grep '"tag_name"' | head -n1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')
	[ -n "$VERSION" ] || {
		echo "assay: could not resolve the latest release — is one published yet?" >&2
		exit 1
	}
fi
# GoReleaser's archive names strip the leading 'v' from the version.
ver_noV=$(echo "$VERSION" | sed 's/^v//')

ext="tar.gz"
archive="assay_${ver_noV}_${os}_${arch}.${ext}"
base="https://github.com/${REPO}/releases/download/${VERSION}"
sums="assay_${ver_noV}_checksums.txt"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo "assay: downloading ${archive} (${VERSION})" >&2
fetch "${base}/${archive}" "${tmp}/${archive}"
fetch "${base}/${sums}" "${tmp}/${sums}"

# --- verify checksum ---------------------------------------------------------
expected=$(grep " ${archive}\$" "${tmp}/${sums}" | awk '{print $1}')
[ -n "$expected" ] || {
	echo "assay: ${archive} is not listed in ${sums} — refusing to install unverified" >&2
	exit 1
}
if command -v sha256sum >/dev/null 2>&1; then
	actual=$(sha256sum "${tmp}/${archive}" | awk '{print $1}')
elif command -v shasum >/dev/null 2>&1; then
	actual=$(shasum -a 256 "${tmp}/${archive}" | awk '{print $1}')
else
	echo "assay: need sha256sum or shasum to verify the download" >&2
	exit 1
fi
if [ "$expected" != "$actual" ]; then
	echo "assay: checksum mismatch for ${archive}" >&2
	echo "  expected ${expected}" >&2
	echo "  actual   ${actual}" >&2
	exit 1
fi

# --- install -----------------------------------------------------------------
tar -xzf "${tmp}/${archive}" -C "$tmp" assay
mkdir -p "$BINDIR"
mv "${tmp}/assay" "${BINDIR}/assay"
chmod +x "${BINDIR}/assay"

echo "assay: installed ${VERSION} to ${BINDIR}/assay" >&2
case ":$PATH:" in
*":${BINDIR}:"*) ;;
*)
	# Not on PATH: hand the user a copy-pasteable next step instead of a
	# description of one -- "assay: command not found" right after a
	# successful install is this script's most likely support question.
	case "$BINDIR" in
	/*) absdir="$BINDIR" ;;
	*) absdir="$(pwd)/${BINDIR#./}" ;;
	esac
	echo "assay: ${BINDIR} is not on your PATH. Either:" >&2
	echo "assay:   sudo install ${absdir}/assay /usr/local/bin/" >&2
	echo "assay:   # or: export PATH=\"${absdir}:\$PATH\"" >&2
	;;
esac
