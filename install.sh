#!/bin/sh
# assay installer. Downloads this release's prebuilt binary for your OS/arch
# from the GitHub Release, verifies the release's checksums file against the
# project's signing key embedded below (D137), verifies the archive's SHA256
# against that file, and installs the one binary.
#
#   curl -sSfL https://raw.githubusercontent.com/kun9497/assay/<commit>/install.sh | sh
#
# The README names the commit each release was built from: pin that, not a
# branch or a tag -- a branch moves, and so can a tag; the commit cannot.
# This script installs the version it was published with (VERSION below);
# `sh -s -- vX.Y.Z` installs another release, still verified against the
# keys embedded here, so an older script cannot install a release signed by
# a key it predates (run the installer published with that release).
#
# Flags (after `sh -s --`):
#   -b <dir>   install directory (default: ./bin)
#   <version>  a tag to install, e.g. v0.12.0 (default: VERSION below)
#
# Environment:
#   ASSAY_ALLOW_UNSIGNED=1   if neither openssl nor cosign is available,
#                            fall back to the SHA256 check alone (loudly).
#                            Never needed on a stock Linux or macOS.
#   ASSAY_OS / ASSAY_ARCH    override the detected platform (cross-install).
#
# POSIX sh, no bashisms -- needs curl (or wget), tar, sha256sum (or shasum),
# base64, and openssl (or cosign) to verify the signature. It never runs
# anything it downloads; it only extracts one binary.
set -eu

REPO="kun9497/assay"
BINDIR="./bin"
# Set by scripts/prepare-release.sh in the commit a release is cut from.
# Releases before the first signed one carry no checksums signature and are
# refused by this script; the README says which release that is.
VERSION="v0.10.0"
RELEASE_BASE="${ASSAY_RELEASE_BASE:-https://github.com/${REPO}/releases/download}"

# The public keys this installer trusts, PEM, one per release signing key.
# Rotation: release N+1's script carries keys N and N+1; a later one drops N.
# BEGIN TRUSTED KEYS
TRUSTED_KEYS='
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIJp1pXQuHML8/s3OnIas+O/upoke
VxyV0PZvba/q+F7T/1S10tKP7JL5QUE9DXJZPcYDVWoCyvM0NfUJuNvv0Q==
-----END PUBLIC KEY-----
'
# END TRUSTED KEYS

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
os="${ASSAY_OS:-$(uname -s | tr '[:upper:]' '[:lower:]')}"
case "$os" in
linux | darwin) ;;
*)
	echo "assay: no prebuilt binary for OS '$os' — try 'go install github.com/${REPO}/cmd/assay@latest'" >&2
	exit 1
	;;
esac

arch="${ASSAY_ARCH:-$(uname -m)}"
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
elif command -v wget >/dev/null 2>&1; then
	fetch() { wget -qO "$2" "$1"; }
else
	echo "assay: need curl or wget to download" >&2
	exit 1
fi

# GoReleaser's archive names strip the leading 'v' from the version.
ver_noV=$(echo "$VERSION" | sed 's/^v//')
archive="assay_${ver_noV}_${os}_${arch}.tar.gz"
sums="assay_${ver_noV}_checksums.txt"
base="${RELEASE_BASE}/${VERSION}"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo "assay: downloading ${archive} (${VERSION})" >&2
fetch "${base}/${archive}" "${tmp}/${archive}"
fetch "${base}/${sums}" "${tmp}/${sums}"
if ! fetch "${base}/${sums}.sig" "${tmp}/${sums}.sig" 2>/dev/null; then
	# Refused, never warned about: every release from the first signed one
	# onward attaches the signature, so a missing one is a stripped one.
	echo "assay: ${sums}.sig is missing from the ${VERSION} release — refusing to install an unsigned checksums file" >&2
	exit 1
fi

# --- verify the checksums file's signature -----------------------------------
# cosign sign-blob writes the base64 of a DER ECDSA-P256-SHA256 signature;
# openssl verifies exactly that once decoded, and is on every stock Linux and
# macOS where cosign is not. Each embedded key is tried in turn.
verified=""
n=0
printf '%s\n' "$TRUSTED_KEYS" | awk -v dir="$tmp" '
	/-----BEGIN PUBLIC KEY-----/ { n++; f = dir "/key" n ".pub" }
	f != "" { print > f }
	/-----END PUBLIC KEY-----/ { close(f); f = "" }
'
for k in "$tmp"/key*.pub; do
	[ -f "$k" ] || continue
	n=$((n + 1))
done
[ "$n" -gt 0 ] || {
	echo "assay: this installer embeds no trusted key; it is not a published copy — refusing to install" >&2
	exit 1
}
# The key files are iterated as a quoted glob, never through a space-joined
# list: a temp dir with a space in its path would otherwise split every
# key path and refuse a genuine release as "does not verify".
verify_with_openssl() {
	base64 -d "${tmp}/${sums}.sig" >"${tmp}/sig.der" 2>/dev/null || return 1
	for k in "$tmp"/key*.pub; do
		[ -f "$k" ] || continue
		if openssl dgst -sha256 -verify "$k" -signature "${tmp}/sig.der" "${tmp}/${sums}" >/dev/null 2>&1; then
			verified="$(basename "$k")"
			return 0
		fi
	done
	return 1
}
verify_with_cosign() {
	for k in "$tmp"/key*.pub; do
		[ -f "$k" ] || continue
		if cosign verify-blob --key "$k" --signature "${tmp}/${sums}.sig" --insecure-ignore-tlog=true "${tmp}/${sums}" >/dev/null 2>&1; then
			verified="$(basename "$k")"
			return 0
		fi
	done
	return 1
}
if command -v openssl >/dev/null 2>&1; then
	verify_with_openssl || {
		echo "assay: signature on ${sums} does not verify against any key embedded in this installer (${VERSION}) — refusing to install" >&2
		echo "assay:   run the installer published with the release you want; see the README" >&2
		exit 1
	}
	echo "assay: signature on ${sums} verified (openssl, ${verified})" >&2
elif command -v cosign >/dev/null 2>&1; then
	verify_with_cosign || {
		echo "assay: signature on ${sums} does not verify against any key embedded in this installer (${VERSION}) — refusing to install" >&2
		echo "assay:   run the installer published with the release you want; see the README" >&2
		exit 1
	}
	echo "assay: signature on ${sums} verified (cosign, ${verified})" >&2
elif [ "${ASSAY_ALLOW_UNSIGNED:-}" = "1" ]; then
	echo "assay: WARNING: neither openssl nor cosign is available; ${sums}.sig was NOT checked and the checksums file itself is not authenticated — continuing with the SHA256 check alone because ASSAY_ALLOW_UNSIGNED=1" >&2
else
	echo "assay: neither openssl nor cosign is available to verify ${sums}.sig — refusing to install (set ASSAY_ALLOW_UNSIGNED=1 to accept the sha256 check alone)" >&2
	exit 1
fi

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
