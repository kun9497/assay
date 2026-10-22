#!/bin/sh
# Attack harness for install.sh (D137). Builds two fake releases signed with
# two test keys (openssl, so CI needs nothing installed), serves them from a
# local python http.server, renders the installer with the test keys in
# place of the embedded ones, and runs every case the design names. Each
# case asserts the exit code and a message substring; any mismatch fails
# the harness. Run from the repository root: sh scripts/install_test.sh
set -eu

here=$(cd "$(dirname "$0")/.." && pwd)
INSTALL_SH="${INSTALL_SH:-$here/install.sh}"
PY=$(command -v python3 2>/dev/null || command -v python 2>/dev/null || { echo "harness: need python3"; exit 2; })
tmp=$(mktemp -d)
trap '[ -n "${srvpid:-}" ] && kill "$srvpid" 2>/dev/null; sleep 0.3; rm -rf "$tmp" 2>/dev/null || true' EXIT
fail=0
os="${ASSAY_OS:-$(uname -s | tr '[:upper:]' '[:lower:]')}"
case "$os" in linux | darwin) ;; *) os=linux ;; esac
arch="${ASSAY_ARCH:-amd64}"
case "$arch" in x86_64) arch=amd64 ;; aarch64) arch=arm64 ;; esac
export ASSAY_OS="$os" ASSAY_ARCH="$arch"

# --- keys ---------------------------------------------------------------------
for k in key1 key2 attacker; do
	openssl ecparam -name prime256v1 -genkey -noout -out "$tmp/$k.pem" 2>/dev/null
	openssl ec -in "$tmp/$k.pem" -pubout -out "$tmp/$k.pub" 2>/dev/null
done

# --- fake releases ------------------------------------------------------------
# release <tag> <key> <dir> [label]: archive + GoReleaser-format checksums +
# base64 DER signature, the shape cosign sign-blob writes.
release() {
	tag=$1 key=$2 dir=$3 label=${4:-genuine}
	ver=${tag#v}
	mkdir -p "$dir/$tag"
	work="$tmp/work-$tag-$label"
	mkdir -p "$work"
	printf '#!/bin/sh\necho "assay %s (%s build)"\n' "$tag" "$label" >"$work/assay"
	chmod +x "$work/assay"
	(cd "$work" && tar -czf "$dir/$tag/assay_${ver}_${os}_${arch}.tar.gz" assay)
	(cd "$dir/$tag" && sha256sum --text "assay_${ver}_${os}_${arch}.tar.gz" | sed 's/ \*/  /' >"assay_${ver}_checksums.txt")
	openssl dgst -sha256 -sign "$tmp/$key.pem" -out "$tmp/sig-$tag-$label.der" "$dir/$tag/assay_${ver}_checksums.txt"
	base64 -w0 "$tmp/sig-$tag-$label.der" >"$dir/$tag/assay_${ver}_checksums.txt.sig"
}
root="$tmp/releases"
release v9.9.1 key1 "$root"
release v9.9.2 key2 "$root"

# --- server -------------------------------------------------------------------
port=$("$PY" -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')
(cd "$root" && exec "$PY" -m http.server "$port" --bind 127.0.0.1 >"$tmp/server.log" 2>&1) &
srvpid=$!
i=0
until curl -sf "http://127.0.0.1:$port/" >/dev/null 2>&1; do
	i=$((i + 1))
	[ "$i" -lt 50 ] || { echo "harness: server did not start"; cat "$tmp/server.log"; exit 2; }
	sleep 0.1
done
export ASSAY_RELEASE_BASE="http://127.0.0.1:$port"

# --- render installers --------------------------------------------------------
# render <out> <version> <pubfiles...>: install.sh with VERSION set and the
# embedded key block replaced by the given test keys.
render() {
	out=$1 version=$2
	shift 2
	{
		sed -n '1,/^# BEGIN TRUSTED KEYS$/p' "$INSTALL_SH" | sed "s/^VERSION=.*/VERSION=\"$version\"/"
		printf "TRUSTED_KEYS='\n"
		for p in "$@"; do cat "$p"; done
		printf "'\n"
		sed -n '/^# END TRUSTED KEYS$/,$p' "$INSTALL_SH"
	} >"$out"
	grep -q '^# BEGIN TRUSTED KEYS$' "$out" && grep -q '^# END TRUSTED KEYS$' "$out" || { echo "harness: install.sh lacks the TRUSTED KEYS markers"; exit 2; }
}
render "$tmp/install-k1.sh" v9.9.1 "$tmp/key1.pub"
render "$tmp/install-k12.sh" v9.9.2 "$tmp/key1.pub" "$tmp/key2.pub"

# --- runner -------------------------------------------------------------------
# run <case> <script> <want-exit> <want-substring> [args...]
# The env ABSENT, when set, names a substring stderr must NOT contain, so a
# case can tell the refusal it names from a refusal by a later guard.
run() {
	name=$1 script=$2 want=$3 needle=$4
	shift 4
	bin="$tmp/bin-$name"
	rm -rf "$bin"
	set +e
	sh "$script" -b "$bin" "$@" >"$tmp/$name.out" 2>"$tmp/$name.err"
	code=$?
	set -e
	if [ "$code" != "$want" ] || ! grep -q -- "$needle" "$tmp/$name.err" || { [ -n "${ABSENT:-}" ] && grep -q -- "$ABSENT" "$tmp/$name.err"; }; then
		echo "FAIL $name: exit=$code want=$want; stderr:"; sed 's/^/    /' "$tmp/$name.err"
		fail=1
	else
		echo "ok   $name (exit $code)"
	fi
}

# C1 clean install
run C1 "$tmp/install-k1.sh" 0 "installed v9.9.1"
"$tmp/bin-C1/assay" | grep -q "v9.9.1 (genuine build)" || { echo "FAIL C1: wrong binary installed"; fail=1; }

# C2 archive tampered, checksums + sig untouched
cp -r "$root" "$tmp/c2"
printf '#!/bin/sh\necho EVIL\n' >"$tmp/evil"
(cd "$tmp" && tar -czf "c2/v9.9.1/assay_9.9.1_${os}_${arch}.tar.gz" -C "$tmp" evil --transform 's/evil/assay/' 2>/dev/null || tar -czf "c2/v9.9.1/assay_9.9.1_${os}_${arch}.tar.gz" -C "$tmp" evil)
ASSAY_RELEASE_BASE="http://127.0.0.1:$port/../c2" true
# http.server cannot escape its root, so serve each mutated tree under it.
mv "$tmp/c2" "$root/c2"
ASSAY_RELEASE_BASE="http://127.0.0.1:$port/c2" run C2 "$tmp/install-k1.sh" 1 "checksum mismatch"

# C3a release assets rewritten consistently, stale .sig left
release v9.9.1 attacker "$root/c3a" EVIL
cp "$root/v9.9.1/assay_9.9.1_checksums.txt.sig" "$root/c3a/v9.9.1/assay_9.9.1_checksums.txt.sig"
ASSAY_RELEASE_BASE="http://127.0.0.1:$port/c3a" run C3a "$tmp/install-k1.sh" 1 "does not verify against any key embedded"

# C3a-nosig: .sig deleted -- refused by the missing-signature guard itself,
# not by a later one (ABSENT pins which guard fired).
release v9.9.1 attacker "$root/c3n" EVIL
rm "$root/c3n/v9.9.1/assay_9.9.1_checksums.txt.sig"
ABSENT="does not verify" ASSAY_RELEASE_BASE="http://127.0.0.1:$port/c3n" run C3a-nosig "$tmp/install-k1.sh" 1 "is missing from the v9.9.1 release"
# ...and ASSAY_ALLOW_UNSIGNED does not excuse a missing signature.
ABSENT="does not verify" ASSAY_ALLOW_UNSIGNED=1 ASSAY_RELEASE_BASE="http://127.0.0.1:$port/c3n" run C3a-nosig-allow "$tmp/install-k1.sh" 1 "is missing from the v9.9.1 release"

# C3b: attacker re-signed with their own key (the embedded key never changes)
release v9.9.1 attacker "$root/c3b" EVIL
ASSAY_RELEASE_BASE="http://127.0.0.1:$port/c3b" run C3b "$tmp/install-k1.sh" 1 "does not verify against any key embedded"
# ASSAY_ALLOW_UNSIGNED is scoped to "no verifier on the host": with openssl
# present and a bad signature it changes nothing.
ASSAY_ALLOW_UNSIGNED=1 ASSAY_RELEASE_BASE="http://127.0.0.1:$port/c3b" run C3b-allow "$tmp/install-k1.sh" 1 "does not verify against any key embedded"

# C1-space: a temp dir with a space in its path still verifies a genuine release.
mkdir -p "$tmp/sp ace"
TMPDIR="$tmp/sp ace" run C1-space "$tmp/install-k1.sh" 0 "installed v9.9.1"

# C5: neither openssl nor cosign on PATH. The narrowed PATH holds copies of
# the tools the installer needs minus the two verifiers; copied binaries
# only run where they carry no sibling DLLs, so this runs on Linux/macOS
# (CI) and is reported, not silently passed, elsewhere.
case "$(uname -s)" in
Linux | Darwin)
	narrow="$tmp/narrowbin"
	mkdir -p "$narrow"
	for t in sh uname tr curl tar sha256sum shasum awk grep sed mktemp rm mkdir mv chmod base64 head cat basename dirname pwd sleep gzip; do
		p=$(command -v "$t" 2>/dev/null || true)
		[ -n "$p" ] && [ -f "$p" ] && ln -s "$p" "$narrow/$t" 2>/dev/null || true
	done
	oldpath=$PATH
	PATH="$narrow" run C5 "$tmp/install-k1.sh" 1 "neither openssl nor cosign"
	PATH="$narrow" ASSAY_ALLOW_UNSIGNED=1 run C5-allow "$tmp/install-k1.sh" 0 "WARNING"
	PATH="$narrow" ASSAY_ALLOW_UNSIGNED=1 ASSAY_RELEASE_BASE="http://127.0.0.1:$port/c2" run C5-allow-tampered "$tmp/install-k1.sh" 1 "checksum mismatch"
	PATH=$oldpath
	;;
*)
	echo "SKIP C5 C5-allow C5-allow-tampered: PATH narrowing needs Linux/macOS (CI runs them)"
	;;
esac

# C6 rotation: v9.9.2 is signed by key2
run C6-new-script "$tmp/install-k12.sh" 0 "installed v9.9.2"
run C6-old-script "$tmp/install-k1.sh" 1 "does not verify against any key embedded" v9.9.2
run C6-new-script-old-release "$tmp/install-k12.sh" 0 "installed v9.9.1" v9.9.1

# C7: no latest lookup -- the script never contacts anything but the release base
grep -q "api.github.com" "$INSTALL_SH" && { echo "FAIL C7: install.sh still calls api.github.com"; fail=1; } || echo "ok   C7 (no api.github.com call)"

[ "$fail" = 0 ] && echo "install harness: all cases passed" || { echo "install harness: FAILURES"; exit 1; }
