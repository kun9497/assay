#!/bin/sh
# Fails unless the Go toolchain in use meets go.mod's minimum Go version.
#
# QA 2026-10-30: v0.12.0 was built with go1.26.9 because setup-go's
# go-version "1.26" took whatever patch release the runner cache held, and
# go1.26.9 carries GO-2026-6809 (crypto/x509, fixed in go1.26.10). The
# patch-level go directive also applies to customers building with
# go install module@version. A toolchain directive alone does not.
#
#   sh scripts/check-go-toolchain.sh [path/to/go.mod]
set -eu
mod=${1:-go.mod}
want=$(sed -n 's/^go //p' "$mod")
if [ -z "$want" ]; then
  echo "error: $mod has no go directive specifying the minimum Go version" >&2
  exit 1
fi
# Read separately so a failed toolchain lookup exits with the Go command's
# status. A development build reports "devel go1.27-<revision> ...".
reported=$(go env GOVERSION)
have=$(printf '%s\n' "${reported#devel }" |
  sed -nE 's/^go([0-9]+\.[0-9]+(\.[0-9]+|(beta|rc)[0-9]+)?)([- ].*)?$/\1/p')
if [ -z "$have" ]; then
  echo "error: cannot determine the Go version from GOVERSION '$reported'" >&2
  exit 1
fi
lowest=$(printf '%s\n%s\n' "$want" "$have" | sort -V | head -n 1)
if [ "$lowest" != "$want" ]; then
  echo "error: Go $have is older than go$want, the toolchain $mod requires" >&2
  exit 1
fi
echo "Go $have meets go$want ($mod)"
