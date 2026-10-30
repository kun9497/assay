#!/bin/sh
# Fails unless the Go toolchain in use is at least go.mod's toolchain line.
#
# QA 2026-10-30: v0.12.0 was built with go1.26.9 because setup-go's
# go-version "1.26" took whatever patch release the runner cache held, and
# go1.26.9 carries GO-2026-6809 (crypto/x509, fixed in go1.26.10). go.mod's
# toolchain line is the floor, raised when a stdlib advisory names a fix;
# this checks the toolchain a build actually used against it, so a runner
# that pins GOTOOLCHAIN=local to an older Go fails here instead of shipping.
#
#   sh scripts/check-go-toolchain.sh [path/to/go.mod]
set -eu
mod=${1:-go.mod}
want=$(sed -n 's/^toolchain go//p' "$mod")
if [ -z "$want" ]; then
  echo "error: $mod names no toolchain line to hold the build to" >&2
  exit 1
fi
# GOVERSION can carry a GOEXPERIMENT suffix ("go1.26.10 X:boringcrypto").
have=$(go env GOVERSION | sed 's/^go//; s/[ -].*//')
lowest=$(printf '%s\n%s\n' "$want" "$have" | sort -V | head -n 1)
if [ "$lowest" != "$want" ]; then
  echo "error: Go $have is older than go$want, the toolchain $mod requires" >&2
  exit 1
fi
echo "Go $have meets go$want ($mod)"
