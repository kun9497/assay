#!/bin/sh
# Scans one built release binary for known Go vulnerabilities, before
# anything is published. GoReleaser runs it as each build's post hook
# (.goreleaser.yaml), so it reads the exact binary that goes into the
# archive -- stripped, cross-compiled, built by the toolchain the release
# used -- and a finding stops the release before the GitHub Release exists.
#
# QA 2026-10-30: v0.12.0 shipped with GO-2026-6809 reachable. A source scan
# on a developer's machine judges that machine's toolchain, not the
# release's; this judges the deliverable.
#
# govulncheck is pinned, and exits nonzero on any finding it can place.
#
#   sh scripts/release-vulncheck.sh dist/assay_linux_amd64_v1/assay
set -eu
GOVULNCHECK_VERSION=v1.9.0
echo "govulncheck $GOVULNCHECK_VERSION: $1"
go run "golang.org/x/vuln/cmd/govulncheck@${GOVULNCHECK_VERSION}" -mode=binary "$1"
