#!/bin/sh
# Writes status.json for the published database and commits it to the
# `status` branch (D138), served at
#   https://raw.githubusercontent.com/kun9497/assay/status/status.json
#
#   sh scripts/publish-status.sh <workflow> <success|failure|cancelled> <run-url>
#
# Run from a checkout of main by the `status` job of db-publish.yml,
# db-sign.yml and db-backfill.yml, with contents:write. The branch holds status.json and nothing
# else, one small commit per run; it is created on first use. The writer
# workflows share the db-artifact-writer concurrency group, so two runs never
# push it at once.
set -eu

workflow="$1" result="$2" url="$3"
work=$(mktemp -d)
trap 'git worktree remove --force "$work/tree" >/dev/null 2>&1 || true; rm -rf "$work"' EXIT

if git fetch --quiet origin status 2>/dev/null; then
	git show FETCH_HEAD:status.json >"$work/prev.json" 2>/dev/null || rm -f "$work/prev.json"
	git worktree add --quiet --detach "$work/tree" FETCH_HEAD
else
	# First run: an orphan branch, so status history never mixes with code.
	git worktree add --quiet --orphan -b status "$work/tree"
fi

prev=""
[ -f "$work/prev.json" ] && prev="$work/prev.json"
go run ./cmd/dbstatus -workflow "$workflow" -result "$result" -run-url "$url" \
	${prev:+-prev "$prev"} -out "$work/tree/status.json"

cd "$work/tree"
git add status.json
git -c user.name="github-actions[bot]" -c user.email="41898282+github-actions[bot]@users.noreply.github.com" \
	commit --quiet -m "status: ${workflow} ${result}"
git push --quiet origin HEAD:refs/heads/status
echo "status.json published to the status branch"
