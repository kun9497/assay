#!/bin/sh
# Opens, updates or closes the pinned "is failing" issue for one ops
# workflow (D138). Run as the last job of db-publish, scanner-diff, release,
# db-backfill and db-sign, with the result of the jobs it watches:
#
#   sh scripts/ops-alert.sh <workflow> <success|failure|cancelled|skipped> <run-url>
#
# failure: comment on the open issue for <workflow>, or open one, label it
#          ops-alert and pin it -- so a broken nightly is on the repository's
#          front page and in the maintainer's notifications, not only in an
#          Actions tab nobody opens (two nightlies failed unseen on
#          2026-08-04 and 08-05).
# success: if an issue is open, say which run recovered, unpin and close it.
# cancelled / skipped: nothing. A run cancelled by its concurrency group is
#          not a failure, and alerting on it would teach the reader to
#          ignore the issue.
#
# One issue per workflow, found by its exact title, so a week of failed
# nightlies is one issue with seven comments rather than seven issues.
# Needs GH_TOKEN with issues:write and GH_REPO (Actions sets both when the
# job passes them through).
set -eu

workflow="${1:?usage: ops-alert.sh <workflow> <result> <run-url>}"
result="${2:?usage: ops-alert.sh <workflow> <result> <run-url>}"
url="${3:?usage: ops-alert.sh <workflow> <result> <run-url>}"
title="ops: ${workflow} is failing"
label="ops-alert"
when=$(date -u +%Y-%m-%dT%H:%MZ)

case "$result" in
success | failure) ;;
cancelled | skipped)
	echo "ops-alert: ${workflow} ${result}; nothing to do"
	exit 0
	;;
*)
	echo "ops-alert: unknown result '${result}'" >&2
	exit 2
	;;
esac

# The open issue for this workflow, matched on the whole title: a search
# would also match "ops: db-publish-v2 is failing".
open=$(gh issue list --label "$label" --state open --limit 100 --json number,title \
	--jq ".[] | select(.title == \"${title}\") | .number" | head -n 1)

if [ "$result" = "failure" ]; then
	if [ -n "$open" ]; then
		gh issue comment "$open" --body "Failed again at ${when}: ${url}"
		echo "ops-alert: commented on #${open}"
		exit 0
	fi
	# --force: create the label if it does not exist, leave it if it does.
	gh label create "$label" --color B60205 --description "An ops workflow is failing" --force >/dev/null
	new=$(gh issue create --title "$title" --label "$label" --body "\`${workflow}\` failed at ${when}.

Run: ${url}

This issue stays open and pinned while the workflow keeps failing; each further failure adds a comment. The next successful run closes it.
If \`db-publish\` or \`db-sign\` failed after \`db push\`, the tag may serve an unsigned digest, which every \`db update\` refuses: see docs/DESIGN.md, \"An unsigned digest on the tag is an outage\".")
	n=${new##*/}
	# Pinning fails once three issues are pinned; the issue still exists
	# and still notifies, so that is a warning, not a failed alert.
	gh issue pin "$n" || echo "ops-alert: could not pin #${n}" >&2
	echo "ops-alert: opened #${n}"
	exit 0
fi

if [ -n "$open" ]; then
	gh issue comment "$open" --body "Recovered at ${when}: ${url}"
	gh issue unpin "$open" || true
	gh issue close "$open"
	echo "ops-alert: closed #${open}"
else
	echo "ops-alert: ${workflow} succeeded; no open issue"
fi
