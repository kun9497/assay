#!/bin/sh
# Harness for scripts/ops-alert.sh (D138): a fake `gh` on PATH records every
# call, and FAKE_OPEN sets the number `gh issue list` reports (empty: no
# open issue). Each case asserts the exact calls made, in order, because
# the order is part of the contract: an issue is created before it is
# pinned, and commented on before it is closed.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/bin"
cat >"$tmp/bin/gh" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" | head -n 1 | cut -c1-60 >>"$FAKE_LOG"
printf '%s\n' "$*" >>"$FAKE_LOG.full"
case "$1 $2" in
"issue list")
	[ -n "${FAKE_LIST_FAILS:-}" ] && { echo "HTTP 502" >&2; exit 1; }
	[ -n "${FAKE_OPEN:-}" ] && echo "$FAKE_OPEN"
	exit 0
	;;
"issue create") echo "https://github.com/o/r/issues/42" ;;
esac
exit 0
EOF
chmod +x "$tmp/bin/gh"

fail=0
# case <name> <open> <result> <want-exit> <want calls, one per line>
check() {
	name=$1 open=$2 result=$3 wantexit=$4 want=$5
	log="$tmp/$name.log"
	: >"$log"
	set +e
	FAKE_LOG="$log" FAKE_OPEN="$open" PATH="$tmp/bin:$PATH" sh "$here/ops-alert.sh" db-publish "$result" https://example.test/run/1 >"$tmp/$name.out" 2>&1
	code=$?
	set -e
	got=$(cut -d' ' -f1-3 "$log")
	if [ "$code" != "$wantexit" ] || [ "$got" != "$want" ]; then
		echo "FAIL $name (exit $code, want $wantexit)"
		echo "  calls:"; sed 's/^/    /' "$log"
		echo "  want:"; echo "$want" | sed 's/^/    /'
		sed 's/^/  out: /' "$tmp/$name.out"
		fail=1
	else
		echo "ok   $name"
	fi
}

check first-failure "" failure 0 "issue list --label
label create ops-alert
issue create --title
issue pin 42"

check repeat-failure 7 failure 0 "issue list --label
issue comment 7"

check recovery 7 success 0 "issue list --label
issue comment 7
issue unpin 7
issue close 7"

check success-nothing-open "" success 0 "issue list --label"

# A job that hits timeout-minutes reaches needs.<job>.result as `cancelled`,
# and these workflows never cancel a running job through their concurrency
# group (cancel-in-progress: false), so a cancelled run is a hung one or a
# hand-cancelled one: both are alerted on (D138 review).
check cancelled "" cancelled 0 "issue list --label
label create ops-alert
issue create --title
issue pin 42"
check skipped 7 skipped 0 ""
check unknown-result "" maybe 2 ""

# The open issue is found by its whole title (a prefix would also match
# "ops: db-publish-v2 is failing"), and a failure comment names the run.
: >"$tmp/full.log"
FAKE_LOG="$tmp/full.log" FAKE_OPEN=7 PATH="$tmp/bin:$PATH" sh "$here/ops-alert.sh" db-publish failure https://example.test/run/9 >/dev/null
if grep -qF 'select(.title == "ops: db-publish is failing")' "$tmp/full.log.full" &&
	grep -qF 'https://example.test/run/9' "$tmp/full.log.full"; then
	echo "ok   exact-title-and-run-url"
else
	echo "FAIL exact-title-and-run-url"; sed 's/^/    /' "$tmp/full.log.full"; fail=1
fi

# The new issue carries the label every later lookup filters on: without it
# the next failure finds nothing and opens a second issue.
if grep -q '^issue create .*--label ops-alert' "$tmp/first-failure.log.full"; then
	echo "ok   create-carries-the-label"
else
	echo "FAIL create-carries-the-label"; sed 's/^/    /' "$tmp/first-failure.log.full"; fail=1
fi

# A failed lookup is a failed alert, never "no open issue": that would open
# a duplicate on a failure night and leave the old issue open on recovery.
for r in failure success; do
	: >"$tmp/lf-$r.log"
	set +e
	FAKE_LOG="$tmp/lf-$r.log" FAKE_LIST_FAILS=1 FAKE_OPEN=7 PATH="$tmp/bin:$PATH" sh "$here/ops-alert.sh" db-publish "$r" u >/dev/null 2>&1
	code=$?
	set -e
	if [ "$code" != 0 ] && [ "$(wc -l <"$tmp/lf-$r.log" | tr -d ' ')" = 1 ]; then
		echo "ok   lookup-fails-$r"
	else
		echo "FAIL lookup-fails-$r (exit $code)"; sed 's/^/    /' "$tmp/lf-$r.log"; fail=1
	fi
done

[ "$fail" = 0 ] && echo "ops-alert harness: all cases passed"
exit "$fail"
