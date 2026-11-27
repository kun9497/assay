#!/bin/sh
# Harness for scripts/memwatch.sh (Linux: it reads /proc). The wrapper must
# keep the command's exit status and stdout, and its summary must name a
# resident set the command really held -- a sampler that measured nothing
# would print zeros and look like a quiet night.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
export MEMWATCH_LOG="$tmp/mem.log" MEMWATCH_EVERY=1
fail() { echo "FAIL: $*" >&2; exit 1; }

# Exit status and stdout pass through.
set +e
out=$(sh "$here/memwatch.sh" sh -c 'echo payload; sleep 2; exit 7' 2>"$tmp/err")
rc=$?
set -e
[ "$rc" -eq 7 ] || fail "exit status $rc, want 7"
[ "$out" = payload ] || fail "stdout '$out', want 'payload' alone"
grep -q '^memwatch: peak rss ' "$tmp/err" || fail "no summary on stderr: $(cat "$tmp/err")"

# A command holding ~200 MiB is measured as holding it: python3 is on the
# runner, and a bytearray is resident once written.
sh "$here/memwatch.sh" python3 -c 'b = bytearray(200 << 20); b[::4096] = b"x" * len(b[::4096]); import time; time.sleep(3)' 2>"$tmp/err"
line=$(grep '^memwatch: peak rss ' "$tmp/err") || fail "no summary: $(cat "$tmp/err")"
rss=$(echo "$line" | awk '{ print $4 }')
avail=$(echo "$line" | sed -n 's/.*lowest available \([0-9][0-9]*\) MiB.*/\1/p')
[ "$rss" -ge 150 ] || fail "peak rss $rss MiB, want >= 150: $line"
[ -n "$avail" ] && [ "$avail" -gt 0 ] || fail "no available memory read: $line"
grep -q '^memwatch: rss [0-9]* MiB, available [0-9]* MiB, swap used [0-9]* MiB$' "$tmp/err" || fail "no periodic line: $(cat "$tmp/err")"

# Usage error is exit 2.
set +e
sh "$here/memwatch.sh" 2>/dev/null
rc=$?
set -e
[ "$rc" -eq 2 ] || fail "no command: exit $rc, want 2"

echo "memwatch harness: ok"
