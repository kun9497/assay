#!/bin/sh
# memwatch.sh CMD [ARG...] -- run CMD, sampling memory every 30 seconds, and
# exit with CMD's status.
#
# The nightly's runner was lost mid-Build on 2026-11-24 and 2026-11-25,
# ~50 minutes in, with no failed step and no log. Memory is the suspect
# (Red Hat alone holds ~3M affected entries) but nothing measured it. This
# prints a line every 5 minutes, so a partial log shows the trend, and a
# summary at the end of every run that finishes, so a good night says how
# close it came. It changes nothing about the build.
#
# Linux only: it reads /proc. Without /proc it runs CMD unsampled.
set -u
[ $# -gt 0 ] || { echo "usage: memwatch.sh CMD [ARG...]" >&2; exit 2; }
log=${MEMWATCH_LOG:-/tmp/memwatch.log}
every=${MEMWATCH_EVERY:-30}

if [ ! -r /proc/meminfo ]; then
	"$@"
	exit $?
fi

meminfo() { awk -v k="$1:" '$1 == k { print int($2 / 1024) }' /proc/meminfo; }

: >"$log"
"$@" &
cmd=$!
(
	n=0
	while kill -0 "$cmd" 2>/dev/null; do
		# The command's own resident set, children included (db build
		# shells out to git for the Ubuntu tracker).
		rss=$(ps -o rss= --pid "$cmd" --ppid "$cmd" 2>/dev/null | awk '{ s += $1 } END { print int(s / 1024) }')
		avail=$(meminfo MemAvailable)
		swap=$(($(meminfo SwapTotal) - $(meminfo SwapFree)))
		echo "$rss $avail $swap" >>"$log"
		if [ $((n % 10)) -eq 0 ]; then
			echo "memwatch: rss ${rss} MiB, available ${avail} MiB, swap used ${swap} MiB" >&2
		fi
		n=$((n + 1))
		sleep "$every"
	done
) &
sampler=$!
wait "$cmd"
rc=$?
kill "$sampler" 2>/dev/null
wait "$sampler" 2>/dev/null

total=$(meminfo MemTotal)
awk -v total="$total" -v every="$every" '
	NR == 1 { minavail = $2 }
	{ if ($1 > rss) rss = $1; if ($2 < minavail) minavail = $2; if ($3 > swap) swap = $3 }
	END {
		printf "memwatch: peak rss %d MiB of %d MiB, lowest available %d MiB, peak swap used %d MiB (%d samples, every %ss)\n", rss, total, minavail, swap, NR, every
	}' "$log" >&2
exit "$rc"
