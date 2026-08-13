package dbcmd

import (
	"fmt"
	"io"
	"sort"
	"time"
)

// stageTiming is how long one provider, annotator or enricher took (D56).
type stageTiming struct {
	Kind    string
	Name    string
	Elapsed time.Duration
	Records int
	// Stored is how much of Elapsed went into the store rather than into
	// fetching and parsing. Zero for a stage that does not write through an
	// emit callback, and rendered only when it is not.
	//
	// It exists because a provider's total cannot tell you which half to
	// fix, and the two answers call for opposite work: a download-bound
	// stage wants concurrency, a store-bound one wants fewer and larger
	// transactions — and concurrency would make a store-bound stage worse,
	// since bolt permits one writer at a time.
	Stored time.Duration
	Failed bool
}

// reportTimings prints where a build spent its time, slowest first.
//
// The question it answers stopped being idle when the publish job went from 29
// minutes to 85 after Ubuntu landed, and one nightly run was cancelled at the
// 120-minute timeout with nothing in the log to say which provider to blame.
// Raising the timeout without this would be guessing at which stage to raise it
// for.
//
// To STDERR, with every other diagnostic. The database path on stdout is what a
// script reads, and a table appearing in front of it would break the stream
// discipline the rest of this tool keeps.
//
// Slowest first rather than in run order, because the question is always "what
// do I fix" and never "what ran when" — run order is already visible in the
// fetching/annotating lines above.
//
// A FAILED stage is listed with its elapsed time and marked, never omitted. A
// provider that died after forty minutes is the most useful row in the table,
// and a summary printed only on success is guaranteed to be missing it.
func reportTimings(stderr io.Writer, ts []stageTiming, started time.Time) {
	if len(ts) == 0 {
		return
	}
	sorted := append([]stageTiming(nil), ts...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Elapsed > sorted[j].Elapsed })

	total := time.Since(started)
	fmt.Fprintf(stderr, "\ntiming (%s total):\n", roundDur(total))

	var accounted time.Duration
	for _, s := range sorted {
		accounted += s.Elapsed
		note := ""
		if s.Failed {
			note = " (failed)"
		}
		share := ""
		if total > 0 {
			share = fmt.Sprintf(" %4.1f%%", 100*s.Elapsed.Seconds()/total.Seconds())
		}
		split := ""
		if s.Stored > 0 {
			// Both halves, named. A single percentage would leave the reader
			// to subtract, and the whole point is that the two numbers lead
			// to different work.
			split = fmt.Sprintf(" [%s fetch, %s store]",
				roundDur(s.Elapsed-s.Stored), roundDur(s.Stored))
		}
		fmt.Fprintf(stderr, "  %-9s %-22s %10s%s  %d record(s)%s%s\n",
			s.Kind, s.Name, roundDur(s.Elapsed), share, s.Records, split, note)
	}

	// The remainder is everything that is not a stage: opening the store,
	// seeding, computing coverage, the final rename. Named rather than left as
	// an unexplained gap between the rows and the total — a build whose stages
	// sum to a fraction of its wall clock is telling you the bottleneck is
	// somewhere this table does not look, and that is worth being able to see.
	if rest := total - accounted; rest > 0 {
		fmt.Fprintf(stderr, "  %-9s %-22s %10s\n", "", "everything else", roundDur(rest))
	}
}

// roundDur keeps the table comparable between runs. Sub-second precision on a
// stage that runs for an hour is noise.
func roundDur(d time.Duration) string {
	if d >= time.Minute {
		return d.Round(time.Second).String()
	}
	return d.Round(time.Millisecond).String()
}
