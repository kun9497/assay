package scancmd

import (
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/kun9497/assay/internal/store"
)

// checkDBAge refuses a scan against vulnerability data older than max (D59).
//
// Freshness is measured from the UPSTREAM data, never from when the database
// was assembled — that is D12, and it is the whole reason this can be honest.
// A mirror serving a six-month-old snapshot fetched an hour ago has a recent
// BuiltAt and an ancient DataAsOf, and judging by the former would call it
// fresh.
//
// The age is the OLDEST provider's, because a database is only as fresh as its
// stalest source. Taking the newest would let one daily provider vouch for
// another that stopped updating in March.
//
// Exit 2, not 1 (D11). An out-of-date database does not mean "found nothing",
// it means the result cannot be trusted — which is exactly the distinction the
// exit codes exist to keep, and the same reason a schema mismatch exits 2.
//
// No default. A scan with no --db-max-age behaves as it always has: this
// refuses to invent a number, because the right one depends on how the caller
// runs `db update` and any value picked here would be a policy nobody chose.
func checkDBAge(m store.Meta, max time.Duration, now time.Time, stderr io.Writer) int {
	if max <= 0 {
		return 0
	}
	oldest, name, unknown := oldestProvider(m)

	// An unknown age is refused, not passed. This is D17's discipline applied
	// to time: a provider that could not say when its data was current has not
	// said it is fresh, and treating silence as "recent enough" would let
	// exactly the stale database this flag exists to catch through — the
	// provider whose feed died is also the one least likely to report a date.
	if len(unknown) > 0 {
		fmt.Fprintf(stderr, "error: --db-max-age given, but %s did not record when its "+
			"data was current, so this database's age cannot be established\n",
			joinNames(unknown))
		fmt.Fprintln(stderr, "  run `assay db update` for a database whose providers all "+
			"report a date, or drop --db-max-age to scan without the check")
		return 2
	}
	if oldest.IsZero() {
		// No providers at all. A database with none cannot serve a scan for
		// other reasons and D20's coverage check will say so; failing here too
		// would report the wrong cause.
		return 0
	}

	if age := now.Sub(oldest); age > max {
		fmt.Fprintf(stderr, "error: vulnerability data is %s old (%s, as of %s), past the "+
			"%s allowed by --db-max-age\n",
			roundAge(age), name, oldest.UTC().Format("2006-01-02"), max)
		fmt.Fprintln(stderr, "  run `assay db update`; this result would not be trustworthy")
		return 2
	}
	return 0
}

// oldestProvider returns the stalest provider's timestamp and name, plus the
// names of any that recorded none.
//
// Ratings and enrichment are deliberately NOT considered. Both are additive:
// a stale NVD window means some findings carry no score, which the report
// already says (D17), and stale KISA prose is display copy that cannot move a
// verdict (D3). Only the ADVISORIES decide whether a package is reported
// affected, so only their age can make a clean result untrustworthy.
func oldestProvider(m store.Meta) (oldest time.Time, name string, unknown []string) {
	// Sorted, so the named provider does not depend on map iteration order
	// when two share a timestamp — design goal #3 reaches error messages too.
	names := make([]string, 0, len(m.Providers))
	for n := range m.Providers {
		names = append(names, n)
	}
	sort.Strings(names)

	for _, n := range names {
		p := m.Providers[n]
		if p.DataAsOf.IsZero() {
			unknown = append(unknown, n)
			continue
		}
		if oldest.IsZero() || p.DataAsOf.Before(oldest) {
			oldest, name = p.DataAsOf, n
		}
	}
	return oldest, name, unknown
}

func joinNames(ns []string) string {
	switch len(ns) {
	case 1:
		return ns[0]
	case 2:
		return ns[0] + " and " + ns[1]
	}
	out := ""
	for i, n := range ns[:len(ns)-1] {
		if i > 0 {
			out += ", "
		}
		out += n
	}
	return out + " and " + ns[len(ns)-1]
}

// roundAge renders a duration the way someone reads an age: days once it is
// past a day, because "1583h24m" is a number a reader has to convert before
// they can act on it.
func roundAge(d time.Duration) string {
	if d >= 24*time.Hour {
		days := int(d.Hours() / 24)
		if days == 1 {
			return "1 day"
		}
		return fmt.Sprintf("%d days", days)
	}
	return d.Round(time.Minute).String()
}
