package scancmd

import (
	"fmt"
	"io"
	"maps"
	"slices"
	"sort"
	"time"

	"github.com/kun9497/assay/internal/pkgmeta"
	"github.com/kun9497/assay/internal/store"
)

// checkDBAge refuses a scan against vulnerability data older than max (D59),
// judged for keys — the ecosystem keys the scanned inventory holds (D113).
//
// Freshness is measured from the UPSTREAM data, never from when the database
// was assembled — that is D12, and it is the whole reason this can be honest.
// A mirror serving a six-month-old snapshot fetched an hour ago has a recent
// BuiltAt and an ancient DataAsOf, and judging by the former would call it
// fresh.
//
// The age is the OLDEST in-scope provider's, because a scan is only as fresh
// as the stalest source it consulted. Taking the newest would let one daily
// provider vouch for another that stopped updating in March. Providers that
// declare none of the scan's keys are not consulted by the matcher, so they
// are not measured either: before D113 the published artifact's floor was one
// finished Amazon extras topic, and an Alpine scan under --db-max-age 24h
// exited 2 over a feed it never read.
//
// Exit 2, not 1 (D11). An out-of-date database does not mean "found nothing",
// it means the result cannot be trusted — which is exactly the distinction the
// exit codes exist to keep, and the same reason a schema mismatch exits 2.
//
// No default. A scan with no --db-max-age behaves as it always has: this
// refuses to invent a number, because the right one depends on how the caller
// runs `db update` and any value picked here would be a policy nobody chose.
func checkDBAge(m store.Meta, keys []string, max time.Duration, now time.Time, stderr io.Writer) int {
	if max <= 0 {
		return 0
	}
	f := oldestProvider(m, keys)

	// An unknown age is refused, not passed. This is D17's discipline applied
	// to time: a provider that could not say when its data was current has not
	// said it is fresh, and treating silence as "recent enough" would let
	// exactly the stale database this flag exists to catch through — the
	// provider whose feed died is also the one least likely to report a date.
	// Only an in-scope provider can trip it (D113): one the scan never
	// consults is no more this scan's concern undated than it is stale.
	if len(f.unknown) > 0 {
		fmt.Fprintf(stderr, "error: --db-max-age given, but %s did not record when its "+
			"data was current, so this database's age cannot be established\n",
			joinNames(f.unknown))
		fmt.Fprintln(stderr, "  run `assay db update` for a database whose providers all "+
			"report a date, or drop --db-max-age to scan without the check")
		return 2
	}
	if f.at.IsZero() {
		// No provider declares any key this inventory holds — an empty
		// inventory, or keys the database does not cover. There is nothing to
		// measure, and D20's coverage check (D111's coverage[] beside it)
		// already reports an uncovered key; failing here too would report the
		// wrong cause.
		return 0
	}

	age := now.Sub(f.at)
	if age <= max {
		return 0
	}
	if f.frozenKey != "" {
		// Named for the key, not the provider: the provider's own date is
		// fresher than the data this scan was judged against, and an
		// unattributed "as of" would read as the provider's (D111's coverage
		// line names it the same way).
		fmt.Fprintf(stderr, "error: vulnerability data for %s is %s old (%s, frozen since %s), "+
			"past the %s allowed by --db-max-age\n",
			f.frozenKey, roundAge(age), f.provider, f.at.UTC().Format("2006-01-02"), max)
		// A different remedy from the live case: the upstream stopped
		// publishing the key (D110), so `db update` cannot make it newer. The
		// operator who scans past-EOL images through a freshness gate sets the
		// gate to the age they accept (D113 declined a third flag for this).
		fmt.Fprintf(stderr, "  the upstream stopped publishing %s, so `assay db update` will not "+
			"make it newer; set --db-max-age to the age you accept for it, or drop the flag\n", f.frozenKey)
		return 2
	}
	fmt.Fprintf(stderr, "error: vulnerability data is %s old (%s, as of %s), past the "+
		"%s allowed by --db-max-age\n",
		roundAge(age), f.provider, f.at.UTC().Format("2006-01-02"), max)
	fmt.Fprintln(stderr, "  run `assay db update`; this result would not be trustworthy")
	return 2
}

// dataFloor is the oldest data a scan's keys are judged against.
type dataFloor struct {
	at       time.Time
	provider string
	// frozenKey is the key whose freeze set at (D110), "" when a provider's
	// own DataAsOf did. The refusal names it, because the provider's date is
	// not the one that failed.
	frozenKey string
	// unknown names the in-scope providers that recorded no date.
	unknown []string
}

// oldestProvider folds the providers that declare at least one of keys into
// the oldest date among them (D113 — D59's stalest-wins inside that set).
//
// Inside the set a key Provenance.Frozen names is as old as its freeze: it
// contributes the earlier of the provider's DataAsOf and the freeze date. A
// frozen key must not read as fresher than its data (D110's own invariant),
// and the provider's DataAsOf is that morning's while the key's data stopped
// in August.
//
// A provider whose DataAsOf is zero, or whose in-scope frozen key carries a
// zero freeze date, has no age to report and lands in unknown: either way the
// age of the data this scan reads from it was not recorded.
//
// Ratings and enrichment are deliberately NOT considered. Both are additive:
// a stale NVD window means some findings carry no score, which the report
// already says (D17), and stale KISA prose is display copy that cannot move a
// verdict (D3). Only the ADVISORIES decide whether a package is reported
// affected, so only their age can make a clean result untrustworthy — ratings
// have their own gate, checkRatingAge, which a caller asks for separately.
func oldestProvider(m store.Meta, keys []string) dataFloor {
	var f dataFloor
	// Sorted, so the named provider does not depend on map iteration order
	// when two share a timestamp — design goal #3 reaches error messages too.
	for _, n := range slices.Sorted(maps.Keys(m.Providers)) {
		p := m.Providers[n]
		var in []string
		for _, k := range keys {
			if slices.Contains(p.Ecosystems, k) {
				in = append(in, k)
			}
		}
		if len(in) == 0 {
			continue
		}
		if p.DataAsOf.IsZero() || frozenUndated(p, in) {
			f.unknown = append(f.unknown, n)
			continue
		}
		for _, k := range in {
			at, frozenKey := p.DataAsOf, ""
			// Not After rather than Before: a freeze dated the same instant as
			// the provider is still the key's own date, and naming the freeze
			// tells the reader the thing they can act on.
			if since, ok := p.Frozen[k]; ok && !since.After(at) {
				at, frozenKey = since, k
			}
			if f.at.IsZero() || at.Before(f.at) {
				f.at, f.provider, f.frozenKey = at, n, frozenKey
			}
		}
	}
	return f
}

// frozenUndated reports whether any of keys is frozen with no freeze date.
func frozenUndated(p store.Provenance, keys []string) bool {
	for _, k := range keys {
		if since, ok := p.Frozen[k]; ok && since.IsZero() {
			return true
		}
	}
	return false
}

// scanKeys is the set of ecosystem keys a scan's packages are cataloged under,
// sorted: exactly the keys the matcher looks advisories up under (it calls
// Lookup with Package.Ecosystem and nothing else), and the keys D111's
// coverage[] reports, so the age gate measures what the scan consulted.
func scanKeys(t pkgmeta.Target) []string {
	seen := map[string]bool{}
	for _, p := range t.Packages {
		seen[p.Ecosystem] = true
	}
	return slices.Sorted(maps.Keys(seen))
}

// checkRatingAge refuses a scan whose rating data is older than max (D113).
//
// Not scoped to the target the way checkDBAge is: a rating is per CVE, not per
// ecosystem key, so every source rates findings under every key and there is
// no subset of them a scan did not consult.
//
// The fold is the one `db push` performs for the artifact's data-as-of
// annotation (dbcmd.oldestDataAsOf's Ratings half), so a service reading that
// annotation and a scan under this flag agree on which source is the floor —
// except that a source with no date is refused here rather than skipped,
// D59's unknown-age rule: a gate that passed silence would vouch for the one
// feed least likely to report a date, which is the one that died.
func checkRatingAge(m store.Meta, max time.Duration, now time.Time, stderr io.Writer) int {
	if max <= 0 {
		return 0
	}
	oldest, name, unknown := oldestRating(m)
	if len(unknown) > 0 {
		fmt.Fprintf(stderr, "error: --db-max-rating-age given, but %s did not record when its "+
			"data was current, so this database's rating age cannot be established\n",
			joinNames(unknown))
		fmt.Fprintln(stderr, "  run `assay db update` for a database whose rating sources all "+
			"report a date, or drop --db-max-rating-age to scan without the check")
		return 2
	}
	if oldest.IsZero() {
		// No rating source at all. Unlike an advisory-less database, nothing
		// else in the scan would say so — findings simply carry no score — so
		// this is the only place the cause can be named, and a caller who asked
		// for ratings no older than N has not been given any.
		fmt.Fprintln(stderr, "error: --db-max-rating-age given, but this database carries no "+
			"rating source, so its rating age cannot be established")
		fmt.Fprintln(stderr, "  run `assay db update` for a database with ratings, or drop "+
			"--db-max-rating-age to scan without the check")
		return 2
	}
	if age := now.Sub(oldest); age > max {
		fmt.Fprintf(stderr, "error: rating data is %s old (%s, as of %s), past the "+
			"%s allowed by --db-max-rating-age\n",
			roundAge(age), name, oldest.UTC().Format("2006-01-02"), max)
		fmt.Fprintln(stderr, "  run `assay db update`; the severity and exploit ratings in "+
			"this result would not be current")
		return 2
	}
	return 0
}

// oldestRating returns the stalest rating source's timestamp and name, plus
// the names of any that recorded none — oldestProvider's shape over
// Meta.Ratings, ranged in sorted order for the same determinism.
func oldestRating(m store.Meta) (oldest time.Time, name string, unknown []string) {
	names := make([]string, 0, len(m.Ratings))
	for n := range m.Ratings {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		p := m.Ratings[n]
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
