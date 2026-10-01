package report

import (
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/kun9497/assay/internal/matcher"
	"github.com/kun9497/assay/internal/pkgmeta"
	"github.com/kun9497/assay/internal/store"
	"github.com/kun9497/assay/internal/version"
)

// The four states a scanned ecosystem key can be in (D111). Each reuses a
// question the matcher already asks, in the order it asks it, so a key's state
// is the reason its packages were or were not judged: version.For (D9), then
// Covers (D20), then Provenance.Frozen (D110).
const (
	// CoverageLive is a key the database holds and still refreshes.
	CoverageLive = "live"
	// CoverageFrozen is a key the database holds from data carried forward
	// because the upstream stopped publishing some or all of it (D110).
	// Its packages ARE evaluated — against data that will not be refreshed.
	CoverageFrozen = "frozen"
	// CoverageNotInDatabase is a key this build can compare versions for and
	// the database does not hold: a routed release the data lacks.
	CoverageNotInDatabase = "not-in-database"
	// CoverageNoComparer is a key this build cannot compare versions for at
	// all, which includes "" — the key an inventory from an /etc/os-release
	// assay does not route is cataloged under.
	CoverageNoComparer = "no-comparer"
)

// The three values each InventoryScopeRecord field takes (D111).
const (
	ScopeRead    = "read"
	ScopeNone    = "none"
	ScopeNotRead = "not-read"
)

// CoverageRecord is what the database could do for one ecosystem key the
// scanned inventory holds (D111) — present for every key, whether or not a
// finding sits under it. That is the point: D110 put frozenSince on a
// finding, and a clean scan has no finding to carry it, so an image whose only
// key was frozen read exactly like a clean scan on current data.
//
// No omitempty except FrozenSince, on SkippedRecord.Cause's reasoning: an empty
// provider or dataAsOf is an answer ("no provider declares this key", "the
// provider recorded no date"), and the shape must not vary per record.
// FrozenSince is omitted on a live key the way FindingRecord.FrozenSince is.
type CoverageRecord struct {
	Ecosystem string `json:"ecosystem"`
	// Packages is how many inventory packages sit under the key; Evaluated is
	// how many of them the matcher judged — Summarize's own definition, split
	// by key, so these sum to summary.evaluated.
	Packages  int    `json:"packages"`
	Evaluated int    `json:"evaluated"`
	State     string `json:"state"`
	// Provider is the Meta.Providers entry that declares the key, "" when
	// none does. DataAsOf is that provider's Provenance.DataAsOf (D12) as a
	// full-date, "" when it recorded none.
	Provider    string `json:"provider"`
	DataAsOf    string `json:"dataAsOf"`
	FrozenSince string `json:"frozenSince,omitempty"`
}

// DistroRecord is the scanned target's /etc/os-release identity (D111). It
// exists so a distro assay does not route (CentOS, D50) is NAMED in the
// result: before it, the only trace was the skip reason
// `no version comparer for ecosystem ""`, indistinguishable by cause from a
// routed release the database happens to lack, and D36 forbids a policy to
// match on reason text.
//
// No omitempty: recognized false and ecosystem "" are the statement this
// record exists to make.
type DistroRecord struct {
	ID         string `json:"id"`
	VersionID  string `json:"versionId"`
	Ecosystem  string `json:"ecosystem"`
	Recognized bool   `json:"recognized"`
}

// InventoryScopeRecord says which halves of an image's contents the inventory
// came from (D111), each ScopeRead, ScopeNone or ScopeNotRead — so the limit
// D70 recorded (application packages inside an image are not read) reaches the
// reader of the document, not only the reader of the docs.
//
// Image targets only. A directory, an SBOM or a binary has no OS database or
// /opt/bitnami to have read or not, and an object saying so would be three
// claims about things that are not there.
type InventoryScopeRecord struct {
	OSPackages          string `json:"osPackages"`
	Bitnami             string `json:"bitnami"`
	ApplicationPackages string `json:"applicationPackages"`
}

// Coverage carries D111's target-level facts from scancmd.Run to every
// renderer, the way EOLStatus carries D87's: computed once, so the table, the
// JSON and the SARIF cannot disagree about what the scan covered.
//
// The zero value is what a caller with nothing to say passes, and every
// renderer prints exactly what it printed before D111 for it — no coverage
// line, no frozen-data result, an empty coverage array.
type Coverage struct {
	Keys           []CoverageRecord
	Distro         *DistroRecord
	InventoryScope *InventoryScopeRecord
}

// CoverageOf builds one record per ecosystem key in t's inventory, sorted by
// key. m is the Meta scancmd.Run already read for --db-max-age, and skipped
// is the matcher's Result.Skipped, for the per-key Evaluated count.
//
// Always non-nil, so Document.Coverage encodes as [] for an empty inventory —
// the shape discipline Skipped and Unread follow.
func CoverageOf(t pkgmeta.Target, m store.Meta, skipped []matcher.Skipped) []CoverageRecord {
	packages := map[string]int{}
	for _, p := range t.Packages {
		packages[p.Ecosystem]++
	}
	unevaluated := map[string]int{}
	for _, s := range skipped {
		if wholePackage(s) {
			unevaluated[s.Package.Ecosystem]++
		}
	}
	// Meta.Ecosystems, not a second derivation from the providers: it is the
	// exact set store.Bolt.Covers hands the matcher, so a key's state here
	// cannot disagree with whether the matcher looked it up.
	covered := make(map[string]bool, len(m.Ecosystems))
	for _, e := range m.Ecosystems {
		covered[e] = true
	}
	frozen := frozenSinceByKey(m)

	out := make([]CoverageRecord, 0, len(packages))
	for _, key := range slices.Sorted(maps.Keys(packages)) {
		rec := CoverageRecord{
			Ecosystem: key,
			Packages:  packages[key],
			Evaluated: packages[key] - unevaluated[key],
		}
		rec.Provider, rec.DataAsOf = providerOf(m, key)
		since, isFrozen := frozen[key]
		// The matcher's own order (matcher.Match): a key with no comparer is
		// skipped before coverage is consulted, and an uncovered key before any
		// advisory is read, so neither can be "frozen" in any sense a reader
		// could act on even if a hand-built Meta said so.
		_, hasComparer := version.For(key)
		switch {
		case !hasComparer:
			rec.State = CoverageNoComparer
		case !covered[key]:
			rec.State = CoverageNotInDatabase
		case isFrozen:
			rec.State = CoverageFrozen
			rec.FrozenSince = dateOnly(since)
		default:
			rec.State = CoverageLive
		}
		out = append(out, rec)
	}
	return out
}

// DistroOf builds the document's distro object, nil when the target carries no
// distro identity (every SPDX SBOM, D84; every directory and binary), which
// omitempty then drops — the EOLRecord precedent.
func DistroOf(d *pkgmeta.Distro) *DistroRecord {
	if d == nil {
		return nil
	}
	rec := &DistroRecord{ID: d.ID, VersionID: d.VersionID}
	if eco, err := d.Ecosystem(); err == nil {
		rec.Ecosystem, rec.Recognized = eco, true
	}
	return rec
}

// providerOf names the provider that declares key and that provider's
// DataAsOf. The build refuses two providers declaring one key, so normally
// there is one candidate. If a hand-built database ever has two, the one whose
// data is OLDEST wins — a zero DataAsOf, "not recorded", counting as oldest —
// and among equals the first by name. matcher.frozenKeys keeps the earlier
// freeze date on the same reasoning: a disclosure that understates staleness is
// the one that misleads (D12). Ranged over sorted names so the answer never
// depends on map order.
func providerOf(m store.Meta, key string) (string, string) {
	var (
		name  string
		asOf  time.Time
		found bool
	)
	for _, n := range slices.Sorted(maps.Keys(m.Providers)) {
		p := m.Providers[n]
		if !slices.Contains(p.Ecosystems, key) {
			continue
		}
		if !found || p.DataAsOf.Before(asOf) {
			name, asOf, found = n, p.DataAsOf, true
		}
	}
	return name, dateOnly(asOf)
}

// frozenSinceByKey flattens every provider's Frozen map (D110) by key, keeping
// the earlier date where two disagree. It is matcher.frozenKeys' rule, repeated
// here because the matcher is untouched by D111 and keeps it unexported: the
// two must agree, or a finding's frozenSince and its key's coverage record
// would name different dates for one freeze.
func frozenSinceByKey(m store.Meta) map[string]time.Time {
	out := map[string]time.Time{}
	for _, p := range m.Providers {
		for key, since := range p.Frozen {
			if cur, ok := out[key]; !ok || since.Before(cur) {
				out[key] = since
			}
		}
	}
	return out
}

// dateOnly renders a time as a full-date, or "" for the zero time. A date, not
// a timestamp: what a reader weighs is the day (D110's frozenDate reasoning).
func dateOnly(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.DateOnly)
}

// wholePackage is the one definition of "the matcher never judged this
// package": a skip with no AdvisoryID (matcher.Skipped's own contract).
// Summarize counts evaluated with it and CoverageOf splits the same count by
// key, so the per-key numbers sum to the summary's.
func wholePackage(s matcher.Skipped) bool {
	return s.AdvisoryID == ""
}

// records returns the keys as a non-nil slice, so a zero Coverage still
// encodes as [] rather than null.
func (c Coverage) records() []CoverageRecord {
	if c.Keys == nil {
		return []CoverageRecord{}
	}
	return c.Keys
}

// frozenCount is Summary.FrozenKeys.
func (c Coverage) frozenCount() int {
	n := 0
	for _, k := range c.Keys {
		if k.State == CoverageFrozen {
			n++
		}
	}
	return n
}

// coverageLines is the table's coverage block (D111): one line for every live
// key together, then one line per key in any other state, in key order.
//
// The live keys share a line because they are the expected case and a line per
// key would bury the exceptions under it; the line still carries the oldest
// data date among them, because data age otherwise reached no renderer at all
// (only `db status` and a failed --db-max-age said it), and the oldest is the
// one that bounds how current the scan is (D12).
//
// Nothing at all for an empty inventory: there is no key to have covered, and
// the summary line already says 0 components.
func coverageLines(keys []CoverageRecord) []string {
	var (
		live   int
		oldest string
		other  []string
	)
	for _, k := range keys {
		if k.State == CoverageLive {
			live++
			// Full-dates compare correctly as strings.
			if k.DataAsOf != "" && (oldest == "" || k.DataAsOf < oldest) {
				oldest = k.DataAsOf
			}
			continue
		}
		line := fmt.Sprintf("coverage: %s %s", coverageKeyLabel(k.Ecosystem), k.State)
		if k.FrozenSince != "" {
			line += " since " + k.FrozenSince
		}
		// Named for its provider: on a frozen key the provider's date is
		// later than the key's own, and an unattributed "data as of" beside
		// "frozen since" would read as the key's.
		if k.DataAsOf != "" {
			line += fmt.Sprintf(", %s data as of %s", k.Provider, k.DataAsOf)
		}
		other = append(other, line)
	}
	var out []string
	if live > 0 {
		line := fmt.Sprintf("coverage: %d key(s) live", live)
		if oldest != "" {
			line += ", data as of " + oldest
		}
		out = append(out, line)
	}
	return append(out, other...)
}

// coverageKeyLabel renders the empty key as "" — the matcher's own %q spelling
// of it in the skip reason, so a reader grepping either finds both — because
// an empty field between two spaces reads as a formatting slip, not a key.
func coverageKeyLabel(key string) string {
	if key == "" {
		return `""`
	}
	return key
}

// frozenFootnotes is every key the table's '@' footnote must explain, with its
// date: each frozen coverage key — whether or not a finding sits under it, the
// gap D111 closes — and each key an active or suppressed row is marked under.
// Through scancmd.Run the second set is inside the first; it is unioned anyway
// so no row can wear the marker without the footnote that explains it, for a
// caller that passes no coverage. Where two dates disagree the earlier wins
// (frozenSinceByKey's rule).
func frozenFootnotes(res matcher.Result, cov Coverage) map[string]string {
	out := map[string]string{}
	add := func(key, date string) {
		if date == "" {
			return
		}
		if cur, ok := out[key]; !ok || date < cur {
			out[key] = date
		}
	}
	for _, k := range cov.Keys {
		if k.State == CoverageFrozen {
			add(k.Ecosystem, k.FrozenSince)
		}
	}
	for _, f := range res.Findings {
		add(f.Package.Ecosystem, dateOnly(f.FrozenSince))
	}
	for _, s := range res.Suppressed {
		add(s.Finding.Package.Ecosystem, dateOnly(s.Finding.FrozenSince))
	}
	return out
}
