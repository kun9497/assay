// Package advisory holds the normalized vulnerability record. The shape follows
// the OSV schema (D1): every provider converts into this rather than the store
// growing a variant per source, which is what makes a KISA provider possible.
package advisory

import "time"

// Kind separates vulnerability reports from malicious-package reports. Only
// KindVulnerability is ingested today (D15), but the field is stored from the
// start because adding one later means rebuilding the database.
type Kind string

const (
	KindVulnerability Kind = "vulnerability"
	KindMalicious     Kind = "malicious"
)

type Advisory struct {
	ID       string     `json:"id"`       // CVE-… | GHSA-… | GO-… | ALPINE-… | KVE-…
	Database string     `json:"database"` // the record's own namespace: "GHSA" | "PYSEC" | "GO" | "ALPINE" | … (D25)
	Aliases  []string   `json:"aliases,omitempty"`
	Upstream []string   `json:"upstream,omitempty"` // OSV 1.7 puts the CVE link here, not in Aliases (D3)
	Source   string     `json:"source"`             // "osv" | "kisa"
	Kind     Kind       `json:"kind"`
	Summary  string     `json:"summary,omitempty"`
	Modified time.Time  `json:"modified,omitempty"`
	Affected []Affected `json:"affected"`
	Severity []Severity `json:"severity,omitempty"` // CVSS vectors, banded at query time (D13)
}

type Affected struct {
	Ecosystem string   `json:"ecosystem"` // "Go" | "npm" | "PyPI" | "Alpine:v3.19" (D6)
	Name      string   `json:"name"`
	Ranges    []Range  `json:"ranges,omitempty"`
	Versions  []string `json:"versions,omitempty"` // enumerated; the only data when Ranges is empty
}

// RangeType mirrors OSV. GIT ranges carry commit SHAs, not versions, and must
// never reach a Comparer.
type RangeType string

const (
	RangeSemver    RangeType = "SEMVER"
	RangeEcosystem RangeType = "ECOSYSTEM"
	RangeGit       RangeType = "GIT"
)

type Range struct {
	Type   RangeType `json:"type"`
	Events []Event   `json:"events"`
	// FixState says WHY a range carries no `fixed` event (D52). It is stored
	// only on fix-less ranges: a range that has a `fixed` event is fixed by
	// construction, and storing that separately would be a second copy of a
	// fact the events already carry — one that a later ingestion bug could make
	// disagree with them. Derived at query time instead (D13).
	FixState FixState `json:"fix_state,omitempty"`
}

// FixState distinguishes "the vendor has decided never to fix this" from "no
// fix yet" (D52). The two read alike in a report and mean opposite things to
// whoever has to act: one leaves only mitigation or removal, the other is a
// reason to watch the CVE.
//
// Spellings follow grype (D18) so a differential run compares field to field.
type FixState string

const (
	// FixStateUnknown is a state rather than a default (the discipline D17 sets
	// for severity). A fix-less range from a source that does not publish a
	// reason gets this and keeps it: every provider except Red Hat's CSAF VEX
	// feed is in that position today, and coercing them to NotFixed would put
	// words in their mouth — OSV records that no fix is known, not that a
	// vendor intends one.
	//
	// A STORED range spells it as the empty string, which is what the zero
	// value and `omitempty` give for free; unknown is the overwhelmingly common
	// case and a word repeated across a million records is real bytes on a
	// database that already runs 1.07 GB. Readers get the word instead —
	// matcher.fixStateOf resolves it — so nothing outside the store has to know
	// that "" and "unknown" are the same answer.
	FixStateUnknown FixState = "unknown"
	// FixStateNotFixed is affected with no fix available yet.
	FixStateNotFixed FixState = "not-fixed"
	// FixStateWontFix is affected and the vendor has said it will stay that
	// way. Requires positive evidence — nothing derives it.
	FixStateWontFix FixState = "wont-fix"
	// FixStateFixed is never stored; it is what a range with a `fixed` event
	// resolves to at query time. It exists so the four states a report can show
	// are all named in one place.
	FixStateFixed FixState = "fixed"
)

// String resolves the store's empty spelling of unknown to the word.
//
// Every renderer goes through here rather than converting with string(), so a
// value that reached one without passing matcher.fixStateOf — a Finding built
// by hand, a provider that forgot the field — still comes out as one of the
// four states. The JSON document promises exactly that and no omitempty to
// hide behind, and a promise held only on the paths someone remembered is not
// one a consumer can code against.
func (s FixState) String() string {
	if s == "" {
		return string(FixStateUnknown)
	}
	return string(s)
}

// Event carries exactly one populated field. LastAffected is an inclusive upper
// bound; Fixed is exclusive. Conflating them shifts every boundary by one
// version.
type Event struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	Limit        string `json:"limit,omitempty"`
}

type Severity struct {
	Type  string `json:"type"`  // CVSS_V2 | CVSS_V3 | CVSS_V4
	Score string `json:"score"` // the vector string
}

// Rating is one authority's assessment of one CVE, stored independently of
// any advisory record.
type Rating struct {
	CVE      string     // "CVE-2026-39822"
	Source   string     // "NVD"
	Severity []Severity // the same (Type, Score) pairs an Advisory carries
	URL      string     // where a reader can check the claim
}
