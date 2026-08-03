package report

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/kun9497/assay/internal/cataloger/cyclonedx"
	"github.com/kun9497/assay/internal/matcher"
	"github.com/kun9497/assay/internal/pkgmeta"
)

// schemaVersion is part of the JSON document's own contract with whatever
// reads it (a jq script, a CI policy). It changes only when the shape below
// changes, so a consumer can tell "the format I know" apart from "something
// new I have not seen" without having to guess from field presence.
const schemaVersion = 1

// Document is the stable shape of `assay scan --output json` (design goal
// #3). It carries what Table shows plus what Table cannot: the full
// Evidence, the source package (D8), the layer digest a package was found
// at, the raw score alongside the band, and exactly the counts Table's own
// summary line prints — computed through Summarize, the same function Table
// itself now calls, so the two can never silently disagree.
//
// Every field here is a plain struct, never a map: encoding/json preserves
// struct field order exactly as declared, so key order is fixed by this
// type's own source, not by iteration order at runtime. Findings and Skipped
// arrive from matcher.Result already sorted (sortFindings / sortSkipped), and
// this type does not reorder them, so array order is equally deterministic.
type Document struct {
	SchemaVersion int             `json:"schemaVersion"`
	Findings      []FindingRecord `json:"findings"`
	Skipped       []SkippedRecord `json:"skipped"`
	Summary       Summary         `json:"summary"`
}

// FindingRecord is one matcher.Finding, reshaped for stable JSON rather than
// marshaled directly — deliberately not embedding matcher.Finding or
// advisory.Advisory, so a field either of those types gains for an unrelated
// reason (say, a new Advisory.Affected variant, per D1) does not silently
// change this document's shape out from under a consumer relying on it.
type FindingRecord struct {
	Package PackageRecord `json:"package"`
	// MatchedName is always present, never omitted even when it equals
	// Package.Name (a direct match): a field that only appears for the D8
	// indirection case would make its own absence ambiguous between "matched
	// directly" and "this document predates the field".
	MatchedName string         `json:"matchedName"`
	Advisory    AdvisoryRecord `json:"advisory"`
	// Severity is severity.Band's String() form (D17's own
	// none/low/medium/high/critical/unknown), never the numeric iota — a
	// numeric band would make the document depend on Band's declaration
	// order, which is an implementation detail, not part of the schema.
	Severity string `json:"severity"`
	// Score is meaningful only when Severity is a rated band. An unrated
	// finding serializes as {"severity":"unknown","score":0}, and that 0 is
	// an absence, not a rating of zero — a real 0.0 is {"severity":"none"}.
	//
	// The table deliberately prints "unknown" with no parenthetical for the
	// same finding, because "unknown (0.0)" reads as a measured zero and
	// that is D17's coercion arriving through formatting. JSON keeps the
	// field rather than omitting it so the shape does not vary per finding,
	// which is what a schema is for; the band is the authoritative one of
	// the pair, and a consumer that gates on score alone should read
	// severity first.
	Score    float64        `json:"score"`
	Evidence EvidenceRecord `json:"evidence"`
	// Ratings carries every source's own assessment, never collapsed to the
	// one that set Severity/Score above (D25): 5,423 of 8,893 measured
	// multi-record groups have one record rated where another is not, so a
	// consumer building its own policy — e.g. "always take the more
	// conservative fixed version" — needs the whole array, not just the
	// highest band. JSON is the machine-readable view and the one a filter
	// would read from, so nothing here is collapsed the way the table's
	// single SEVERITY cell is.
	//
	// Always a slice, never nil (empty is `[]`, not `null`), matching
	// Document.Findings/Skipped's own convention — a hand-built Finding with
	// no ratings must not turn into a schema-breaking null for a consumer
	// that assumes an array.
	Ratings []RatingRecord `json:"ratings"`
}

// RatingRecord is one matcher.Rating, reshaped for stable JSON exactly like
// FindingRecord itself: a plain struct rather than matcher.Rating embedded
// directly, so a field matcher.Rating gains for an unrelated reason does not
// silently change this document's shape.
//
// Order matters and is NOT re-derived here: matcher.Finding.Ratings arrives
// already sorted by Database then AdvisoryID (D25's own sortRatings), and
// findingRecord copies it element for element rather than through a map, so
// this array is exactly as deterministic as the rest of the document.
type RatingRecord struct {
	Database   string `json:"database"`
	AdvisoryID string `json:"advisoryId"`
	// Severity is the band this one source gave — severity.Band's own
	// String() form, same as FindingRecord.Severity above — which can
	// legitimately differ from FindingRecord.Severity when this is not the
	// source that set it.
	Severity string  `json:"severity"`
	Score    float64 `json:"score"`
	// Fixed is the fixed version THIS record gives, which is why it lives
	// here and not on FindingRecord: sources disagree on it too (152 of 169
	// measured groups), and pulling one to the top level would make every
	// source appear to agree about remediation.
	//
	// No omitempty, for the same reason Score above has none: a source that
	// gave no fixed version is exactly the interesting case — disagreeing
	// fixed versions are half of D25's own measurement — and with omitempty
	// a consumer cannot tell "this source said there is no fix yet" apart
	// from "this document predates the field". The shape must not vary per
	// rating, which is what a schema is for.
	Fixed string `json:"fixed"`
}

type PackageRecord struct {
	Name      string           `json:"name"`
	Version   string           `json:"version"`
	Ecosystem string           `json:"ecosystem"`
	PURL      string           `json:"purl,omitempty"`
	Source    *SourceRecord    `json:"source,omitempty"`
	Locations []LocationRecord `json:"locations,omitempty"`
}

type SourceRecord struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

type LocationRecord struct {
	Path        string `json:"path"`
	LayerDigest string `json:"layerDigest,omitempty"`
}

type AdvisoryRecord struct {
	ID       string   `json:"id"`
	Aliases  []string `json:"aliases,omitempty"`
	Upstream []string `json:"upstream,omitempty"`
	Summary  string   `json:"summary,omitempty"`
}

// EvidenceRecord mirrors version.Evidence field for field (D10): which range
// type matched, the introduced/fixed/lastAffected bounds that decided it, and
// the human-readable Reason the version package already computed.
type EvidenceRecord struct {
	RangeType    string `json:"rangeType,omitempty"`
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"lastAffected,omitempty"`
	Reason       string `json:"reason,omitempty"`
}

// SkippedRecord is one matcher.Skipped. AdvisoryID is empty exactly when the
// whole package was skipped (matcher.Skipped's own contract), which is also
// what Table's "Not evaluated:" block relies on to tell the two skip kinds
// apart.
type SkippedRecord struct {
	Package    PackageRecord `json:"package"`
	AdvisoryID string        `json:"advisoryId,omitempty"`
	Reason     string        `json:"reason"`
}

// JSON renders res as the Document above and writes it to w as the only
// thing written — `assay scan ... --output json | jq` must see nothing else
// on stdout, so every byte here is the document itself, nothing appended.
//
// This is an additional renderer, not a rewrite of Table: it never calls
// Table, never reuses its wording, and Table's own tests are untouched by
// this file. The counts come from Summarize, the exact function Table calls
// for the same numbers, so JSON and the table cannot drift apart on what
// "evaluated" means.
func JSON(w io.Writer, res matcher.Result, cat cyclonedx.Stats) (Summary, error) {
	sum := Summarize(res, cat)

	doc := Document{
		SchemaVersion: schemaVersion,
		Findings:      make([]FindingRecord, 0, len(res.Findings)),
		Skipped:       make([]SkippedRecord, 0, len(res.Skipped)),
		Summary:       sum,
	}
	for _, f := range res.Findings {
		doc.Findings = append(doc.Findings, findingRecord(f))
	}
	for _, s := range res.Skipped {
		doc.Skipped = append(doc.Skipped, SkippedRecord{
			Package:    packageRecord(s.Package),
			AdvisoryID: s.AdvisoryID,
			Reason:     s.Reason,
		})
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return Summary{}, fmt.Errorf("encode json report: %w", err)
	}
	return sum, nil
}

func findingRecord(f matcher.Finding) FindingRecord {
	// make(..., 0, len(...)), never a nil append target: an empty result must
	// still encode as "ratings": [], the same reasoning Document.Findings and
	// Document.Skipped already follow (TestJSON_EmptyResultHasEmptyArraysNotNull).
	ratings := make([]RatingRecord, 0, len(f.Ratings))
	for _, r := range f.Ratings {
		ratings = append(ratings, RatingRecord{
			Database:   r.Database,
			AdvisoryID: r.AdvisoryID,
			Severity:   r.Severity.String(),
			Score:      r.Score,
			Fixed:      r.Fixed,
		})
	}
	return FindingRecord{
		Package:     packageRecord(f.Package),
		MatchedName: f.MatchedName,
		Advisory: AdvisoryRecord{
			ID:       f.Advisory.ID,
			Aliases:  f.Advisory.Aliases,
			Upstream: f.Advisory.Upstream,
			Summary:  f.Advisory.Summary,
		},
		Severity: f.Severity.String(),
		Score:    f.Score,
		Evidence: EvidenceRecord{
			RangeType:    string(f.Evidence.RangeType),
			Introduced:   f.Evidence.Introduced,
			Fixed:        f.Evidence.Fixed,
			LastAffected: f.Evidence.LastAffected,
			Reason:       f.Evidence.Reason,
		},
		Ratings: ratings,
	}
}

func packageRecord(p pkgmeta.Package) PackageRecord {
	pr := PackageRecord{
		Name:      p.Name,
		Version:   p.Version,
		Ecosystem: p.Ecosystem,
		PURL:      p.PURL,
	}
	if p.Source != nil {
		pr.Source = &SourceRecord{Name: p.Source.Name, Version: p.Source.Version}
	}
	for _, l := range p.Locations {
		pr.Locations = append(pr.Locations, LocationRecord{Path: l.Path, LayerDigest: l.LayerDigest})
	}
	return pr
}
