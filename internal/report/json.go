package report

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/cataloger/cyclonedx"
	"github.com/kun9497/assay/internal/matcher"
	"github.com/kun9497/assay/internal/pkgmeta"
)

// schemaVersion is part of the JSON document's own contract with whatever
// reads it (a jq script, a CI policy). It changes only when the shape below
// changes, so a consumer can tell "the format I know" apart from "something
// new I have not seen" without having to guess from field presence.
//
// Bumped to 2 when FindingRecord gained `enrichment` (D3), to 3 when
// EnrichmentRecord gained `claims` (D33), and to 4 when SkippedRecord gained
// `cause` and Summary gained `targetIncomplete` (D36), and to 5 when
// FindingRecord gained `unfixable` and Summary gained `unfixable` (D48), and to
// 6 when both gained `fixState` and RatingRecord gained one too (D52), and to
// 7 when RatingRecord gained `epss`/`epssPercentile`/`epssModel`/`kev`/
// `kevDateAdded`/`kevRansomware` and Summary gained `knownExploited` (D86),
// and to 8 when Document gained the target-level `eol` object (D87).
// Two earlier additions should have bumped it and did not — `ratings` (D25)
// and RatingRecord.URL (D27) both changed the shape while this constant
// stayed at 1 — so version 1 in the wild denotes three different documents.
// That is the cost of the misses, and it cannot be repaired retroactively;
// what it does mean is that a consumer reading 2 or later can rely on every
// field below being present, which is the guarantee the constant exists to
// give.
const schemaVersion = 8

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
	// EOL is the scanned target's distro end-of-life status (D87), nil when
	// there is no answer — see EOLRecord's own doc comment for the three
	// reasons and why nil, not a zero-value object, is what "no answer"
	// must serialize as. omitempty on top of the nil check: an older
	// consumer's `.eol` lookup on a document from before this field existed
	// and one where the target carried no distro identity should not have
	// to distinguish "absent key" from "null value" — both already mean
	// the same thing here.
	EOL *EOLRecord `json:"eol,omitempty"`
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
	// one that set Severity/Score above (D25): the sources land on different
	// bands in 5,693 of 8,893 measured multi-record groups, so a
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
	// Unfixable says no rating above names a version to upgrade to (D48).
	//
	// Derived rather than left for a consumer to compute, and that is the
	// point: "every element of ratings has an empty fixed" is a rule a jq
	// script would have to get right, and getting it wrong in the safe
	// direction means silently treating a will-not-fix vulnerability as
	// remediable. Present on every finding, never omitempty, so `false` is a
	// statement rather than an absence.
	Unfixable bool `json:"unfixable"`
	// FixState says WHY there is no fix, when a source was willing to say
	// (D52): "wont-fix" once any source reports the vendor has closed the
	// matter, "not-fixed" when one says a fix is merely absent, "unknown"
	// when none said, and "fixed" whenever Unfixable above is false.
	//
	// Spelled as grype spells it so the two documents can be diffed field to
	// field (D18). Present on every finding, never omitempty: "unknown" is an
	// answer, and a consumer must not have to tell it apart from a missing key.
	FixState string `json:"fixState"`
	// Enrichment is what another authority wrote about this vulnerability in
	// prose (D3) — KISA's Korean headline, overview and notice link. It is
	// display copy: nothing here contributes to Severity or Score above, and a
	// consumer must not derive a band from it, because the source that wrote
	// it frequently cannot say which package is affected at all.
	//
	// Empty on most findings (the measured KISA overlap is 2.4% of the
	// advisories this tool holds), and — like Ratings above — always a slice,
	// never nil. A shape that varied with whether a Korean notice happened to
	// exist would make `.enrichment | length` a runtime error on most
	// findings, which is exactly what a schema is for preventing.
	Enrichment []EnrichmentRecord `json:"enrichment"`
}

// EnrichmentRecord is one matcher.Enrichment, reshaped for stable JSON on the
// same reasoning as RatingRecord: a plain struct rather than the matcher type
// embedded, so a field that type gains for an unrelated reason cannot silently
// change this document.
//
// Order is not re-derived here either — matcher.Finding.Enrichment arrives
// sorted by source (matcher's own dedupSortedEnrichment) and findingRecord
// copies it element for element.
//
// There is no severity field and there must never be one (D17): enrichment
// carries no band, and a null or zero severity here would be read as a rating
// of none by exactly the consumers this document exists to serve.
type EnrichmentRecord struct {
	// Source is the authority that wrote it — "KISA". No omitempty on any
	// field here, for the reason RatingRecord.Fixed gives: an absent value is
	// a fact about the record ("this notice has no overview"), and a shape
	// that varies per record is not a schema.
	Source  string `json:"source"`
	Title   string `json:"title"`
	Summary string `json:"summary"`
	URL     string `json:"url"`
	// Claims is how many vulnerabilities this notice named (D33). A consumer
	// filtering for prose that is actually about the finding wants
	// `.claims == 1`; without it, a monthly bulletin naming a thousand CVEs is
	// indistinguishable from an advisory written about this one. Zero means the
	// source does not report breadth, which is why there is no omitempty: an
	// absent number and an unreported one would otherwise look alike.
	Claims int `json:"claims"`
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
	// here and not on FindingRecord: sources disagree on it in 2,210 of the
	// 8,893 measured multi-record groups, and pulling one to the top level
	// would make every source appear to agree about remediation.
	//
	// No omitempty, for the same reason Score above has none: a source that
	// gave no fixed version is exactly the interesting case — and with omitempty
	// a consumer cannot tell "this source said there is no fix yet" apart
	// from "this document predates the field". The shape must not vary per
	// rating, which is what a schema is for.
	Fixed string `json:"fixed"`
	// URL is where a reader can check this rating (D27) — empty for an OSV
	// record, whose AdvisoryID above already names something to look up, and
	// populated for an annotation such as NVD's, which carries no advisory of
	// its own to point at. No omitempty, same reasoning as Fixed above: an
	// OSV rating's empty URL is meaningful ("look up the advisory instead"),
	// not an absent field, and the shape must not vary per rating.
	URL string `json:"url"`
	// FixState is what THIS record says about a fix, on the same reasoning
	// that puts Fixed here (D52): the finding-level value is the strongest
	// claim any source made, and a consumer checking whether Red Hat
	// specifically called something will-not-fix needs the per-source answer.
	// No omitempty, same reasoning as Fixed and URL above.
	FixState string `json:"fixState"`
	// EPSS/KEV fields (D86), copied verbatim from matcher.Rating's own typed
	// fields -- never folded into Severity/Score, on advisory.Rating's own
	// reasoning (its doc comment): an exploit probability is not a severity
	// opinion.
	//
	// omitempty on all six, UNLIKE every other field on this record. Every
	// other field's own comment argues the opposite -- an absent value is a
	// fact worth keeping present in the shape -- but these six are zero on
	// every rating from every OTHER source (GHSA, PYSEC, NVD, and so on),
	// which on a typical finding is most of Ratings. Printing six zero/empty
	// keys on every one of those rows would not be an absence worth keeping
	// visible the way an empty Fixed is; it would be six columns of noise
	// repeated once per rating, on a shape only two sources (EPSS, KEV) ever
	// populate.
	EPSS           float64 `json:"epss,omitempty"`
	EPSSPercentile float64 `json:"epssPercentile,omitempty"`
	EPSSModel      string  `json:"epssModel,omitempty"`
	KEV            bool    `json:"kev,omitempty"`
	KEVDateAdded   string  `json:"kevDateAdded,omitempty"`
	KEVRansomware  string  `json:"kevRansomware,omitempty"`
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
	// Cause is whose data made this incomplete (D36): "target" for the artifact
	// being scanned, "advisory" for the vulnerability record, "coverage" for an
	// ecosystem this database or this build does not handle. A CI policy that
	// wants to fail only on its own broken input filters on `.cause ==
	// "target"`; matching on the reason text instead would break the first time
	// the wording changed, which it did one decision ago.
	//
	// No omitempty: an absent cause and an unclassified one would look alike,
	// and the shape must not vary per record.
	Cause matcher.SkipCause `json:"cause"`
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
func JSON(w io.Writer, res matcher.Result, cat cyclonedx.Stats, eol EOLStatus) (Summary, error) {
	sum := Summarize(res, cat)

	doc := Document{
		SchemaVersion: schemaVersion,
		Findings:      make([]FindingRecord, 0, len(res.Findings)),
		Skipped:       make([]SkippedRecord, 0, len(res.Skipped)),
		Summary:       sum,
		EOL:           eol.Record(),
	}
	for _, f := range res.Findings {
		doc.Findings = append(doc.Findings, findingRecord(f))
	}
	for _, s := range res.Skipped {
		doc.Skipped = append(doc.Skipped, SkippedRecord{
			Package:    packageRecord(s.Package),
			AdvisoryID: s.AdvisoryID,
			Reason:     s.Reason,
			Cause:      s.Cause,
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
			Database:       r.Database,
			AdvisoryID:     r.AdvisoryID,
			Severity:       r.Severity.String(),
			Score:          r.Score,
			Fixed:          r.Fixed,
			URL:            r.URL,
			FixState:       ratingFixState(r),
			EPSS:           r.EPSS,
			EPSSPercentile: r.EPSSPercentile,
			EPSSModel:      r.EPSSModel,
			KEV:            r.KEV,
			KEVDateAdded:   r.KEVDateAdded,
			KEVRansomware:  r.KEVRansomware,
		})
	}
	// Same reasoning as ratings above: an empty result encodes as
	// "enrichment": [], never null.
	enrichment := make([]EnrichmentRecord, 0, len(f.Enrichment))
	for _, e := range f.Enrichment {
		enrichment = append(enrichment, EnrichmentRecord{
			Source:  e.Source,
			Title:   e.Title,
			Summary: e.Summary,
			URL:     e.URL,
			Claims:  e.Claims,
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
		Ratings:    ratings,
		Unfixable:  f.Unfixable(),
		FixState:   f.FixState().String(),
		Enrichment: enrichment,
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

// ratingFixState keeps one rating's two fix columns from contradicting each
// other in the document.
//
// A rating that names a fixed version IS fixed, whatever its FixState field
// happens to hold. Match sets the two together (matcher.fixStateOf), but
// matcher.go explicitly allows a Finding built any other way, and a
// "fixed" of 2.0.0 beside a "fixState" of unknown is not something a consumer
// can act on — it would have to decide which of the two this document meant.
// Derived rather than trusted, which is D13's reason for deriving anything: two
// copies of one fact can disagree, and here the disagreement would be
// published.
func ratingFixState(r matcher.Rating) string {
	if r.Fixed != "" {
		return advisory.FixStateFixed.String()
	}
	return r.FixState.String()
}
