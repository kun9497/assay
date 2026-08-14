// Package store holds the local advisory database.
//
// The database is orthogonal to a scan (D14): `assay db build` populates it
// from upstream sources, `assay db update` downloads one someone else built
// (D28), and a scan only ever reads. That is what makes offline operation the
// default rather than a flag.
package store

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/kun9497/assay/internal/advisory"
)

// SchemaVersion is part of the on-disk path (D5). A schema change rebuilds
// into a new directory rather than migrating in place, because migration code
// is a liability for a project with one user.
//
// Bumped to 2 in slice 2a: the by-source bucket was removed once measurement
// showed OSV writes the source package name straight into Affected[].Name.
// The bucket set is the on-disk shape, so that is a schema change even though
// no record's encoding moved — and without the bump a database built before
// Alpine support is accepted unchanged, evaluates every Alpine package against
// data it never ingested, and reports "no known vulnerabilities found" at exit
// 0. That is the silent false negative, arriving through a stale cache rather
// than a bug.
//
// Bumped to 3 to add Meta.Ecosystems (D20), and to 4 immediately after: the
// first version of that field was derived from what Put indexed, which
// over-claims, so a v3 database built by that revision declares coverage of
// ecosystems it never fetched. Reading such a database is exactly the failure
// D20 closes, and nothing else would prompt a rebuild — the field is present
// and well-formed, only wrong. A schema change is the only signal that reaches
// a database already on disk.
//
// Bumped to 5 to add Advisory.Database (D25): a database built before this
// field has it empty on every record, and an empty Database renders as a
// rating from a source with no name rather than failing loudly.
//
// Bumped to 6 to add the ratings bucket (an authority's CVSS opinion about a
// CVE, stored separately from any advisory — see internal/advisory.Rating).
// A schema-5 database has no such bucket, and reading a missing bucket would
// silently return zero ratings for every CVE rather than failing, which is a
// scan that quietly loses every NVD score while looking healthy.
//
// Bumped to 7 to add the enrichment bucket (an authority's prose about a CVE
// — title, summary, link — stored separately from any advisory or rating;
// see internal/advisory.Enrichment). Same reasoning as the bump to 6: a
// schema-6 database has no such bucket, and a missing bucket read as "nothing
// enriched" is indistinguishable from a scan that ran before KISA prose
// existed at all.
//
// Bumped to 8 to add Range.FixState (D52) — Red Hat's own statement that a
// package will never be fixed, which no shape the store had could express. A
// schema-7 database carries the field empty on every range, and empty means
// "the source did not say": the whole feed would read as unknown, so the
// distinction would be silently absent from a database that otherwise looks
// current. That is the same failure the bump to 4 exists for — a field present
// and well-formed, only wrong — and a schema change is the only signal that
// reaches a database already on disk.
const SchemaVersion = 8

var (
	ErrNotFound       = errors.New("vulnerability database not found")
	ErrSchemaMismatch = errors.New("vulnerability database schema mismatch")
	// ErrIncomplete marks a database whose build was interrupted. It exists
	// because the alternative is worse than an error: a half-built database
	// answers lookups with empty results and no error, which is
	// indistinguishable from a clean scan.
	ErrIncomplete = errors.New("vulnerability database is incomplete")
)

type Store interface {
	// Lookup answers for a package name. Source-package advisories (D8) need
	// no separate method: OSV writes the source name into Affected[].Name, so
	// the caller queries this with the source name as a second key.
	Lookup(ecosystem, name string) ([]advisory.Advisory, error)
	// RatingsFor answers a third-party severity opinion for one CVE, sorted by
	// Source so two runs against the same database agree. An unrated CVE
	// returns an empty slice and a nil error — the matcher calls this for
	// every finding, so "nobody rated this" is a normal answer, not a failure.
	RatingsFor(cve string) ([]advisory.Rating, error)
	// EachRating walks every stored rating, in key order, so a caller
	// (a seeded `db build`, D-seed) can copy the whole ratings bucket forward
	// without knowing which CVEs it holds ahead of time. Key order is the
	// store's own byte order, not an incidental one — see Bolt.EachRating's
	// doc comment for why that determinism matters here specifically.
	EachRating(fn func(advisory.Rating) error) error
	// EnrichmentFor answers a third-party's prose about one CVE -- title,
	// summary, link -- sorted by Source so two runs against the same
	// database agree. An un-enriched CVE returns an empty slice and a nil
	// error, mirroring RatingsFor: most CVEs have no Korean notice, and that
	// is a normal answer, not a failure.
	EnrichmentFor(cve string) ([]advisory.Enrichment, error)
	// EachEnrichment walks every stored enrichment, in key order, mirroring
	// EachRating -- a seeded `db build` can copy the whole bucket forward
	// without knowing which CVEs it holds ahead of time.
	EachEnrichment(fn func(advisory.Enrichment) error) error
	// Covers reports which ecosystem keys this database actually holds (D20).
	// A caller that skips this cannot distinguish "no advisories for this
	// package" from "this ecosystem was never ingested".
	Covers() (map[string]bool, error)
	Meta() (Meta, error)
	Close() error
}

// Writer is the build-side half. Separate from Store so a scan cannot be
// handed something it could write through.
type Writer interface {
	Put(a advisory.Advisory) error
	// PutMany stores a batch in one transaction (D57). Semantically Put in
	// a loop, with one difference the caller has to accept: it is ALL OR
	// NOTHING, so an error means none of the batch landed. A build that
	// loses records is not one anyone should publish, which is what makes
	// that the right trade.
	PutMany(as []advisory.Advisory) error
	// PutRating stores one authority's CVSS opinion about a CVE, keyed on
	// (CVE, Source) so re-putting the same source replaces rather than
	// duplicates.
	PutRating(r advisory.Rating) error
	// PutEnrichment stores one authority's prose about a CVE, keyed on (CVE,
	// Source) exactly like PutRating, for the same replace-not-duplicate
	// reason.
	PutEnrichment(e advisory.Enrichment) error
	SetMeta(m Meta) error
	Close() error
}

type Meta struct {
	Schema    int                   `json:"schema"`
	BuiltAt   time.Time             `json:"built_at"` // when this database was assembled locally
	Providers map[string]Provenance `json:"providers"`
	// Ecosystems is the union of every provider's coverage, sorted (D20).
	//
	// It exists so a lookup that finds nothing can be told apart from a lookup
	// in an ecosystem this database never held. Both return zero advisories,
	// and without this the second reads as a clean scan.
	Ecosystems []string `json:"ecosystems"`
	// Databases is the set of authoring databases (Advisory.Database, D25)
	// among the records actually stored, sorted.
	//
	// Unlike Ecosystems this is read from the stored records themselves, not
	// from provider self-report: a record's Database describes only that one
	// record, so there is no foreign-ecosystem-style over-claim to guard
	// against the way D20 requires for Ecosystems.
	Databases []string `json:"databases"`
	// Ratings is per-authority provenance for CVE ratings (D27): the DataAsOf
	// and fetch Source URL an Annotator self-reports about its own run,
	// written directly by dbcmd.Update from each Annotator's return value,
	// mirroring Providers. Self-report is the only source for these two
	// fields specifically — a stored advisory.Rating records neither when
	// NVD's data was current nor which URL fetched it (D12) — unlike
	// Advisory.Database, which every stored Advisory record carries and
	// Databases below reads directly.
	//
	// Records on an entry here is NOT authoritative and must never be read
	// for "did this authority rate anything" or "how many": an annotator
	// that runs and emits nothing (or fewer than it claims) would otherwise
	// let this map assert a rating count the stored data does not back up —
	// exactly the over-claim D20 refuses to let Ecosystems make, one bucket
	// over. RatingCounts below is the derived, trustworthy answer to that
	// question; consult it, not this, for anything db status states as fact.
	//
	// Deliberately a separate map rather than folded into Providers, even
	// though both hold store.Provenance: Bolt.SetMeta derives Ecosystems by
	// trusting every entry in Providers to describe advisory coverage (D20).
	// An annotator answers a different question — what a CVE is worth, never
	// which package is affected — so mixing it into Providers would make a
	// future annotator's non-empty Provenance.Ecosystems (a bug, but one nothing
	// here should be able to trigger) silently widen Covers(). Keeping the two
	// maps apart makes that impossible by construction rather than by
	// discipline.
	Ratings map[string]Provenance `json:"ratings"`
	// RatingCounts is how many CVEs each authority actually rated, read from
	// the ratings bucket itself (Bolt.SetMeta) — the Databases pattern
	// applied to the ratings bucket instead of the advisories one. A
	// rating's Source is recoverable from its own key
	// ("<CVE>\x00<Source>"), so — unlike Providers/Ecosystems — there is no
	// reason to trust self-report here: this is what db status actually
	// treats as ground truth for which rating sources exist and how many
	// CVEs they rated, never Ratings above.
	RatingCounts map[string]int `json:"ratingCounts"`
	// Enrichment is per-authority provenance for CVE prose (D3): the DataAsOf
	// and fetch Source URL an Enricher self-reports about its own run, written
	// by dbcmd.Update from each Enricher's return value. It is the Ratings
	// pattern one bucket over, and everything Ratings' own doc comment says
	// about self-report applies here verbatim — Records on an entry is NOT
	// authoritative, and EnrichmentCounts below is the derived answer to "did
	// this authority enrich anything, and how much".
	//
	// A source whose run FAILED is here too, with Provenance.Error set and
	// nothing else. That is deliberate and it is the second version of this
	// decision: recording nothing meant a total failure produced no row at
	// all while a PARTIAL failure produced one anyway (its records are in the
	// bucket, so the derived half of the union answers for it) — the same
	// fault rendering as visible or invisible depending on when the feed
	// died. A failure is always visible now, whatever it managed to write
	// first.
	//
	// It is stripped, along with EnrichmentCounts, from any database `db push`
	// publishes (D29): the artifact must not name a source whose records it
	// deliberately does not carry.
	Enrichment map[string]Provenance `json:"enrichment"`
	// EnrichmentCounts is how many CVEs each authority actually enriched, read
	// from the enrichment bucket itself (Bolt.SetMeta) — RatingCounts applied
	// one bucket over, for the same reason: an enrichment's Source is
	// recoverable from its own key ("<CVE>\x00<Source>"), so there is no need
	// to trust a self-report that has already over-claimed once on this
	// branch. This is what `db status` treats as ground truth.
	EnrichmentCounts map[string]int `json:"enrichmentCounts"`
}

type Provenance struct {
	Source string `json:"source"` // the URL actually fetched
	// DataAsOf is when the UPSTREAM data was current, which is not the same as
	// BuiltAt (D12). A mirror serving a stale snapshot fetched today has a
	// recent BuiltAt and an old DataAsOf; judging freshness by the former
	// reports quarter-old data as fresh.
	DataAsOf time.Time `json:"data_as_of"`
	Records  int       `json:"records"`
	// Ecosystems is what this provider actually covers (D20): the keys it
	// fetched, expanded to the release-qualified ones a fetched family
	// contains.
	//
	// The provider reports it because only the provider knows both halves.
	// The store cannot: it sees every ecosystem named in every record, and
	// records deliberately keep entries for ecosystems that were NOT fetched
	// (slice 1's cross-ecosystem fix), so a store-side set silently claims
	// coverage of Maven, NuGet and crates.io on a database that fetched none
	// of them. Nor can a naive caller: db update fetches one archive named
	// "Alpine" whose records carry Alpine:v3.2 through Alpine:v3.24, so the
	// fetch list alone names a key nothing is looked up under and omits the 23
	// that are.
	Ecosystems []string `json:"ecosystems"`
	// Window is what a RATING source actually covered, in its own words
	// ("the whole feed", "modified 2026-07-04..2026-08-03"). Empty for
	// advisory providers, which answer the same question with Ecosystems.
	//
	// It exists because a rating source can be fetched in part (D27's
	// NVD_SINCE_DAYS bounds a sync to CVEs modified recently, since a full
	// NVD pass is about seven hours) and Update rebuilds the database from
	// empty every time. A bounded run's window is therefore the database's
	// ENTIRE coverage from that source, not a delta layered on an earlier
	// pass — so without this, a database holding one day of NVD looks
	// exactly like one holding all of it, and every finding whose CVE fell
	// outside the window silently keeps a lower band (D20).
	//
	// Self-reported, unlike RatingCounts, and that is sound here: the risk
	// D20 guards against is a source claiming MORE coverage than it has,
	// and a declared window only ever claims less. The count beside it is
	// still derived.
	Window string `json:"window,omitempty"`
	// CoversSince is the same fact as Window, in a form a machine can
	// compare: the earliest modification date this source was asked for.
	// Zero means unbounded — the whole feed — and therefore sorts as
	// broader than any date, not narrower.
	//
	// Window stays because it is what a human reads in `db status`. This
	// exists because the publish path has to answer "is the artifact I am
	// about to push narrower than the one already published", and deriving
	// that by parsing "modified 2026-07-05..2026-08-04" would make a
	// coverage guard depend on the wording of a display string.
	CoversSince time.Time `json:"covers_since,omitempty"`
	// CoversSinceKnown separates "unbounded" from "not recorded". Both are
	// a zero CoversSince, and they are opposites: one is the broadest
	// coverage there is, the other is no information at all.
	//
	// Without it the only way to tell them apart is reading Window, and a
	// correctness path that parses a display string is what CoversSince
	// exists to avoid. A database built before this field simply has false
	// here, which is the truthful answer for it.
	CoversSinceKnown bool `json:"covers_since_known,omitempty"`
	// CoversUntil is the other end of the window, and it exists because a
	// backfill asks for an OLDER range than the one already covered (D65).
	// The two ends together are what decide whether a slice EXTENDS the
	// covered range or leaves a hole in it, and a hole is the difference
	// between a database that covers a span and one that merely holds
	// ratings from both sides of it. Zero means "up to when the run
	// happened".
	CoversUntil time.Time `json:"covers_until,omitempty"`
	// CoversUntilKnown separates "ran up to now" from "not recorded", the
	// same distinction CoversSinceKnown draws at the other end.
	CoversUntilKnown bool `json:"covers_until_known,omitempty"`
	// Error is why this source's last run did not finish, empty when it did.
	//
	// Below CoversSince/CoversSinceKnown rather than between them: those two
	// are one fact in two fields, and a reader who meets the second without
	// the first immediately above it has to go looking for what it qualifies.
	//
	// It exists because "ran and produced nothing" and "did not finish" are
	// different facts with different remedies, and every other field renders
	// identically for both: a zero DataAsOf, a zero Records, an empty Source.
	// Without it, `db status` shows a failed enrichment run and a successful
	// but empty one in exactly the same words.
	//
	// Only dbcmd.Update writes it, and only for a source whose failure is not
	// fatal to the build — an Enricher (D3). A failing Provider or Annotator
	// aborts the build outright, so no metadata describing it is ever written
	// at all, which is why this field would have nothing to say for them.
	//
	// A display string, never something to branch on: it is whatever the
	// source's error said, flattened to one line so it cannot break the table
	// it is rendered into.
	Error string `json:"error,omitempty"`
}

// DefaultPath returns <user cache>/assay/db/v<schema>/vulnerability.db,
// honouring ASSAY_DB_DIR for CI caching and air-gapped environments.
func DefaultPath() (string, error) {
	if dir := os.Getenv("ASSAY_DB_DIR"); dir != "" {
		return filepath.Join(dir, "vulnerability.db"), nil
	}
	cache, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	// Derived from the constant rather than written out, so the comment above
	// stays true. Hardcoding "v1" here meant a schema bump produced a mismatch
	// error against the old file instead of a clean rebuild into a new
	// directory, which is what D5 actually asks for.
	return filepath.Join(cache, "assay", "db",
		"v"+strconv.Itoa(SchemaVersion), "vulnerability.db"), nil
}
