// Package store holds the local advisory database.
//
// The database is orthogonal to a scan (D14): providers write it through
// `assay db update` and a scan only ever reads. That is what makes offline
// operation the default rather than a flag.
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
const SchemaVersion = 6

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
	// PutRating stores one authority's CVSS opinion about a CVE, keyed on
	// (CVE, Source) so re-putting the same source replaces rather than
	// duplicates.
	PutRating(r advisory.Rating) error
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
