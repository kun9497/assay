package dbcmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"time"

	"github.com/kun9497/assay/internal/store"
)

// statusSchemaVersion is the `db status --output json` document's own
// contract version; docs/compatibility.md says what a bump means.
const statusSchemaVersion = 1

// statusDocument is `db status --output json`: the same facts the table
// prints, as data. It keeps the table's rules -- counts derived from the
// stored buckets rather than self-reported, a source that ran and produced
// nothing kept as a row (records 0) rather than dropped, an unknown date
// left out rather than zero -- and spells as words the states the table
// spells as words. Lists are sorted and never null, so two runs over one
// database are byte-identical.
type statusDocument struct {
	SchemaVersion     int                      `json:"schemaVersion"`
	Path              string                   `json:"path"`
	Schema            int                      `json:"schema"`
	BuiltAt           time.Time                `json:"builtAt"`
	Artifact          *statusArtifact          `json:"artifact,omitempty"`
	Ecosystems        []string                 `json:"ecosystems"`
	Databases         []string                 `json:"databases"`
	EOL               statusEOL                `json:"eol"`
	Providers         []statusProvider         `json:"providers"`
	RatingSources     []statusRatingSource     `json:"ratingSources"`
	EnrichmentSources []statusEnrichmentSource `json:"enrichmentSources"`
}

type statusArtifact struct {
	Reference string    `json:"reference"`
	Digest    string    `json:"digest"`
	PulledAt  time.Time `json:"pulledAt"`
	// Signature is "verified" (a trusted key verified it, SignedBy names
	// which), "unverified" (installed with --allow-unsigned), or
	// "unrecorded" (pulled before D137 recorded either).
	Signature string `json:"signature"`
	SignedBy  string `json:"signedBy,omitempty"`
}

type statusEOL struct {
	Releases int        `json:"releases"`
	Distros  int        `json:"distros"`
	DataAsOf *time.Time `json:"dataAsOf,omitempty"`
}

type statusProvider struct {
	Name       string         `json:"name"`
	DataAsOf   *time.Time     `json:"dataAsOf,omitempty"`
	Records    int            `json:"records"`
	Source     string         `json:"source,omitempty"`
	Ecosystems []string       `json:"ecosystems"`
	Frozen     []statusFrozen `json:"frozen,omitempty"`
	Closed     []statusClosed `json:"closed,omitempty"`
	Renamed    []statusRename `json:"renamed,omitempty"`
}

type statusFrozen struct {
	Key   string    `json:"key"`
	Since time.Time `json:"since"`
}

type statusClosed struct {
	Topic        string    `json:"topic"`
	LastAdvisory time.Time `json:"lastAdvisory"`
}

type statusRename struct {
	From string `json:"from"`
	To   string `json:"to"`
}

type statusRatingSource struct {
	Name     string     `json:"name"`
	DataAsOf *time.Time `json:"dataAsOf,omitempty"`
	// Records is derived from the ratings bucket; 0 means the source ran
	// and rated nothing (the table's "investigate the sync").
	Records int    `json:"records"`
	Covered string `json:"covered,omitempty"`
	Source  string `json:"source,omitempty"`
}

type statusEnrichmentSource struct {
	Name     string     `json:"name"`
	DataAsOf *time.Time `json:"dataAsOf,omitempty"`
	Records  int        `json:"records"`
	// Error is why the source's run did not finish; with Records > 0 the
	// run wrote that many and then failed.
	Error  string `json:"error,omitempty"`
	Source string `json:"source,omitempty"`
}

// StatusJSON writes `db status --output json`. A database that cannot be
// opened is refused exactly as Status refuses it, with nothing on stdout.
func StatusJSON(dbPath string, stdout, stderr io.Writer) int {
	m, ok := readStatusMeta(dbPath, stderr)
	if !ok {
		return 2
	}
	b, err := json.MarshalIndent(statusDocumentOf(dbPath, m), "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "error: encode status: %v\n", err)
		return 2
	}
	if _, err := fmt.Fprintf(stdout, "%s\n", b); err != nil {
		fmt.Fprintf(stderr, "error: write status: %v\n", err)
		return 2
	}
	return 0
}

// readStatusMeta opens the database read-only and returns its Meta, or
// reports why it cannot on stderr. Both `db status` outputs refuse through
// it, so the table and the JSON cannot disagree about what is missing.
func readStatusMeta(dbPath string, stderr io.Writer) (store.Meta, bool) {
	db, err := store.Open(dbPath)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrSchemaMismatch) ||
			errors.Is(err, store.ErrIncomplete) {
			fmt.Fprintf(stderr, "error: %v\n", err)
			fmt.Fprintln(stderr, "run `assay db update` to download it, or `assay db build` to build it from source")
			return store.Meta{}, false
		}
		fmt.Fprintf(stderr, "error: open database: %v\n", err)
		return store.Meta{}, false
	}
	defer db.Close()
	m, err := db.Meta()
	if err != nil {
		fmt.Fprintf(stderr, "error: read metadata: %v\n", err)
		return store.Meta{}, false
	}
	return m, true
}

func statusDocumentOf(dbPath string, m store.Meta) statusDocument {
	doc := statusDocument{
		SchemaVersion:     statusSchemaVersion,
		Path:              dbPath,
		Schema:            m.Schema,
		BuiltAt:           m.BuiltAt.UTC(),
		Ecosystems:        sortedOrEmpty(m.Ecosystems),
		Databases:         sortedOrEmpty(m.Databases),
		Providers:         []statusProvider{},
		RatingSources:     []statusRatingSource{},
		EnrichmentSources: []statusEnrichmentSource{},
	}
	if a := m.Artifact; a != nil {
		art := statusArtifact{Reference: a.Reference, Digest: a.Digest, PulledAt: a.PulledAt.UTC(), Signature: "unrecorded"}
		switch {
		case a.SignedBy != "":
			art.Signature, art.SignedBy = "verified", a.SignedBy
		case a.Unverified:
			art.Signature = "unverified"
		}
		doc.Artifact = &art
	}

	distros := map[string]struct{}{}
	for _, r := range m.EOL {
		distros[r.DistroID] = struct{}{}
	}
	doc.EOL = statusEOL{Releases: len(m.EOL), Distros: len(distros)}
	if m.EOLProvenance != nil {
		doc.EOL.DataAsOf = dateOrNil(m.EOLProvenance.DataAsOf)
	}

	for _, name := range sortedKeys(m.Providers) {
		p := m.Providers[name]
		sp := statusProvider{Name: name, DataAsOf: dateOrNil(p.DataAsOf), Records: p.Records,
			Source: p.Source, Ecosystems: sortedOrEmpty(p.Ecosystems)}
		for _, k := range sortedKeys(p.Frozen) {
			sp.Frozen = append(sp.Frozen, statusFrozen{Key: k, Since: p.Frozen[k].UTC()})
		}
		for _, k := range sortedKeys(p.Closed) {
			sp.Closed = append(sp.Closed, statusClosed{Topic: k, LastAdvisory: p.Closed[k].UTC()})
		}
		for _, k := range sortedKeys(p.Renamed) {
			sp.Renamed = append(sp.Renamed, statusRename{From: k, To: p.Renamed[k]})
		}
		doc.Providers = append(doc.Providers, sp)
	}

	// The union of self-reported and derived names, as the table builds it:
	// a derived-only name still gets a row, a self-reported one with no
	// count gets records 0.
	for _, name := range unionKeys(m.Ratings, m.RatingCounts) {
		p := m.Ratings[name]
		doc.RatingSources = append(doc.RatingSources, statusRatingSource{Name: name,
			DataAsOf: dateOrNil(p.DataAsOf), Records: m.RatingCounts[name], Covered: p.Window, Source: p.Source})
	}
	for _, name := range unionKeys(m.Enrichment, m.EnrichmentCounts) {
		p := m.Enrichment[name]
		doc.EnrichmentSources = append(doc.EnrichmentSources, statusEnrichmentSource{Name: name,
			DataAsOf: dateOrNil(p.DataAsOf), Records: m.EnrichmentCounts[name], Error: p.Error, Source: p.Source})
	}
	return doc
}

func dateOrNil(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	u := t.UTC()
	return &u
}

func sortedOrEmpty(s []string) []string {
	out := append([]string{}, s...)
	slices.Sort(out)
	return out
}

func unionKeys(a map[string]store.Provenance, b map[string]int) []string {
	set := map[string]struct{}{}
	for k := range a {
		set[k] = struct{}{}
	}
	for k := range b {
		set[k] = struct{}{}
	}
	return sortedKeys(set)
}
