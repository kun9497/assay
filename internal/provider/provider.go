// Package provider defines how upstream advisory data enters the store.
//
// The abstraction exists from day one (D2) because KISA/KNVD data will not
// arrive in OSV format, so some collection and normalization is unavoidable —
// but committing to hand-rolling every upstream feed is not.
package provider

import (
	"context"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/store"
)

type Provider interface {
	Name() string
	// Fetch streams advisories to emit rather than returning a slice: the
	// unfiltered OSV download is ~244 MB for slice 1's ecosystems, most of
	// which is discarded, and holding it all in memory buys nothing.
	Fetch(ctx context.Context, emit func(advisory.Advisory) error) (store.Provenance, error)
}

// Annotator is an upstream that says what a CVE is worth, rather than which
// package is affected. NVD is the first; KISA is the reason the interface is
// not called "NVDProvider".
type Annotator interface {
	Name() string
	Annotate(ctx context.Context, emit func(advisory.Rating) error) (store.Provenance, error)
}

// Enricher is an upstream that describes a CVE in prose, rather than saying
// which package is affected or what the CVE is worth. KISA/KNVD is the first
// and the reason the interface exists (D3): much of its corpus names a CVE
// and describes it in Korean with no ecosystem and no package version, so
// treating it as a Provider would invent findings nothing can substantiate
// and treating it as an Annotator would put a band on data that carries no
// score.
//
// A third interface rather than a flag on Provider because the difference is
// what the data may do, not where it came from. Nothing an Enricher emits
// may reach a verdict: a scan against a database with a full enrichment
// bucket and one with none must agree on every exit code.
type Enricher interface {
	Name() string
	Enrich(ctx context.Context, emit func(advisory.Enrichment) error) (store.Provenance, error)
}

// EOLSource is an upstream that says when a distro RELEASE stops being
// supported, rather than which package is affected (Provider) or what a CVE
// is worth (Annotator) or in prose about a CVE (Enricher). None of the three
// fits (D87): end-of-life data is keyed on (distro, release) rather than a
// CVE or a package, it is meant to gate a scan (`--fail-on-eol`) rather than
// stay inert like an Enricher's prose, and — unlike KISA/KNVD (D29) — it IS
// meant to ride the published artifact, so it cannot share Enricher's
// failure-is-not-fatal treatment either: a build that silently shipped
// without EOL data would leave the gate unable to answer at all.
//
// Fetch returns the whole small corpus (~200 rows) as a slice rather than
// streaming through an emit callback the way Provider does — there is no
// multi-hundred-megabyte corpus here to avoid holding in memory.
type EOLSource interface {
	Name() string
	Fetch(ctx context.Context) ([]store.EOLRelease, store.Provenance, error)
}
