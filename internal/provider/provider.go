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
