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
	"time"

	"github.com/kun9497/assay/internal/advisory"
)

// SchemaVersion is part of the on-disk path (D5). A schema change rebuilds
// into a new directory rather than migrating in place, because migration code
// is a liability for a project with one user.
const SchemaVersion = 1

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
	Meta() (Meta, error)
	Close() error
}

// Writer is the build-side half. Separate from Store so a scan cannot be
// handed something it could write through.
type Writer interface {
	Put(a advisory.Advisory) error
	SetMeta(m Meta) error
	Close() error
}

type Meta struct {
	Schema    int                   `json:"schema"`
	BuiltAt   time.Time             `json:"built_at"` // when this database was assembled locally
	Providers map[string]Provenance `json:"providers"`
}

type Provenance struct {
	Source string `json:"source"` // the URL actually fetched
	// DataAsOf is when the UPSTREAM data was current, which is not the same as
	// BuiltAt (D12). A mirror serving a stale snapshot fetched today has a
	// recent BuiltAt and an old DataAsOf; judging freshness by the former
	// reports quarter-old data as fresh.
	DataAsOf time.Time `json:"data_as_of"`
	Records  int       `json:"records"`
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
	return filepath.Join(cache, "assay", "db", "v1", "vulnerability.db"), nil
}
