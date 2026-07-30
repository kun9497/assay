// Package matcher decides whether an installed package is affected by a stored
// advisory, and records why.
package matcher

import (
	"fmt"
	"sort"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/pkgmeta"
	"github.com/kun9497/assay/internal/store"
	"github.com/kun9497/assay/internal/version"
)

type Finding struct {
	Package  pkgmeta.Package
	Advisory advisory.Advisory
	// Evidence is on the type, not in a log line, because explainability is
	// goal #1 and anything left to logging effectively does not exist (D10).
	Evidence version.Evidence
}

// Skipped is a package the matcher could not evaluate. It exists so that
// "we could not tell" never renders as "nothing found".
type Skipped struct {
	Package pkgmeta.Package
	Reason  string
}

type Result struct {
	Findings []Finding
	Skipped  []Skipped
}

type Matcher struct {
	store store.Store
}

func New(s store.Store) *Matcher { return &Matcher{store: s} }

func (m *Matcher) Match(t pkgmeta.Target) (Result, error) {
	var res Result

	for _, p := range t.Packages {
		cmp, ok := version.For(p.Ecosystem)
		if !ok {
			res.Skipped = append(res.Skipped, Skipped{
				Package: p,
				Reason:  fmt.Sprintf("no version comparer for ecosystem %q", p.Ecosystem),
			})
			continue
		}

		candidates, err := m.store.Lookup(p.Ecosystem, p.Name)
		if err != nil {
			// A store error is not a clean result. Fail the whole scan rather
			// than reporting a subset that reads as "fewer vulnerabilities".
			return Result{}, fmt.Errorf("lookup %s/%s: %w", p.Ecosystem, p.Name, err)
		}

		seen := make(map[string]bool, len(candidates))
		var skipReason string

		for _, a := range candidates {
			if seen[a.ID] {
				continue
			}
			for _, aff := range a.Affected {
				if aff.Ecosystem != p.Ecosystem || aff.Name != p.Name {
					continue
				}
				hit, ev, err := version.AffectsVersion(cmp, p.Version, aff)
				if err != nil {
					// Record the first reason and keep going: one malformed
					// advisory bound must not hide the rest.
					if skipReason == "" {
						skipReason = fmt.Sprintf("comparing %s: %v", p.Version, err)
					}
					continue
				}
				if hit {
					seen[a.ID] = true
					res.Findings = append(res.Findings, Finding{Package: p, Advisory: a, Evidence: ev})
					break
				}
			}
		}

		if skipReason != "" && !anyFindingFor(res.Findings, p) {
			res.Skipped = append(res.Skipped, Skipped{Package: p, Reason: skipReason})
		}
	}

	sortFindings(res.Findings)
	sortSkipped(res.Skipped)
	return res, nil
}

func anyFindingFor(fs []Finding, p pkgmeta.Package) bool {
	for _, f := range fs {
		if f.Package.Name == p.Name && f.Package.Ecosystem == p.Ecosystem {
			return true
		}
	}
	return false
}

// Sorting keeps output deterministic and diffable, which is design goal #3.
func sortFindings(fs []Finding) {
	sort.Slice(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.Package.Ecosystem != b.Package.Ecosystem {
			return a.Package.Ecosystem < b.Package.Ecosystem
		}
		if a.Package.Name != b.Package.Name {
			return a.Package.Name < b.Package.Name
		}
		return a.Advisory.ID < b.Advisory.ID
	})
}

func sortSkipped(ss []Skipped) {
	sort.Slice(ss, func(i, j int) bool {
		a, b := ss[i], ss[j]
		if a.Package.Ecosystem != b.Package.Ecosystem {
			return a.Package.Ecosystem < b.Package.Ecosystem
		}
		return a.Package.Name < b.Package.Name
	})
}
