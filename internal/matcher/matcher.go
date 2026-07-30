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

// Skipped is something the matcher could not evaluate. It exists so that "we
// could not tell" never renders as "nothing found".
//
// It is per (package, advisory), not per package. A package can produce a
// finding from one advisory and be unevaluable against another, and the second
// fact must survive the first — the unevaluated advisory may carry the higher
// severity or a higher fix floor, which would make the remediation shown next
// to the visible finding actively wrong.
type Skipped struct {
	Package pkgmeta.Package
	// AdvisoryID is empty when the whole package was skipped, e.g. because no
	// comparer is registered for its ecosystem.
	AdvisoryID string
	Reason     string
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
		// NOTE for whoever adds a distro comparer to version.registry: distro
		// advisories are keyed on SOURCE packages while installed packages are
		// binary packages (D8), so this loop must also consult
		// store.LookupBySource with p.Source. Until then a distro package exits
		// here as Skipped, which is safe. Registering the comparer without
		// adding that lookup flips it from safe to silently under-reporting.
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
		// Skips are deduplicated separately from findings: `seen` is only set
		// on a hit, and the error path must not rely on it. One advisory can
		// carry several Affected entries for the same package — measured at
		// 145 of 313 real Django records — and the same advisory can appear
		// twice in a lookup result, so without this a single bad bound emits
		// byte-identical skips and buries the rest of the report.
		skipped := make(map[string]bool, len(candidates))

		for _, a := range candidates {
			if seen[a.ID] {
				continue
			}
			for _, aff := range a.Affected {
				// The store is keyed on (ecosystem, name), so a returned
				// advisory can still carry entries for sibling packages — a Go
				// advisory naming both github.com/foo/bar and .../bar/v2, for
				// instance. Evaluating a v1 version against a v2 range would be
				// wrong, so entries that are not this package are skipped.
				//
				// This mirrors the store's key equality exactly. If either side
				// ever starts normalizing names, the two must change together
				// or this filter will silently discard real advisories.
				if aff.Ecosystem != p.Ecosystem || aff.Name != p.Name {
					continue
				}
				hit, ev, err := version.AffectsVersion(cmp, p.Version, aff)
				if err != nil {
					// One advisory this package cannot be evaluated against.
					// Recorded against that advisory and the loop continues, so
					// a single malformed bound hides neither the other
					// advisories nor the fact that this one was unevaluable.
					if !skipped[a.ID] {
						skipped[a.ID] = true
						res.Skipped = append(res.Skipped, Skipped{
							Package:    p,
							AdvisoryID: a.ID,
							Reason:     fmt.Sprintf("comparing %s: %v", p.Version, err),
						})
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
	}

	sortFindings(res.Findings)
	sortSkipped(res.Skipped)
	return res, nil
}

// Sorting keeps output deterministic and diffable, which is design goal #3.
//
// Both comparators key all the way down to something that distinguishes any
// two distinct entries. A partial key would leave ties to sort.Slice, which is
// not stable, so two runs over identical input could order them differently —
// the exact churn the goal forbids. SliceStable is used as well, so that even
// a genuine tie resolves the same way every time.
func sortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.Package.Ecosystem != b.Package.Ecosystem {
			return a.Package.Ecosystem < b.Package.Ecosystem
		}
		if a.Package.Name != b.Package.Name {
			return a.Package.Name < b.Package.Name
		}
		if a.Package.Version != b.Package.Version {
			return a.Package.Version < b.Package.Version
		}
		if a.Advisory.ID != b.Advisory.ID {
			return a.Advisory.ID < b.Advisory.ID
		}
		if a.Package.PURL != b.Package.PURL {
			return a.Package.PURL < b.Package.PURL
		}
		// Two installs of one package at one version share a purl and differ
		// only in where they were found — nested node_modules produce exactly
		// that. Location is the last thing that tells them apart.
		return firstPath(a.Package) < firstPath(b.Package)
	})
}

func sortSkipped(ss []Skipped) {
	sort.SliceStable(ss, func(i, j int) bool {
		a, b := ss[i], ss[j]
		if a.Package.Ecosystem != b.Package.Ecosystem {
			return a.Package.Ecosystem < b.Package.Ecosystem
		}
		if a.Package.Name != b.Package.Name {
			return a.Package.Name < b.Package.Name
		}
		if a.Package.Version != b.Package.Version {
			return a.Package.Version < b.Package.Version
		}
		if a.AdvisoryID != b.AdvisoryID {
			return a.AdvisoryID < b.AdvisoryID
		}
		if a.Reason != b.Reason {
			return a.Reason < b.Reason
		}
		if a.Package.PURL != b.Package.PURL {
			return a.Package.PURL < b.Package.PURL
		}
		return firstPath(a.Package) < firstPath(b.Package)
	})
}

// firstPath returns where a package was found, for use as a final sort key.
// Empty when the source did not record one.
func firstPath(p pkgmeta.Package) string {
	if len(p.Locations) == 0 {
		return ""
	}
	return p.Locations[0].Path
}
