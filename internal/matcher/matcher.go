// Package matcher decides whether an installed package is affected by a stored
// advisory, and records why.
package matcher

import (
	"fmt"
	"sort"
	"strings"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/pkgmeta"
	"github.com/kun9497/assay/internal/severity"
	"github.com/kun9497/assay/internal/store"
	"github.com/kun9497/assay/internal/version"
)

type Finding struct {
	Package  pkgmeta.Package
	Advisory advisory.Advisory
	// Evidence is on the type, not in a log line, because explainability is
	// goal #1 and anything left to logging effectively does not exist (D10).
	Evidence version.Evidence
	// MatchedName is the package name that reached the advisory. It differs
	// from Package.Name when the advisory was written against the source
	// package (D8) — an openssl advisory matching libssl3. Without it the
	// report claims a package is vulnerable and gives the reader no way to
	// check the claim against the advisory they look up.
	//
	// It lives here rather than on version.Evidence because the version package
	// compares versions; which name reached the advisory is a matcher fact.
	MatchedName string
	// Severity and Score are derived from the advisory's own CVSS vectors at
	// match time (D13), never read from a value baked in when the database
	// was built. A record carrying several vectors is banded by the highest
	// of them (severity.Highest) — a finding is as severe as its worst
	// rating, and taking the first vector would make the result depend on
	// OSV's serialization order rather than on the vulnerability. Advisories
	// with no scorable vector — roughly a quarter of the live database —
	// carry Severity == severity.Unknown, never a coerced low band (D17).
	Severity severity.Band
	Score    float64
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

	// Which ecosystems this database actually holds (D20). Read once, before
	// any lookup, because a lookup cannot answer the question: an ecosystem
	// that was never ingested returns exactly what a package with no advisories
	// returns, and calling that clean is the failure this whole tool exists to
	// avoid. Measured before this check existed — same package, same version,
	// only the Alpine release changed:
	//
	//	3.19.9 -> 1 finding
	//	3.25.0 -> "No known vulnerabilities found", exit 0
	covered, err := m.store.Covers()
	if err != nil {
		return Result{}, fmt.Errorf("read database coverage: %w", err)
	}

	for _, p := range t.Packages {
		cmp, ok := version.For(p.Ecosystem)
		if !ok {
			res.Skipped = append(res.Skipped, Skipped{
				Package: p,
				Reason:  fmt.Sprintf("no version comparer for ecosystem %q", p.Ecosystem),
			})
			continue
		}
		if !covered[p.Ecosystem] {
			// A whole-package skip, so the report counts it as not evaluated
			// and a scan where nothing else was checked exits 2 (D11).
			res.Skipped = append(res.Skipped, Skipped{
				Package: p,
				Reason: fmt.Sprintf("ecosystem %q is not in this database; "+
					"run `assay db update`", p.Ecosystem),
			})
			continue
		}

		// Distro advisories are written against SOURCE packages while what is
		// installed are binary packages (D8), so the source name is a second
		// lookup key. Both are queried because they coincide for most packages
		// and diverge for the ones that matter: alpine:3.19 has nine of fifteen
		// diverging, with libssl3 and libcrypto3 both sourced from openssl, so a
		// single openssl advisory is unreachable from either without this.
		//
		// No separate by-source index is needed. OSV puts the source name
		// directly in Affected[].Name — 32,069 of 33,589 Alpine affected entries
		// carry ?arch=source — which the ordinary advisory index already covers.
		// Slice 1 reserved a by-source bucket on the assumption it would be
		// required; measuring the data retired it.
		//
		// The version needs no adjustment: an Alpine binary package carries its
		// source package's version, which is what makes indirect matching sound.
		names := []string{p.Name}
		if p.Source != nil && p.Source.Name != "" && p.Source.Name != p.Name {
			names = append(names, p.Source.Name)
		}

		// The dedup maps below are per package, not per lookup name, so an
		// advisory reachable under both names is still one finding.
		seen := make(map[string]bool)
		// Skips are deduplicated separately from findings: `seen` is only set
		// on a hit, and the error path must not rely on it. One advisory can
		// carry several Affected entries for the same package — measured at
		// 145 of 313 real Django records — and the same advisory can appear
		// twice in a lookup result, so without this a single bad bound emits
		// byte-identical skips and buries the rest of the report.
		skipped := make(map[string]bool)
		// One vulnerability commonly has records under several IDs. OSV's Go
		// ecosystem carries both the GHSA and the GO- identifier for the same
		// issue, which doubled every Go finding in a real scan against grype.
		// The first record to match wins; the rest are recognized through the
		// aliases they declare.
		reported := make(map[string]bool)

		for _, lookupName := range names {
			wantName := pkgmeta.NormalizeName(p.Ecosystem, lookupName)
			candidates, err := m.store.Lookup(p.Ecosystem, lookupName)
			if err != nil {
				// A store error is not a clean result. Fail the whole scan
				// rather than reporting a subset that reads as "fewer
				// vulnerabilities".
				return Result{}, fmt.Errorf("lookup %s/%s: %w", p.Ecosystem, lookupName, err)
			}

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
					if aff.Ecosystem != p.Ecosystem ||
						pkgmeta.NormalizeName(aff.Ecosystem, aff.Name) != wantName {
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
						if reported[a.ID] {
							break // already reported under another identifier
						}
						for _, id := range identifiers(a) {
							reported[id] = true
						}
						band, score := severity.Highest(vectorsOf(a))
						res.Findings = append(res.Findings, Finding{
							Package:     p,
							Advisory:    a,
							Evidence:    ev,
							MatchedName: lookupName,
							Severity:    band,
							Score:       score,
						})
						break
					}
				}
			}
		}
	}

	sortFindings(res.Findings)
	sortSkipped(res.Skipped)
	return res, nil
}

// vectorsOf unwraps the CVSS vector strings carried on an advisory. It does
// no picking of its own — severity.Highest already skips what does not score
// and takes the worst of what does — this only exists because Advisory.Severity
// is a slice of (type, vector) pairs and Highest wants the vectors alone.
func vectorsOf(a advisory.Advisory) []string {
	vectors := make([]string, 0, len(a.Severity))
	for _, s := range a.Severity {
		vectors = append(vectors, s.Score)
	}
	return vectors
}

// identifiers returns the IDs that denote the same vulnerability as a: its own
// and its aliases.
//
// Upstream is deliberately excluded. OSV defines it as "derived from", not as
// identity, so treating it as one would suppress a genuinely distinct advisory
// — a false negative, where an extra alias line is only noise. It is still read
// for the KISA join (D3), which is a different question: which records describe
// the same CVE, not which are the same finding. Measured on the live Go dump,
// upstream is empty on all 8,510 records while aliases already carry the CVE,
// GO- and BIT- identifiers, so nothing is lost by leaving it out.
func identifiers(a advisory.Advisory) []string {
	ids := make([]string, 0, 1+len(a.Aliases))
	ids = append(ids, a.ID)
	ids = append(ids, a.Aliases...)
	return ids
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
		return locationKey(a.Package) < locationKey(b.Package)
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
		return locationKey(a.Package) < locationKey(b.Package)
	})
}

// locationKey renders every location a package was found at into one
// comparable string, so the comparators above are genuinely total orders.
//
// Reading only Locations[0] would leave two installs that agree on their first
// location but differ later comparing equal, and their order would then depend
// on input order surviving unchanged. LayerDigest is included because image
// scanning will populate it, and two copies of a package in different layers
// are different findings.
func locationKey(p pkgmeta.Package) string {
	var b strings.Builder
	for i, l := range p.Locations {
		if i > 0 {
			b.WriteString("\x00")
		}
		b.WriteString(l.Path)
		b.WriteString("\x00")
		b.WriteString(l.LayerDigest)
	}
	return b.String()
}
