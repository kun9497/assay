// Package osv converts OSV records into the internal advisory shape.
//
// OSV is the primary provider and passes through nearly unchanged (D1) — the
// internal type IS the OSV shape. What this package does is filter.
package osv

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/kun9497/assay/internal/advisory"
)

// SourceName identifies records this provider supplied (D15's groundwork for
// splitting data by provider later).
const SourceName = "osv"

type rawRecord struct {
	ID        string        `json:"id"`
	Summary   string        `json:"summary"`
	Modified  time.Time     `json:"modified"`
	Withdrawn *time.Time    `json:"withdrawn"`
	Aliases   []string      `json:"aliases"`
	Upstream  []string      `json:"upstream"`
	Affected  []rawAffected `json:"affected"`
	Severity  []rawSeverity `json:"severity"`
}

type rawAffected struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
		PURL      string `json:"purl"`
	} `json:"package"`
	Ranges   []rawRange `json:"ranges"`
	Versions []string   `json:"versions"`
}

type rawRange struct {
	Type   string     `json:"type"`
	Events []rawEvent `json:"events"`
}

type rawEvent struct {
	Introduced   string `json:"introduced"`
	Fixed        string `json:"fixed"`
	LastAffected string `json:"last_affected"`
	Limit        string `json:"limit"`
}

type rawSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

// familyMatches reports whether a record's affected ecosystem key belongs to
// the family being fetched. Every ecosystem but Alpine matches by exact
// equality: "Go" must not start matching "GoFoo".
//
// Alpine is the one exception. There is a single archive ("Alpine/all.zip")
// for every release rather than one archive per release — unlike its
// ecosystem KEYS, which stay release-qualified (D6: "Alpine:v3.19", never a
// bare "Alpine"). wantEcosystem "Alpine" therefore has to match any
// "Alpine:vX.Y" entry the archive contains, not just an exact "Alpine" that
// never appears in real data. Narrowing this back to exact equality would
// match nothing at all and silently ingest zero Alpine records.
func familyMatches(ecosystem, want string) bool {
	if want == "Alpine" {
		return ecosystem == "Alpine" || strings.HasPrefix(ecosystem, "Alpine:")
	}
	return ecosystem == want
}

// databaseOf returns the database that authored an advisory, read from its
// identifier's namespace.
//
// Resolved once, at ingest, rather than at query time: a prefix is a naming
// convention rather than a field, and these identifiers nest —
// ALPINE-CVE-2025-46394 is an ALPINE record whose subject has a CVE. A parser
// in the read path would have to get that right on every call, silently.
func databaseOf(id string) string {
	i := strings.Index(id, "-")
	if i <= 0 {
		return ""
	}
	return id[:i]
}

// Convert parses one OSV record and keeps only the parts relevant to
// wantEcosystem. ok is false when the record is deliberately filtered out;
// err is non-nil only when the record is malformed. Distinguishing the two
// keeps "we chose to skip this" from looking like "the database is broken".
func Convert(data []byte, wantEcosystem string) (advisory.Advisory, bool, error) {
	var r rawRecord
	if err := json.Unmarshal(data, &r); err != nil {
		return advisory.Advisory{}, false, fmt.Errorf("decode osv record: %w", err)
	}
	if r.ID == "" {
		return advisory.Advisory{}, false, fmt.Errorf("osv record has no id")
	}

	// Withdrawn advisories were retracted upstream; reporting them is a plain
	// false positive. Dropped here rather than at query time so no lookup path
	// can forget the check (D16).
	if r.Withdrawn != nil {
		return advisory.Advisory{}, false, nil
	}

	kind := advisory.KindVulnerability
	if strings.HasPrefix(r.ID, "MAL-") {
		kind = advisory.KindMalicious
	}
	// Malicious-package reports are a different finding class with no severity
	// and no fixed version (D15). Kind is computed above and would be stored
	// faithfully; the filter is what changes when they are enabled.
	if kind != advisory.KindVulnerability {
		return advisory.Advisory{}, false, nil
	}

	out := advisory.Advisory{
		ID:       r.ID,
		Database: databaseOf(r.ID),
		Aliases:  r.Aliases,
		Upstream: r.Upstream,
		Source:   SourceName,
		Kind:     kind,
		Summary:  r.Summary,
		Modified: r.Modified,
	}
	for _, sev := range r.Severity {
		out.Severity = append(out.Severity, advisory.Severity{Type: sev.Type, Score: sev.Score})
	}

	var matchesWanted bool
	for _, ra := range r.Affected {
		// Every entry is kept, including other ecosystems'. Stripping them made
		// the record lossy in a way that destroyed data: Fetch emits the same
		// advisory once per ecosystem, Put overwrites by ID, and the last pass
		// left a record holding only its own ecosystem's entries while the
		// earlier ecosystem's index still pointed at it. The matcher then
		// discarded every entry and reported nothing — no error, no skip.
		// Measured on the live Go dump: 15 of 8,497 records clobbered, 3 with
		// no GO- twin to rescue them.
		//
		// Selecting the right entries is the matcher's job, and it already
		// filters on ecosystem and name. This also restores D13.
		if ra.Package.Name == "" {
			continue
		}
		if familyMatches(ra.Package.Ecosystem, wantEcosystem) {
			matchesWanted = true
		}
		aff := advisory.Affected{
			Ecosystem: ra.Package.Ecosystem,
			Name:      ra.Package.Name,
			Versions:  ra.Versions, // verbatim: OSV publishes non-canonical forms (D13)
		}
		for _, rr := range ra.Ranges {
			typ := advisory.RangeType(strings.ToUpper(rr.Type))
			// GIT ranges carry commit SHAs, not versions.
			if typ == advisory.RangeGit {
				continue
			}
			rng := advisory.Range{Type: typ}
			for _, re := range rr.Events {
				// D35 repairs one documented Alpine typo here, at ingestion,
				// so no query path can forget it (D16's rule). Everything else
				// is stored exactly as published.
				rng.Events = append(rng.Events, advisory.Event{
					Introduced:   repairBound(ra.Package.Ecosystem, re.Introduced),
					Fixed:        repairBound(ra.Package.Ecosystem, re.Fixed),
					LastAffected: repairBound(ra.Package.Ecosystem, re.LastAffected),
					Limit:        repairBound(ra.Package.Ecosystem, re.Limit),
				})
			}
			if len(rng.Events) > 0 {
				aff.Ranges = append(aff.Ranges, rng)
			}
		}
		if len(aff.Ranges) == 0 && len(aff.Versions) == 0 {
			continue // nothing left to match on
		}
		out.Affected = append(out.Affected, aff)
	}

	// The record is dropped only when it says nothing about the ecosystem being
	// ingested. It is stored whole when it does.
	if len(out.Affected) == 0 || !matchesWanted {
		return advisory.Advisory{}, false, nil
	}
	return out, true, nil
}
