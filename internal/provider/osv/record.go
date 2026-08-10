// Package osv converts OSV records into the internal advisory shape.
//
// OSV is the primary provider and passes through nearly unchanged (D1) — the
// internal type IS the OSV shape. What this package does is filter.
package osv

import (
	"encoding/json"
	"fmt"
	"regexp"
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

// mainlineUbuntuKey is the only Ubuntu shape this build ingests: a long-term
// release carries the suffix, an interim one does not. It is deliberately a
// copy of the pattern in internal/version rather than an import — that one
// decides what a scan can COMPARE, this one decides what a build STORES, and
// a single shared constant would make the two look like one decision when
// either could legitimately move without the other.
var mainlineUbuntuKey = regexp.MustCompile(`^Ubuntu:[0-9]{2}\.[0-9]{2}(:LTS)?$`)

// ubuntuLineage reports whether a key names one of the Ubuntu lineages this
// build does not ingest — Pro, FIPS, FIPS-updates, FIPS-preview, Realtime,
// Nvidia-BlueField, and whatever OSV adds next.
//
// Written as "Ubuntu but not mainline" rather than as a list of the six
// families, because OSV's schema documents only the bare :Pro: prefix. The
// other spellings are convention, two non-canonical shapes are already in
// the live export (Ubuntu:22.04:LTS:for:NVIDIA:BlueField), and a list would
// silently start storing whatever family is invented next.
func ubuntuLineage(ecosystem string) bool {
	return strings.HasPrefix(ecosystem, "Ubuntu") && !mainlineUbuntuKey.MatchString(ecosystem)
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
	// The rule was written as a special case for "Alpine" and is general: a
	// distro archive is fetched under its family name and holds
	// release-qualified keys inside it (D6). Debian arrived and the hardcoded
	// name silently matched nothing, which the fetch guard caught — an archive
	// of 62,318 records yielding zero.
	//
	// Harmless for the language ecosystems: there is no "Go:1.22" key, so the
	// prefix clause never fires for them.
	return ecosystem == want || strings.HasPrefix(ecosystem, want+":")
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
		// The one exception to the paragraph above, and it is safe for the
		// reason that paragraph gives rather than in spite of it (D53).
		//
		// What made stripping lossy was that another PASS had already
		// indexed the entries being dropped. No pass ever indexes an Ubuntu
		// lineage key: Ecosystems never names one, familyMatches can never
		// return true for one, and version.For refuses to resolve one. An
		// entry dropped here is therefore unreachable by construction, not
		// merely unreached today.
		//
		// It is dropped on EVERY fetch rather than only the Ubuntu one, so
		// the invariant does not depend on pass ordering.
		//
		// This is also what makes the corpus affordable. Ubuntu records carry
		// 38.9 affected entries each against Debian's 3.4 — 6.03 GB unpacked
		// against 254 MB — and the multiplier is one entry per
		// (lineage x release x binary package), not longer version lists.
		if ubuntuLineage(ra.Package.Ecosystem) {
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
