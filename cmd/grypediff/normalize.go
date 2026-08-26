package main

import "regexp"

// cveRe matches a bare CVE identifier -- nothing else. GHSA-, ALAS2023-,
// RLSA-, RHSA- and similar advisory IDs are deliberately NOT CVE-shaped, so
// they never get treated as the join key between assay and grype: the two
// tools almost never mint the same non-CVE ID for the same vulnerability,
// but they draw the same CVE from their own aliases, and the CVE is the
// only vocabulary both sides reliably speak.
var cveRe = regexp.MustCompile(`^CVE-\d{4}-\d+$`)

func isCVE(s string) bool { return cveRe.MatchString(s) }

// tuple is the join key between one assay finding and one grype match: a
// subject (the package/artifact name each tool already reports on its own
// terms) paired with one identifier. A finding or match that names several
// CVEs becomes several tuples, which is what lets set intersection do the
// comparison -- see assayTuples and grypeTuples below.
type tuple struct {
	Subject string
	ID      string
}

// --- assay's `scan --output json` shape (schema 8) ---
//
// Deliberately NOT internal/report.Document reused here: this tool reads
// assay's stdout the way any other CI consumer would, through the schema
// contract alone, not through the producing package's own types. Field
// names were read from internal/report/json.go (FindingRecord, AdvisoryRecord,
// Summary), not guessed.

type assayDocument struct {
	SchemaVersion int            `json:"schemaVersion"`
	Findings      []assayFinding `json:"findings"`
	Summary       assaySummary   `json:"summary"`
}

type assayFinding struct {
	Package  assayPackage  `json:"package"`
	Advisory assayAdvisory `json:"advisory"`
	Ratings  []assayRating `json:"ratings"`
}

// assayRating is read for its advisoryId alone. Annotation sources (NVD,
// EPSS, KEV) attach to a finding BY CVE, so their advisoryId IS the CVE --
// and for AlmaLinux and Oracle Linux it is the only place the document
// spells one at all: ALSA/ELSA records carry their CVE link in the OSV
// `related` field (D71), which AdvisoryRecord does not expose, while the
// annotations that attach through it do. The first seeding run measured
// agree=0 on both ecosystems for exactly this reason.
type assayRating struct {
	AdvisoryID string `json:"advisoryId"`
}

type assayPackage struct {
	Name string `json:"name"`
}

type assayAdvisory struct {
	ID       string   `json:"id"`
	Aliases  []string `json:"aliases"`
	Upstream []string `json:"upstream"`
}

type assaySummary struct {
	NotEvaluated int `json:"notEvaluated"`
	Findings     int `json:"findings"`
}

// assayTuples extracts the (package, CVE) set from one assay document (D93's
// normalization step). A finding contributes one tuple per CVE-shaped
// identifier found across its advisory ID, aliases, upstream (D3: both
// fields carry CVE links depending on the OSV record's own vintage) and its
// ratings' advisoryIds (see assayRating: for ALSA/ELSA findings the
// annotations are the only CVE spelling in the whole document); a
// finding with no CVE-shaped identifier at all contributes exactly one
// tuple keyed on its bare advisory ID, so it is never silently dropped from
// the comparison.
func assayTuples(doc assayDocument) map[tuple]struct{} {
	set := make(map[tuple]struct{})
	for _, f := range doc.Findings {
		ratingIDs := make([]string, 0, len(f.Ratings))
		for _, r := range f.Ratings {
			ratingIDs = append(ratingIDs, r.AdvisoryID)
		}
		ids := collectCVEs(f.Advisory.ID, f.Advisory.Aliases, f.Advisory.Upstream, ratingIDs)
		if len(ids) == 0 {
			ids = []string{f.Advisory.ID}
		}
		for _, id := range ids {
			set[tuple{Subject: f.Package.Name, ID: id}] = struct{}{}
		}
	}
	return set
}

func collectCVEs(id string, lists ...[]string) []string {
	seen := make(map[string]bool)
	var out []string
	add := func(s string) {
		if isCVE(s) && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	add(id)
	for _, l := range lists {
		for _, s := range l {
			add(s)
		}
	}
	return out
}

// --- grype's `-o json` shape ---

type grypeDocument struct {
	Matches []grypeMatch `json:"matches"`
}

type grypeMatch struct {
	Vulnerability          grypeVuln     `json:"vulnerability"`
	RelatedVulnerabilities []grypeVuln   `json:"relatedVulnerabilities"`
	Artifact               grypeArtifact `json:"artifact"`
}

type grypeVuln struct {
	ID string `json:"id"`
}

type grypeArtifact struct {
	Name string `json:"name"`
}

// grypeTuples extracts the (artifact, CVE) set from one grype document,
// mirroring assayTuples: vulnerability.id counts when it is itself
// CVE-shaped, every CVE-shaped relatedVulnerabilities[].id counts too (a
// distro advisory such as ALAS2023-2023-377 routinely wraps several CVEs
// there), and a match with no CVE-shaped identifier anywhere falls back to
// vulnerability.id verbatim -- same reasoning as assayTuples' fallback, kept
// symmetric so neither side privileges its own non-CVE IDs over the other's.
func grypeTuples(doc grypeDocument) map[tuple]struct{} {
	set := make(map[tuple]struct{})
	for _, m := range doc.Matches {
		var ids []string
		seen := make(map[string]bool)
		add := func(s string) {
			if isCVE(s) && !seen[s] {
				seen[s] = true
				ids = append(ids, s)
			}
		}
		add(m.Vulnerability.ID)
		for _, r := range m.RelatedVulnerabilities {
			add(r.ID)
		}
		if len(ids) == 0 {
			ids = []string{m.Vulnerability.ID}
		}
		for _, id := range ids {
			set[tuple{Subject: m.Artifact.Name, ID: id}] = struct{}{}
		}
	}
	return set
}

// compareSets computes the differential's three headline numbers: how many
// tuples both tools reported, and how many each reported alone. Neither
// input is mutated, and the result does not depend on map iteration order
// (only counts come out), which is what keeps this deterministic across
// runs of the same two documents.
func compareSets(a, g map[tuple]struct{}) (agree, onlyAssay, onlyGrype int) {
	for t := range a {
		if _, ok := g[t]; ok {
			agree++
		} else {
			onlyAssay++
		}
	}
	for t := range g {
		if _, ok := a[t]; !ok {
			onlyGrype++
		}
	}
	return agree, onlyAssay, onlyGrype
}
