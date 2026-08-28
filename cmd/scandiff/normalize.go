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
	// Components backs the minComponents floor: on a target whose expected
	// finding count is genuinely zero (cleanstart), zero findings and "the
	// cataloger silently saw nothing" are indistinguishable through every
	// other number this tool reads -- the component count is the one that
	// still separates them.
	Components int `json:"components"`
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
	// Advisories carries the upstream advisory IDs grype attaches to a
	// CVE-keyed vulnerability (a Bodhi FEDORA-*, a Debian DSA-*). Read for
	// the bare-ID bridge below: when assay could extract no CVE and fell
	// back to that same advisory ID, this column is the only place the two
	// documents' vocabularies still meet.
	Advisories []grypeAdvisory `json:"advisories"`
}

type grypeAdvisory struct {
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

// --- trivy's `--format json` shape (D105) ---
//
// trivy's document is Results[]{Class, Vulnerabilities[]{PkgName,
// VulnerabilityID}}, read from https://trivy.dev's JSON output spec, not
// guessed. Class distinguishes "os-pkgs" from "lang-pkgs" (and other
// non-vulnerability result kinds such as "secret" or "config"); this tool
// does not need to switch on it because only Vulnerabilities is read, and a
// Class with no vulnerabilities in it (or none at all) simply contributes
// nothing.

type trivyDocument struct {
	Results []trivyResult `json:"Results"`
}

type trivyResult struct {
	Class           string      `json:"Class"`
	Vulnerabilities []trivyVuln `json:"Vulnerabilities"`
}

type trivyVuln struct {
	PkgName         string   `json:"PkgName"`
	VulnerabilityID string   `json:"VulnerabilityID"`
	References      []string `json:"References"`
}

// refCVERe finds a CVE identifier EMBEDDED in a reference URL, where cveRe's
// whole-string anchors cannot reach it. \d+ is greedy, so an ID is never
// truncated mid-number; a digit directly after a real CVE in a URL would be
// part of the ID anyway.
var refCVERe = regexp.MustCompile(`CVE-\d{4}-\d+`)

// trivyTuples extracts the (package, CVE) set from one trivy document.
//
// trivy normalizes its VulnerabilityID to a CVE for most ecosystems, but NOT
// for SUSE: SLE findings are keyed by patch advisory (SUSE-SU-YYYY:NNNN-N),
// with the CVE appearing only inside References URLs -- measured on the D105
// seeding run, where bci156's 58 real trivy findings joined as zero tuples
// and the differential wrongly read as "trivy found nothing". So a
// non-CVE-shaped VulnerabilityID falls back to every CVE named in its
// References, the same lesson D93's seeding taught for ALSA/ELSA (the CVE
// lives in a column the primary ID field does not carry). An entry with no
// CVE anywhere is still dropped rather than joined on its bare ID: unlike
// assayTuples/grypeTuples there is no bare-ID fallback, because a
// trivy-only advisory ID can never agree with anything and would only
// inflate onlyAssay-style noise.
//
// A document with no Results at all (a clean image) and a Result whose
// Vulnerabilities is null or absent both contribute zero tuples, not an
// error -- ranging over a nil slice is simply zero iterations, so no
// explicit nil check is needed for either.
func trivyTuples(doc trivyDocument) map[tuple]struct{} {
	set := make(map[tuple]struct{})
	for _, res := range doc.Results {
		for _, v := range res.Vulnerabilities {
			if isCVE(v.VulnerabilityID) {
				set[tuple{Subject: v.PkgName, ID: v.VulnerabilityID}] = struct{}{}
				continue
			}
			for _, ref := range v.References {
				for _, cve := range refCVERe.FindAllString(ref, -1) {
					set[tuple{Subject: v.PkgName, ID: cve}] = struct{}{}
				}
			}
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

// bridgeBareIDs is the third instance of one lesson: when a tool cannot
// spell a CVE, the identifier that CAN join the two documents lives in a
// column the primary extraction does not read. D93's seeding found it in
// assay's ratings (ALSA/ELSA), D105's correction in trivy's References
// (SUSE-SU), and the 2026-08-28 audit found it between assay and grype on
// Fedora and Debian: one side falls back to a bare advisory ID
// (FEDORA-..., DSA-...) because its own record extracts no CVE, while the
// OTHER side carries that exact advisory ID in a secondary column
// (grype's vulnerability.advisories[], assay's advisory id/aliases/
// upstream) next to the CVE it did extract.
//
// The bridge is deliberately one-way per tuple and keyed on the ids a side
// ACTUALLY fell back to: only a bare (non-CVE) tuple already present in one
// set earns the other side a matching tuple, and only when the other
// document names that id for the same subject. Unconditional enrichment --
// emitting every advisory id on both sides -- was measured on the audit's
// captures and rejected: it inflates ubi8n18's onlyAssay from 4531 to
// 10152 while recovering the same dozen tuples this recovers.
func bridgeBareIDs(adoc assayDocument, gdoc grypeDocument, aSet, gSet map[tuple]struct{}) {
	assayNames := make(map[tuple]struct{})
	for _, f := range adoc.Findings {
		add := func(id string) {
			if id != "" && !isCVE(id) {
				assayNames[tuple{Subject: f.Package.Name, ID: id}] = struct{}{}
			}
		}
		add(f.Advisory.ID)
		for _, a := range f.Advisory.Aliases {
			add(a)
		}
		for _, u := range f.Advisory.Upstream {
			add(u)
		}
	}

	grypeNames := make(map[tuple]struct{})
	for _, m := range gdoc.Matches {
		add := func(id string) {
			if id != "" && !isCVE(id) {
				grypeNames[tuple{Subject: m.Artifact.Name, ID: id}] = struct{}{}
			}
		}
		add(m.Vulnerability.ID)
		for _, a := range m.Vulnerability.Advisories {
			add(a.ID)
		}
		for _, r := range m.RelatedVulnerabilities {
			add(r.ID)
			for _, a := range r.Advisories {
				add(a.ID)
			}
		}
	}

	for t := range aSet {
		if isCVE(t.ID) {
			continue
		}
		if _, ok := grypeNames[t]; ok {
			gSet[t] = struct{}{}
		}
	}
	for t := range gSet {
		if isCVE(t.ID) {
			continue
		}
		if _, ok := assayNames[t]; ok {
			aSet[t] = struct{}{}
		}
	}
}
