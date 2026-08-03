// Package advisory holds the normalized vulnerability record. The shape follows
// the OSV schema (D1): every provider converts into this rather than the store
// growing a variant per source, which is what makes a KISA provider possible.
package advisory

import "time"

// Kind separates vulnerability reports from malicious-package reports. Only
// KindVulnerability is ingested today (D15), but the field is stored from the
// start because adding one later means rebuilding the database.
type Kind string

const (
	KindVulnerability Kind = "vulnerability"
	KindMalicious     Kind = "malicious"
)

type Advisory struct {
	ID       string     `json:"id"`       // CVE-… | GHSA-… | GO-… | ALPINE-… | KVE-…
	Database string     `json:"database"` // the record's own namespace: "GHSA" | "PYSEC" | "GO" | "ALPINE" | … (D25)
	Aliases  []string   `json:"aliases,omitempty"`
	Upstream []string   `json:"upstream,omitempty"` // OSV 1.7 puts the CVE link here, not in Aliases (D3)
	Source   string     `json:"source"`             // "osv" | "kisa"
	Kind     Kind       `json:"kind"`
	Summary  string     `json:"summary,omitempty"`
	Modified time.Time  `json:"modified,omitempty"`
	Affected []Affected `json:"affected"`
	Severity []Severity `json:"severity,omitempty"` // CVSS vectors, banded at query time (D13)
}

type Affected struct {
	Ecosystem string   `json:"ecosystem"` // "Go" | "npm" | "PyPI" | "Alpine:v3.19" (D6)
	Name      string   `json:"name"`
	Ranges    []Range  `json:"ranges,omitempty"`
	Versions  []string `json:"versions,omitempty"` // enumerated; the only data when Ranges is empty
}

// RangeType mirrors OSV. GIT ranges carry commit SHAs, not versions, and must
// never reach a Comparer.
type RangeType string

const (
	RangeSemver    RangeType = "SEMVER"
	RangeEcosystem RangeType = "ECOSYSTEM"
	RangeGit       RangeType = "GIT"
)

type Range struct {
	Type   RangeType `json:"type"`
	Events []Event   `json:"events"`
}

// Event carries exactly one populated field. LastAffected is an inclusive upper
// bound; Fixed is exclusive. Conflating them shifts every boundary by one
// version.
type Event struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	Limit        string `json:"limit,omitempty"`
}

type Severity struct {
	Type  string `json:"type"`  // CVSS_V2 | CVSS_V3 | CVSS_V4
	Score string `json:"score"` // the vector string
}
