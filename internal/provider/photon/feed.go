package photon

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/kun9497/assay/internal/advisory"
)

// row is one entry in a cve_data_photon<major>.json array. The feed is a
// flat JSON array of these, no nesting, no dates anywhere in the payload
// (measured 2026-08-26 against the live feed) -- unlike updateinfo XML or a
// Bodhi update, there is no grouping object above row at all; (cve_id, pkg)
// is the only structure the data has.
//
// Two fields the upstream sends are deliberately NOT decoded here:
//
//   - aff_ver is free-text prose ("all versions before 1.17-15.ph4 are
//     vulnerable") or the literal "NA", never a structured bound. Nothing
//     in advisory.Event has a slot for prose, and res_ver is the only bound
//     this schema states in a shape a Comparer can read.
//   - cve_score is a BARE CVSS NUMBER with no vector string anywhere
//     alongside it (measured 2026-08-26: 0% carry one). See buildAdvisories'
//     own doc comment for why this is dropped rather than stored.
type row struct {
	CVEID  string `json:"cve_id"`
	Pkg    string `json:"pkg"`
	ResVer string `json:"res_ver"`
	Status string `json:"status"`
}

// cveIDPattern is Photon's own CVE spelling, matched anchored (not searched)
// against the WHOLE cve_id field -- measured 2026-08-26: 99.58% of rows
// across all three majors match exactly. Four digits for the year, four or
// more for the sequence number, the same shape fedora.cveRegex uses for its
// (searched, not anchored) free-text extraction.
var cveIDPattern = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)

// idClass is which of Photon's three cve_id shapes one row carries.
type idClass int

const (
	idCVE idClass = iota
	// idBDSA is Broadcom/VMware's own private advisory id ("BDSA-2025-0719")
	// -- 783 rows measured 2026-08-26 (207 in the 4.0 feed, 576 in 5.0's),
	// none carrying a CVE anywhere else in the row. Dropped rather than
	// stored under its own namespace: D25's cross-source grouping joins on a
	// shared identifier, and a BDSA id is not one any other database in this
	// project's store ever names, so a "BDSA" advisory would sit permanently
	// unjoinable and unreachable by anything but its own bare id. There is
	// also no public URL a reader could follow to verify one, unlike a CVE.
	idBDSA
	// idSentinel is everything else -- garbled or placeholder ids ("Re",
	// "UNK-1", "UNK-2"; 17 rows measured 2026-08-26, all status=Not
	// Affected, and dropped anyway by the Not-Affected rule below even
	// before this classification runs). Kept as its own class rather than
	// folded into idBDSA so Fetch's summary counts the two hazards
	// separately -- they have different upstream causes and a reader
	// deciding whether to file an upstream bug report needs to know which.
	idSentinel
)

func classifyID(id string) idClass {
	switch {
	case cveIDPattern.MatchString(id):
		return idCVE
	case strings.HasPrefix(id, "BDSA-"):
		return idBDSA
	default:
		return idSentinel
	}
}

// pkgKey identifies one (CVE, package) pair within a SINGLE Photon major --
// the granularity the Fixed-wins policy (policy 1) resolves at. Measured
// per-major, not globally: a key's Fixed/Not-Affected rows in the 3.0 feed
// say nothing about whether the same (cve, pkg) is fixed, unaffected, or
// absent in the 4.0 feed -- each major is its own independent statement.
type pkgKey struct {
	CVE string
	Pkg string
}

// majorResult is what processMajor hands back: for every (CVE, package) key
// that carried at least one Fixed row in this major, the set of distinct
// res_ver strings seen for it. A key with ONLY Not-Affected rows (or a
// Fixed row whose res_ver could not be used) is absent from this map
// entirely -- Photon's schema has no affected-no-fix state (measured
// 2026-08-26: status is only ever "Fixed" or "Not Affected", never
// anything a fix-less-but-affected range could be built from), so a
// Not-Affected verdict produces no range at all, the same as a key with no
// row for it produces no range at all. The two are indistinguishable to a
// scan, which is correct: neither one says "affected, no fix yet".
type majorResult map[pkgKey]map[string]bool

// processMajor classifies and folds one major's rows into a majorResult,
// applying policy 1 (Fixed wins over Not Affected) and policies 2/3 (BDSA
// and sentinel ids dropped) along the way, and counts every decision into
// st so Fetch's summary line makes the drops visible rather than silent
// (D20's discipline, applied to a provider's own ingestion choices rather
// than to a store-level coverage gap).
//
// Two passes over each key rather than one: a row cannot be classified
// "the Fixed row won" or "this key is Not-Affected only" until every row
// sharing its key has been seen, and Fixed/Not-Affected rows for one key are
// not guaranteed adjacent in the array (measured: they are not sorted by
// key at all).
func processMajor(rows []row, st *stats) majorResult {
	type keyState struct {
		fixed       map[string]bool
		notAffected bool
	}
	states := map[pkgKey]*keyState{}
	order := make([]pkgKey, 0, len(rows))

	for _, r := range rows {
		st.Records++
		switch classifyID(r.CVEID) {
		case idBDSA:
			st.BDSADropped++
			continue
		case idSentinel:
			st.SentinelDropped++
			continue
		}
		if r.Pkg == "" {
			st.SkippedNoPackage++
			continue
		}
		key := pkgKey{CVE: r.CVEID, Pkg: r.Pkg}
		ks, ok := states[key]
		if !ok {
			ks = &keyState{fixed: map[string]bool{}}
			states[key] = ks
			order = append(order, key)
		}
		switch r.Status {
		case "Fixed":
			st.FixedRows++
			if r.ResVer != "" && r.ResVer != "NA" {
				ks.fixed[r.ResVer] = true
			} else {
				// Not observed live (0 of 165,850 Fixed rows measured
				// 2026-08-26), but a Fixed row with nothing to fix TO is not
				// data a Comparer can use either way -- counted rather than
				// fed to advisory.Event.Fixed as an empty string, which
				// version.InRange would read as an unbounded-fixed range
				// (every version affected forever) rather than the "no
				// usable answer" this actually is.
				st.SkippedUnusableFixed++
			}
		case "Not Affected":
			st.NotAffectedRows++
			ks.notAffected = true
		default:
			// Not observed live (status is one of exactly two values on
			// every one of 189,368 rows measured 2026-08-26), kept as a
			// named branch rather than folded into one of the two above:
			// D17's rule applied to a status word instead of a severity one
			// -- an unrecognized value must not be silently read as
			// whichever case happens to run last.
			st.UnrecognizedStatus++
		}
	}

	result := make(majorResult, len(order))
	for _, key := range order {
		ks := states[key]
		if len(ks.fixed) == 0 {
			// Not-Affected only, or a Fixed row with an unusable res_ver:
			// either way this key contributes no advisory entry.
			continue
		}
		if ks.notAffected {
			// Policy 1: Fixed wins. This key's Not-Affected row(s) are
			// dropped -- not stored, not counted as a separate "affected,
			// no fix" state -- but the conflict itself is counted so the
			// choice is visible rather than silent.
			st.FixedWinsConflicts++
		}
		if len(ks.fixed) > 1 {
			// Not one of the three user-decided policies, but real: 14,939
			// (cve, pkg) keys measured 2026-08-26 (almost all in the 5.0
			// feed) carry more than one distinct Fixed res_ver -- e.g. gmp
			// fixed at both "6.2.1-2.ph5" and "6.2.1-5.1.ph5". See
			// buildAdvisories' own doc comment for how these become
			// multiple Range entries rather than a single guessed winner.
			st.MultiFixedVersionKeys++
		}
		result[key] = ks.fixed
	}
	return result
}

// affectedKey identifies one (ecosystem, package) pair inside a merged
// advisory -- the granularity advisory.Affected itself is built at, after
// processMajor's per-major pkgKey has been re-keyed onto a release-qualified
// ecosystem (D6).
type affectedKey struct {
	Ecosystem string
	Pkg       string
}

// buildAdvisories merges every major's processMajor result into one
// advisory.Advisory PER CVE, across ALL majors and packages that carry a
// Fixed verdict for it.
//
// This is the one shape decision the task brief left open ("merge into one
// advisory with several affected entries OR stay separate advisories per
// (cve,pkg)"), and it is forced, not a style choice: the SAME cve_id is
// reused, bare, across Photon's three per-major feed files, with no
// release-specific advisory id anywhere in the schema -- unlike ALAS
// (ALAS2-* vs ALAS2023-*) or FEDORA-* (one alias per Bodhi update), which
// are already unique per release and so never collide. Every advisory in
// this store is keyed on Advisory.ID in a last-writer-wins bucket (D90) --
// emitting one "PHOTON-"+cve record per major, or per (major, pkg), would
// silently clobber all but the last one written for any CVE fixed in more
// than one major or more than one package: measured 2026-08-26, 5,865 of
// 14,341 CVEs with at least one Fixed verdict span more than one Photon
// major, and every multi-package CVE would collide the same way at
// (cve, pkg) granularity. Merging globally before ANY advisory is built
// avoids the hazard by construction rather than by getting emission order
// right -- the same fix D90 made for Red Hat/SUSE colliding on each
// OTHER's records, applied here to one provider colliding with ITSELF.
//
// A (CVE, package) pair carrying more than one distinct Fixed res_ver
// (processMajor's MultiFixedVersionKeys, 14,939 measured) becomes MULTIPLE
// Range entries on one Affected, each {introduced:"0", fixed:v} -- the exact
// shape redhat.convert's own fixed[k] loop uses for a package fixed at
// different EVRs on different point releases sharing one ecosystem key.
// version.AffectsVersion evaluates a package's Ranges with OR semantics (any
// range that reports a hit wins), and every range here starts at
// introduced="0", so this is equivalent to comparing against the single
// HIGHEST fixed version without this package ever needing to run a
// comparison itself -- multiple ranges were chosen over pre-computing a max
// specifically so ingestion stays comparer-free, matching every other
// provider in this project (D9's per-ecosystem Comparer lives in
// internal/version, never inside a provider).
func buildAdvisories(byMajor []majorResult, majorEco []string) []advisory.Advisory {
	merged := map[string]map[affectedKey]map[string]bool{} // cve -> affectedKey -> fixed version set
	cveOrder := make([]string, 0, 16384)
	seenCVE := map[string]bool{}

	for i, mr := range byMajor {
		eco := majorEco[i]
		for key, fixed := range mr {
			byAff, ok := merged[key.CVE]
			if !ok {
				byAff = map[affectedKey]map[string]bool{}
				merged[key.CVE] = byAff
			}
			if !seenCVE[key.CVE] {
				seenCVE[key.CVE] = true
				cveOrder = append(cveOrder, key.CVE)
			}
			ak := affectedKey{Ecosystem: eco, Pkg: key.Pkg}
			versions, ok := byAff[ak]
			if !ok {
				versions = map[string]bool{}
				byAff[ak] = versions
			}
			for v := range fixed {
				versions[v] = true
			}
		}
	}

	// Sorted lexically for a deterministic Fetch, the same reasoning
	// redhat.sortedKeys' own doc comment gives: this is a set of identifier
	// and version strings whose only job here is reproducible output, not
	// an ordering a Comparer should be involved in.
	sort.Strings(cveOrder)

	out := make([]advisory.Advisory, 0, len(cveOrder))
	for _, cve := range cveOrder {
		byAff := merged[cve]
		keys := make([]affectedKey, 0, len(byAff))
		for k := range byAff {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			if keys[i].Ecosystem != keys[j].Ecosystem {
				return keys[i].Ecosystem < keys[j].Ecosystem
			}
			return keys[i].Pkg < keys[j].Pkg
		})

		affected := make([]advisory.Affected, 0, len(keys))
		for _, k := range keys {
			versions := sortedStrings(byAff[k])
			ranges := make([]advisory.Range, 0, len(versions))
			for _, v := range versions {
				ranges = append(ranges, advisory.Range{
					Type:   advisory.RangeEcosystem,
					Events: []advisory.Event{{Introduced: "0"}, {Fixed: v}},
				})
			}
			affected = append(affected, advisory.Affected{
				Ecosystem: k.Ecosystem,
				Name:      k.Pkg,
				Ranges:    ranges,
			})
		}

		out = append(out, advisory.Advisory{
			// D90: prefixed, following REDHAT-CVE-*/SUSE-CVE-*/DEBIAN-CVE-*'s
			// convention (redhat/csaf.go's own comment on its identical
			// "ID:" line) -- the bare cve_id is what every OTHER provider in
			// this store might also key a record on (Red Hat's CSAF VEX
			// prefixes it the same way, but a database built before D90
			// shipped, or a third distro CSAF feed added later without the
			// lesson, would collide on the bare CVE the same way Red
			// Hat/SUSE once did). Aliases carries the bare CVE so D25's
			// cross-source grouping (matcher.identifiers, which reads
			// ID+Aliases) still joins this record with NVD/EPSS/KEV/KISA
			// ratings and with any other database's record for the same
			// CVE. PHOTON-CVE-2026-1234 containing CVE-2026-1234 as a
			// substring is a KNOWN collision shape for a test fixture
			// (CLAUDE.md's substring-assertion rule) -- covered by using
			// distinct, non-nesting CVE numbers across test cases rather
			// than asserting Contains on either the ID or the alias alone.
			ID:       "PHOTON-" + cve,
			Database: "PHOTON",
			Aliases:  []string{cve},
			Source:   SourceName,
			Kind:     advisory.KindVulnerability,
			Affected: affected,
			// No Summary: the feed carries no title, description, or any
			// other prose field at all (measured 2026-08-26).
			//
			// No Severity: cve_score is a bare CVSS NUMBER with no vector
			// string anywhere alongside it (measured 2026-08-26: 0% of rows
			// carry one). internal/severity's Of() derives a band from a
			// stored CVSS VECTOR (D13), never from a bare number, and
			// inventing one (e.g. "the score alone implies base metrics
			// AV:N/AC:L/...") is exactly what this project's escape-hatch
			// rule against guessing forbids -- there is no vector to invent
			// it from, unlike a source that carries a partial one.
			// internal/provider/knvd (KISA) is the precedent this follows:
			// it carries no CVSS vector of its own at all and stores no
			// Severity for the records it enriches either, leaving the band
			// to arrive through whichever OTHER source (NVD, an OSV
			// advisory, ...) rates the same CVE and joins through this
			// record's Aliases (D25). A finding whose only Photon-side data
			// is a fixed version and no other source has rated its CVE
			// reports Unknown, which is the honest answer D17 requires --
			// not a fabricated band, and not a dropped finding either.
		})
	}
	return out
}

func sortedStrings(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// stats accumulates what one Fetch discarded or merged, for Options.Progress
// -- the same discipline amazon.stats, oracle.stats and fedora.stats exist
// for: a provider that quietly drops part of its input looks exactly like
// one that is broken.
type stats struct {
	Records               int
	BDSADropped           int
	SentinelDropped       int
	SkippedNoPackage      int
	SkippedUnusableFixed  int
	UnrecognizedStatus    int
	FixedRows             int
	NotAffectedRows       int
	FixedWinsConflicts    int
	MultiFixedVersionKeys int
	Advisories            int
}

func (s stats) String() string {
	return fmt.Sprintf(
		"%d record(s) across every major -> %d advisories; %d Fixed rows, %d Not-Affected rows; "+
			"dropped %d BDSA-* record(s) (no CVE, no public URL, D25 cannot join them), "+
			"%d with a garbled/sentinel id, %d with no package name, %d Fixed rows with no usable res_ver; "+
			"%d row(s) carried a status other than Fixed/Not Affected; "+
			"%d (cve,pkg,major) key(s) carried both Fixed and Not-Affected rows (Fixed won); "+
			"%d key(s) carried more than one distinct fixed version",
		s.Records, s.Advisories, s.FixedRows, s.NotAffectedRows,
		s.BDSADropped, s.SentinelDropped, s.SkippedNoPackage, s.SkippedUnusableFixed,
		s.UnrecognizedStatus, s.FixedWinsConflicts, s.MultiFixedVersionKeys)
}
