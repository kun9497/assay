package arch

import (
	"fmt"
	"regexp"
	"sort"

	"github.com/kun9497/assay/internal/advisory"
)

// row is one AVG (Arch Vulnerability Group) entry in the JSON array
// security.archlinux.org/issues/all.json serves. The feed is a flat array
// of these, no wrapper object, no per-record date field, no nesting beyond
// the two string slices below (measured 2026-08-26 against the live feed,
// 2,444 records) -- unlike Photon's per-major files, there is exactly ONE
// of these across all of Arch.
//
// Two fields the upstream sends and this struct does not decode:
//
//   - severity is a WORD (Critical/High/Medium/Low/Unknown), never a CVSS
//     vector -- see buildAdvisories' own doc comment for why it is read
//     nowhere in this provider.
//   - ticket and advisories carry Arch's own bug-tracker and ASA-advisory
//     cross-references. Neither is a version bound or an identifier D25's
//     cross-source grouping can join through (ASA-YYYYMM-N names an
//     advisory bulletin, not a CVE), so nothing here reads them.
type row struct {
	Name     string   `json:"name"`     // the AVG id, e.g. "AVG-2843"
	Packages []string `json:"packages"` // pacman package names
	Status   string   `json:"status"`   // "Fixed" | "Testing" | "Vulnerable" | anything else (D17)
	// Fixed is a pointer because the feed sends a JSON null, not an absent
	// key or an empty string, when no fix exists -- measured 100% of
	// status=Vulnerable rows (85/85) send null, and 100% of status=Fixed
	// rows (2,151/2,151) send a real string.
	Fixed  *string  `json:"fixed"`
	Issues []string `json:"issues"` // CVE ids, measured 100% CVE-shaped (8,036/8,036) -- verified below anyway
}

// cveIDPattern anchors the same shape photon.cveIDPattern and fedora's own
// extraction regex use: four digits for the year, four or more for the
// sequence number. Matched anchored against the WHOLE issues[] entry, not
// searched, because every entry measured is already a bare CVE id with
// nothing around it to search past -- unlike fedora's free-text extraction.
var cveIDPattern = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)

// buildAdvisories converts every row into zero or one advisory.Advisory,
// applying D97's status policy along the way and counting every decision
// into st (D20's discipline: a provider that quietly drops part of its
// input looks exactly like one that is broken).
//
// One advisory PER GROUP, unlike photon.buildAdvisories' cross-major merge:
// the AVG id (row.Name) is unique across the whole feed (2,444/2,444
// measured 2026-08-26) and never collides with a bare CVE the way a second
// provider keying on the same CVE would (D90) -- "AVG-2843" shares no
// substring shape with "CVE-2026-12345" the way "PHOTON-CVE-2026-12345"
// deliberately does contain its own CVE. So unlike Photon, Amazon Linux's
// ALAS2-*, or Fedora's FEDORA-*, this ID needs no provider prefix at all;
// Database "AVG" is enough to say where it came from.
//
// Status policy (D97, verified against the live feed and vunnel's own
// archlinux parser, which -- unlike this decoder -- branches only on
// "Not affected" and treats every other status as fixed-if-fixed-is-set):
//
//   - "Fixed": fixed is always non-null (measured 2,151/2,151) -> one Range
//     {introduced:"0", fixed:<fixed>}.
//   - "Testing": NOT OBSERVED in the 2026-08-26 capture (0/2,444) -- Arch's
//     own tracker still documents it as a real status (the fix has landed
//     in the testing repository, not yet in the stable one) -- treated
//     identically to "Fixed": the person running the scan can `pacman -S`
//     from testing today, and reporting the package as unfixable would
//     misreport a fix that already exists as though none did.
//   - "Vulnerable": fixed is always null (measured 85/85) -> one fix-less
//     Range {introduced:"0"} with FixState NotFixed -- Arch's own status
//     word IS the positive evidence D52 requires (the tracker distinguishes
//     Vulnerable from Not-affected by construction, not by this provider
//     inferring intent from an absence).
//   - anything else ("Not affected", 193/2,444; "Unknown", 15/2,444; and
//     any future status this build has not measured): skipped and counted,
//     D17's discipline applied to a status word instead of a severity one.
//     "Not affected" is Arch's own explicit "never applied" state, which
//     this provider treats the same as an unrecognized one rather than
//     inventing a record that says nothing.
func buildAdvisories(rows []row) ([]advisory.Advisory, stats) {
	st := stats{OtherStatus: map[string]int{}}
	out := make([]advisory.Advisory, 0, len(rows))

	for _, r := range rows {
		st.Records++
		if r.Name == "" {
			// Not observed live (2,444/2,444 rows carry a name), but a group
			// with no id at all is not one D25's cross-source grouping or a
			// reader's --explain lookup could ever reach.
			st.SkippedNoName++
			continue
		}

		var rng advisory.Range
		switch r.Status {
		case "Fixed", "Testing":
			if r.Fixed == nil || *r.Fixed == "" {
				// Not observed live for either status (0/2,151 Fixed rows
				// carry a null/empty fixed), but a Fixed-or-Testing row with
				// nothing to fix TO is not data a Comparer can use -- counted
				// rather than fed to advisory.Event.Fixed as an empty
				// string, which version.InRange would read as an unbounded
				// range (everything affected forever).
				st.SkippedUnusableFixed++
				continue
			}
			if r.Status == "Fixed" {
				st.FixedRows++
			} else {
				st.TestingRows++
			}
			rng = advisory.Range{
				Type:   advisory.RangeEcosystem,
				Events: []advisory.Event{{Introduced: "0"}, {Fixed: *r.Fixed}},
			}
		case "Vulnerable":
			st.VulnerableRows++
			rng = advisory.Range{
				Type:     advisory.RangeEcosystem,
				Events:   []advisory.Event{{Introduced: "0"}},
				FixState: advisory.FixStateNotFixed,
			}
		default:
			st.OtherStatus[r.Status]++
			continue
		}

		affected := make([]advisory.Affected, 0, len(r.Packages))
		for _, pkg := range r.Packages {
			if pkg == "" {
				// Not observed live (0 empty entries across 2,444 records'
				// packages[]), but an empty name is a lookup key that can
				// only ever miss.
				st.SkippedEmptyPackage++
				continue
			}
			affected = append(affected, advisory.Affected{
				Ecosystem: Ecosystem,
				Name:      pkg,
				Ranges:    []advisory.Range{rng},
			})
		}
		if len(affected) == 0 {
			// Not observed live (every one of 2,444 records carries at
			// least one non-empty package name), but a group with nothing
			// left to attach a range to would otherwise still be emitted as
			// an advisory with zero Affected entries -- indistinguishable
			// from a genuine data-shape bug in a later reader.
			st.SkippedNoUsablePackage++
			continue
		}

		var aliases []string
		for _, issue := range r.Issues {
			if cveIDPattern.MatchString(issue) {
				aliases = append(aliases, issue)
			} else {
				// Not observed live (8,036/8,036 issues[] entries measured
				// CVE-shaped), but D17's discipline applies to a claimed
				// identifier the same way it applies to a claimed severity:
				// verify rather than trust, so a future non-CVE identifier
				// in this field cannot silently become an alias D25 joins
				// the wrong record through.
				st.NonCVEIssueDropped++
			}
		}

		out = append(out, advisory.Advisory{
			ID:       r.Name,
			Database: "AVG",
			Aliases:  aliases,
			Source:   SourceName,
			Kind:     advisory.KindVulnerability,
			Affected: affected,
			// No Severity: the tracker's severity field is a WORD
			// (Critical/High/Medium/Low/Unknown), never a CVSS vector.
			// internal/severity.Of derives a band from a stored vector
			// (D13), never from a word, and inventing a vector from a word
			// is exactly the escape-hatch rule against guessing this
			// project refuses (the same call internal/provider/photon and
			// internal/provider/knvd (KISA) already made for their own
			// vectorless severity signals). A finding whose only Arch-side
			// data is a fixed version and no other source has rated its CVE
			// reports Unknown, which is D17's honest answer -- not a
			// fabricated band, and not a dropped finding either. Bands
			// arrive instead through whichever OTHER source (NVD, an OSV
			// advisory, ...) rates the same CVE and joins through Aliases
			// (D25).
		})
		st.Advisories++
	}

	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, st
}

// stats accumulates what one Fetch discarded, for Options.Progress -- the
// same discipline photon.stats, amazon.stats, oracle.stats and fedora.stats
// exist for.
type stats struct {
	Records                int
	Advisories             int
	FixedRows              int
	TestingRows            int
	VulnerableRows         int
	OtherStatus            map[string]int // status word -> count, for every row this provider drops
	SkippedNoName          int
	SkippedUnusableFixed   int
	SkippedEmptyPackage    int
	SkippedNoUsablePackage int
	NonCVEIssueDropped     int
}

func (s stats) String() string {
	return fmt.Sprintf(
		"%d record(s) -> %d advisories; %d Fixed, %d Testing, %d Vulnerable rows; "+
			"dropped rows by status: %v; %d with no name, %d Fixed/Testing rows with no usable "+
			"fixed version, %d with no usable package name; %d non-CVE issues[] entries dropped",
		s.Records, s.Advisories, s.FixedRows, s.TestingRows, s.VulnerableRows,
		s.OtherStatus, s.SkippedNoName, s.SkippedUnusableFixed, s.SkippedNoUsablePackage,
		s.NonCVEIssueDropped)
}
