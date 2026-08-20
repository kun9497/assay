package fedora

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/kun9497/assay/internal/advisory"
)

// bodhiPage is one page of Bodhi's updates REST API
// (GET .../updates/?status=stable&type=security&releases=F43&page=N).
type bodhiPage struct {
	Updates []bodhiUpdate `json:"updates"`
	Page    int           `json:"page"`
	Pages   int           `json:"pages"`
	Total   int           `json:"total"`
}

type bodhiUpdate struct {
	// Alias is the update's own id ("FEDORA-2026-abcdef1234"), the field
	// name the research this slice shipped from names directly: vunnel
	// "keys by FEDORA-* alias" when an update carries no CVE at all.
	Alias string `json:"alias"`
	Title string `json:"title"`
	// Notes is free-text markdown prose, scanned for CVE ids alongside
	// Title -- hazard #2 in the package doc comment. Bodhi's REST API has
	// no dedicated CVE reference field to prefer over this.
	Notes string `json:"notes"`
	// Severity is Bodhi's own five-word ladder: "urgent", "high", "medium",
	// "low", "unspecified" (measured 2026-08-19, always lowercase in the
	// live feed). "unspecified" is a real value Bodhi returns, not an
	// absent field -- it is deliberately left unrecognized by
	// normalizeSeverityWord below, the same way D74's OVAL parser leaves
	// Oracle's "N/A" unrecognized rather than guessing a band for it (D17).
	Severity string `json:"severity"`
	// Type distinguishes a security update from "bugfix"/"enhancement"/
	// "newpackage" -- the query already asks for type=security, but this is
	// re-checked in convertUpdate as defense in depth, mirroring
	// amazon.convertUpdate's identical re-check of its own type filter.
	Type       string       `json:"type"`
	Release    bodhiRelease `json:"release"`
	Builds     []bodhiBuild `json:"builds"`
	DateStable string       `json:"date_stable"`
}

type bodhiRelease struct {
	Name string `json:"name"`
	// IDPrefix is "FEDORA" for a real Fedora release and "FEDORA-EPEL" for
	// an EPEL one -- EPEL-9's own Version field is literally "9", which is
	// why id_prefix, not version, is what tells the two apart (hazard #1).
	IDPrefix string `json:"id_prefix"`
	Version  string `json:"version"`
}

type bodhiBuild struct {
	// NVR is a Koji SOURCE-package name-version-release string
	// ("openssh-8.7p1-1.fc43"). Epoch is a SEPARATE field, not embedded in
	// this string (measured 2026-08-19: 6.8% of builds carry a nonzero
	// one) -- rpmEVR below is what reassembles the two.
	NVR   string `json:"nvr"`
	Epoch *int   `json:"epoch"`
	// Type is "rpm" on every build measured 2026-08-19. Read and checked in
	// buildAffected rather than assumed, the same defensive posture
	// oval.go's own doc comment takes toward Oracle's criteria tree: a
	// future container/module/flatpak build type must not be judged
	// against ordinary RPM version ordering.
	Type string `json:"type"`
}

// cveRegex matches a CVE id anywhere in free text. Four digits for the
// year, four OR MORE for the sequence number -- CVE-2014-0001-style
// short ids and the newer CVE-2017-1000001-style long ones both match.
var cveRegex = regexp.MustCompile(`CVE-[0-9]{4}-[0-9]{4,}`)

// extractCVEs scans title then notes for CVE ids, deduplicated in
// first-seen order. There is no structured field to prefer (see bodhiUpdate
// doc comments) -- this IS the whole of hazard #2's extraction, not a
// fallback beneath one.
func extractCVEs(title, notes string) []string {
	var out []string
	seen := map[string]bool{}
	for _, s := range []string{title, notes} {
		for _, m := range cveRegex.FindAllString(s, -1) {
			if seen[m] {
				continue
			}
			seen[m] = true
			out = append(out, m)
		}
	}
	return out
}

// severityWordCanon maps Bodhi's own lowercase severity words to the
// Title-case spelling stored in the advisory and, for "medium"/"low", the
// spelling internal/severity.vendorSeverityWords already keys on.
//
// "urgent" and "high" are Bodhi's OWN vocabulary, not RHSA's -- Bodhi has no
// word spelled "Critical" or "Important" at all. Renaming "urgent" to
// "Critical" at ingestion would misattribute an assertion Bodhi never made
// in those words to a different vendor's convention; instead
// internal/severity's vendorSeverityWords map gained two new entries
// ("Urgent", "High") alongside the existing RHSA ones, so the STORED word
// stays exactly what Fedora's packager wrote while still banding to the
// same ordinal place (Critical/High respectively) that severity.Highest
// compares against a mix of every other source's ratings.
//
// "unspecified" has no entry on purpose (D17): it is Bodhi's own "nobody
// set a severity" value, not a band, and coercing it to one would be
// exactly the guess D17 forbids -- those updates carry no vector either and
// band Unknown until the NVD join rates their CVE.
var severityWordCanon = map[string]string{
	"urgent": "Urgent",
	"high":   "High",
	"medium": "Medium",
	"low":    "Low",
}

// normalizeSeverityWord folds s to lowercase and looks it up in
// severityWordCanon. A word not in the table -- "unspecified", or anything
// Bodhi has not been measured to send -- is left unrecognized rather than
// guessed at (D17): convertUpdate then stores no severity entry for it and
// counts it in stats.UnrecognizedSeverity.
func normalizeSeverityWord(s string) (string, bool) {
	canon, ok := severityWordCanon[strings.ToLower(strings.TrimSpace(s))]
	return canon, ok
}

// databaseOf reads the record's own namespace off its alias
// ("FEDORA-2026-abcdef1234" -> "FEDORA"), the identical convention
// amazon.databaseOf and oracle.databaseOf use (D25). An EPEL update's alias
// would read as "FEDORA-EPEL" here, which is one more reason the id_prefix
// guard in fetchRelease drops it before convertUpdate is ever reached.
func databaseOf(id string) string {
	i := strings.Index(id, "-")
	if i <= 0 {
		return id
	}
	return id[:i]
}

// fedoraDateLayouts covers the shapes date_stable is expected to take.
// "2006-01-02 15:04:05" (no 'T', no offset) is the ordinary Python
// datetime str() rendering and the shape amazon's own ALAS feed uses for
// the identical reason (both are yum-tooling-adjacent APIs); the other two
// are defensive fallbacks in case Bodhi's JSON serializer renders it as a
// proper ISO 8601 timestamp instead -- unverified beyond the research's
// "date_stable present on all but 2" note, so failing closed to a later
// layout rather than a hard-coded single format is the safer assumption
// where the exact wire shape was not directly observed.
var fedoraDateLayouts = []string{
	"2006-01-02 15:04:05",
	time.RFC3339,
	"2006-01-02T15:04:05",
}

// updateWhen parses date_stable, or the zero value if it is empty or
// unparseable. Computed even for an update convertUpdate goes on to skip,
// so one bad or filtered record does not cost the release's freshness
// reading (D12).
func updateWhen(u bodhiUpdate) time.Time {
	if u.DateStable == "" {
		return time.Time{}
	}
	for _, layout := range fedoraDateLayouts {
		if t, err := time.Parse(layout, u.DateStable); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

// parseNVR splits a Koji NVR string into name, version, release. RPM
// version and release fields never contain '-' by construction, so
// splitting from the right at the last two hyphens is exact, not a
// heuristic: measured 2026-08-19 across 4,835 real builds, 0 malformed.
func parseNVR(nvr string) (name, version, release string, ok bool) {
	nvr = strings.TrimSpace(nvr)
	i := strings.LastIndexByte(nvr, '-')
	if i <= 0 || i == len(nvr)-1 {
		return "", "", "", false
	}
	release = nvr[i+1:]
	rest := nvr[:i]
	j := strings.LastIndexByte(rest, '-')
	if j <= 0 || j == len(rest)-1 {
		return "", "", "", false
	}
	version = rest[j+1:]
	name = rest[:j]
	if name == "" || version == "" || release == "" {
		return "", "", "", false
	}
	return name, version, release, true
}

// rpmEVR renders epoch:version-release, omitting the epoch when it is nil
// or zero -- the same convention amazon.rpmEVR uses for the identical
// reason: rpmdb/header.go's own evr() and every other RPM-family provider's
// fixed strings omit a zero epoch, and Bodhi's epoch field being present
// and explicit (unlike an absent one) must not turn into a "0:" prefix no
// other source ever prints.
func rpmEVR(epoch *int, version, release string) string {
	v := version + "-" + release
	if epoch != nil && *epoch != 0 {
		return fmt.Sprintf("%d:%s", *epoch, v)
	}
	return v
}

// buildAffected turns one update's builds into one advisory.Affected per
// distinct SOURCE package name. Unlike amazon's updateinfo pkglist (which
// enumerates every binary subpackage across every arch), Bodhi's builds[]
// names only the SOURCE build Koji produced -- one entry per source
// package, no arch fan-out -- which is exactly why D8's Package.Source
// lookup is mandatory for this provider: 93.7% of a real release's security
// updates ship more than one distinct binary subpackage name, none of which
// appear here at all.
func buildAffected(builds []bodhiBuild, ecosystem string, st *stats) []advisory.Affected {
	order := make([]string, 0, len(builds))
	type parsed struct {
		version, release string
		epoch            *int
	}
	byName := map[string]parsed{}
	for _, b := range builds {
		st.Packages++
		if b.Type != "" && !strings.EqualFold(b.Type, "rpm") {
			st.SkippedNonRPMBuild++
			continue
		}
		name, version, release, ok := parseNVR(b.NVR)
		if !ok {
			st.SkippedBadNVR++
			continue
		}
		if _, dup := byName[name]; dup {
			continue
		}
		byName[name] = parsed{version, release, b.Epoch}
		order = append(order, name)
	}
	affected := make([]advisory.Affected, 0, len(order))
	for _, name := range order {
		pb := byName[name]
		affected = append(affected, advisory.Affected{
			Ecosystem: ecosystem,
			Name:      name,
			Ranges: []advisory.Range{{
				Type: advisory.RangeEcosystem,
				Events: []advisory.Event{
					{Introduced: "0"},
					{Fixed: rpmEVR(pb.epoch, pb.version, pb.release)},
				},
			}},
		})
	}
	return affected
}

// convertUpdate turns one Bodhi update into an advisory.Advisory. when is
// the update's own updateWhen, returned even when ok is false so the
// release's freshness reading does not depend on which updates were kept.
func convertUpdate(u bodhiUpdate, ecosystem string, st *stats) (advisory.Advisory, time.Time, bool) {
	when := updateWhen(u)

	// Defense in depth: the query already asks for type=security, but a
	// future Bodhi change that stopped honouring it must not turn a
	// bugfix/enhancement/newpackage update into a finding with no
	// vulnerability behind it (amazon.convertUpdate's identical re-check).
	if u.Type != "security" {
		st.SkippedNonSecurity++
		return advisory.Advisory{}, when, false
	}
	if u.Alias == "" {
		st.SkippedNoID++
		return advisory.Advisory{}, when, false
	}

	affected := buildAffected(u.Builds, ecosystem, st)
	if len(affected) == 0 {
		st.SkippedNoPackages++
		return advisory.Advisory{}, when, false
	}

	related := extractCVEs(u.Title, u.Notes)
	if len(related) == 0 {
		// Hazard #2, counted rather than silent: the measured ceiling is
		// 81.7% (research, 2026-08-19), so 18.3% of updates carry no
		// extractable CVE anywhere in title+notes. The advisory still
		// emits, reachable by its own FEDORA-* id -- mirroring
		// amazon.TestFetch_NoCVERefsStillEmits's identical proof for ALAS
		// records with no CVE reference at all -- but every such record is
		// tallied here so the miss shows up in Fetch's own summary line
		// rather than only in this package's doc comment.
		st.NoExtractableCVE++
	}

	var sev []advisory.Severity
	if canon, ok := normalizeSeverityWord(u.Severity); ok {
		sev = append(sev, advisory.Severity{Type: "VENDOR_WORD", Score: canon})
	} else {
		st.UnrecognizedSeverity++
	}

	return advisory.Advisory{
		ID:       u.Alias,
		Database: databaseOf(u.Alias),
		// CVE refs are the record's OWN authored identifiers, the same
		// Related placement D71 decision 1 established for AlmaLinux and
		// D73/D74 reused for Amazon Linux and Oracle Linux -- Bodhi carries
		// no aliases or upstream field at all.
		Related:  related,
		Source:   SourceName,
		Kind:     advisory.KindVulnerability,
		Summary:  u.Title,
		Modified: when,
		Affected: affected,
		Severity: sev,
	}, when, true
}
