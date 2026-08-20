package amazon

import (
	"encoding/xml"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/kun9497/assay/internal/advisory"
)

// repomdXML is the handful of repomd.xml that Fetch needs: which file
// carries updateinfo. Every other <data type="..."> entry (primary,
// filelists, other, group, ...) is read and discarded by encoding/xml
// because Data has no matching case for it -- there is no allowlist to keep
// in sync as Amazon adds metadata types.
type repomdXML struct {
	XMLName xml.Name     `xml:"repomd"`
	Data    []repomdData `xml:"data"`
}

type repomdData struct {
	Type     string `xml:"type,attr"`
	Location struct {
		Href string `xml:"href,attr"`
	} `xml:"location"`
}

// xmlUpdates is the yum "updateinfo" schema's root element -- the same shape
// CentOS, Fedora and Rocky's own repos publish, verified directly against
// AL2 and AL2023's live feeds 2026-08-19 (both cdn.amazonlinux.com
// core/updateinfo.xml.gz).
type xmlUpdates struct {
	XMLName xml.Name    `xml:"updates"`
	Updates []xmlUpdate `xml:"update"`
}

type xmlUpdate struct {
	// Type is "security" on every core advisory measured (2,320/2,320 AL2,
	// 2,010/2,010 AL2023) but read and checked anyway rather than assumed:
	// yum updateinfo also carries "bugfix" and "enhancement" types on other
	// repos, the same distinction AlmaLinux's ALBA/ALEA namespaces draw, and
	// a non-security entry names no vulnerability at all.
	Type string `xml:"type,attr"`
	// Severity is a CHILD ELEMENT ("<severity>Important</severity>"), not an
	// attribute -- verified directly against both live feeds. AL2 spells all
	// four words lowercase, AL2023 capitalizes them; normalizeSeverityWord
	// reconciles both into the one casing severity.vendorSeverityWords keys
	// on.
	ID         string         `xml:"id"`
	Title      string         `xml:"title"`
	Issued     xmlDate        `xml:"issued"`
	Updated    xmlDate        `xml:"updated"`
	Severity   string         `xml:"severity"`
	References []xmlReference `xml:"references>reference"`
	PkgList    []xmlPackage   `xml:"pkglist>collection>package"`
}

type xmlDate struct {
	Date string `xml:"date,attr"`
}

type xmlReference struct {
	Type string `xml:"type,attr"`
	ID   string `xml:"id,attr"`
}

type xmlPackage struct {
	Name    string `xml:"name,attr"`
	Epoch   string `xml:"epoch,attr"`
	Version string `xml:"version,attr"`
	Release string `xml:"release,attr"`
}

// alasDateLayout is the format both issued and updated dates use in the live
// feed ("2018-01-11 21:05:00") -- no timezone marker, read as UTC like every
// other upstream timestamp this project stores (D12).
const alasDateLayout = "2006-01-02 15:04:05"

// latestDate returns the later of an update's issued and updated dates, or
// the zero value if neither parses. Computed even for an update convertUpdate
// goes on to skip (a non-security entry, say), so one bad record does not
// cost the repo's freshness reading (D12) -- repomd's own <revision> is not a
// substitute; it is a build timestamp for the repo tooling, and the research
// this slice shipped from measured it lagging the advisories' own issued
// dates by days on a live feed.
func latestDate(u xmlUpdate) time.Time {
	var best time.Time
	for _, s := range []string{u.Issued.Date, u.Updated.Date} {
		if s == "" {
			continue
		}
		t, err := time.Parse(alasDateLayout, s)
		if err != nil {
			continue
		}
		t = t.UTC()
		if t.After(best) {
			best = t
		}
	}
	return best
}

// databaseOf reads the record's own namespace off its ALAS id
// ("ALAS2-2018-939" -> "ALAS2", "ALAS2023-2023-001" -> "ALAS2023"),
// mirroring osv.databaseOf's identical convention (D25). The two AL
// generations already spell different prefixes, so this single rule tells
// them apart with no extra field.
func databaseOf(id string) string {
	i := strings.Index(id, "-")
	if i <= 0 {
		return id
	}
	return id[:i]
}

// severityWordCanon maps every casing Amazon Linux's feed uses to the
// canonical spelling severity.vendorSeverityWords keys on (D72's convention,
// extended here). AL2 spells all four words lowercase, AL2023 capitalizes
// them -- measured directly against both live feeds 2026-08-19 -- the same
// four-band vocabulary spelled two ways by two repos of the same distro
// family, not a real ambiguity to preserve. Normalized here, at ingestion,
// so no query path has to know both spellings exist (D16's rule, applied to
// casing rather than a withdrawal). severity.Of itself stays case-sensitive
// on purpose (its own doc comment) -- reconciling the casing is this
// provider's job, not a general relaxation of that rule.
var severityWordCanon = map[string]string{
	"critical":  "Critical",
	"important": "Important",
	"medium":    "Medium",
	"low":       "Low",
}

// normalizeSeverityWord folds s to lowercase and looks it up in
// severityWordCanon, so "critical", "Critical" and "CRITICAL" all resolve
// the same way. A word not in the table is left unrecognized rather than
// guessed at (D17): Convert then stores no severity entry for it, and
// severity.Highest treats an advisory with none as Unknown, same as it
// treats a garbled CVSS vector.
func normalizeSeverityWord(s string) (string, bool) {
	canon, ok := severityWordCanon[strings.ToLower(strings.TrimSpace(s))]
	return canon, ok
}

// rpmEVR renders epoch:version-release, omitting the epoch when it is zero.
// This is the SAME convention rpmdb/header.go's own evr() uses for an
// installed package's version and AlmaLinux/Rocky's OSV archives use for a
// fixed one (D46: "an absent epoch is zero, on both sides") -- Amazon's feed
// always states the epoch attribute explicitly, even when it is "0", so this
// is what reconciles that with the sparser convention the comparer and every
// other RPM-family provider already agree on. Getting this backwards would
// not break comparison (rpm.parseEVR reads an absent epoch as zero either
// way) but WOULD make every Amazon Linux fixed version print "0:" where
// every other source's never does, which is confusing on its own and turns
// out-of-band comparisons against real installed data noisier for no
// benefit.
func rpmEVR(epoch, version, release string) string {
	v := version + "-" + release
	if e, err := strconv.Atoi(epoch); err == nil && e != 0 {
		return fmt.Sprintf("%d:%s", e, v)
	}
	return v
}

// convertUpdate turns one <update> into an advisory.Advisory. when is the
// update's own latestDate, returned even when ok is false so the repo's
// freshness reading does not depend on which updates were kept.
func convertUpdate(u xmlUpdate, ecosystem string, st *stats) (advisory.Advisory, time.Time, bool) {
	when := latestDate(u)

	// Every core update measured is type=security, but the check stays: a
	// non-security entry names no vulnerability, the same reason D72 drops
	// ALBA/ALEA at ingestion rather than storing and filtering them later
	// (D16's rule).
	if u.Type != "security" {
		st.SkippedNonSecurity++
		return advisory.Advisory{}, when, false
	}
	if u.ID == "" {
		st.SkippedNoID++
		return advisory.Advisory{}, when, false
	}

	var related []string
	seenCVE := map[string]bool{}
	for _, ref := range u.References {
		if !strings.EqualFold(ref.Type, "cve") || ref.ID == "" || seenCVE[ref.ID] {
			continue
		}
		seenCVE[ref.ID] = true
		related = append(related, ref.ID)
	}

	affected := buildAffected(u.PkgList, ecosystem, st)
	if len(affected) == 0 {
		st.SkippedNoPackages++
		return advisory.Advisory{}, when, false
	}

	var sev []advisory.Severity
	if canon, ok := normalizeSeverityWord(u.Severity); ok {
		// D72's shape, reused rather than reinvented: a distro record whose
		// only severity signal is a vendor word is stored losslessly as a
		// VENDOR_WORD entry (D13) and banded at query time by
		// internal/severity, never banded here.
		sev = append(sev, advisory.Severity{Type: "VENDOR_WORD", Score: canon})
	} else {
		st.UnrecognizedSeverity++
	}

	return advisory.Advisory{
		ID:       u.ID,
		Database: databaseOf(u.ID),
		// CVE refs are the record's OWN authored identifiers, populated the
		// same way D71 decision 1 populates AlmaLinux's -- ALAS carries no
		// aliases or upstream field at all, only references, so Related is
		// the one place a scan or --explain can reach the CVE from.
		Related:  related,
		Source:   SourceName,
		Kind:     advisory.KindVulnerability,
		Summary:  u.Title,
		Modified: when,
		Affected: affected,
		Severity: sev,
	}, when, true
}

// buildAffected turns one update's package list into one advisory.Affected
// per distinct binary package name.
//
// Deduplicated by name across arch, not preserved per-arch: cross-arch EVR
// divergence was measured at 0 across 43,232 (advisory, name) pairs on both
// live feeds 2026-08-19, so a second entry for the same fixed version under
// a different arch adds nothing a matcher (which does not filter on arch at
// all) could ever use. First occurrence wins deterministically because the
// upstream XML lists arches together for one package, contiguously.
//
// debuginfo and debugsource entries are KEPT, deliberately not filtered
// despite being 13-37% of pkglist entries measured: they are ordinary,
// separately-installable RPM names (a debug-enabled AL2 image can have
// "kernel-debuginfo" installed same as "kernel"), and D8's own lesson is
// that dropping a real binary-package name from Affected is a silent false
// negative, not a size optimization. The corpus is affordable either way
// (medium cost estimate, ~4,330 advisories total) — see the research this
// slice shipped from.
func buildAffected(pkgs []xmlPackage, ecosystem string, st *stats) []advisory.Affected {
	order := make([]string, 0, len(pkgs))
	byName := map[string]xmlPackage{}
	for _, pk := range pkgs {
		st.Packages++
		if pk.Name == "" {
			continue
		}
		if _, ok := byName[pk.Name]; ok {
			continue
		}
		byName[pk.Name] = pk
		order = append(order, pk.Name)
	}
	affected := make([]advisory.Affected, 0, len(order))
	for _, name := range order {
		pk := byName[name]
		affected = append(affected, advisory.Affected{
			Ecosystem: ecosystem,
			Name:      name,
			Ranges: []advisory.Range{{
				Type: advisory.RangeEcosystem,
				Events: []advisory.Event{
					{Introduced: "0"},
					{Fixed: rpmEVR(pk.Epoch, pk.Version, pk.Release)},
				},
			}},
		})
	}
	return affected
}
