package matcher

import (
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/pkgmeta"
)

// QA 2026-11-10: a skipped advisory carries the CVEs it names, from its ID,
// aliases, upstream and related, deduplicated and sorted, so a reader holding
// a CVE can tell whether the skip is about it.
func TestMatch_SkipCarriesTheAdvisoryCVEs(t *testing.T) {
	bad := advWithRange("ALAS2031-0001", "Go", "x", "0", "not-a-version", advisory.RangeSemver)
	bad.Aliases = []string{"cve-2031-0002", "GHSA-xxxx-yyyy-zzzz"}
	bad.Upstream = []string{"CVE-2031-0001"}
	bad.Related = []string{"CVE-2031-0002", "CVE-2031-0003"}
	plain := advWithRange("GHSA-noid", "Go", "y", "0", "not-a-version", advisory.RangeSemver)
	s := fakeStore{byKey: map[string][]advisory.Advisory{"Go\x00x": {bad}, "Go\x00y": {plain}}}
	res, err := New(s).Match(pkgmeta.Target{Packages: []pkgmeta.Package{pkg("x", "1.0.0", "Go"), pkg("y", "1.0.0", "Go")}})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, sk := range res.Skipped {
		got[sk.AdvisoryID] = strings.Join(sk.CVEs, ",")
	}
	if got["ALAS2031-0001"] != "CVE-2031-0001,CVE-2031-0002,CVE-2031-0003" {
		t.Errorf("ALAS skip CVEs = %q", got["ALAS2031-0001"])
	}
	if got["GHSA-noid"] != "" {
		t.Errorf("an advisory naming no CVE must carry none: %q", got["GHSA-noid"])
	}
}

// The other two skips name their CVEs too, upper-cased (QA 2026-11-20).
func TestMatch_EverySkipCarriesTheAdvisoryCVEs(t *testing.T) {
	list := advWithRange("ALAS-list", "Go", "x", "5.0.0", "6.0.0", advisory.RangeSemver)
	list.Aliases = []string{"cve-2031-0009"}
	list.Affected[0].Versions = []string{"not a version"}
	module := advWithRange("ALAS-module", "Red Hat:9", "m", "0", "1.0-1.module+el9.1.0+1+abc", advisory.RangeEcosystem)
	module.Aliases = []string{"cve-2031-0010"}
	s := fakeStore{byKey: map[string][]advisory.Advisory{
		"Go" + string(rune(0)) + "x":        {list},
		"Red Hat:9" + string(rune(0)) + "m": {module},
	}}
	res, err := New(s).Match(pkgmeta.Target{Packages: []pkgmeta.Package{pkg("x", "1.0.0", "Go"), pkg("m", "0.9-1.el9", "Red Hat:9")}})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, sk := range res.Skipped {
		got[sk.AdvisoryID] = strings.Join(sk.CVEs, ",")
	}
	if got["ALAS-list"] != "CVE-2031-0009" || got["ALAS-module"] != "CVE-2031-0010" {
		t.Errorf("skip CVEs %v, want both named in upper case", got)
	}
}

// A record joining two groups keeps the identifiers of both (QA 2026-11-20).
func TestMatch_AMergeKeepsBothGroupsIdentifiers(t *testing.T) {
	a := advWithRange("GHSA-a", "Go", "x", "0", "2.0.0", advisory.RangeSemver)
	a.Aliases = []string{"CVE-2031-1"}
	b := advWithRange("GHSA-b", "Go", "x", "0", "2.0.0", advisory.RangeSemver)
	b.Aliases = []string{"CVE-2031-2"}
	c := advWithRange("GHSA-c", "Go", "x", "0", "2.0.0", advisory.RangeSemver)
	c.Aliases = []string{"GHSA-a", "GHSA-b"}
	s := fakeStore{byKey: map[string][]advisory.Advisory{"Go" + string(rune(0)) + "x": {a, b, c}}}
	res, err := New(s).Match(pkgmeta.Target{Packages: []pkgmeta.Package{pkg("x", "1.0.0", "Go")}})
	if err != nil || len(res.Findings) != 1 {
		t.Fatalf("%d findings, %v; want one", len(res.Findings), err)
	}
	if got := strings.Join(res.Findings[0].Identifiers, " "); got != "CVE-2031-1 CVE-2031-2 GHSA-a GHSA-b GHSA-c" {
		t.Errorf("identifiers %q", got)
	}
}
