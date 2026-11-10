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
