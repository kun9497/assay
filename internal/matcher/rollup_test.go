package matcher

import (
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/pkgmeta"
)

const rollEco = "Ubuntu:22.04:LTS"

func rollRec(id, fixed string, upstream ...string) advisory.Advisory {
	ev := []advisory.Event{{Introduced: "0"}}
	if fixed != "" {
		ev = append(ev, advisory.Event{Fixed: fixed})
	}
	return advisory.Advisory{ID: id, Database: strings.SplitN(id, "-", 2)[0], Kind: advisory.KindVulnerability, Upstream: upstream,
		Affected: []advisory.Affected{{Ecosystem: rollEco, Name: "openssl", Ranges: []advisory.Range{{Type: "ECOSYSTEM", Events: ev}}}}}
}

func keyed(advs []advisory.Advisory) map[string][]advisory.Advisory {
	return map[string][]advisory.Advisory{rollEco + string(rune(0)) + "openssl": advs}
}

// QA 2026-11-20, D172. A notice whose every CVE is reported for the package
// is not a second finding; one that says anything more stays.
func TestMatch_ANoticeIsFoldedOnlyWhenNothingIsLost(t *testing.T) {
	a := rollRec("UBUNTU-CVE-2023-1", "2.0", "CVE-2023-1")
	b := rollRec("UBUNTU-CVE-2023-2", "2.0", "CVE-2023-2")
	bNoFix := rollRec("UBUNTU-CVE-2023-2", "", "CVE-2023-2")
	bNotHit := rollRec("UBUNTU-CVE-2023-2", "0.5", "CVE-2023-2")
	usn := rollRec("USN-1-1", "2.0", "CVE-2023-1", "CVE-2023-2", "UBUNTU-CVE-2023-1", "UBUNTU-CVE-2023-2")
	usn2 := rollRec("USN-2-1", "2.0", "UBUNTU-CVE-2023-1")
	usnOpen := rollRec("USN-1-1", "", "CVE-2023-1", "CVE-2023-2")
	for _, tc := range []struct {
		name string
		advs []advisory.Advisory
		want string // findings, with notices
	}{
		{"every CVE reported", []advisory.Advisory{usn, a, b}, "UBUNTU-CVE-2023-1[USN-1-1] UBUNTU-CVE-2023-2[USN-1-1]"},
		{"two notices", []advisory.Advisory{a, b, usn2, usn}, "UBUNTU-CVE-2023-1[USN-1-1 USN-2-1] UBUNTU-CVE-2023-2[USN-1-1]"},
		{"one CVE has no record", []advisory.Advisory{usn, a}, "UBUNTU-CVE-2023-1[] USN-1-1[]"},
		{"one CVE does not match", []advisory.Advisory{usn, a, bNotHit}, "UBUNTU-CVE-2023-1[] USN-1-1[]"},
		{"one CVE's finding has no fix", []advisory.Advisory{usn, a, bNoFix}, "UBUNTU-CVE-2023-1[] UBUNTU-CVE-2023-2[] USN-1-1[]"},
		{"the notice has no fix either", []advisory.Advisory{usnOpen, a, bNoFix}, "UBUNTU-CVE-2023-1[USN-1-1] UBUNTU-CVE-2023-2[USN-1-1]"},
		{"it names no CVE", []advisory.Advisory{rollRec("USN-3-1", "2.0"), a}, "UBUNTU-CVE-2023-1[] USN-3-1[]"},
		{"it names something else too", []advisory.Advisory{rollRec("USN-4-1", "2.0", "CVE-2023-1", "LP-1"), a}, "UBUNTU-CVE-2023-1[] USN-4-1[]"},
		{"another record naming the CVE upstream is not its finding", []advisory.Advisory{usn2, rollRec("USN-5-1", "2.0", "CVE-2023-1", "CVE-2023-9")}, "USN-2-1[] USN-5-1[]"},
		{"an errata is not a notice", []advisory.Advisory{rollRec("ALAS-1", "2.0", "CVE-2023-1"), a}, "ALAS-1[] UBUNTU-CVE-2023-1[]"},
		{"DSA", []advisory.Advisory{rollRec("DSA-1-1", "2.0", "DEBIAN-CVE-2023-1"), rollRec("DEBIAN-CVE-2023-1", "2.0")}, "DEBIAN-CVE-2023-1[DSA-1-1]"},
		{"DLA", []advisory.Advisory{rollRec("DLA-1-1", "2.0", "CVE-2023-1"), rollRec("DEBIAN-CVE-2023-1", "2.0")}, "DEBIAN-CVE-2023-1[DLA-1-1]"},
	} {
		st := fakeStore{byKey: keyed(tc.advs)}
		res, err := New(st).Match(pkgmeta.Target{Packages: []pkgmeta.Package{{Name: "openssl", Version: "1.0", Type: "deb", Ecosystem: rollEco}}})
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, f := range res.Findings {
			got = append(got, f.Advisory.ID+"["+strings.Join(f.Notices, " ")+"]")
		}
		if s := strings.Join(dedupSorted(got), " "); s != tc.want {
			t.Errorf("%s: %s, want %s", tc.name, s, tc.want)
		}
	}
}

// A CVE reported for one package covers no other package's notice.
func TestMatch_ANoticeIsFoldedPerPackage(t *testing.T) {
	usn := rollRec("USN-1-1", "2.0", "CVE-2023-1")
	a := rollRec("UBUNTU-CVE-2023-1", "0.9", "CVE-2023-1")
	res, err := New(fakeStore{byKey: keyed([]advisory.Advisory{usn, a})}).Match(pkgmeta.Target{Packages: []pkgmeta.Package{
		{Name: "openssl", Version: "0.5", Type: "deb", Ecosystem: rollEco},
		{Name: "openssl", Version: "1.0", Type: "deb", Ecosystem: rollEco},
	}})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, f := range res.Findings {
		got = append(got, f.Package.Version+":"+f.Advisory.ID)
	}
	if s := strings.Join(dedupSorted(got), " "); s != "0.5:UBUNTU-CVE-2023-1 1.0:USN-1-1" {
		t.Errorf("findings %s", s)
	}
}

// A kept notice bundles its CVEs: one CVE's waiver leaves the others standing.
func TestMatch_AKeptNoticeBundlesItsCVEs(t *testing.T) {
	res, err := New(fakeStore{byKey: keyed([]advisory.Advisory{rollRec("USN-1-1", "2.0", "CVE-2023-1", "CVE-2023-2")})}).
		Match(pkgmeta.Target{Packages: []pkgmeta.Package{{Name: "openssl", Version: "1.0", Type: "deb", Ecosystem: rollEco}}})
	if err != nil || len(res.Findings) != 1 {
		t.Fatalf("%d findings, %v", len(res.Findings), err)
	}
	if got := strings.Join(res.Findings[0].Bundled, " "); got != "CVE-2023-1 CVE-2023-2" {
		t.Errorf("Bundled = %q, want both CVEs", got)
	}
}
