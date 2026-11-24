package matcher

import (
	"testing"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/pkgmeta"
)

// P4 of the 2026-11-20 audit. A second record of the same group that outranks
// the first takes the finding's matched name with it.
func TestMatch_AWinnerSwapCarriesTheMatchedName(t *testing.T) {
	const eco = "Alpaquita:stream"
	own := advWithRange("BELL-1", eco, "bin", "0", "99.0-r0", advisory.RangeEcosystem)
	src := advWithRange("BELL-2", eco, "src", "0", "99.0-r0", advisory.RangeEcosystem)
	own.Aliases, src.Aliases = []string{"CVE-2026-1"}, []string{"CVE-2026-1"}
	p := pkg("bin", "1.0-r0", eco)
	p.Source = &pkgmeta.SourcePackage{Name: "src"}
	for _, tc := range []struct {
		critical *advisory.Advisory
		want     string
	}{{&own, "bin"}, {&src, "src"}} {
		own.Severity, src.Severity = nil, nil
		tc.critical.Severity = []advisory.Severity{{Type: "CVSS_V3", Score: vecCritical}}
		res, err := New(fakeStore{byKey: map[string][]advisory.Advisory{key(eco, "bin"): {own}, key(eco, "src"): {src}}}).
			Match(pkgmeta.Target{Packages: []pkgmeta.Package{p}})
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Findings) != 1 || res.Findings[0].Advisory.ID != tc.critical.ID || res.Findings[0].MatchedName != tc.want {
			t.Errorf("findings %+v, want one by %s via %s", res.Findings, tc.critical.ID, tc.want)
		}
	}
}

// One record is one rating, however many of its entries name the package.
func TestMatch_ARecordRatesAPackageOnce(t *testing.T) {
	const eco = "Alpine:v3.19"
	a := advWithRange("ALPINE-1", eco, "x", "0", "2.0-r0", advisory.RangeEcosystem)
	a.Affected = append(a.Affected, advWithRange("ALPINE-1", eco, "x", "0", "3.0-r0", advisory.RangeEcosystem).Affected...)
	res, err := New(fakeStore{byKey: map[string][]advisory.Advisory{key(eco, "x"): {a}}}).
		Match(pkgmeta.Target{Packages: []pkgmeta.Package{pkg("x", "1.0-r0", eco)}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 || len(res.Findings[0].Ratings) != 1 {
		t.Errorf("findings %+v, want one with one rating", res.Findings)
	}
}

func TestModuleBuildBound_ReadsALimit(t *testing.T) {
	const mod = "1-1.module+el9.6.0+1+a"
	aff := advisory.Affected{Ranges: []advisory.Range{{Events: []advisory.Event{{Introduced: "0"}, {Limit: mod}}}}}
	if got, ok := moduleBuildBound(aff); !ok || got != mod {
		t.Errorf("moduleBuildBound = %q, %v", got, ok)
	}
}
