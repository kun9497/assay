package matcher

import (
	"slices"
	"testing"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/pkgmeta"
)

// D176, through Match. The fixes are Red Hat's own for libpng, which the feed
// writes without the epoch 2 its builds have; want is the fix the finding
// names, "-" for a finding with none, "" for no finding.
func TestMatch_D176_AFixWithoutAnEpochIsReadAtTheInstalledOne(t *testing.T) {
	for _, tc := range []struct {
		name, eco, installed string
		fixes                []string
		want                 string
	}{
		{"below the fix", "Hummingbird", "2:1.6.56-1.1.hum1", []string{"1.6.58-1.hum1"}, "2:1.6.58-1.hum1"},
		{"at the fix", "Hummingbird", "2:1.6.58-1.hum1", []string{"1.6.58-1.hum1"}, ""},
		{"above the fix", "Hummingbird", "2:1.6.59-1.hum1", []string{"1.6.58-1.hum1"}, ""},
		{"a two-digit epoch", "Hummingbird", "12:1.6.56-1.hum1", []string{"1.6.58-1.hum1"}, "12:1.6.58-1.hum1"},
		{"below a fix with the same epoch", "Hummingbird", "2:1.6.56-1.hum1", []string{"2:1.6.58-1.hum1"}, "2:1.6.58-1.hum1"},
		{"no fix", "Hummingbird", "2:1.6.56-1.hum1", []string{""}, "-"},
		// nodejs24-npm went from epoch 1 to 2, so its fixes are left unsettled.
		{"an epoch the fix states is its own", "Hummingbird", "2:11.11.0-1.hum1", []string{"1:11.19.0-1.hum1"}, ""},
		{"one fix with an epoch, one without", "Hummingbird", "2:11.11.0-1.hum1", []string{"1:11.19.0-1.hum1", "11.12.0-1.hum1"}, "2:11.12.0-1.hum1"},
		{"a build with no epoch", "Hummingbird", "1.6.56-1.1.hum1", []string{"1.6.58-1.hum1"}, "1.6.58-1.hum1"},
		{"a build with no epoch, above the fix", "Hummingbird", "1.6.59-1.hum1", []string{"1.6.58-1.hum1"}, ""},
		{"a build with no epoch under a fix with one", "Hummingbird", "1.6.59-1.hum1", []string{"2:1.6.58-1.hum1"}, "2:1.6.58-1.hum1"},
		{"an epoch of zero", "Hummingbird", "0:1.6.56-1.1.hum1", []string{"1.6.58-1.hum1"}, "1.6.58-1.hum1"},
		{"another key's bare fix is epoch 0", "Red Hat:10", "2:1.6.56-1.1.el10", []string{"1.6.58-1.el10"}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			aff := advisory.Affected{Ecosystem: tc.eco, Name: "libpng"}
			for _, f := range tc.fixes {
				r := advisory.Range{Type: advisory.RangeEcosystem, Events: []advisory.Event{{Introduced: "0"}}}
				if f != "" {
					r.Events = append(r.Events, advisory.Event{Fixed: f})
				}
				aff.Ranges = append(aff.Ranges, r)
			}
			s := fakeStore{byKey: map[string][]advisory.Advisory{tc.eco + "\x00libpng": {{
				ID: "REDHAT-CVE-2026-40930", Database: "REDHAT", Kind: advisory.KindVulnerability, Affected: []advisory.Affected{aff}}}}}
			pkg := pkgmeta.Package{Name: "libpng", Version: tc.installed, Type: "rpm", Ecosystem: tc.eco}
			// Twice: the stored record must not keep the first build's epoch.
			for range 2 {
				res, err := New(s).Match(pkgmeta.Target{Packages: []pkgmeta.Package{pkg}})
				if err != nil {
					t.Fatal(err)
				}
				if len(res.Skipped) != 0 {
					t.Fatalf("skipped %v", res.Skipped)
				}
				got := ""
				if len(res.Findings) > 0 {
					if got = res.Findings[0].Evidence.Fixed; got == "" {
						got = "-"
					}
				}
				if len(res.Findings) > 1 || got != tc.want {
					t.Errorf("%d findings, fix %q; want %q", len(res.Findings), got, tc.want)
				}
			}
			for i, r := range aff.Ranges {
				if fixOf(r) != tc.fixes[i] {
					t.Errorf("stored fix became %q", fixOf(r))
				}
			}
		})
	}
}

// Only a fixed event is rewritten.
func TestReadAtInstalledEpoch_LeavesTheOtherEvents(t *testing.T) {
	aff := advisory.Affected{Ecosystem: "Hummingbird", Ranges: []advisory.Range{{
		Events: []advisory.Event{{Introduced: "0"}, {LastAffected: "1.0-1.hum1"}, {Introduced: "2.0"}, {Fixed: "2.1-1.hum1"}}}}}
	got := readAtInstalledEpoch(aff, "2:1.0-1.hum1").Ranges[0].Events
	want := []advisory.Event{{Introduced: "0"}, {LastAffected: "1.0-1.hum1"}, {Introduced: "2.0"}, {Fixed: "2:2.1-1.hum1"}}
	if !slices.Equal(got, want) {
		t.Errorf("events %+v, want %+v", got, want)
	}
}
