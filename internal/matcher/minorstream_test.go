package matcher

import (
	"sort"
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/pkgmeta"
)

// D175, through Match. Fixes are Red Hat's own for the CVE named; want is the
// fix the finding names, "-" for a finding with none, "" for no finding.
func TestMatch_D175_ABuildIsJudgedByItsOwnMinorsFix(t *testing.T) {
	// CVE-2026-1965, curl.
	curl := []string{"0:8.12.1-4.el10_2.3", "0:8.12.1-9.el10_3"}
	// CVE-2024-8088, python3.9: the rebase that follows carries a bare tag.
	python := []string{"0:3.9.18-3.el9_4.5", "0:3.9.19-8.el9"}
	for _, tc := range []struct {
		name, eco, installed string
		fixes                []string
		open                 bool
		want                 string
	}{
		{"carries its minor's fix", "Red Hat:10", "8.12.1-4.el10_2.7", curl, false, ""},
		{"is its minor's fix", "Red Hat:10", "8.12.1-4.el10_2.3", curl, false, ""},
		{"below its minor's fix", "Red Hat:10", "8.12.1-4.el10_2.2", curl, false, "0:8.12.1-4.el10_2.3"},
		{"unfixed build of the next minor", "Red Hat:10", "8.12.1-7.el10_3", curl, false, "0:8.12.1-9.el10_3"},
		{"a minor with no fix of its own", "Red Hat:10", "8.12.1-4.el10_1.9", curl, false, "0:8.12.1-9.el10_3"},
		{"el10_20 is not el10_2", "Red Hat:10", "8.12.1-4.el10_20.7", curl, false, "0:8.12.1-9.el10_3"},
		{"no minor in the release", "Red Hat:10", "8.12.1-8.el10", curl, false, "0:8.12.1-9.el10_3"},
		{"a bare build above a bare fix", "Red Hat:9", "1-5.el9", []string{"0:1-3.el9", "0:1-9.el9_4"}, false, "0:1-9.el9_4"},
		{"a bare fix above it", "Red Hat:9", "3.9.18-3.el9_4.5", python, false, ""},
		{"a bare build is not el9_4's", "Red Hat:9", "3.9.19-1.el9", python, false, "0:3.9.19-8.el9"},
		{"below both fixes of one minor", "Red Hat:9", "1-1.el9_4.1", []string{"0:1-1.el9_4.2", "0:1-1.el9_4.5"}, false, "0:1-1.el9_4.5"},
		{"between two fixes of one minor", "Red Hat:9", "1-1.el9_4.3", []string{"0:1-1.el9_4.2", "0:1-1.el9_4.5", "0:2-1.el9_5"}, false, "0:1-1.el9_4.5"},
		{"still listed as affected", "Red Hat:10", "8.12.1-4.el10_2.7", curl, true, "-"},
		{"another vendor's rebuild", "Rocky Linux:9", "8.12.1-4.el10_2.7", curl, false, "0:8.12.1-9.el10_3"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			aff := advisory.Affected{Ecosystem: tc.eco, Name: "curl"}
			for _, f := range tc.fixes {
				aff.Ranges = append(aff.Ranges, advisory.Range{Type: advisory.RangeEcosystem,
					Events: []advisory.Event{{Introduced: "0"}, {Fixed: f}}})
			}
			if tc.open {
				aff.Ranges = append(aff.Ranges, advisory.Range{Type: advisory.RangeEcosystem,
					Events: []advisory.Event{{Introduced: "0"}}, FixState: advisory.FixStateNotFixed})
			}
			id, ver, _ := strings.Cut(tc.eco, ":")
			s := fakeStore{byKey: map[string][]advisory.Advisory{tc.eco + "\x00curl": {{
				ID: "REDHAT-CVE-2026-1965", Database: "REDHAT", Kind: advisory.KindVulnerability, Affected: []advisory.Affected{aff}}}}}
			res, err := New(s).Match(pkgmeta.Target{
				Distro:   &pkgmeta.Distro{ID: map[string]string{"Red Hat": "rhel", "Rocky Linux": "rocky"}[id], VersionID: ver},
				Packages: []pkgmeta.Package{{Name: "curl", Version: tc.installed, Type: "rpm", Ecosystem: tc.eco}},
			})
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, f := range res.Findings {
				fix := f.Evidence.Fixed
				if fix == "" {
					fix = "-"
				}
				got = append(got, fix)
			}
			sort.Strings(got)
			if strings.Join(got, " ") != tc.want {
				t.Errorf("%s: findings %v, want %q", tc.installed, got, tc.want)
			}
			if len(res.Skipped) != 0 {
				t.Errorf("skipped %v", res.Skipped)
			}
		})
	}
}

// An open range is not a fix of the installed minor, so it takes no fixed range
// away: the reason still names the build the record released (D163).
func TestMatch_D175_AnOpenRangeNamesNoMinor(t *testing.T) {
	s := fakeStore{byKey: map[string][]advisory.Advisory{"Red Hat:10\x00curl": {{
		ID: "REDHAT-CVE-2026-1", Database: "REDHAT", Kind: advisory.KindVulnerability, Affected: []advisory.Affected{{
			Ecosystem: "Red Hat:10", Name: "curl", Ranges: []advisory.Range{
				{Type: advisory.RangeEcosystem, Events: []advisory.Event{{Introduced: "0"}, {Fixed: "0:8.12.1-4.el10_2.3"}}},
				{Type: advisory.RangeEcosystem, Events: []advisory.Event{{Introduced: "0"}}, FixState: advisory.FixStateNotFixed},
			}}}}}}}
	res, err := New(s).Match(pkgmeta.Target{
		Distro:   &pkgmeta.Distro{ID: "rhel", VersionID: "10"},
		Packages: []pkgmeta.Package{{Name: "curl", Version: "8.12.1-9.el10_3", Type: "rpm", Ecosystem: "Red Hat:10"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 || !strings.Contains(res.Findings[0].Evidence.Reason, "released fix 0:8.12.1-4.el10_2.3") {
		t.Errorf("findings %+v, want one naming the released fix", res.Findings)
	}
}

// The version whose minor counts is the one compared: a binary judged under
// its source's name is judged on the source's build.
func TestMatch_D175_TheSourceBuildsMinorCounts(t *testing.T) {
	aff := advisory.Affected{Ecosystem: "Red Hat:9", Name: "src"}
	for _, f := range []string{"0:1-4.el9_2.3", "0:1-9.el9_3"} {
		aff.Ranges = append(aff.Ranges, advisory.Range{Type: advisory.RangeEcosystem,
			Events: []advisory.Event{{Introduced: "0"}, {Fixed: f}}})
	}
	s := fakeStore{byKey: map[string][]advisory.Advisory{"Red Hat:9\x00src": {{
		ID: "REDHAT-CVE-2026-1", Database: "REDHAT", Kind: advisory.KindVulnerability, Affected: []advisory.Affected{aff}}}}}
	for src, want := range map[string]int{"1-4.el9_2.7": 0, "1-4.el9_1.7": 1} {
		res, err := New(s).Match(pkgmeta.Target{
			Distro: &pkgmeta.Distro{ID: "rhel", VersionID: "9"},
			Packages: []pkgmeta.Package{{Name: "bin", Version: "7-1.el9", Type: "rpm", Ecosystem: "Red Hat:9",
				Source: &pkgmeta.SourcePackage{Name: "src", Version: src}}},
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Findings) != want {
			t.Errorf("source %s: %d findings, want %d", src, len(res.Findings), want)
		}
	}
}
