package amazon

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/version"
)

// D174, through Fetch, with the builds and fixes of the live feeds of
// 2026-11-23. Each row is an installed build and the advisories reported for
// it with the fix each names ("-" for none).
func TestFetch_AL2VersionLinesAreJudgedByTheirOwnRepository(t *testing.T) {
	k := func(v, r string) []pkgFixture { return []pkgFixture{{"kernel", "0", v, r, "x86_64"}} }
	p := func(v, r string) []pkgFixture { return []pkgFixture{{"postgresql", "0", v, r, "x86_64"}} }
	d := func(v, r string) []pkgFixture { return []pkgFixture{{"docker", "0", v, r, "x86_64"}} }
	topics := []string{"kernel-5.4", "kernel-5.10", "postgresql13", "postgresql14", "docker", "ecs", "kernel-ng"}
	mux := http.NewServeMux()
	mountExtrasCatalog(t, mux, topics)
	mountRepo(t, mux, "/core", []updateFixture{
		{id: "ALAS2-1", cves: []string{"CVE-2018-1"}, pkgs: k("4.9.76", "38.79.amzn2")},
		{id: "ALAS2-2", cves: []string{"CVE-2019-25162"}, pkgs: k("4.14.291", "218.527.amzn2")},
		{id: "ALAS2-3", cves: []string{"CVE-2026-1"}, pkgs: k("4.14.355", "287.769.amzn2")},
	})
	for topic, ups := range map[string][]updateFixture{
		"kernel-5.4":   {{id: "ALAS2KERNEL-5.4-1", cves: []string{"CVE-2020-1"}, pkgs: k("5.4.20", "12.75.amzn2")}, {id: "ALAS2KERNEL-5.4-2", cves: []string{"CVE-2026-1"}, pkgs: k("5.4.302", "229.517.amzn2")}},
		"kernel-5.10":  {{id: "ALAS2KERNEL-5.10-1", cves: []string{"CVE-2021-1"}, pkgs: k("5.10.29", "27.126.amzn2")}, {id: "ALAS2KERNEL-5.10-2022-020", cves: []string{"CVE-2019-25162"}, pkgs: k("5.10.144", "127.601.amzn2")}},
		"postgresql13": {{id: "ALAS2POSTGRESQL13-1", cves: []string{"CVE-2022-1552"}, pkgs: p("13.7", "1.amzn2.0.1")}, {id: "ALAS2POSTGRESQL13-2", cves: []string{"CVE-2025-1"}, pkgs: p("13.22", "1.amzn2.0.1")}},
		"postgresql14": {{id: "ALAS2POSTGRESQL14-2023-002", cves: []string{"CVE-2022-1552"}, pkgs: p("14.3", "2.amzn2.0.1")}},
		"docker":       {{id: "ALAS2DOCKER-1", cves: []string{"CVE-1"}, pkgs: d("20.10", "1.amzn2")}, {id: "ALAS2DOCKER-2", cves: []string{"CVE-2"}, pkgs: d("25.0", "1.amzn2")}},
		"ecs":          {{id: "ALAS2ECS-1", cves: []string{"CVE-2"}, pkgs: d("24.0", "1.amzn2")}},
	} {
		mountRepo(t, mux, "/extras/"+topic+"/latest/x86_64", ups)
	}
	mountRepo(t, mux, "/extras/kernel-ng/latest/x86_64", nil)
	server := httptest.NewServer(mux)
	defer server.Close()
	var advs []advisory.Advisory
	var log strings.Builder
	if _, err := New(Options{
		Repos:         []Repo{{Ecosystem: "Amazon Linux:2", MirrorListURL: server.URL + "/core/mirror.list"}},
		ExtrasBaseURL: server.URL, Progress: &log,
	}).Fetch(context.Background(), func(a advisory.Advisory) error { advs = append(advs, a); return nil }); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, installed, want string }{
		// A patched build of each line draws nothing from the others.
		{"kernel", "4.14.355-287.769.amzn2", ""},
		{"kernel", "5.4.302-229.517.amzn2", ""},
		{"kernel", "5.10.144-127.601.amzn2", ""},
		{"postgresql", "13.22-1.amzn2.0.1", ""},
		// An unpatched build draws its own line's advisory and fix. One from
		// before its line's first advisory is in no span and keeps the other
		// line's report too, without its fix.
		{"kernel", "4.14.290-217.505.amzn2", "ALAS2-2=4.14.291-218.527.amzn2 ALAS2-3=4.14.355-287.769.amzn2"},
		{"kernel", "5.4.100-1.amzn2", "ALAS2KERNEL-5.4-2=5.4.302-229.517.amzn2"},
		{"kernel", "5.10.100-1.amzn2", "ALAS2KERNEL-5.10-2022-020=5.10.144-127.601.amzn2"},
		{"postgresql", "13.6-1.amzn2.0.1", "ALAS2POSTGRESQL13-1=13.7-1.amzn2.0.1 ALAS2POSTGRESQL13-2=13.22-1.amzn2.0.1 ALAS2POSTGRESQL14-2023-002=-"},
		{"postgresql", "14.2-1.amzn2.0.1", "ALAS2POSTGRESQL14-2023-002=14.3-2.amzn2.0.1"},
		// A build before its line's first advisory is still its line's.
		{"kernel", "5.10.28-1.amzn2", "ALAS2KERNEL-5.10-1=5.10.29-27.126.amzn2 ALAS2KERNEL-5.10-2022-020=5.10.144-127.601.amzn2"},
		// A line nobody publishes for keeps the reports, without a fix where
		// the gap holds it and with the covering line's where it is in one.
		{"kernel", "4.19.1-1.amzn2", "ALAS2KERNEL-5.10-1=- ALAS2KERNEL-5.10-2022-020=- ALAS2KERNEL-5.4-1=5.4.20-12.75.amzn2 ALAS2KERNEL-5.4-2=5.4.302-229.517.amzn2"},
		// Below everything.
		{"kernel", "4.9.62-10.57.amzn2", "ALAS2-1=4.9.76-38.79.amzn2 ALAS2-2=4.14.291-218.527.amzn2 ALAS2-3=4.14.355-287.769.amzn2 " +
			"ALAS2KERNEL-5.10-1=- ALAS2KERNEL-5.10-2022-020=- ALAS2KERNEL-5.4-1=- ALAS2KERNEL-5.4-2=-"},
		// The ends of a span belong to it, and nothing beside them does.
		{"kernel", "4.9.76-38.79.amzn2", "ALAS2-2=4.14.291-218.527.amzn2 ALAS2-3=4.14.355-287.769.amzn2"},
		{"kernel", "4.14.355-287.770.amzn2", "ALAS2KERNEL-5.10-1=- ALAS2KERNEL-5.10-2022-020=- ALAS2KERNEL-5.4-1=5.4.20-12.75.amzn2 ALAS2KERNEL-5.4-2=5.4.302-229.517.amzn2"},
		// One line side by side: overlapping spans cut nothing.
		{"docker", "23.0-1.amzn2", "ALAS2DOCKER-2=25.0-1.amzn2 ALAS2ECS-1=24.0-1.amzn2"},
	} {
		var got []string
		for _, a := range advs {
			for _, aff := range a.Affected {
				if aff.Name != tc.name {
					continue
				}
				hit, ev, _, err := version.AffectsVersion(version.RPM{}, tc.installed, aff)
				if err != nil {
					t.Fatalf("%s %s: %v", tc.name, tc.installed, err)
				}
				if hit {
					fix := ev.Fixed
					if fix == "" {
						fix = "-"
					}
					got = append(got, a.ID+"="+fix)
				}
			}
		}
		sort.Strings(got)
		want := strings.Fields(tc.want)
		sort.Strings(want)
		if strings.Join(got, " ") != strings.Join(want, " ") {
			t.Errorf("%s %s:\n got %v\nwant %v", tc.name, tc.installed, got, want)
		}
	}
	if !strings.Contains(log.String(), "narrowed to their own version line") {
		t.Errorf("the build log does not say what was narrowed:\n%s", log.String())
	}
}

func lineRec(repo int, eco, fixed string) collected {
	return collected{repo: repo, adv: advisory.Advisory{Affected: []advisory.Affected{{Ecosystem: eco, Name: "x",
		Ranges: []advisory.Range{{Events: []advisory.Event{{Introduced: "0"}, {Fixed: fixed}}}}}}}}
}

// Spans that overlap are cut as one, in any order the repositories were read.
func TestSeparateLines_OverlappingSpansBelow(t *testing.T) {
	for n := 0; n < 20; n++ { // the spans are held in a map
		recs := []collected{
			lineRec(0, linesKey, "9.0-1"),
			lineRec(1, linesKey, "4.0-1"), lineRec(1, linesKey, "2.0-1"), // [2, 4]
			lineRec(2, linesKey, "3.0-1"), lineRec(2, linesKey, "5.0-1"), // [3, 5]
			lineRec(3, linesKey, "3.5-1"),                                // inside both
			lineRec(4, linesKey, "7.0-1"),                                // apart
			lineRec(5, linesKey, "1.5-1"),                                // apart, lowest
		}
		if _, err := separateLines(recs); err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, e := range recs[0].adv.Affected[0].Ranges[0].Events {
			got = append(got, e.Introduced+e.LastAffected+e.Fixed)
		}
		if s := strings.Join(got, " "); s != "0 1.5-1~ 1.5-1^ 2.0-1~ 5.0-1^ 7.0-1~ 7.0-1^ 9.0-1" {
			t.Fatalf("events %s", s)
		}
	}
}

// Only AL2, and a record a comparison cannot read is an error.
func TestSeparateLines_Scope(t *testing.T) {
	recs := []collected{lineRec(0, "Amazon Linux:2023", "9.0-1"), lineRec(1, "Amazon Linux:2023", "2.0-1")}
	if n, err := separateLines(recs); err != nil || n != 0 || len(recs[0].adv.Affected[0].Ranges[0].Events) != 2 {
		t.Errorf("AL2023: %d narrowed, %v", n, err)
	}
	one := []collected{lineRec(0, linesKey, "9.0-1"), lineRec(0, linesKey, "2.0-1")}
	if n, err := separateLines(one); err != nil || n != 0 {
		t.Errorf("one repository: %d narrowed, %v", n, err)
	}
}
